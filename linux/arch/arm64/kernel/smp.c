// SPDX-License-Identifier: GPL-2.0-only
/*
 * SMP initialisation and IPI support
 * Based on arch/arm/kernel/smp.c
 *
 * Copyright (C) 2012 ARM Ltd.
 */

#include <linux/acpi.h>
#include <linux/arm_sdei.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/sched/mm.h>
#include <linux/sched/hotplug.h>
#include <linux/sched/task_stack.h>
#include <linux/interrupt.h>
#include <linux/cache.h>
#include <linux/profile.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/err.h>
#include <linux/cpu.h>
#include <linux/smp.h>
#include <linux/seq_file.h>
#include <linux/irq.h>
#include <linux/irqchip/arm-gic-v3.h>
#include <linux/percpu.h>
#include <linux/clockchips.h>
#include <linux/completion.h>
#include <linux/of.h>
#include <linux/irq_work.h>
#include <linux/kernel_stat.h>
#include <linux/kexec.h>
#include <linux/kvm_host.h>

#include <asm/alternative.h>
#include <asm/atomic.h>
#include <asm/cacheflush.h>
#include <asm/cpu.h>
#include <asm/cputype.h>
#include <asm/cpu_ops.h>
#include <asm/daifflags.h>
#include <asm/kvm_mmu.h>
#include <asm/mmu_context.h>
#include <asm/numa.h>
#include <asm/processor.h>
#include <asm/smp_plat.h>
#include <asm/sections.h>
#include <asm/tlbflush.h>
#include <asm/ptrace.h>
#include <asm/virt.h>

#define CREATE_TRACE_POINTS
#include <trace/events/ipi.h>

DEFINE_PER_CPU_READ_MOSTLY(int, cpu_number);
EXPORT_PER_CPU_SYMBOL(cpu_number);

/*
 * as from 2.5, kernels no longer have an init_tasks structure
 * so we need some other way of telling a new secondary core
 * where to place its SVC stack
 */
struct secondary_data secondary_data;
/* Number of CPUs which aren't online, but looping in kernel text. */
static int cpus_stuck_in_kernel;

enum ipi_msg_type {
	IPI_RESCHEDULE,
	IPI_CALL_FUNC,
	IPI_CPU_STOP,
	IPI_CPU_CRASH_STOP,
	IPI_TIMER,
	IPI_IRQ_WORK,
	IPI_WAKEUP,
	NR_IPI
};

static int ipi_irq_base __read_mostly;
static int nr_ipi __read_mostly = NR_IPI;
static struct irq_desc *ipi_desc[NR_IPI] __read_mostly;

static void ipi_setup(int cpu);

static inline int op_cpu_kill(unsigned int cpu)
{
	return -ENOSYS;
}

/*
 * Boot a secondary CPU, and assign it the specified idle task.
 * This also gives us the initial stack to use for this CPU.
 */
static int boot_secondary(unsigned int cpu, struct task_struct *idle)
{
	const struct cpu_operations *ops = get_cpu_ops(cpu);

	if (ops->cpu_boot)
		return ops->cpu_boot(cpu);

	return -EOPNOTSUPP;
}

static DECLARE_COMPLETION(cpu_running);

int __cpu_up(unsigned int cpu, struct task_struct *idle)
{
	int ret;
	long status;

	/*
	 * We need to tell the secondary core where to find its stack and the
	 * page tables.
	 */
	secondary_data.task = idle;
	secondary_data.stack = task_stack_page(idle) + THREAD_SIZE;
	update_cpu_boot_status(CPU_MMU_OFF);
	__flush_dcache_area(&secondary_data, sizeof(secondary_data));

	/* Now bring the CPU into our world */
	ret = boot_secondary(cpu, idle);
	if (ret) {
		pr_err("CPU%u: failed to boot: %d\n", cpu, ret);
		return ret;
	}

	/*
	 * CPU was successfully started, wait for it to come online or
	 * time out.
	 */
	wait_for_completion_timeout(&cpu_running,
				    msecs_to_jiffies(5000));
	if (cpu_online(cpu))
		return 0;

	pr_crit("CPU%u: failed to come online\n", cpu);
	secondary_data.task = NULL;
	secondary_data.stack = NULL;
	__flush_dcache_area(&secondary_data, sizeof(secondary_data));
	status = READ_ONCE(secondary_data.status);
	if (status == CPU_MMU_OFF)
		status = READ_ONCE(__early_cpu_boot_status);

	switch (status & CPU_BOOT_STATUS_MASK) {
	default:
		pr_err("CPU%u: failed in unknown state : 0x%lx\n",
		       cpu, status);
		cpus_stuck_in_kernel++;
		break;
	case CPU_KILL_ME:
		if (!op_cpu_kill(cpu)) {
			pr_crit("CPU%u: died during early boot\n", cpu);
			break;
		}
		pr_crit("CPU%u: may not have shut down cleanly\n", cpu);
		fallthrough;
	case CPU_STUCK_IN_KERNEL:
		pr_crit("CPU%u: is stuck in kernel\n", cpu);
		if (status & CPU_STUCK_REASON_52_BIT_VA)
			pr_crit("CPU%u: does not support 52-bit VAs\n", cpu);
		if (status & CPU_STUCK_REASON_NO_GRAN) {
			pr_crit("CPU%u: does not support %luK granule\n",
				cpu, PAGE_SIZE / SZ_1K);
		}
		cpus_stuck_in_kernel++;
		break;
	case CPU_PANIC_KERNEL:
		panic("CPU%u detected unsupported configuration\n", cpu);
	}

	return -EIO;
}

static void init_gic_priority_masking(void)
{
	u32 cpuflags;

	if (WARN_ON(!gic_enable_sre()))
		return;

	cpuflags = read_sysreg(daif);

	WARN_ON(!(cpuflags & PSR_I_BIT));

	gic_write_pmr(GIC_PRIO_IRQON | GIC_PRIO_PSR_I_SET);
}

/*
 * This is the secondary CPU boot entry.  We're using this CPUs
 * idle thread stack, but a set of temporary page tables.
 */
asmlinkage notrace void secondary_start_kernel(void)
{
	u64 mpidr = read_cpuid_mpidr() & MPIDR_HWID_BITMASK;
	struct mm_struct *mm = &init_mm;
	const struct cpu_operations *ops;
	unsigned int cpu;

	cpu = task_cpu(current);
	set_my_cpu_offset(per_cpu_offset(cpu));

	/*
	 * All kernel threads share the same mm context; grab a
	 * reference and switch to it.
	 */
	mmgrab(mm);
	current->active_mm = mm;

	/*
	 * TTBR0 is only used for the identity mapping at this stage. Make it
	 * point to zero page to avoid speculatively fetching new entries.
	 */
	cpu_uninstall_idmap();

	if (system_uses_irq_prio_masking())
		init_gic_priority_masking();

	rcu_cpu_starting(cpu);

	/*
	 * If the system has established the capabilities, make sure
	 * this CPU ticks all of those. If it doesn't, the CPU will
	 * fail to come online.
	 */
	check_local_cpu_capabilities();

	ops = get_cpu_ops(cpu);
	if (ops->cpu_postboot)
		ops->cpu_postboot();

	/*
	 * Log the CPU info before it is marked online and might get read.
	 */
	cpuinfo_store_cpu();

	/*
	 * Enable GIC and timers.
	 */
	notify_cpu_starting(cpu);

	ipi_setup(cpu);

	store_cpu_topology(cpu);
	numa_add_cpu(cpu);

	/*
	 * OK, now it's safe to let the boot CPU continue.  Wait for
	 * the CPU migration code to notice that the CPU is online
	 * before we continue.
	 */
	pr_info("CPU%u: Booted secondary processor 0x%010lx [0x%08x]\n",
					 cpu, (unsigned long)mpidr,
					 read_cpuid_id());
	update_cpu_boot_status(CPU_BOOT_SUCCESS);
	set_cpu_online(cpu, true);
	complete(&cpu_running);

	local_daif_restore(DAIF_PROCCTX);

	/*
	 * OK, it's off to the idle thread for us
	 */
	cpu_startup_entry(CPUHP_AP_ONLINE_IDLE);
}

/*
 * Kill the calling secondary CPU, early in bringup before it is turned
 * online.
 */
void cpu_die_early(void)
{
	int cpu = smp_processor_id();

	pr_crit("CPU%d: will not boot\n", cpu);

	/* Mark this CPU absent */
	set_cpu_present(cpu, 0);
	rcu_report_dead(cpu);

	update_cpu_boot_status(CPU_STUCK_IN_KERNEL);

	cpu_park_loop();
}

static void __init hyp_mode_check(void)
{
	if (is_hyp_mode_available())
		pr_info("CPU: All CPU(s) started at EL2\n");
	else if (is_hyp_mode_mismatched())
		WARN_TAINT(1, TAINT_CPU_OUT_OF_SPEC,
			   "CPU: CPUs started in inconsistent modes");
	else
		pr_info("CPU: All CPU(s) started at EL1\n");
	if (IS_ENABLED(CONFIG_KVM))
		kvm_compute_layout();
}

void __init smp_cpus_done(unsigned int max_cpus)
{
	pr_info("SMP: Total of %d processors activated.\n", num_online_cpus());
	setup_cpu_features();
	hyp_mode_check();
	apply_alternatives_all();
	mark_linear_text_alias_ro();
}

void __init smp_prepare_boot_cpu(void)
{
	set_my_cpu_offset(per_cpu_offset(smp_processor_id()));
	cpuinfo_store_boot_cpu();

	/*
	 * We now know enough about the boot CPU to apply the
	 * alternatives that cannot wait until interrupt handling
	 * and/or scheduling is enabled.
	 */
	apply_boot_alternatives();

	/* Conditionally switch to GIC PMR for interrupt masking */
	if (system_uses_irq_prio_masking())
		init_gic_priority_masking();
}

static u64 __init of_get_cpu_mpidr(struct device_node *dn)
{
	const __be32 *cell;
	u64 hwid;

	/*
	 * A cpu node with missing "reg" property is
	 * considered invalid to build a cpu_logical_map
	 * entry.
	 */
	cell = of_get_property(dn, "reg", NULL);
	if (!cell) {
		pr_err("%pOF: missing reg property\n", dn);
		return INVALID_HWID;
	}

	hwid = of_read_number(cell, of_n_addr_cells(dn));
	/*
	 * Non affinity bits must be set to 0 in the DT
	 */
	if (hwid & ~MPIDR_HWID_BITMASK) {
		pr_err("%pOF: invalid reg property\n", dn);
		return INVALID_HWID;
	}
	return hwid;
}

/*
 * Duplicate MPIDRs are a recipe for disaster. Scan all initialized
 * entries and check for duplicates. If any is found just ignore the
 * cpu. cpu_logical_map was initialized to INVALID_HWID to avoid
 * matching valid MPIDR values.
 */
static bool __init is_mpidr_duplicate(unsigned int cpu, u64 hwid)
{
	unsigned int i;

	for (i = 1; (i < cpu) && (i < NR_CPUS); i++)
		if (cpu_logical_map(i) == hwid)
			return true;
	return false;
}

/*
 * Initialize cpu operations for a logical cpu and
 * set it in the possible mask on success
 */
static int __init smp_cpu_setup(int cpu)
{
	const struct cpu_operations *ops;

	if (init_cpu_ops(cpu))
		return -ENODEV;

	ops = get_cpu_ops(cpu);
	if (ops->cpu_init(cpu))
		return -ENODEV;

	set_cpu_possible(cpu, true);

	return 0;
}

static bool bootcpu_valid __initdata;
static unsigned int cpu_count = 1;

/*
 * Enumerate the possible CPU set from the device tree and build the
 * cpu logical map array containing MPIDR values related to logical
 * cpus. Assumes that cpu_logical_map(0) has already been initialized.
 */
static void __init of_parse_and_init_cpus(void)
{
	struct device_node *dn;

	for_each_of_cpu_node(dn) {
		u64 hwid = of_get_cpu_mpidr(dn);

		if (hwid == INVALID_HWID)
			goto next;

		if (is_mpidr_duplicate(cpu_count, hwid)) {
			pr_err("%pOF: duplicate cpu reg properties in the DT\n",
				dn);
			goto next;
		}

		/*
		 * The numbering scheme requires that the boot CPU
		 * must be assigned logical id 0. Record it so that
		 * the logical map built from DT is validated and can
		 * be used.
		 */
		if (hwid == cpu_logical_map(0)) {
			if (bootcpu_valid) {
				pr_err("%pOF: duplicate boot cpu reg property in DT\n",
					dn);
				goto next;
			}

			bootcpu_valid = true;
			early_map_cpu_to_node(0, of_node_to_nid(dn));

			/*
			 * cpu_logical_map has already been
			 * initialized and the boot cpu doesn't need
			 * the enable-method so continue without
			 * incrementing cpu.
			 */
			continue;
		}

		if (cpu_count >= NR_CPUS)
			goto next;

		pr_debug("cpu logical map 0x%llx\n", hwid);
		set_cpu_logical_map(cpu_count, hwid);

		early_map_cpu_to_node(cpu_count, of_node_to_nid(dn));
next:
		cpu_count++;
	}
}

/*
 * Enumerate the possible CPU set from the device tree or ACPI and build the
 * cpu logical map array containing MPIDR values related to logical
 * cpus. Assumes that cpu_logical_map(0) has already been initialized.
 */
void __init smp_init_cpus(void)
{
	int i;

	if (acpi_disabled)
		of_parse_and_init_cpus();

	if (cpu_count > nr_cpu_ids)
		pr_warn("Number of cores (%d) exceeds configured maximum of %u - clipping\n",
			cpu_count, nr_cpu_ids);

	if (!bootcpu_valid) {
		pr_err("missing boot CPU MPIDR, not enabling secondaries\n");
		return;
	}

	/*
	 * We need to set the cpu_logical_map entries before enabling
	 * the cpus so that cpu processor description entries (DT cpu nodes
	 * and ACPI MADT entries) can be retrieved by matching the cpu hwid
	 * with entries in cpu_logical_map while initializing the cpus.
	 * If the cpu set-up fails, invalidate the cpu_logical_map entry.
	 */
	for (i = 1; i < nr_cpu_ids; i++) {
		if (cpu_logical_map(i) != INVALID_HWID) {
			if (smp_cpu_setup(i))
				set_cpu_logical_map(i, INVALID_HWID);
		}
	}
}

void __init smp_prepare_cpus(unsigned int max_cpus)
{
	const struct cpu_operations *ops;
	int err;
	unsigned int cpu;
	unsigned int this_cpu;

	init_cpu_topology();

	this_cpu = smp_processor_id();
	store_cpu_topology(this_cpu);
	numa_store_cpu_info(this_cpu);
	numa_add_cpu(this_cpu);

	/*
	 * If UP is mandated by "nosmp" (which implies "maxcpus=0"), don't set
	 * secondary CPUs present.
	 */
	if (max_cpus == 0)
		return;

	/*
	 * Initialise the present map (which describes the set of CPUs
	 * actually populated at the present time) and release the
	 * secondaries from the bootloader.
	 */
	for_each_possible_cpu(cpu) {

		per_cpu(cpu_number, cpu) = cpu;

		if (cpu == smp_processor_id())
			continue;

		ops = get_cpu_ops(cpu);
		if (!ops)
			continue;

		err = ops->cpu_prepare(cpu);
		if (err)
			continue;

		set_cpu_present(cpu, true);
		numa_store_cpu_info(cpu);
	}
}

static const char *ipi_types[NR_IPI] = {
#define S(x,s)	[x] = s
	S(IPI_RESCHEDULE, "Rescheduling interrupts"),
	S(IPI_CALL_FUNC, "Function call interrupts"),
	S(IPI_CPU_STOP, "CPU stop interrupts"),
	S(IPI_CPU_CRASH_STOP, "CPU stop (for crash dump) interrupts"),
	S(IPI_TIMER, "Timer broadcast interrupts"),
	S(IPI_IRQ_WORK, "IRQ work interrupts"),
	S(IPI_WAKEUP, "CPU wake-up interrupts"),
};

static void smp_cross_call(const struct cpumask *target, unsigned int ipinr);

unsigned long irq_err_count;

int arch_show_interrupts(struct seq_file *p, int prec)
{
	unsigned int cpu, i;

	for (i = 0; i < NR_IPI; i++) {
		unsigned int irq = irq_desc_get_irq(ipi_desc[i]);
		seq_printf(p, "%*s%u:%s", prec - 1, "IPI", i,
			   prec >= 4 ? " " : "");
		for_each_online_cpu(cpu)
			seq_printf(p, "%10u ", kstat_irqs_cpu(irq, cpu));
		seq_printf(p, "      %s\n", ipi_types[i]);
	}

	seq_printf(p, "%*s: %10lu\n", prec, "Err", irq_err_count);
	return 0;
}

void arch_send_call_function_ipi_mask(const struct cpumask *mask)
{
	smp_cross_call(mask, IPI_CALL_FUNC);
}

void arch_send_call_function_single_ipi(int cpu)
{
	smp_cross_call(cpumask_of(cpu), IPI_CALL_FUNC);
}

#ifdef CONFIG_IRQ_WORK
void arch_irq_work_raise(void)
{
	smp_cross_call(cpumask_of(smp_processor_id()), IPI_IRQ_WORK);
}
#endif

static void local_cpu_stop(void)
{
	set_cpu_online(smp_processor_id(), false);

	local_daif_mask();
	sdei_mask_local_cpu();
	cpu_park_loop();
}

/*
 * We need to implement panic_smp_self_stop() for parallel panic() calls, so
 * that cpu_online_mask gets correctly updated and smp_send_stop() can skip
 * CPUs that have already stopped themselves.
 */
void panic_smp_self_stop(void)
{
	local_cpu_stop();
}

/*
 * Main handler for inter-processor interrupts
 */
static void do_handle_IPI(int ipinr)
{
	unsigned int cpu = smp_processor_id();

	switch (ipinr) {
	case IPI_RESCHEDULE:
		scheduler_ipi();
		break;

	case IPI_CALL_FUNC:
		generic_smp_call_function_interrupt();
		break;

	case IPI_CPU_STOP:
		local_cpu_stop();
		break;

	case IPI_CPU_CRASH_STOP:
		break;

#ifdef CONFIG_GENERIC_CLOCKEVENTS_BROADCAST
	case IPI_TIMER:
		tick_receive_broadcast();
		break;
#endif

#ifdef CONFIG_IRQ_WORK
	case IPI_IRQ_WORK:
		irq_work_run();
		break;
#endif

	default:
		pr_crit("CPU%u: Unknown IPI message 0x%x\n", cpu, ipinr);
		break;
	}

}

static irqreturn_t ipi_handler(int irq, void *data)
{
	do_handle_IPI(irq - ipi_irq_base);
	return IRQ_HANDLED;
}

static void smp_cross_call(const struct cpumask *target, unsigned int ipinr)
{
	__ipi_send_mask(ipi_desc[ipinr], target);
}

static void ipi_setup(int cpu)
{
	int i;

	if (WARN_ON_ONCE(!ipi_irq_base))
		return;

	for (i = 0; i < nr_ipi; i++)
		enable_percpu_irq(ipi_irq_base + i, 0);
}

void __init set_smp_ipi_range(int ipi_base, int n)
{
	int i;

	WARN_ON(n < NR_IPI);
	nr_ipi = min(n, NR_IPI);

	for (i = 0; i < nr_ipi; i++) {
		int err;

		err = request_percpu_irq(ipi_base + i, ipi_handler,
					 "IPI", &cpu_number);
		WARN_ON(err);

		ipi_desc[i] = irq_to_desc(ipi_base + i);
		irq_set_status_flags(ipi_base + i, IRQ_HIDDEN);
	}

	ipi_irq_base = ipi_base;

	/* Setup the boot CPU immediately */
	ipi_setup(smp_processor_id());
}

void smp_send_reschedule(int cpu)
{
	smp_cross_call(cpumask_of(cpu), IPI_RESCHEDULE);
}

#ifdef CONFIG_GENERIC_CLOCKEVENTS_BROADCAST
void tick_broadcast(const struct cpumask *mask)
{
	smp_cross_call(mask, IPI_TIMER);
}
#endif

/*
 * The number of CPUs online, not counting this CPU (which may not be
 * fully online and so not counted in num_online_cpus()).
 */
static inline unsigned int num_other_online_cpus(void)
{
	unsigned int this_cpu_online = cpu_online(smp_processor_id());

	return num_online_cpus() - this_cpu_online;
}

void smp_send_stop(void)
{
	unsigned long timeout;

	if (num_other_online_cpus()) {
		cpumask_t mask;

		cpumask_copy(&mask, cpu_online_mask);
		cpumask_clear_cpu(smp_processor_id(), &mask);

		if (system_state <= SYSTEM_RUNNING)
			pr_crit("SMP: stopping secondary CPUs\n");
		smp_cross_call(&mask, IPI_CPU_STOP);
	}

	/* Wait up to one second for other CPUs to stop */
	timeout = USEC_PER_SEC;
	while (num_other_online_cpus() && timeout--)
		udelay(1);

	if (num_other_online_cpus())
		pr_warn("SMP: failed to stop secondary CPUs %*pbl\n",
			cpumask_pr_args(cpu_online_mask));

	sdei_mask_local_cpu();
}

/*
 * not supported here
 */
int setup_profiling_timer(unsigned int multiplier)
{
	return -EINVAL;
}

static bool have_cpu_die(void)
{
	return false;
}

bool cpus_are_stuck_in_kernel(void)
{
	bool smp_spin_tables = (num_possible_cpus() > 1 && !have_cpu_die());

	return !!cpus_stuck_in_kernel || smp_spin_tables;
}
