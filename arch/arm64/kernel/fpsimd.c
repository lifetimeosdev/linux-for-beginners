// SPDX-License-Identifier: GPL-2.0-only
/*
 * FP/SIMD context switching and fault handling
 *
 * Copyright (C) 2012 ARM Ltd.
 * Author: Catalin Marinas <catalin.marinas@arm.com>
 */

#include <linux/bitmap.h>
#include <linux/bitops.h>
#include <linux/bottom_half.h>
#include <linux/bug.h>
#include <linux/cache.h>
#include <linux/compat.h>
#include <linux/compiler.h>
#include <linux/cpu.h>
#include <linux/cpu_pm.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/irqflags.h>
#include <linux/init.h>
#include <linux/percpu.h>
#include <linux/prctl.h>
#include <linux/preempt.h>
#include <linux/ptrace.h>
#include <linux/sched/signal.h>
#include <linux/sched/task_stack.h>
#include <linux/signal.h>
#include <linux/slab.h>
#include <linux/stddef.h>
#include <linux/sysctl.h>
#include <linux/swab.h>

#include <asm/esr.h>
#include <asm/exception.h>
#include <asm/fpsimd.h>
#include <asm/cpufeature.h>
#include <asm/cputype.h>
#include <asm/neon.h>
#include <asm/processor.h>
#include <asm/simd.h>
#include <asm/sigcontext.h>
#include <asm/sysreg.h>
#include <asm/traps.h>
#include <asm/virt.h>

#define FPEXC_IOF	(1 << 0)
#define FPEXC_DZF	(1 << 1)
#define FPEXC_OFF	(1 << 2)
#define FPEXC_UFF	(1 << 3)
#define FPEXC_IXF	(1 << 4)
#define FPEXC_IDF	(1 << 7)

/*
 * (Note: in this discussion, statements about FPSIMD apply equally to SVE.)
 *
 * In order to reduce the number of times the FPSIMD state is needlessly saved
 * and restored, we need to keep track of two things:
 * (a) for each task, we need to remember which CPU was the last one to have
 *     the task's FPSIMD state loaded into its FPSIMD registers;
 * (b) for each CPU, we need to remember which task's userland FPSIMD state has
 *     been loaded into its FPSIMD registers most recently, or whether it has
 *     been used to perform kernel mode NEON in the meantime.
 *
 * For (a), we add a fpsimd_cpu field to thread_struct, which gets updated to
 * the id of the current CPU every time the state is loaded onto a CPU. For (b),
 * we add the per-cpu variable 'fpsimd_last_state' (below), which contains the
 * address of the userland FPSIMD state of the task that was loaded onto the CPU
 * the most recently, or NULL if kernel mode NEON has been performed after that.
 *
 * With this in place, we no longer have to restore the next FPSIMD state right
 * when switching between tasks. Instead, we can defer this check to userland
 * resume, at which time we verify whether the CPU's fpsimd_last_state and the
 * task's fpsimd_cpu are still mutually in sync. If this is the case, we
 * can omit the FPSIMD restore.
 *
 * As an optimization, we use the thread_info flag TIF_FOREIGN_FPSTATE to
 * indicate whether or not the userland FPSIMD state of the current task is
 * present in the registers. The flag is set unless the FPSIMD registers of this
 * CPU currently contain the most recent userland FPSIMD state of the current
 * task.
 *
 * In order to allow softirq handlers to use FPSIMD, kernel_neon_begin() may
 * save the task's FPSIMD context back to task_struct from softirq context.
 * To prevent this from racing with the manipulation of the task's FPSIMD state
 * from task context and thereby corrupting the state, it is necessary to
 * protect any manipulation of a task's fpsimd_state or TIF_FOREIGN_FPSTATE
 * flag with {, __}get_cpu_fpsimd_context(). This will still allow softirqs to
 * run but prevent them to use FPSIMD.
 *
 * For a certain task, the sequence may look something like this:
 * - the task gets scheduled in; if both the task's fpsimd_cpu field
 *   contains the id of the current CPU, and the CPU's fpsimd_last_state per-cpu
 *   variable points to the task's fpsimd_state, the TIF_FOREIGN_FPSTATE flag is
 *   cleared, otherwise it is set;
 *
 * - the task returns to userland; if TIF_FOREIGN_FPSTATE is set, the task's
 *   userland FPSIMD state is copied from memory to the registers, the task's
 *   fpsimd_cpu field is set to the id of the current CPU, the current
 *   CPU's fpsimd_last_state pointer is set to this task's fpsimd_state and the
 *   TIF_FOREIGN_FPSTATE flag is cleared;
 *
 * - the task executes an ordinary syscall; upon return to userland, the
 *   TIF_FOREIGN_FPSTATE flag will still be cleared, so no FPSIMD state is
 *   restored;
 *
 * - the task executes a syscall which executes some NEON instructions; this is
 *   preceded by a call to kernel_neon_begin(), which copies the task's FPSIMD
 *   register contents to memory, clears the fpsimd_last_state per-cpu variable
 *   and sets the TIF_FOREIGN_FPSTATE flag;
 *
 * - the task gets preempted after kernel_neon_end() is called; as we have not
 *   returned from the 2nd syscall yet, TIF_FOREIGN_FPSTATE is still set so
 *   whatever is in the FPSIMD registers is not saved to memory, but discarded.
 */
struct fpsimd_last_state_struct {
	struct user_fpsimd_state *st;
	void *sve_state;
	unsigned int sve_vl;
};

static DEFINE_PER_CPU(struct fpsimd_last_state_struct, fpsimd_last_state);

/* Default VL for tasks that don't set it explicitly: */
// static int __sve_default_vl = -1;

// static int get_sve_default_vl(void)
// {
// 	return READ_ONCE(__sve_default_vl);
// }

/* Dummy declaration for code that will be optimised out: */
extern __ro_after_init DECLARE_BITMAP(sve_vq_map, SVE_VQ_MAX);
extern __ro_after_init DECLARE_BITMAP(sve_vq_partial_map, SVE_VQ_MAX);
extern void __percpu *efi_sve_state;

DEFINE_PER_CPU(bool, fpsimd_context_busy);
EXPORT_PER_CPU_SYMBOL(fpsimd_context_busy);

static void __get_cpu_fpsimd_context(void)
{
	bool busy = __this_cpu_xchg(fpsimd_context_busy, true);

	WARN_ON(busy);
}

/*
 * Claim ownership of the CPU FPSIMD context for use by the calling context.
 *
 * The caller may freely manipulate the FPSIMD context metadata until
 * put_cpu_fpsimd_context() is called.
 *
 * The double-underscore version must only be called if you know the task
 * can't be preempted.
 */
static void get_cpu_fpsimd_context(void)
{
	preempt_disable();
	__get_cpu_fpsimd_context();
}

static void __put_cpu_fpsimd_context(void)
{
	bool busy = __this_cpu_xchg(fpsimd_context_busy, false);

	WARN_ON(!busy); /* No matching get_cpu_fpsimd_context()? */
}

/*
 * Release the CPU FPSIMD context.
 *
 * Must be called from a context in which get_cpu_fpsimd_context() was
 * previously called, with no call to put_cpu_fpsimd_context() in the
 * meantime.
 */
static void put_cpu_fpsimd_context(void)
{
	__put_cpu_fpsimd_context();
	preempt_enable();
}

static bool have_cpu_fpsimd_context(void)
{
	return !preemptible() && __this_cpu_read(fpsimd_context_busy);
}

/*
 * Call __sve_free() directly only if you know task can't be scheduled
 * or preempted.
 */
// static void __sve_free(struct task_struct *task)
// {
// 	kfree(task->thread.sve_state);
// 	task->thread.sve_state = NULL;
// }

// static void sve_free(struct task_struct *task)
// {
// 	WARN_ON(test_tsk_thread_flag(task, TIF_SVE));

// 	__sve_free(task);
// }

/*
 * TIF_SVE controls whether a task can use SVE without trapping while
 * in userspace, and also the way a task's FPSIMD/SVE state is stored
 * in thread_struct.
 *
 * The kernel uses this flag to track whether a user task is actively
 * using SVE, and therefore whether full SVE register state needs to
 * be tracked.  If not, the cheaper FPSIMD context handling code can
 * be used instead of the more costly SVE equivalents.
 *
 *  * TIF_SVE set:
 *
 *    The task can execute SVE instructions while in userspace without
 *    trapping to the kernel.
 *
 *    When stored, Z0-Z31 (incorporating Vn in bits[127:0] or the
 *    corresponding Zn), P0-P15 and FFR are encoded in in
 *    task->thread.sve_state, formatted appropriately for vector
 *    length task->thread.sve_vl.
 *
 *    task->thread.sve_state must point to a valid buffer at least
 *    sve_state_size(task) bytes in size.
 *
 *    During any syscall, the kernel may optionally clear TIF_SVE and
 *    discard the vector state except for the FPSIMD subset.
 *
 *  * TIF_SVE clear:
 *
 *    An attempt by the user task to execute an SVE instruction causes
 *    do_sve_acc() to be called, which does some preparation and then
 *    sets TIF_SVE.
 *
 *    When stored, FPSIMD registers V0-V31 are encoded in
 *    task->thread.uw.fpsimd_state; bits [max : 128] for each of Z0-Z31 are
 *    logically zero but not stored anywhere; P0-P15 and FFR are not
 *    stored and have unspecified values from userspace's point of
 *    view.  For hygiene purposes, the kernel zeroes them on next use,
 *    but userspace is discouraged from relying on this.
 *
 *    task->thread.sve_state does not need to be non-NULL, valid or any
 *    particular size: it must not be dereferenced.
 *
 *  * FPSR and FPCR are always stored in task->thread.uw.fpsimd_state
 *    irrespective of whether TIF_SVE is clear or set, since these are
 *    not vector length dependent.
 */

/*
 * Update current's FPSIMD/SVE registers from thread_struct.
 *
 * This function should be called only when the FPSIMD/SVE state in
 * thread_struct is known to be up to date, when preparing to enter
 * userspace.
 */
static void task_fpsimd_load(void)
{
	WARN_ON(!system_supports_fpsimd());
	WARN_ON(!have_cpu_fpsimd_context());

	// if (system_supports_sve() && test_thread_flag(TIF_SVE))
	// 	sve_load_state(sve_pffr(&current->thread),
	// 		       &current->thread.uw.fpsimd_state.fpsr,
	// 		       sve_vq_from_vl(current->thread.sve_vl) - 1);
	// else
		fpsimd_load_state(&current->thread.uw.fpsimd_state);
}

/*
 * Ensure FPSIMD/SVE storage in memory for the loaded context is up to
 * date with respect to the CPU registers.
 */
static void fpsimd_save(void)
{
	struct fpsimd_last_state_struct const *last =
		this_cpu_ptr(&fpsimd_last_state);
	/* set by fpsimd_bind_task_to_cpu() or fpsimd_bind_state_to_cpu() */

	WARN_ON(!system_supports_fpsimd());
	WARN_ON(!have_cpu_fpsimd_context());

	if (!test_thread_flag(TIF_FOREIGN_FPSTATE)) {
		// if (system_supports_sve() && test_thread_flag(TIF_SVE)) {
		// 	if (WARN_ON(sve_get_vl() != last->sve_vl)) {
		// 		/*
		// 		 * Can't save the user regs, so current would
		// 		 * re-enter user with corrupt state.
		// 		 * There's no way to recover, so kill it:
		// 		 */
		// 		force_signal_inject(SIGKILL, SI_KERNEL, 0, 0);
		// 		return;
		// 	}

		// 	sve_save_state((char *)last->sve_state +
		// 				sve_ffr_offset(last->sve_vl),
		// 		       &last->st->fpsr);
		// } else
			fpsimd_save_state(last->st);
	}
}

/*
 * All vector length selection from userspace comes through here.
 * We're on a slow path, so some sanity-checks are included.
 * If things go wrong there's a bug somewhere, but try to fall back to a
 * safe choice.
 */
// static unsigned int find_supported_vector_length(unsigned int vl)
// {
// 	int bit;
// 	int max_vl = sve_max_vl;

// 	if (WARN_ON(!sve_vl_valid(vl)))
// 		vl = SVE_VL_MIN;

// 	if (WARN_ON(!sve_vl_valid(max_vl)))
// 		max_vl = SVE_VL_MIN;

// 	if (vl > max_vl)
// 		vl = max_vl;

// 	bit = find_next_bit(sve_vq_map, SVE_VQ_MAX,
// 			    __vq_to_bit(sve_vq_from_vl(vl)));
// 	return sve_vl_from_vq(__bit_to_vq(bit));
// }

#if defined(CONFIG_ARM64_SVE) && defined(CONFIG_SYSCTL)

static int sve_proc_do_default_vl(struct ctl_table *table, int write,
				  void *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;
	int vl = get_sve_default_vl();
	struct ctl_table tmp_table = {
		.data = &vl,
		.maxlen = sizeof(vl),
	};

	ret = proc_dointvec(&tmp_table, write, buffer, lenp, ppos);
	if (ret || !write)
		return ret;

	/* Writing -1 has the special meaning "set to max": */
	if (vl == -1)
		vl = sve_max_vl;

	if (!sve_vl_valid(vl))
		return -EINVAL;

	set_sve_default_vl(find_supported_vector_length(vl));
	return 0;
}

static struct ctl_table sve_default_vl_table[] = {
	{
		.procname	= "sve_default_vector_length",
		.mode		= 0644,
		.proc_handler	= sve_proc_do_default_vl,
	},
	{ }
};

static int __init sve_sysctl_init(void)
{
	if (system_supports_sve())
		if (!register_sysctl("abi", sve_default_vl_table))
			return -EINVAL;

	return 0;
}

#else /* ! (CONFIG_ARM64_SVE && CONFIG_SYSCTL) */
static int __init sve_sysctl_init(void) { return 0; }
#endif /* ! (CONFIG_ARM64_SVE && CONFIG_SYSCTL) */

#define ZREG(sve_state, vq, n) ((char *)(sve_state) +		\
	(SVE_SIG_ZREG_OFFSET(vq, n) - SVE_SIG_REGS_OFFSET))

static __uint128_t arm64_cpu_to_le128(__uint128_t x)
{
	return x;
}

#define arm64_le128_to_cpu(x) arm64_cpu_to_le128(x)

static void __fpsimd_to_sve(void *sst, struct user_fpsimd_state const *fst,
			    unsigned int vq)
{
	unsigned int i;
	__uint128_t *p;

	for (i = 0; i < SVE_NUM_ZREGS; ++i) {
		p = (__uint128_t *)ZREG(sst, vq, i);
		*p = arm64_cpu_to_le128(fst->vregs[i]);
	}
}

/*
 * Transfer the FPSIMD state in task->thread.uw.fpsimd_state to
 * task->thread.sve_state.
 *
 * Task can be a non-runnable task, or current.  In the latter case,
 * the caller must have ownership of the cpu FPSIMD context before calling
 * this function.
 * task->thread.sve_state must point to at least sve_state_size(task)
 * bytes of allocated kernel memory.
 * task->thread.uw.fpsimd_state must be up to date before calling this
 * function.
 */
static void fpsimd_to_sve(struct task_struct *task)
{
	unsigned int vq;
	void *sst = task->thread.sve_state;
	struct user_fpsimd_state const *fst = &task->thread.uw.fpsimd_state;

	if (!system_supports_sve())
		return;

	vq = sve_vq_from_vl(task->thread.sve_vl);
	__fpsimd_to_sve(sst, fst, vq);
}

/*
 * Transfer the SVE state in task->thread.sve_state to
 * task->thread.uw.fpsimd_state.
 *
 * Task can be a non-runnable task, or current.  In the latter case,
 * the caller must have ownership of the cpu FPSIMD context before calling
 * this function.
 * task->thread.sve_state must point to at least sve_state_size(task)
 * bytes of allocated kernel memory.
 * task->thread.sve_state must be up to date before calling this function.
 */
static void sve_to_fpsimd(struct task_struct *task)
{
	unsigned int vq;
	void const *sst = task->thread.sve_state;
	struct user_fpsimd_state *fst = &task->thread.uw.fpsimd_state;
	unsigned int i;
	__uint128_t const *p;

	if (!system_supports_sve())
		return;

	vq = sve_vq_from_vl(task->thread.sve_vl);
	for (i = 0; i < SVE_NUM_ZREGS; ++i) {
		p = (__uint128_t const *)ZREG(sst, vq, i);
		fst->vregs[i] = arm64_le128_to_cpu(*p);
	}
}

/*
 * Trapped SVE access
 *
 * Storage is allocated for the full SVE state, the current FPSIMD
 * register contents are migrated across, and TIF_SVE is set so that
 * the SVE access trap will be disabled the next time this task
 * reaches ret_to_user.
 *
 * TIF_SVE should be clear on entry: otherwise, fpsimd_restore_current_state()
 * would have disabled the SVE access trap for userspace during
 * ret_to_user, making an SVE access trap impossible in that case.
 */
void do_sve_acc(unsigned int esr, struct pt_regs *regs)
{
	/* Even if we chose not to use SVE, the hardware could still trap: */
	if (unlikely(!system_supports_sve()) || WARN_ON(is_compat_task())) {
		force_signal_inject(SIGILL, ILL_ILLOPC, regs->pc, 0);
		return;
	}

	sve_alloc(current);

	get_cpu_fpsimd_context();

	fpsimd_save();

	/* Force ret_to_user to reload the registers: */
	fpsimd_flush_task_state(current);

	fpsimd_to_sve(current);
	if (test_and_set_thread_flag(TIF_SVE))
		WARN_ON(1); /* SVE access shouldn't have trapped */

	put_cpu_fpsimd_context();
}

/*
 * Trapped FP/ASIMD access.
 */
void do_fpsimd_acc(unsigned int esr, struct pt_regs *regs)
{
	/* TODO: implement lazy context saving/restoring */
	WARN_ON(1);
}

/*
 * Raise a SIGFPE for the current process.
 */
void do_fpsimd_exc(unsigned int esr, struct pt_regs *regs)
{
	unsigned int si_code = FPE_FLTUNK;

	if (esr & ESR_ELx_FP_EXC_TFV) {
		if (esr & FPEXC_IOF)
			si_code = FPE_FLTINV;
		else if (esr & FPEXC_DZF)
			si_code = FPE_FLTDIV;
		else if (esr & FPEXC_OFF)
			si_code = FPE_FLTOVF;
		else if (esr & FPEXC_UFF)
			si_code = FPE_FLTUND;
		else if (esr & FPEXC_IXF)
			si_code = FPE_FLTRES;
	}

	send_sig_fault(SIGFPE, si_code,
		       (void __user *)instruction_pointer(regs),
		       current);
}

void fpsimd_thread_switch(struct task_struct *next)
{
	bool wrong_task, wrong_cpu;

	if (!system_supports_fpsimd())
		return;

	__get_cpu_fpsimd_context();

	/* Save unsaved fpsimd state, if any: */
	fpsimd_save();

	/*
	 * Fix up TIF_FOREIGN_FPSTATE to correctly describe next's
	 * state.  For kernel threads, FPSIMD registers are never loaded
	 * and wrong_task and wrong_cpu will always be true.
	 */
	wrong_task = __this_cpu_read(fpsimd_last_state.st) !=
					&next->thread.uw.fpsimd_state;
	wrong_cpu = next->thread.fpsimd_cpu != smp_processor_id();

	update_tsk_thread_flag(next, TIF_FOREIGN_FPSTATE,
			       wrong_task || wrong_cpu);

	__put_cpu_fpsimd_context();
}

void fpsimd_flush_thread(void)
{
	// int vl, supported_vl;

	if (!system_supports_fpsimd())
		return;

	get_cpu_fpsimd_context();

	fpsimd_flush_task_state(current);
	memset(&current->thread.uw.fpsimd_state, 0,
	       sizeof(current->thread.uw.fpsimd_state));

	// if (system_supports_sve()) {
	// 	clear_thread_flag(TIF_SVE);
	// 	sve_free(current);

	// 	/*
	// 	 * Reset the task vector length as required.
	// 	 * This is where we ensure that all user tasks have a valid
	// 	 * vector length configured: no kernel task can become a user
	// 	 * task without an exec and hence a call to this function.
	// 	 * By the time the first call to this function is made, all
	// 	 * early hardware probing is complete, so __sve_default_vl
	// 	 * should be valid.
	// 	 * If a bug causes this to go wrong, we make some noise and
	// 	 * try to fudge thread.sve_vl to a safe value here.
	// 	 */
	// 	vl = current->thread.sve_vl_onexec ?
	// 		current->thread.sve_vl_onexec : get_sve_default_vl();

	// 	if (WARN_ON(!sve_vl_valid(vl)))
	// 		vl = SVE_VL_MIN;

	// 	supported_vl = find_supported_vector_length(vl);
	// 	if (WARN_ON(supported_vl != vl))
	// 		vl = supported_vl;

	// 	current->thread.sve_vl = vl;

	// 	/*
	// 	 * If the task is not set to inherit, ensure that the vector
	// 	 * length will be reset by a subsequent exec:
	// 	 */
	// 	if (!test_thread_flag(TIF_SVE_VL_INHERIT))
	// 		current->thread.sve_vl_onexec = 0;
	// }

	put_cpu_fpsimd_context();
}

/*
 * Save the userland FPSIMD state of 'current' to memory, but only if the state
 * currently held in the registers does in fact belong to 'current'
 */
void fpsimd_preserve_current_state(void)
{
	if (!system_supports_fpsimd())
		return;

	get_cpu_fpsimd_context();
	fpsimd_save();
	put_cpu_fpsimd_context();
}

/*
 * Like fpsimd_preserve_current_state(), but ensure that
 * current->thread.uw.fpsimd_state is updated so that it can be copied to
 * the signal frame.
 */
void fpsimd_signal_preserve_current_state(void)
{
	fpsimd_preserve_current_state();
	if (system_supports_sve() && test_thread_flag(TIF_SVE))
		sve_to_fpsimd(current);
}

/*
 * Associate current's FPSIMD context with this cpu
 * The caller must have ownership of the cpu FPSIMD context before calling
 * this function.
 */
void fpsimd_bind_task_to_cpu(void)
{
	struct fpsimd_last_state_struct *last =
		this_cpu_ptr(&fpsimd_last_state);

	WARN_ON(!system_supports_fpsimd());
	last->st = &current->thread.uw.fpsimd_state;
	last->sve_state = current->thread.sve_state;
	last->sve_vl = current->thread.sve_vl;
	current->thread.fpsimd_cpu = smp_processor_id();

	if (system_supports_sve()) {
		/* Toggle SVE trapping for userspace if needed */
		if (test_thread_flag(TIF_SVE))
			sve_user_enable();
		else
			sve_user_disable();

		/* Serialised by exception return to user */
	}
}

void fpsimd_bind_state_to_cpu(struct user_fpsimd_state *st, void *sve_state,
			      unsigned int sve_vl)
{
	struct fpsimd_last_state_struct *last =
		this_cpu_ptr(&fpsimd_last_state);

	WARN_ON(!system_supports_fpsimd());
	WARN_ON(!in_softirq() && !irqs_disabled());

	last->st = st;
	last->sve_state = sve_state;
	last->sve_vl = sve_vl;
}

/*
 * Load the userland FPSIMD state of 'current' from memory, but only if the
 * FPSIMD state already held in the registers is /not/ the most recent FPSIMD
 * state of 'current'
 */
void fpsimd_restore_current_state(void)
{
	/*
	 * For the tasks that were created before we detected the absence of
	 * FP/SIMD, the TIF_FOREIGN_FPSTATE could be set via fpsimd_thread_switch(),
	 * e.g, init. This could be then inherited by the children processes.
	 * If we later detect that the system doesn't support FP/SIMD,
	 * we must clear the flag for  all the tasks to indicate that the
	 * FPSTATE is clean (as we can't have one) to avoid looping for ever in
	 * do_notify_resume().
	 */
	if (!system_supports_fpsimd()) {
		clear_thread_flag(TIF_FOREIGN_FPSTATE);
		return;
	}

	get_cpu_fpsimd_context();

	if (test_and_clear_thread_flag(TIF_FOREIGN_FPSTATE)) {
		task_fpsimd_load();
		fpsimd_bind_task_to_cpu();
	}

	put_cpu_fpsimd_context();
}

/*
 * Load an updated userland FPSIMD state for 'current' from memory and set the
 * flag that indicates that the FPSIMD register contents are the most recent
 * FPSIMD state of 'current'
 */
void fpsimd_update_current_state(struct user_fpsimd_state const *state)
{
	if (WARN_ON(!system_supports_fpsimd()))
		return;

	get_cpu_fpsimd_context();

	current->thread.uw.fpsimd_state = *state;
	if (system_supports_sve() && test_thread_flag(TIF_SVE))
		fpsimd_to_sve(current);

	task_fpsimd_load();
	fpsimd_bind_task_to_cpu();

	clear_thread_flag(TIF_FOREIGN_FPSTATE);

	put_cpu_fpsimd_context();
}

/*
 * Invalidate live CPU copies of task t's FPSIMD state
 *
 * This function may be called with preemption enabled.  The barrier()
 * ensures that the assignment to fpsimd_cpu is visible to any
 * preemption/softirq that could race with set_tsk_thread_flag(), so
 * that TIF_FOREIGN_FPSTATE cannot be spuriously re-cleared.
 *
 * The final barrier ensures that TIF_FOREIGN_FPSTATE is seen set by any
 * subsequent code.
 */
void fpsimd_flush_task_state(struct task_struct *t)
{
	t->thread.fpsimd_cpu = NR_CPUS;
	/*
	 * If we don't support fpsimd, bail out after we have
	 * reset the fpsimd_cpu for this task and clear the
	 * FPSTATE.
	 */
	if (!system_supports_fpsimd())
		return;
	barrier();
	set_tsk_thread_flag(t, TIF_FOREIGN_FPSTATE);

	barrier();
}

/*
 * Invalidate any task's FPSIMD state that is present on this cpu.
 * The FPSIMD context should be acquired with get_cpu_fpsimd_context()
 * before calling this function.
 */
static void fpsimd_flush_cpu_state(void)
{
	WARN_ON(!system_supports_fpsimd());
	__this_cpu_write(fpsimd_last_state.st, NULL);
	set_thread_flag(TIF_FOREIGN_FPSTATE);
}

/*
 * Save the FPSIMD state to memory and invalidate cpu view.
 * This function must be called with preemption disabled.
 */
void fpsimd_save_and_flush_cpu_state(void)
{
	if (!system_supports_fpsimd())
		return;
	WARN_ON(preemptible());
	__get_cpu_fpsimd_context();
	fpsimd_save();
	fpsimd_flush_cpu_state();
	__put_cpu_fpsimd_context();
}

#ifdef CONFIG_KERNEL_MODE_NEON

/*
 * Kernel-side NEON support functions
 */

/*
 * kernel_neon_begin(): obtain the CPU FPSIMD registers for use by the calling
 * context
 *
 * Must not be called unless may_use_simd() returns true.
 * Task context in the FPSIMD registers is saved back to memory as necessary.
 *
 * A matching call to kernel_neon_end() must be made before returning from the
 * calling context.
 *
 * The caller may freely use the FPSIMD registers until kernel_neon_end() is
 * called.
 */
void kernel_neon_begin(void)
{
	if (WARN_ON(!system_supports_fpsimd()))
		return;

	BUG_ON(!may_use_simd());

	get_cpu_fpsimd_context();

	/* Save unsaved fpsimd state, if any: */
	fpsimd_save();

	/* Invalidate any task state remaining in the fpsimd regs: */
	fpsimd_flush_cpu_state();
}
EXPORT_SYMBOL(kernel_neon_begin);

/*
 * kernel_neon_end(): give the CPU FPSIMD registers back to the current task
 *
 * Must be called from a context in which kernel_neon_begin() was previously
 * called, with no call to kernel_neon_end() in the meantime.
 *
 * The caller must not use the FPSIMD registers after this function is called,
 * unless kernel_neon_begin() is called again in the meantime.
 */
void kernel_neon_end(void)
{
	if (!system_supports_fpsimd())
		return;

	put_cpu_fpsimd_context();
}
EXPORT_SYMBOL(kernel_neon_end);

#endif /* CONFIG_KERNEL_MODE_NEON */

#ifdef CONFIG_CPU_PM
static int fpsimd_cpu_pm_notifier(struct notifier_block *self,
				  unsigned long cmd, void *v)
{
	switch (cmd) {
	case CPU_PM_ENTER:
		fpsimd_save_and_flush_cpu_state();
		break;
	case CPU_PM_EXIT:
		break;
	case CPU_PM_ENTER_FAILED:
	default:
		return NOTIFY_DONE;
	}
	return NOTIFY_OK;
}

static struct notifier_block fpsimd_cpu_pm_notifier_block = {
	.notifier_call = fpsimd_cpu_pm_notifier,
};

static void __init fpsimd_pm_init(void)
{
	cpu_pm_register_notifier(&fpsimd_cpu_pm_notifier_block);
}

#else
static inline void fpsimd_pm_init(void) { }
#endif /* CONFIG_CPU_PM */

static inline void fpsimd_hotplug_init(void) { }

/*
 * FP/SIMD support code initialisation.
 */
static int __init fpsimd_init(void)
{
	if (cpu_have_named_feature(FP)) {
		fpsimd_pm_init();
		fpsimd_hotplug_init();
	} else {
		pr_notice("Floating-point is not implemented\n");
	}

	if (!cpu_have_named_feature(ASIMD))
		pr_notice("Advanced SIMD is not implemented\n");

	return sve_sysctl_init();
}
core_initcall(fpsimd_init);
