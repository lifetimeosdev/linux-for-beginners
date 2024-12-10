// SPDX-License-Identifier: GPL-2.0-only
/*
 * Based on arch/arm/kernel/ptrace.c
 *
 * By Ross Biro 1/23/92
 * edited by Linus Torvalds
 * ARM modifications Copyright (C) 2000 Russell King
 * Copyright (C) 2012 ARM Ltd.
 */

#include <linux/audit.h>
#include <linux/compat.h>
#include <linux/kernel.h>
#include <linux/sched/signal.h>
#include <linux/sched/task_stack.h>
#include <linux/mm.h>
#include <linux/nospec.h>
#include <linux/smp.h>
#include <linux/ptrace.h>
#include <linux/user.h>
#include <linux/seccomp.h>
#include <linux/security.h>
#include <linux/init.h>
#include <linux/signal.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/regset.h>
#include <linux/tracehook.h>
#include <linux/elf.h>

#include <asm/compat.h>
#include <asm/cpufeature.h>
#include <asm/debug-monitors.h>
#include <asm/fpsimd.h>
#include <asm/mte.h>
#include <asm/pointer_auth.h>
#include <asm/stacktrace.h>
#include <asm/syscall.h>
#include <asm/traps.h>
#include <asm/system_misc.h>

#define CREATE_TRACE_POINTS
#include <trace/events/syscalls.h>

struct pt_regs_offset {
	const char *name;
	int offset;
};

#define REG_OFFSET_NAME(r) {.name = #r, .offset = offsetof(struct pt_regs, r)}
#define REG_OFFSET_END {.name = NULL, .offset = 0}
#define GPR_OFFSET_NAME(r) \
	{.name = "x" #r, .offset = offsetof(struct pt_regs, regs[r])}

static const struct pt_regs_offset regoffset_table[] = {
	GPR_OFFSET_NAME(0),
	GPR_OFFSET_NAME(1),
	GPR_OFFSET_NAME(2),
	GPR_OFFSET_NAME(3),
	GPR_OFFSET_NAME(4),
	GPR_OFFSET_NAME(5),
	GPR_OFFSET_NAME(6),
	GPR_OFFSET_NAME(7),
	GPR_OFFSET_NAME(8),
	GPR_OFFSET_NAME(9),
	GPR_OFFSET_NAME(10),
	GPR_OFFSET_NAME(11),
	GPR_OFFSET_NAME(12),
	GPR_OFFSET_NAME(13),
	GPR_OFFSET_NAME(14),
	GPR_OFFSET_NAME(15),
	GPR_OFFSET_NAME(16),
	GPR_OFFSET_NAME(17),
	GPR_OFFSET_NAME(18),
	GPR_OFFSET_NAME(19),
	GPR_OFFSET_NAME(20),
	GPR_OFFSET_NAME(21),
	GPR_OFFSET_NAME(22),
	GPR_OFFSET_NAME(23),
	GPR_OFFSET_NAME(24),
	GPR_OFFSET_NAME(25),
	GPR_OFFSET_NAME(26),
	GPR_OFFSET_NAME(27),
	GPR_OFFSET_NAME(28),
	GPR_OFFSET_NAME(29),
	GPR_OFFSET_NAME(30),
	{.name = "lr", .offset = offsetof(struct pt_regs, regs[30])},
	REG_OFFSET_NAME(sp),
	REG_OFFSET_NAME(pc),
	REG_OFFSET_NAME(pstate),
	REG_OFFSET_END,
};

/**
 * regs_query_register_offset() - query register offset from its name
 * @name:	the name of a register
 *
 * regs_query_register_offset() returns the offset of a register in struct
 * pt_regs from its name. If the name is invalid, this returns -EINVAL;
 */
int regs_query_register_offset(const char *name)
{
	const struct pt_regs_offset *roff;

	for (roff = regoffset_table; roff->name != NULL; roff++)
		if (!strcmp(roff->name, name))
			return roff->offset;
	return -EINVAL;
}

/**
 * regs_within_kernel_stack() - check the address in the stack
 * @regs:      pt_regs which contains kernel stack pointer.
 * @addr:      address which is checked.
 *
 * regs_within_kernel_stack() checks @addr is within the kernel stack page(s).
 * If @addr is within the kernel stack, it returns true. If not, returns false.
 */
static bool regs_within_kernel_stack(struct pt_regs *regs, unsigned long addr)
{
	return ((addr & ~(THREAD_SIZE - 1))  ==
		(kernel_stack_pointer(regs) & ~(THREAD_SIZE - 1))) ||
		on_irq_stack(addr, NULL);
}

/**
 * regs_get_kernel_stack_nth() - get Nth entry of the stack
 * @regs:	pt_regs which contains kernel stack pointer.
 * @n:		stack entry number.
 *
 * regs_get_kernel_stack_nth() returns @n th entry of the kernel stack which
 * is specified by @regs. If the @n th entry is NOT in the kernel stack,
 * this returns 0.
 */
unsigned long regs_get_kernel_stack_nth(struct pt_regs *regs, unsigned int n)
{
	unsigned long *addr = (unsigned long *)kernel_stack_pointer(regs);

	addr += n;
	if (regs_within_kernel_stack(regs, (unsigned long)addr))
		return *addr;
	else
		return 0;
}

/*
 * TODO: does not yet catch signals sent when the child dies.
 * in exit.c or in signal.c.
 */

/*
 * Called by kernel/ptrace.c when detaching..
 */
void ptrace_disable(struct task_struct *child)
{
	/*
	 * This would be better off in core code, but PTRACE_DETACH has
	 * grown its fair share of arch-specific worts and changing it
	 * is likely to cause regressions on obscure architectures.
	 */
	user_disable_single_step(child);
}

static int gpr_get(struct task_struct *target,
		   const struct user_regset *regset,
		   struct membuf to)
{
	struct user_pt_regs *uregs = &task_pt_regs(target)->user_regs;
	return membuf_write(&to, uregs, sizeof(*uregs));
}

static int gpr_set(struct task_struct *target, const struct user_regset *regset,
		   unsigned int pos, unsigned int count,
		   const void *kbuf, const void __user *ubuf)
{
	int ret;
	struct user_pt_regs newregs = task_pt_regs(target)->user_regs;

	ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf, &newregs, 0, -1);
	if (ret)
		return ret;

	if (!valid_user_regs(&newregs, target))
		return -EINVAL;

	task_pt_regs(target)->user_regs = newregs;
	return 0;
}

static int fpr_active(struct task_struct *target, const struct user_regset *regset)
{
	if (!system_supports_fpsimd())
		return -ENODEV;
	return regset->n;
}

/*
 * TODO: update fp accessors for lazy context switching (sync/flush hwstate)
 */
static int __fpr_get(struct task_struct *target,
		     const struct user_regset *regset,
		     struct membuf to)
{
	struct user_fpsimd_state *uregs;

	sve_sync_to_fpsimd(target);

	uregs = &target->thread.uw.fpsimd_state;

	return membuf_write(&to, uregs, sizeof(*uregs));
}

static int fpr_get(struct task_struct *target, const struct user_regset *regset,
		   struct membuf to)
{
	if (!system_supports_fpsimd())
		return -EINVAL;

	if (target == current)
		fpsimd_preserve_current_state();

	return __fpr_get(target, regset, to);
}

static int __fpr_set(struct task_struct *target,
		     const struct user_regset *regset,
		     unsigned int pos, unsigned int count,
		     const void *kbuf, const void __user *ubuf,
		     unsigned int start_pos)
{
	int ret;
	struct user_fpsimd_state newstate;

	/*
	 * Ensure target->thread.uw.fpsimd_state is up to date, so that a
	 * short copyin can't resurrect stale data.
	 */
	sve_sync_to_fpsimd(target);

	newstate = target->thread.uw.fpsimd_state;

	ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf, &newstate,
				 start_pos, start_pos + sizeof(newstate));
	if (ret)
		return ret;

	target->thread.uw.fpsimd_state = newstate;

	return ret;
}

static int fpr_set(struct task_struct *target, const struct user_regset *regset,
		   unsigned int pos, unsigned int count,
		   const void *kbuf, const void __user *ubuf)
{
	int ret;

	if (!system_supports_fpsimd())
		return -EINVAL;

	ret = __fpr_set(target, regset, pos, count, kbuf, ubuf, 0);
	if (ret)
		return ret;

	sve_sync_from_fpsimd_zeropad(target);
	fpsimd_flush_task_state(target);

	return ret;
}

static int tls_get(struct task_struct *target, const struct user_regset *regset,
		   struct membuf to)
{
	if (target == current)
		tls_preserve_current_state();

	return membuf_store(&to, target->thread.uw.tp_value);
}

static int tls_set(struct task_struct *target, const struct user_regset *regset,
		   unsigned int pos, unsigned int count,
		   const void *kbuf, const void __user *ubuf)
{
	int ret;
	unsigned long tls = target->thread.uw.tp_value;

	ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf, &tls, 0, -1);
	if (ret)
		return ret;

	target->thread.uw.tp_value = tls;
	return ret;
}

static int system_call_get(struct task_struct *target,
			   const struct user_regset *regset,
			   struct membuf to)
{
	return membuf_store(&to, task_pt_regs(target)->syscallno);
}

static int system_call_set(struct task_struct *target,
			   const struct user_regset *regset,
			   unsigned int pos, unsigned int count,
			   const void *kbuf, const void __user *ubuf)
{
	int syscallno = task_pt_regs(target)->syscallno;
	int ret;

	ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf, &syscallno, 0, -1);
	if (ret)
		return ret;

	task_pt_regs(target)->syscallno = syscallno;
	return ret;
}

#ifdef CONFIG_ARM64_TAGGED_ADDR_ABI
static int tagged_addr_ctrl_get(struct task_struct *target,
				const struct user_regset *regset,
				struct membuf to)
{
	long ctrl = get_tagged_addr_ctrl(target);

	if (IS_ERR_VALUE(ctrl))
		return ctrl;

	return membuf_write(&to, &ctrl, sizeof(ctrl));
}

static int tagged_addr_ctrl_set(struct task_struct *target, const struct
				user_regset *regset, unsigned int pos,
				unsigned int count, const void *kbuf, const
				void __user *ubuf)
{
	int ret;
	long ctrl;

	ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf, &ctrl, 0, -1);
	if (ret)
		return ret;

	return set_tagged_addr_ctrl(target, ctrl);
}
#endif

enum aarch64_regset {
	REGSET_GPR,
	REGSET_FPR,
	REGSET_TLS,
	REGSET_SYSTEM_CALL,
#ifdef CONFIG_ARM64_TAGGED_ADDR_ABI
	REGSET_TAGGED_ADDR_CTRL,
#endif
};

static const struct user_regset aarch64_regsets[] = {
	[REGSET_GPR] = {
		.core_note_type = NT_PRSTATUS,
		.n = sizeof(struct user_pt_regs) / sizeof(u64),
		.size = sizeof(u64),
		.align = sizeof(u64),
		.regset_get = gpr_get,
		.set = gpr_set
	},
	[REGSET_FPR] = {
		.core_note_type = NT_PRFPREG,
		.n = sizeof(struct user_fpsimd_state) / sizeof(u32),
		/*
		 * We pretend we have 32-bit registers because the fpsr and
		 * fpcr are 32-bits wide.
		 */
		.size = sizeof(u32),
		.align = sizeof(u32),
		.active = fpr_active,
		.regset_get = fpr_get,
		.set = fpr_set
	},
	[REGSET_TLS] = {
		.core_note_type = NT_ARM_TLS,
		.n = 1,
		.size = sizeof(void *),
		.align = sizeof(void *),
		.regset_get = tls_get,
		.set = tls_set,
	},
	[REGSET_SYSTEM_CALL] = {
		.core_note_type = NT_ARM_SYSTEM_CALL,
		.n = 1,
		.size = sizeof(int),
		.align = sizeof(int),
		.regset_get = system_call_get,
		.set = system_call_set,
	},
#ifdef CONFIG_ARM64_TAGGED_ADDR_ABI
	[REGSET_TAGGED_ADDR_CTRL] = {
		.core_note_type = NT_ARM_TAGGED_ADDR_CTRL,
		.n = 1,
		.size = sizeof(long),
		.align = sizeof(long),
		.regset_get = tagged_addr_ctrl_get,
		.set = tagged_addr_ctrl_set,
	},
#endif
};

static const struct user_regset_view user_aarch64_view = {
	.name = "aarch64", .e_machine = EM_AARCH64,
	.regsets = aarch64_regsets, .n = ARRAY_SIZE(aarch64_regsets)
};

const struct user_regset_view *task_user_regset_view(struct task_struct *task)
{
	return &user_aarch64_view;
}

long arch_ptrace(struct task_struct *child, long request,
		 unsigned long addr, unsigned long data)
{
	switch (request) {
	case PTRACE_PEEKMTETAGS:
	case PTRACE_POKEMTETAGS:
		return mte_ptrace_copy_tags(child, request, addr, data);
	}

	return ptrace_request(child, request, addr, data);
}

enum ptrace_syscall_dir {
	PTRACE_SYSCALL_ENTER = 0,
	PTRACE_SYSCALL_EXIT,
};

static void tracehook_report_syscall(struct pt_regs *regs,
				     enum ptrace_syscall_dir dir)
{
	int regno;
	unsigned long saved_reg;

	/*
	 * We have some ABI weirdness here in the way that we handle syscall
	 * exit stops because we indicate whether or not the stop has been
	 * signalled from syscall entry or syscall exit by clobbering a general
	 * purpose register (ip/r12 for AArch32, x7 for AArch64) in the tracee
	 * and restoring its old value after the stop. This means that:
	 *
	 * - Any writes by the tracer to this register during the stop are
	 *   ignored/discarded.
	 *
	 * - The actual value of the register is not available during the stop,
	 *   so the tracer cannot save it and restore it later.
	 *
	 * - Syscall stops behave differently to seccomp and pseudo-step traps
	 *   (the latter do not nobble any registers).
	 */
	regno = (is_compat_task() ? 12 : 7);
	saved_reg = regs->regs[regno];
	regs->regs[regno] = dir;

	if (dir == PTRACE_SYSCALL_ENTER) {
		if (tracehook_report_syscall_entry(regs))
			forget_syscall(regs);
		regs->regs[regno] = saved_reg;
	} else if (!test_thread_flag(TIF_SINGLESTEP)) {
		tracehook_report_syscall_exit(regs, 0);
		regs->regs[regno] = saved_reg;
	} else {
		regs->regs[regno] = saved_reg;

		/*
		 * Signal a pseudo-step exception since we are stepping but
		 * tracer modifications to the registers may have rewound the
		 * state machine.
		 */
		tracehook_report_syscall_exit(regs, 1);
	}
}

int syscall_trace_enter(struct pt_regs *regs)
{
	unsigned long flags = READ_ONCE(current_thread_info()->flags);

	if (flags & (_TIF_SYSCALL_EMU | _TIF_SYSCALL_TRACE)) {
		tracehook_report_syscall(regs, PTRACE_SYSCALL_ENTER);
		if (flags & _TIF_SYSCALL_EMU)
			return NO_SYSCALL;
	}

	return regs->syscallno;
}

void syscall_trace_exit(struct pt_regs *regs)
{
	unsigned long flags = READ_ONCE(current_thread_info()->flags);

	if (flags & (_TIF_SYSCALL_TRACE | _TIF_SINGLESTEP))
		tracehook_report_syscall(regs, PTRACE_SYSCALL_EXIT);
}

/*
 * SPSR_ELx bits which are always architecturally RES0 per ARM DDI 0487D.a.
 * We permit userspace to set SSBS (AArch64 bit 12, AArch32 bit 23) which is
 * not described in ARM DDI 0487D.a.
 * We treat PAN and UAO as RES0 bits, as they are meaningless at EL0, and may
 * be allocated an EL0 meaning in future.
 * Userspace cannot use these until they have an architectural meaning.
 * Note that this follows the SPSR_ELx format, not the AArch32 PSR format.
 * We also reserve IL for the kernel; SS is handled dynamically.
 */
#define SPSR_EL1_AARCH64_RES0_BITS \
	(GENMASK_ULL(63, 32) | GENMASK_ULL(27, 26) | GENMASK_ULL(23, 22) | \
	 GENMASK_ULL(20, 13) | GENMASK_ULL(5, 5))
#define SPSR_EL1_AARCH32_RES0_BITS \
	(GENMASK_ULL(63, 32) | GENMASK_ULL(22, 22) | GENMASK_ULL(20, 20))

static int valid_native_regs(struct user_pt_regs *regs)
{
	regs->pstate &= ~SPSR_EL1_AARCH64_RES0_BITS;

	if (user_mode(regs) && !(regs->pstate & PSR_MODE32_BIT) &&
	    (regs->pstate & PSR_D_BIT) == 0 &&
	    (regs->pstate & PSR_A_BIT) == 0 &&
	    (regs->pstate & PSR_I_BIT) == 0 &&
	    (regs->pstate & PSR_F_BIT) == 0) {
		return 1;
	}

	/* Force PSR to a valid 64-bit EL0t */
	regs->pstate &= PSR_N_BIT | PSR_Z_BIT | PSR_C_BIT | PSR_V_BIT;

	return 0;
}

/*
 * Are the current registers suitable for user mode? (used to maintain
 * security in signal handlers)
 */
int valid_user_regs(struct user_pt_regs *regs, struct task_struct *task)
{
	/* https://lore.kernel.org/lkml/20191118131525.GA4180@willie-the-truck */
	user_regs_reset_single_step(regs, task);

	return valid_native_regs(regs);
}
