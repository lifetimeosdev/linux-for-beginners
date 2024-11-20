/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Low-level exception handling code
 *
 * Copyright (C) 2012 ARM Ltd.
 * Authors:	Catalin Marinas <catalin.marinas@arm.com>
 *		Will Deacon <will.deacon@arm.com>
 */

#include <linux/arm-smccc.h>
#include <linux/init.h>
#include <linux/linkage.h>

#include <asm/alternative.h>
#include <asm/assembler.h>
#include <asm/asm-offsets.h>
#include <asm/asm_pointer_auth.h>
#include <asm/bug.h>
#include <asm/cpufeature.h>
#include <asm/errno.h>
#include <asm/esr.h>
#include <asm/irq.h>
#include <asm/memory.h>
#include <asm/mmu.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/scs.h>
#include <asm/thread_info.h>
#include <asm/asm-uaccess.h>
#include <asm/unistd.h>

/*
 * Context tracking and irqflag tracing need to instrument transitions between
 * user and kernel mode.
 */
	.macro user_exit_irqoff
	.endm

	.macro user_enter_irqoff
	.endm

	.macro	clear_gp_regs
	.irp	n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29
	mov	x\n, xzr
	.endr
	.endm

/*
 * Bad Abort numbers
 *-----------------
 */
#define BAD_SYNC	0
#define BAD_IRQ		1
#define BAD_FIQ		2
#define BAD_ERROR	3

	.macro kernel_ventry, el, label, regsize = 64
	.align 7
.Lventry_start\@:
	.if	\el == 0
	/*
	 * This must be the first instruction of the EL0 vector entries. It is
	 * skipped by the trampoline vectors, to trigger the cleanup.
	 */
	b	.Lskip_tramp_vectors_cleanup\@
	.if	\regsize == 64
	mrs	x30, tpidrro_el0
	msr	tpidrro_el0, xzr
	.else
	mov	x30, xzr
	.endif
.Lskip_tramp_vectors_cleanup\@:
	.endif

	sub	sp, sp, #S_FRAME_SIZE
#ifdef CONFIG_VMAP_STACK
	/*
	 * Test whether the SP has overflowed, without corrupting a GPR.
	 * Task and IRQ stacks are aligned so that SP & (1 << THREAD_SHIFT)
	 * should always be zero.
	 */
	add	sp, sp, x0			// sp' = sp + x0
	sub	x0, sp, x0			// x0' = sp' - x0 = (sp + x0) - x0 = sp
	tbnz	x0, #THREAD_SHIFT, 0f
	sub	x0, sp, x0			// x0'' = sp' - x0' = (sp + x0) - sp = x0
	sub	sp, sp, x0			// sp'' = sp' - x0 = (sp + x0) - x0 = sp
	b	el\()\el\()_\label

0:
	/*
	 * Either we've just detected an overflow, or we've taken an exception
	 * while on the overflow stack. Either way, we won't return to
	 * userspace, and can clobber EL0 registers to free up GPRs.
	 */

	/* Stash the original SP (minus S_FRAME_SIZE) in tpidr_el0. */
	msr	tpidr_el0, x0

	/* Recover the original x0 value and stash it in tpidrro_el0 */
	sub	x0, sp, x0
	msr	tpidrro_el0, x0

	/* Switch to the overflow stack */
	adr_this_cpu sp, overflow_stack + OVERFLOW_STACK_SIZE, x0

	/*
	 * Check whether we were already on the overflow stack. This may happen
	 * after panic() re-enables interrupts.
	 */
	mrs	x0, tpidr_el0			// sp of interrupted context
	sub	x0, sp, x0			// delta with top of overflow stack
	tst	x0, #~(OVERFLOW_STACK_SIZE - 1)	// within range?
	b.ne	__bad_stack			// no? -> bad stack pointer

	/* We were already on the overflow stack. Restore sp/x0 and carry on. */
	sub	sp, sp, x0
	mrs	x0, tpidrro_el0
#endif
	b	el\()\el\()_\label
.org .Lventry_start\@ + 128	// Did we overflow the ventry slot?
	.endm

	.macro tramp_alias, dst, sym, tmp
	mov_q	\dst, TRAMP_VALIAS
	adr_l	\tmp, \sym
	add	\dst, \dst, \tmp
	adr_l	\tmp, .entry.tramp.text
	sub	\dst, \dst, \tmp
	.endm

	/*
	 * This macro corrupts x0-x3. It is the caller's duty  to save/restore
	 * them if required.
	 */
	.macro	apply_ssbd, state, tmp1, tmp2
alternative_cb	spectre_v4_patch_fw_mitigation_enable
	b	.L__asm_ssbd_skip\@		// Patched to NOP
alternative_cb_end
	ldr_this_cpu	\tmp2, arm64_ssbd_callback_required, \tmp1
	cbz	\tmp2,	.L__asm_ssbd_skip\@
	ldr	\tmp2, [tsk, #TSK_TI_FLAGS]
	tbnz	\tmp2, #TIF_SSBD, .L__asm_ssbd_skip\@
	mov	w0, #ARM_SMCCC_ARCH_WORKAROUND_2
	mov	w1, #\state
alternative_cb	smccc_patch_fw_mitigation_conduit
	nop					// Patched to SMC/HVC #0
alternative_cb_end
.L__asm_ssbd_skip\@:
	.endm

	/* Check for MTE asynchronous tag check faults */
	.macro check_mte_async_tcf, tmp, ti_flags
	.endm

	/* Clear the MTE asynchronous tag check faults */
	.macro clear_mte_async_tcf
	.endm

	.macro	kernel_entry, el, regsize = 64
	.if	\regsize == 32
	mov	w0, w0				// zero upper 32 bits of x0
	.endif
	stp	x0, x1, [sp, #16 * 0]
	stp	x2, x3, [sp, #16 * 1]
	stp	x4, x5, [sp, #16 * 2]
	stp	x6, x7, [sp, #16 * 3]
	stp	x8, x9, [sp, #16 * 4]
	stp	x10, x11, [sp, #16 * 5]
	stp	x12, x13, [sp, #16 * 6]
	stp	x14, x15, [sp, #16 * 7]
	stp	x16, x17, [sp, #16 * 8]
	stp	x18, x19, [sp, #16 * 9]
	stp	x20, x21, [sp, #16 * 10]
	stp	x22, x23, [sp, #16 * 11]
	stp	x24, x25, [sp, #16 * 12]
	stp	x26, x27, [sp, #16 * 13]
	stp	x28, x29, [sp, #16 * 14]

	.if	\el == 0
	clear_gp_regs
	mrs	x21, sp_el0
	ldr_this_cpu	tsk, __entry_task, x20
	msr	sp_el0, tsk

	/*
	 * Ensure MDSCR_EL1.SS is clear, since we can unmask debug exceptions
	 * when scheduling.
	 */
	ldr	x19, [tsk, #TSK_TI_FLAGS]
	disable_step_tsk x19, x20

	/* Check for asynchronous tag check faults in user space */
	check_mte_async_tcf x22, x23
	apply_ssbd 1, x22, x23

	ptrauth_keys_install_kernel tsk, x20, x22, x23

	scs_load_current
	.else
	add	x21, sp, #S_FRAME_SIZE
	get_current_task tsk
	/* Save the task's original addr_limit and set USER_DS */
	ldr	x20, [tsk, #TSK_TI_ADDR_LIMIT]
	str	x20, [sp, #S_ORIG_ADDR_LIMIT]
	mov	x20, #USER_DS
	str	x20, [tsk, #TSK_TI_ADDR_LIMIT]
	/* No need to reset PSTATE.UAO, hardware's already set it to 0 for us */
	.endif /* \el == 0 */
	mrs	x22, elr_el1
	mrs	x23, spsr_el1
	stp	lr, x21, [sp, #S_LR]

	/*
	 * In order to be able to dump the contents of struct pt_regs at the
	 * time the exception was taken (in case we attempt to walk the call
	 * stack later), chain it together with the stack frames.
	 */
	.if \el == 0
	stp	xzr, xzr, [sp, #S_STACKFRAME]
	.else
	stp	x29, x22, [sp, #S_STACKFRAME]
	.endif
	add	x29, sp, #S_STACKFRAME


	stp	x22, x23, [sp, #S_PC]

	/* Not in a syscall by default (el0_svc overwrites for real syscall) */
	.if	\el == 0
	mov	w21, #NO_SYSCALL
	str	w21, [sp, #S_SYSCALLNO]
	.endif

	/* Save pmr */
alternative_if ARM64_HAS_IRQ_PRIO_MASKING
	mrs_s	x20, SYS_ICC_PMR_EL1
	str	x20, [sp, #S_PMR_SAVE]
	mov	x20, #GIC_PRIO_IRQON | GIC_PRIO_PSR_I_SET
	msr_s	SYS_ICC_PMR_EL1, x20
alternative_else_nop_endif

	/* Re-enable tag checking (TCO set on exception entry) */

	/*
	 * Registers that may be useful after this macro is invoked:
	 *
	 * x20 - ICC_PMR_EL1
	 * x21 - aborted SP
	 * x22 - aborted PC
	 * x23 - aborted PSTATE
	*/
	.endm

	.macro	kernel_exit, el
	.if	\el != 0
	disable_daif

	/* Restore the task's original addr_limit. */
	ldr	x20, [sp, #S_ORIG_ADDR_LIMIT]
	str	x20, [tsk, #TSK_TI_ADDR_LIMIT]

	/* No need to restore UAO, it will be restored from SPSR_EL1 */
	.endif

	/* Restore pmr */
alternative_if ARM64_HAS_IRQ_PRIO_MASKING
	ldr	x20, [sp, #S_PMR_SAVE]
	msr_s	SYS_ICC_PMR_EL1, x20
	mrs_s	x21, SYS_ICC_CTLR_EL1
	tbz	x21, #6, .L__skip_pmr_sync\@	// Check for ICC_CTLR_EL1.PMHE
	dsb	sy				// Ensure priority change is seen by redistributor
.L__skip_pmr_sync\@:
alternative_else_nop_endif

	ldp	x21, x22, [sp, #S_PC]		// load ELR, SPSR

	.if	\el == 0
	ldr	x23, [sp, #S_SP]		// load return stack pointer
	msr	sp_el0, x23
	tst	x22, #PSR_MODE32_BIT		// native task?
	b.eq	3f

#ifdef CONFIG_ARM64_ERRATUM_845719
alternative_if ARM64_WORKAROUND_845719
#ifdef CONFIG_PID_IN_CONTEXTIDR
	mrs	x29, contextidr_el1
	msr	contextidr_el1, x29
#else
	msr contextidr_el1, xzr
#endif
alternative_else_nop_endif
#endif
3:
	scs_save tsk, x0

	/* No kernel C function calls after this as user keys are set. */
	ptrauth_keys_install_user tsk, x0, x1, x2

	apply_ssbd 0, x0, x1
	.endif

	msr	elr_el1, x21			// set up the return data
	msr	spsr_el1, x22
	ldp	x0, x1, [sp, #16 * 0]
	ldp	x2, x3, [sp, #16 * 1]
	ldp	x4, x5, [sp, #16 * 2]
	ldp	x6, x7, [sp, #16 * 3]
	ldp	x8, x9, [sp, #16 * 4]
	ldp	x10, x11, [sp, #16 * 5]
	ldp	x12, x13, [sp, #16 * 6]
	ldp	x14, x15, [sp, #16 * 7]
	ldp	x16, x17, [sp, #16 * 8]
	ldp	x18, x19, [sp, #16 * 9]
	ldp	x20, x21, [sp, #16 * 10]
	ldp	x22, x23, [sp, #16 * 11]
	ldp	x24, x25, [sp, #16 * 12]
	ldp	x26, x27, [sp, #16 * 13]
	ldp	x28, x29, [sp, #16 * 14]

	.if	\el == 0
alternative_if_not ARM64_UNMAP_KERNEL_AT_EL0
	ldr	lr, [sp, #S_LR]
	add	sp, sp, #S_FRAME_SIZE		// restore sp
	eret
alternative_else_nop_endif
#ifdef CONFIG_UNMAP_KERNEL_AT_EL0
	bne	4f
	msr	far_el1, x29
	tramp_alias	x30, tramp_exit_native, x29
	br	x30
4:
	tramp_alias	x30, tramp_exit_compat, x29
	br	x30
#endif
	.else
	ldr	lr, [sp, #S_LR]
	add	sp, sp, #S_FRAME_SIZE		// restore sp

	/* Ensure any device/NC reads complete */
	alternative_insn nop, "dmb sy", ARM64_WORKAROUND_1508412

	eret
	.endif
	sb
	.endm

	.macro	irq_stack_entry
	mov	x19, sp			// preserve the original sp

	/*
	 * Compare sp with the base of the task stack.
	 * If the top ~(THREAD_SIZE - 1) bits match, we are on a task stack,
	 * and should switch to the irq stack.
	 */
	ldr	x25, [tsk, TSK_STACK]
	eor	x25, x25, x19
	and	x25, x25, #~(THREAD_SIZE - 1)
	cbnz	x25, 9998f

	ldr_this_cpu x25, irq_stack_ptr, x26
	mov	x26, #IRQ_STACK_SIZE
	add	x26, x25, x26

	/* switch to the irq stack */
	mov	sp, x26


9998:
	.endm

	/*
	 * The callee-saved regs (x19-x29) should be preserved between
	 * irq_stack_entry and irq_stack_exit, but note that kernel_entry
	 * uses x20-x23 to store data for later use.
	 */
	.macro	irq_stack_exit
	mov	sp, x19
	.endm

/* GPRs used by entry code */
tsk	.req	x28		// current thread_info

/*
 * Interrupt handling.
 */
	.macro	irq_handler, handler:req
	ldr_l	x1, \handler
	mov	x0, sp
	irq_stack_entry
	blr	x1
	irq_stack_exit
	.endm

#ifdef CONFIG_ARM64_PSEUDO_NMI
	/*
	 * Set res to 0 if irqs were unmasked in interrupted context.
	 * Otherwise set res to non-0 value.
	 */
	.macro	test_irqs_unmasked res:req, pmr:req
alternative_if ARM64_HAS_IRQ_PRIO_MASKING
	sub	\res, \pmr, #GIC_PRIO_IRQON
alternative_else
	mov	\res, xzr
alternative_endif
	.endm
#endif

	.macro	gic_prio_kentry_setup, tmp:req
#ifdef CONFIG_ARM64_PSEUDO_NMI
	alternative_if ARM64_HAS_IRQ_PRIO_MASKING
	mov	\tmp, #(GIC_PRIO_PSR_I_SET | GIC_PRIO_IRQON)
	msr_s	SYS_ICC_PMR_EL1, \tmp
	alternative_else_nop_endif
#endif
	.endm

	.macro el1_interrupt_handler, handler:req
	enable_da_f

	mov	x0, sp
	bl	enter_el1_irq_or_nmi

	irq_handler	\handler

#ifdef CONFIG_PREEMPTION
	ldr	x24, [tsk, #TSK_TI_PREEMPT]	// get preempt count
alternative_if ARM64_HAS_IRQ_PRIO_MASKING
	/*
	 * DA_F were cleared at start of handling. If anything is set in DAIF,
	 * we come back from an NMI, so skip preemption
	 */
	mrs	x0, daif
	orr	x24, x24, x0
alternative_else_nop_endif
	cbnz	x24, 1f				// preempt count != 0 || NMI return path
	bl	arm64_preempt_schedule_irq	// irq en/disable is done inside
1:
#endif

	mov	x0, sp
	bl	exit_el1_irq_or_nmi
	.endm

	.macro el0_interrupt_handler, handler:req
	user_exit_irqoff
	enable_da_f

	tbz	x22, #55, 1f
	bl	do_el0_irq_bp_hardening
1:
	irq_handler	\handler
	.endm

	.text

/*
 * Exception vectors.
 */
	.pushsection ".entry.text", "ax"

	.align	11
SYM_CODE_START(vectors)
	kernel_ventry	1, sync_invalid			// Synchronous EL1t
	kernel_ventry	1, irq_invalid			// IRQ EL1t
	kernel_ventry	1, fiq_invalid			// FIQ EL1t
	kernel_ventry	1, error_invalid		// Error EL1t

	kernel_ventry	1, sync				// Synchronous EL1h
	kernel_ventry	1, irq				// IRQ EL1h
	kernel_ventry	1, fiq_invalid			// FIQ EL1h
	kernel_ventry	1, error			// Error EL1h

	kernel_ventry	0, sync				// Synchronous 64-bit EL0
	kernel_ventry	0, irq				// IRQ 64-bit EL0
	kernel_ventry	0, fiq_invalid			// FIQ 64-bit EL0
	kernel_ventry	0, error			// Error 64-bit EL0

	kernel_ventry	0, sync_invalid, 32		// Synchronous 32-bit EL0
	kernel_ventry	0, irq_invalid, 32		// IRQ 32-bit EL0
	kernel_ventry	0, fiq_invalid, 32		// FIQ 32-bit EL0
	kernel_ventry	0, error_invalid, 32		// Error 32-bit EL0
SYM_CODE_END(vectors)

#ifdef CONFIG_VMAP_STACK
	/*
	 * We detected an overflow in kernel_ventry, which switched to the
	 * overflow stack. Stash the exception regs, and head to our overflow
	 * handler.
	 */
__bad_stack:
	/* Restore the original x0 value */
	mrs	x0, tpidrro_el0

	/*
	 * Store the original GPRs to the new stack. The orginal SP (minus
	 * S_FRAME_SIZE) was stashed in tpidr_el0 by kernel_ventry.
	 */
	sub	sp, sp, #S_FRAME_SIZE
	kernel_entry 1
	mrs	x0, tpidr_el0
	add	x0, x0, #S_FRAME_SIZE
	str	x0, [sp, #S_SP]

	/* Stash the regs for handle_bad_stack */
	mov	x0, sp

	/* Time to die */
	bl	handle_bad_stack
	ASM_BUG()
#endif /* CONFIG_VMAP_STACK */

/*
 * Invalid mode handlers
 */
	.macro	inv_entry, el, reason, regsize = 64
	kernel_entry \el, \regsize
	mov	x0, sp
	mov	x1, #\reason
	mrs	x2, esr_el1
	bl	bad_mode
	ASM_BUG()
	.endm

SYM_CODE_START_LOCAL(el0_sync_invalid)
	inv_entry 0, BAD_SYNC
SYM_CODE_END(el0_sync_invalid)

SYM_CODE_START_LOCAL(el0_irq_invalid)
	inv_entry 0, BAD_IRQ
SYM_CODE_END(el0_irq_invalid)

SYM_CODE_START_LOCAL(el0_fiq_invalid)
	inv_entry 0, BAD_FIQ
SYM_CODE_END(el0_fiq_invalid)

SYM_CODE_START_LOCAL(el0_error_invalid)
	inv_entry 0, BAD_ERROR
SYM_CODE_END(el0_error_invalid)

SYM_CODE_START_LOCAL(el1_sync_invalid)
	inv_entry 1, BAD_SYNC
SYM_CODE_END(el1_sync_invalid)

SYM_CODE_START_LOCAL(el1_irq_invalid)
	inv_entry 1, BAD_IRQ
SYM_CODE_END(el1_irq_invalid)

SYM_CODE_START_LOCAL(el1_fiq_invalid)
	inv_entry 1, BAD_FIQ
SYM_CODE_END(el1_fiq_invalid)

SYM_CODE_START_LOCAL(el1_error_invalid)
	inv_entry 1, BAD_ERROR
SYM_CODE_END(el1_error_invalid)

/*
 * EL1 mode handlers.
 */
	.align	6
SYM_CODE_START_LOCAL_NOALIGN(el1_sync)
	kernel_entry 1
	mov	x0, sp
	bl	el1_sync_handler
	kernel_exit 1
SYM_CODE_END(el1_sync)

	.align	6
SYM_CODE_START_LOCAL_NOALIGN(el1_irq)
	kernel_entry 1
	el1_interrupt_handler handle_arch_irq
	kernel_exit 1
SYM_CODE_END(el1_irq)

/*
 * EL0 mode handlers.
 */
	.align	6
SYM_CODE_START_LOCAL_NOALIGN(el0_sync)
	kernel_entry 0
	mov	x0, sp
	bl	el0_sync_handler
	b	ret_to_user
SYM_CODE_END(el0_sync)

	.align	6
SYM_CODE_START_LOCAL_NOALIGN(el0_irq)
	kernel_entry 0
el0_irq_naked:
	el0_interrupt_handler handle_arch_irq
	b	ret_to_user
SYM_CODE_END(el0_irq)

SYM_CODE_START_LOCAL(el1_error)
	kernel_entry 1
	mrs	x1, esr_el1
	enable_dbg
	mov	x0, sp
	bl	do_serror
	kernel_exit 1
SYM_CODE_END(el1_error)

SYM_CODE_START_LOCAL(el0_error)
	kernel_entry 0
el0_error_naked:
	mrs	x25, esr_el1
	user_exit_irqoff
	enable_dbg
	mov	x0, sp
	mov	x1, x25
	bl	do_serror
	enable_da_f
	b	ret_to_user
SYM_CODE_END(el0_error)

/*
 * "slow" syscall return path.
 */
SYM_CODE_START_LOCAL(ret_to_user)
	disable_daif
	gic_prio_kentry_setup tmp=x3
#ifdef CONFIG_TRACE_IRQFLAGS
	bl	trace_hardirqs_off
#endif
	ldr	x19, [tsk, #TSK_TI_FLAGS]
	and	x2, x19, #_TIF_WORK_MASK
	cbnz	x2, work_pending
finish_ret_to_user:
	user_enter_irqoff
	/* Ignore asynchronous tag check faults in the uaccess routines */
	clear_mte_async_tcf
	enable_step_tsk x19, x2
#ifdef CONFIG_GCC_PLUGIN_STACKLEAK
	bl	stackleak_erase
#endif
	kernel_exit 0

/*
 * Ok, we need to do extra processing, enter the slow path.
 */
work_pending:
	mov	x0, sp				// 'regs'
	mov	x1, x19
	bl	do_notify_resume
	ldr	x19, [tsk, #TSK_TI_FLAGS]	// re-check for single-step
	b	finish_ret_to_user
SYM_CODE_END(ret_to_user)

	.popsection				// .entry.text

	// Move from tramp_pg_dir to swapper_pg_dir
	.macro tramp_map_kernel, tmp
	mrs	\tmp, ttbr1_el1
	add	\tmp, \tmp, #(2 * PAGE_SIZE)
	bic	\tmp, \tmp, #USER_ASID_FLAG
	msr	ttbr1_el1, \tmp
#ifdef CONFIG_QCOM_FALKOR_ERRATUM_1003
alternative_if ARM64_WORKAROUND_QCOM_FALKOR_E1003
	/* ASID already in \tmp[63:48] */
	movk	\tmp, #:abs_g2_nc:(TRAMP_VALIAS >> 12)
	movk	\tmp, #:abs_g1_nc:(TRAMP_VALIAS >> 12)
	/* 2MB boundary containing the vectors, so we nobble the walk cache */
	movk	\tmp, #:abs_g0_nc:((TRAMP_VALIAS & ~(SZ_2M - 1)) >> 12)
	isb
	tlbi	vae1, \tmp
	dsb	nsh
alternative_else_nop_endif
#endif /* CONFIG_QCOM_FALKOR_ERRATUM_1003 */
	.endm

	// Move from swapper_pg_dir to tramp_pg_dir
	.macro tramp_unmap_kernel, tmp
	mrs	\tmp, ttbr1_el1
	sub	\tmp, \tmp, #(2 * PAGE_SIZE)
	orr	\tmp, \tmp, #USER_ASID_FLAG
	msr	ttbr1_el1, \tmp
	/*
	 * We avoid running the post_ttbr_update_workaround here because
	 * it's only needed by Cavium ThunderX, which requires KPTI to be
	 * disabled.
	 */
	.endm

	.macro tramp_data_page	dst
	adr_l	\dst, .entry.tramp.text
	sub	\dst, \dst, PAGE_SIZE
	.endm

	.macro tramp_data_read_var	dst, var
	ldr	\dst, =\var
	.endm

#define BHB_MITIGATION_NONE	0
#define BHB_MITIGATION_LOOP	1
#define BHB_MITIGATION_FW	2
#define BHB_MITIGATION_INSN	3

	.macro tramp_ventry, vector_start, regsize, kpti, bhb
	.align	7
1:
	.if	\regsize == 64
	msr	tpidrro_el0, x30	// Restored in kernel_ventry
	.endif

	.if	\bhb == BHB_MITIGATION_LOOP
	/*
	 * This sequence must appear before the first indirect branch. i.e. the
	 * ret out of tramp_ventry. It appears here because x30 is free.
	 */
	__mitigate_spectre_bhb_loop	x30
	.endif // \bhb == BHB_MITIGATION_LOOP

	.if	\bhb == BHB_MITIGATION_INSN
	clearbhb
	isb
	.endif // \bhb == BHB_MITIGATION_INSN

	.if	\kpti == 1
	/*
	 * Defend against branch aliasing attacks by pushing a dummy
	 * entry onto the return stack and using a RET instruction to
	 * enter the full-fat kernel vectors.
	 */
	bl	2f
	b	.
2:
	tramp_map_kernel	x30
alternative_insn isb, nop, ARM64_WORKAROUND_QCOM_FALKOR_E1003
	tramp_data_read_var	x30, vectors
alternative_if_not ARM64_WORKAROUND_CAVIUM_TX2_219_PRFM
	prfm	plil1strm, [x30, #(1b - \vector_start)]
alternative_else_nop_endif

	msr	vbar_el1, x30
	isb
	.else
	ldr	x30, =vectors
	.endif // \kpti == 1

	.if	\bhb == BHB_MITIGATION_FW
	/*
	 * The firmware sequence must appear before the first indirect branch.
	 * i.e. the ret out of tramp_ventry. But it also needs the stack to be
	 * mapped to save/restore the registers the SMC clobbers.
	 */
	__mitigate_spectre_bhb_fw
	.endif // \bhb == BHB_MITIGATION_FW

	add	x30, x30, #(1b - \vector_start + 4)
	ret
.org 1b + 128	// Did we overflow the ventry slot?
	.endm

	.macro tramp_exit, regsize = 64
	tramp_data_read_var	x30, this_cpu_vector
	this_cpu_offset x29
	ldr	x30, [x30, x29]

	msr	vbar_el1, x30
	ldr	lr, [sp, #S_LR]
	tramp_unmap_kernel	x29
	.if	\regsize == 64
	mrs	x29, far_el1
	.endif
	add	sp, sp, #S_FRAME_SIZE		// restore sp
	eret
	sb
	.endm

	.macro	generate_tramp_vector,	kpti, bhb
.Lvector_start\@:
	.space	0x400

	.rept	4
	tramp_ventry	.Lvector_start\@, 64, \kpti, \bhb
	.endr
	.rept	4
	tramp_ventry	.Lvector_start\@, 32, \kpti, \bhb
	.endr
	.endm

#ifdef CONFIG_UNMAP_KERNEL_AT_EL0
/*
 * Exception vectors trampoline.
 * The order must match __bp_harden_el1_vectors and the
 * arm64_bp_harden_el1_vectors enum.
 */
	.pushsection ".entry.tramp.text", "ax"
	.align	11
SYM_CODE_START_NOALIGN(tramp_vectors)
#ifdef CONFIG_MITIGATE_SPECTRE_BRANCH_HISTORY
	generate_tramp_vector	kpti=1, bhb=BHB_MITIGATION_LOOP
	generate_tramp_vector	kpti=1, bhb=BHB_MITIGATION_FW
	generate_tramp_vector	kpti=1, bhb=BHB_MITIGATION_INSN
#endif /* CONFIG_MITIGATE_SPECTRE_BRANCH_HISTORY */
	generate_tramp_vector	kpti=1, bhb=BHB_MITIGATION_NONE
SYM_CODE_END(tramp_vectors)

SYM_CODE_START(tramp_exit_native)
	tramp_exit
SYM_CODE_END(tramp_exit_native)

SYM_CODE_START(tramp_exit_compat)
	tramp_exit	32
SYM_CODE_END(tramp_exit_compat)

	.ltorg
	.popsection				// .entry.tramp.text
#endif /* CONFIG_UNMAP_KERNEL_AT_EL0 */

/*
 * Exception vectors for spectre mitigations on entry from EL1 when
 * kpti is not in use.
 */
	.macro generate_el1_vector, bhb
.Lvector_start\@:
	kernel_ventry	1, sync_invalid			// Synchronous EL1t
	kernel_ventry	1, irq_invalid			// IRQ EL1t
	kernel_ventry	1, fiq_invalid			// FIQ EL1t
	kernel_ventry	1, error_invalid		// Error EL1t

	kernel_ventry	1, sync				// Synchronous EL1h
	kernel_ventry	1, irq				// IRQ EL1h
	kernel_ventry	1, fiq_invalid			// FIQ EL1h
	kernel_ventry	1, error			// Error EL1h

	.rept	4
	tramp_ventry	.Lvector_start\@, 64, 0, \bhb
	.endr
	.rept 4
	tramp_ventry	.Lvector_start\@, 32, 0, \bhb
	.endr
	.endm

/* The order must match tramp_vecs and the arm64_bp_harden_el1_vectors enum. */
	.pushsection ".entry.text", "ax"
	.align	11
SYM_CODE_START(__bp_harden_el1_vectors)
#ifdef CONFIG_MITIGATE_SPECTRE_BRANCH_HISTORY
	generate_el1_vector	bhb=BHB_MITIGATION_LOOP
	generate_el1_vector	bhb=BHB_MITIGATION_FW
	generate_el1_vector	bhb=BHB_MITIGATION_INSN
#endif /* CONFIG_MITIGATE_SPECTRE_BRANCH_HISTORY */
SYM_CODE_END(__bp_harden_el1_vectors)
	.popsection


/*
 * Register switch for AArch64. The callee-saved registers need to be saved
 * and restored. On entry:
 *   x0 = previous task_struct (must be preserved across the switch)
 *   x1 = next task_struct
 * Previous and next are guaranteed not to be the same.
 *
 */
SYM_FUNC_START(cpu_switch_to)
	mov	x10, #THREAD_CPU_CONTEXT
	add	x8, x0, x10
	mov	x9, sp
	stp	x19, x20, [x8], #16		// store callee-saved registers
	stp	x21, x22, [x8], #16
	stp	x23, x24, [x8], #16
	stp	x25, x26, [x8], #16
	stp	x27, x28, [x8], #16
	stp	x29, x9, [x8], #16
	str	lr, [x8]
	add	x8, x1, x10
	ldp	x19, x20, [x8], #16		// restore callee-saved registers
	ldp	x21, x22, [x8], #16
	ldp	x23, x24, [x8], #16
	ldp	x25, x26, [x8], #16
	ldp	x27, x28, [x8], #16
	ldp	x29, x9, [x8], #16
	ldr	lr, [x8]
	mov	sp, x9
	msr	sp_el0, x1
	ptrauth_keys_install_kernel x1, x8, x9, x10
	scs_save x0, x8
	scs_load_current
	ret
SYM_FUNC_END(cpu_switch_to)
NOKPROBE(cpu_switch_to)

/*
 * This is how we return from a fork.
 */
SYM_CODE_START(ret_from_fork)
	bl	schedule_tail
	cbz	x19, 1f				// not a kernel thread
	mov	x0, x20
	blr	x19
1:	get_current_task tsk
	b	ret_to_user
SYM_CODE_END(ret_from_fork)
NOKPROBE(ret_from_fork)
