/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CONTEXT_TRACKING_H
#define _LINUX_CONTEXT_TRACKING_H

#include <linux/sched.h>
#include <linux/vtime.h>
#include <linux/context_tracking_state.h>
#include <linux/instrumentation.h>

#include <asm/ptrace.h>


static inline enum ctx_state exception_enter(void) { return 0; }
static inline enum ctx_state ct_state(void) { return CONTEXT_DISABLED; }

#define CT_WARN_ON(cond) WARN_ON(context_tracking_enabled() && (cond))

static __always_inline void guest_enter_irqoff(void)
{
	/*
	 * This is running in ioctl context so its safe
	 * to assume that it's the stime pending cputime
	 * to flush.
	 */
	current->flags |= PF_VCPU;
	rcu_virt_note_context_switch(smp_processor_id());
}

static __always_inline void context_tracking_guest_exit(void) { }

static __always_inline void vtime_account_guest_exit(void)
{
	current->flags &= ~PF_VCPU;
}

static __always_inline void guest_exit_irqoff(void)
{
	/* Flush the guest cputime we spent on the guest */
	vtime_account_guest_exit();
}

static inline void guest_exit(void)
{
	unsigned long flags;

	local_irq_save(flags);
	guest_exit_irqoff();
	local_irq_restore(flags);
}

#endif
