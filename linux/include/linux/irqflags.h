/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/linux/irqflags.h
 *
 * IRQ flags tracing: follow the state of the hardirq and softirq flags and
 * provide callbacks for transitions between ON and OFF states.
 *
 * This file gets included from lowlevel asm headers too, to provide
 * wrapped versions of the local_irq_*() APIs, based on the
 * raw_local_irq_*() macros from the lowlevel headers.
 */
#ifndef _LINUX_TRACE_IRQFLAGS_H
#define _LINUX_TRACE_IRQFLAGS_H

#include <linux/typecheck.h>
#include <asm/irqflags.h>
#include <asm/percpu.h>

/* Currently lockdep_softirqs_on/off is used only by lockdep */

# define lockdep_hardirq_context()		0
# define lockdep_softirq_context(p)		0
# define lockdep_hardirqs_enabled()		0
# define lockdep_softirqs_enabled(p)		0
# define lockdep_hrtimer_enter(__hrtimer)	false

/*
 * Wrap the arch provided IRQ routines to provide appropriate checks.
 */
#define raw_local_irq_disable()		arch_local_irq_disable()
#define raw_local_irq_enable()		arch_local_irq_enable()
#define raw_local_irq_save(flags)			\
	do {						\
		typecheck(unsigned long, flags);	\
		flags = arch_local_irq_save();		\
	} while (0)
#define raw_local_irq_restore(flags)			\
	do {						\
		typecheck(unsigned long, flags);	\
		arch_local_irq_restore(flags);		\
	} while (0)
#define raw_local_save_flags(flags)			\
	do {						\
		typecheck(unsigned long, flags);	\
		flags = arch_local_save_flags();	\
	} while (0)
#define raw_irqs_disabled_flags(flags)			\
	({						\
		typecheck(unsigned long, flags);	\
		arch_irqs_disabled_flags(flags);	\
	})
#define raw_irqs_disabled()		(arch_irqs_disabled())
#define raw_safe_halt()			arch_safe_halt()

/*
 * The local_irq_*() APIs are equal to the raw_local_irq*()
 * if !TRACE_IRQFLAGS.
 */
#define local_irq_enable()	do { raw_local_irq_enable(); } while (0)
#define local_irq_disable()	do { raw_local_irq_disable(); } while (0)
#define local_irq_save(flags)	do { raw_local_irq_save(flags); } while (0)
#define local_irq_restore(flags) do { raw_local_irq_restore(flags); } while (0)
#define safe_halt()		do { raw_safe_halt(); } while (0)

#define local_save_flags(flags)	raw_local_save_flags(flags)

/*
 * Some architectures don't define arch_irqs_disabled(), so even if either
 * definition would be fine we need to use different ones for the time being
 * to avoid build issues.
 */
#ifdef CONFIG_TRACE_IRQFLAGS_SUPPORT
#define irqs_disabled()					\
	({						\
		unsigned long _flags;			\
		raw_local_save_flags(_flags);		\
		raw_irqs_disabled_flags(_flags);	\
	})
#else /* !CONFIG_TRACE_IRQFLAGS_SUPPORT */
#define irqs_disabled()	raw_irqs_disabled()
#endif /* CONFIG_TRACE_IRQFLAGS_SUPPORT */

#define irqs_disabled_flags(flags) raw_irqs_disabled_flags(flags)

#endif
