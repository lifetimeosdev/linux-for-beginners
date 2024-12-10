/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM timer

#if !defined(_TRACE_TIMER_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_TIMER_H

#include <linux/tracepoint.h>
#include <linux/hrtimer.h>
#include <linux/timer.h>

#define decode_timer_flags(flags)			\
	__print_flags(flags, "|",			\
		{  TIMER_MIGRATING,	"M" },		\
		{  TIMER_DEFERRABLE,	"D" },		\
		{  TIMER_PINNED,	"P" },		\
		{  TIMER_IRQSAFE,	"I" })


#define decode_clockid(type)						\
	__print_symbolic(type,						\
		{ CLOCK_REALTIME,	"CLOCK_REALTIME"	},	\
		{ CLOCK_MONOTONIC,	"CLOCK_MONOTONIC"	},	\
		{ CLOCK_BOOTTIME,	"CLOCK_BOOTTIME"	},	\
		{ CLOCK_TAI,		"CLOCK_TAI"		})

#define decode_hrtimer_mode(mode)					\
	__print_symbolic(mode,						\
		{ HRTIMER_MODE_ABS,		"ABS"		},	\
		{ HRTIMER_MODE_REL,		"REL"		},	\
		{ HRTIMER_MODE_ABS_PINNED,	"ABS|PINNED"	},	\
		{ HRTIMER_MODE_REL_PINNED,	"REL|PINNED"	},	\
		{ HRTIMER_MODE_ABS_SOFT,	"ABS|SOFT"	},	\
		{ HRTIMER_MODE_REL_SOFT,	"REL|SOFT"	},	\
		{ HRTIMER_MODE_ABS_PINNED_SOFT,	"ABS|PINNED|SOFT" },	\
		{ HRTIMER_MODE_REL_PINNED_SOFT,	"REL|PINNED|SOFT" },	\
		{ HRTIMER_MODE_ABS_HARD,	"ABS|HARD" },		\
		{ HRTIMER_MODE_REL_HARD,	"REL|HARD" },		\
		{ HRTIMER_MODE_ABS_PINNED_HARD, "ABS|PINNED|HARD" },	\
		{ HRTIMER_MODE_REL_PINNED_HARD,	"REL|PINNED|HARD" })


#ifdef CONFIG_NO_HZ_COMMON

#define TICK_DEP_NAMES					\
		tick_dep_mask_name(NONE)		\
		tick_dep_name(POSIX_TIMER)		\
		tick_dep_name(PERF_EVENTS)		\
		tick_dep_name(SCHED)			\
		tick_dep_name(CLOCK_UNSTABLE)		\
		tick_dep_name(RCU)			\
		tick_dep_name_end(RCU_EXP)

#undef tick_dep_name
#undef tick_dep_mask_name
#undef tick_dep_name_end

/* The MASK will convert to their bits and they need to be processed too */
#define tick_dep_name(sdep) TRACE_DEFINE_ENUM(TICK_DEP_BIT_##sdep); \
	TRACE_DEFINE_ENUM(TICK_DEP_MASK_##sdep);
#define tick_dep_name_end(sdep)  TRACE_DEFINE_ENUM(TICK_DEP_BIT_##sdep); \
	TRACE_DEFINE_ENUM(TICK_DEP_MASK_##sdep);
/* NONE only has a mask defined for it */
#define tick_dep_mask_name(sdep) TRACE_DEFINE_ENUM(TICK_DEP_MASK_##sdep);

TICK_DEP_NAMES

#undef tick_dep_name
#undef tick_dep_mask_name
#undef tick_dep_name_end

#define tick_dep_name(sdep) { TICK_DEP_MASK_##sdep, #sdep },
#define tick_dep_mask_name(sdep) { TICK_DEP_MASK_##sdep, #sdep },
#define tick_dep_name_end(sdep) { TICK_DEP_MASK_##sdep, #sdep }

#define show_tick_dep_name(val)				\
	__print_symbolic(val, TICK_DEP_NAMES)

#endif

#endif /*  _TRACE_TIMER_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
