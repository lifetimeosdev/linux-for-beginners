/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM alarmtimer

#if !defined(_TRACE_ALARMTIMER_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_ALARMTIMER_H

#include <linux/alarmtimer.h>
#include <linux/rtc.h>
#include <linux/tracepoint.h>

TRACE_DEFINE_ENUM(ALARM_REALTIME);
TRACE_DEFINE_ENUM(ALARM_BOOTTIME);
TRACE_DEFINE_ENUM(ALARM_REALTIME_FREEZER);
TRACE_DEFINE_ENUM(ALARM_BOOTTIME_FREEZER);

#define show_alarm_type(type)	__print_flags(type, " | ",	\
	{ 1 << ALARM_REALTIME, "REALTIME" },			\
	{ 1 << ALARM_BOOTTIME, "BOOTTIME" },			\
	{ 1 << ALARM_REALTIME_FREEZER, "REALTIME Freezer" },	\
	{ 1 << ALARM_BOOTTIME_FREEZER, "BOOTTIME Freezer" })

#endif /* _TRACE_ALARMTIMER_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
