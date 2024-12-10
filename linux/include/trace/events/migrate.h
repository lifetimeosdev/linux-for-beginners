/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM migrate

#if !defined(_TRACE_MIGRATE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_MIGRATE_H

#include <linux/tracepoint.h>

#define MIGRATE_MODE						\
	EM( MIGRATE_ASYNC,	"MIGRATE_ASYNC")		\
	EM( MIGRATE_SYNC_LIGHT,	"MIGRATE_SYNC_LIGHT")		\
	EMe(MIGRATE_SYNC,	"MIGRATE_SYNC")


#define MIGRATE_REASON						\
	EM( MR_COMPACTION,	"compaction")			\
	EM( MR_MEMORY_FAILURE,	"memory_failure")		\
	EM( MR_MEMORY_HOTPLUG,	"memory_hotplug")		\
	EM( MR_SYSCALL,		"syscall_or_cpuset")		\
	EM( MR_MEMPOLICY_MBIND,	"mempolicy_mbind")		\
	EM( MR_NUMA_MISPLACED,	"numa_misplaced")		\
	EMe(MR_CONTIG_RANGE,	"contig_range")

/*
 * First define the enums in the above macros to be exported to userspace
 * via TRACE_DEFINE_ENUM().
 */
#undef EM
#undef EMe
#define EM(a, b)	TRACE_DEFINE_ENUM(a);
#define EMe(a, b)	TRACE_DEFINE_ENUM(a);

MIGRATE_MODE
MIGRATE_REASON

/*
 * Now redefine the EM() and EMe() macros to map the enums to the strings
 * that will be printed in the output.
 */
#undef EM
#undef EMe
#define EM(a, b)	{a, b},
#define EMe(a, b)	{a, b}

#endif /* _TRACE_MIGRATE_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
