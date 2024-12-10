/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM writeback

#if !defined(_TRACE_WRITEBACK_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_WRITEBACK_H

#include <linux/tracepoint.h>
#include <linux/backing-dev.h>
#include <linux/writeback.h>

#define show_inode_state(state)					\
	__print_flags(state, "|",				\
		{I_DIRTY_SYNC,		"I_DIRTY_SYNC"},	\
		{I_DIRTY_DATASYNC,	"I_DIRTY_DATASYNC"},	\
		{I_DIRTY_PAGES,		"I_DIRTY_PAGES"},	\
		{I_NEW,			"I_NEW"},		\
		{I_WILL_FREE,		"I_WILL_FREE"},		\
		{I_FREEING,		"I_FREEING"},		\
		{I_CLEAR,		"I_CLEAR"},		\
		{I_SYNC,		"I_SYNC"},		\
		{I_DIRTY_TIME,		"I_DIRTY_TIME"},	\
		{I_REFERENCED,		"I_REFERENCED"}		\
	)

/* enums need to be exported to user space */
#undef EM
#undef EMe
#define EM(a,b) 	TRACE_DEFINE_ENUM(a);
#define EMe(a,b)	TRACE_DEFINE_ENUM(a);

#define WB_WORK_REASON							\
	EM( WB_REASON_BACKGROUND,		"background")		\
	EM( WB_REASON_VMSCAN,			"vmscan")		\
	EM( WB_REASON_SYNC,			"sync")			\
	EM( WB_REASON_PERIODIC,			"periodic")		\
	EM( WB_REASON_LAPTOP_TIMER,		"laptop_timer")		\
	EM( WB_REASON_FS_FREE_SPACE,		"fs_free_space")	\
	EMe(WB_REASON_FORKER_THREAD,		"forker_thread")

WB_WORK_REASON

/*
 * Now redefine the EM() and EMe() macros to map the enums to the strings
 * that will be printed in the output.
 */
#undef EM
#undef EMe
#define EM(a,b)		{ a, b },
#define EMe(a,b)	{ a, b }

struct wb_writeback_work;

#ifdef CREATE_TRACE_POINTS
#ifdef CONFIG_CGROUP_WRITEBACK

static inline ino_t __trace_wb_assign_cgroup(struct bdi_writeback *wb)
{
	return cgroup_ino(wb->memcg_css->cgroup);
}

static inline ino_t __trace_wbc_assign_cgroup(struct writeback_control *wbc)
{
	if (wbc->wb)
		return __trace_wb_assign_cgroup(wbc->wb);
	else
		return 1;
}
#else	/* CONFIG_CGROUP_WRITEBACK */

static inline ino_t __trace_wb_assign_cgroup(struct bdi_writeback *wb)
{
	return 1;
}

static inline ino_t __trace_wbc_assign_cgroup(struct writeback_control *wbc)
{
	return 1;
}

#endif	/* CONFIG_CGROUP_WRITEBACK */
#endif	/* CREATE_TRACE_POINTS */

#ifdef CONFIG_CGROUP_WRITEBACK
#endif

#define KBps(x)			((x) << (PAGE_SHIFT - 10))

#endif /* _TRACE_WRITEBACK_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
