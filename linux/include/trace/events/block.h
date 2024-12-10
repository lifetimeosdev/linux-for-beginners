/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM block

#if !defined(_TRACE_BLOCK_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_BLOCK_H

#include <linux/blktrace_api.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>
#include <linux/tracepoint.h>

#define RWBS_LEN	8

#endif /* _TRACE_BLOCK_H */

/* This part must be outside protection */
#include <trace/define_trace.h>

