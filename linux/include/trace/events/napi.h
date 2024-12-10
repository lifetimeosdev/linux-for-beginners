/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM napi

#if !defined(_TRACE_NAPI_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_NAPI_H

#include <linux/netdevice.h>
#include <linux/tracepoint.h>
#include <linux/ftrace.h>

#define NO_DEV "(no_device)"

#undef NO_DEV

#endif /* _TRACE_NAPI_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
