/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM emulation

#if !defined(_TRACE_EMULATION_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_EMULATION_H

#include <linux/tracepoint.h>

#endif /* _TRACE_EMULATION_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_PATH .

#define TRACE_INCLUDE_FILE trace-events-emulation
#include <trace/define_trace.h>
