/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM pagemap

#if !defined(_TRACE_PAGEMAP_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_PAGEMAP_H

#include <linux/tracepoint.h>
#include <linux/mm.h>

#define	PAGEMAP_MAPPED		0x0001u
#define PAGEMAP_ANONYMOUS	0x0002u
#define PAGEMAP_FILE		0x0004u
#define PAGEMAP_SWAPCACHE	0x0008u
#define PAGEMAP_SWAPBACKED	0x0010u
#define PAGEMAP_MAPPEDDISK	0x0020u
#define PAGEMAP_BUFFERS		0x0040u

#define trace_pagemap_flags(page) ( \
	(PageAnon(page)		? PAGEMAP_ANONYMOUS  : PAGEMAP_FILE) | \
	(page_mapped(page)	? PAGEMAP_MAPPED     : 0) | \
	(PageSwapCache(page)	? PAGEMAP_SWAPCACHE  : 0) | \
	(PageSwapBacked(page)	? PAGEMAP_SWAPBACKED : 0) | \
	(PageMappedToDisk(page)	? PAGEMAP_MAPPEDDISK : 0) | \
	(page_has_private(page) ? PAGEMAP_BUFFERS    : 0) \
	)

#endif /* _TRACE_PAGEMAP_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
