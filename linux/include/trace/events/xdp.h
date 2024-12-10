/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM xdp

#if !defined(_TRACE_XDP_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_XDP_H

#include <linux/netdevice.h>
#include <linux/filter.h>
#include <linux/tracepoint.h>
#include <linux/bpf.h>

#define __XDP_ACT_MAP(FN)	\
	FN(ABORTED)		\
	FN(DROP)		\
	FN(PASS)		\
	FN(TX)			\
	FN(REDIRECT)

#define __XDP_ACT_TP_FN(x)	\
	TRACE_DEFINE_ENUM(XDP_##x);
#define __XDP_ACT_SYM_FN(x)	\
	{ XDP_##x, #x },
#define __XDP_ACT_SYM_TAB	\
	__XDP_ACT_MAP(__XDP_ACT_SYM_FN) { -1, NULL }
__XDP_ACT_MAP(__XDP_ACT_TP_FN)


#ifndef __DEVMAP_OBJ_TYPE
#define __DEVMAP_OBJ_TYPE
struct _bpf_dtab_netdev {
	struct net_device *dev;
};
#endif /* __DEVMAP_OBJ_TYPE */

#define devmap_ifindex(tgt, map)				\
	(((map->map_type == BPF_MAP_TYPE_DEVMAP ||	\
		  map->map_type == BPF_MAP_TYPE_DEVMAP_HASH)) ? \
	  ((struct _bpf_dtab_netdev *)tgt)->dev->ifindex : 0)

/* Expect users already include <net/xdp.h>, but not xdp_priv.h */
#include <net/xdp_priv.h>

#define __MEM_TYPE_MAP(FN)	\
	FN(PAGE_SHARED)		\
	FN(PAGE_ORDER0)		\
	FN(PAGE_POOL)		\
	FN(XSK_BUFF_POOL)

#define __MEM_TYPE_TP_FN(x)	\
	TRACE_DEFINE_ENUM(MEM_TYPE_##x);
#define __MEM_TYPE_SYM_FN(x)	\
	{ MEM_TYPE_##x, #x },
#define __MEM_TYPE_SYM_TAB	\
	__MEM_TYPE_MAP(__MEM_TYPE_SYM_FN) { -1, 0 }
__MEM_TYPE_MAP(__MEM_TYPE_TP_FN)


#endif /* _TRACE_XDP_H */

#include <trace/define_trace.h>
