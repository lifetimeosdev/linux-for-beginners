/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM sock

#if !defined(_TRACE_SOCK_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_SOCK_H

#include <net/sock.h>
#include <net/ipv6.h>
#include <linux/tracepoint.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>

#define family_names			\
		EM(AF_INET)				\
		EMe(AF_INET6)

/* The protocol traced by inet_sock_set_state */
#define inet_protocol_names		\
		EM(IPPROTO_TCP)			\
		EM(IPPROTO_DCCP)		\
		EM(IPPROTO_SCTP)		\
		EMe(IPPROTO_MPTCP)

#define tcp_state_names			\
		EM(TCP_ESTABLISHED)		\
		EM(TCP_SYN_SENT)		\
		EM(TCP_SYN_RECV)		\
		EM(TCP_FIN_WAIT1)		\
		EM(TCP_FIN_WAIT2)		\
		EM(TCP_TIME_WAIT)		\
		EM(TCP_CLOSE)			\
		EM(TCP_CLOSE_WAIT)		\
		EM(TCP_LAST_ACK)		\
		EM(TCP_LISTEN)			\
		EM(TCP_CLOSING)			\
		EMe(TCP_NEW_SYN_RECV)

#define skmem_kind_names			\
		EM(SK_MEM_SEND)			\
		EMe(SK_MEM_RECV)

/* enums need to be exported to user space */
#undef EM
#undef EMe
#define EM(a)       TRACE_DEFINE_ENUM(a);
#define EMe(a)      TRACE_DEFINE_ENUM(a);

family_names
inet_protocol_names
tcp_state_names
skmem_kind_names

#undef EM
#undef EMe
#define EM(a)       { a, #a },
#define EMe(a)      { a, #a }

#define show_family_name(val)			\
	__print_symbolic(val, family_names)

#define show_inet_protocol_name(val)    \
	__print_symbolic(val, inet_protocol_names)

#define show_tcp_state_name(val)        \
	__print_symbolic(val, tcp_state_names)

#define show_skmem_kind_names(val)	\
	__print_symbolic(val, skmem_kind_names)


#endif /* _TRACE_SOCK_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
