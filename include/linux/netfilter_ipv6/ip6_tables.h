/* SPDX-License-Identifier: GPL-2.0 */
/*
 * 25-Jul-1998 Major changes to allow for ip chain table
 *
 * 3-Jan-2000 Named tables to allow packet selection for different uses.
 */

/*
 * 	Format of an IP6 firewall descriptor
 *
 * 	src, dst, src_mask, dst_mask are always stored in network byte order.
 * 	flags are stored in host byte order (of course).
 * 	Port numbers are stored in HOST byte order.
 */
#ifndef _IP6_TABLES_H
#define _IP6_TABLES_H

#include <linux/if.h>
#include <linux/in6.h>
#include <linux/init.h>
#include <linux/ipv6.h>
#include <linux/skbuff.h>
#include <uapi/linux/netfilter_ipv6/ip6_tables.h>

extern void *ip6t_alloc_initial_table(const struct xt_table *);

int ip6t_register_table(struct net *net, const struct xt_table *table,
			const struct ip6t_replace *repl,
			const struct nf_hook_ops *ops, struct xt_table **res);
void ip6t_unregister_table(struct net *net, struct xt_table *table,
			   const struct nf_hook_ops *ops);
void ip6t_unregister_table_pre_exit(struct net *net, struct xt_table *table,
				    const struct nf_hook_ops *ops);
void ip6t_unregister_table_exit(struct net *net, struct xt_table *table);
extern unsigned int ip6t_do_table(struct sk_buff *skb,
				  const struct nf_hook_state *state,
				  struct xt_table *table);

#endif /* _IP6_TABLES_H */
