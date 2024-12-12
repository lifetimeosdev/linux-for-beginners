/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BPF_CGROUP_H
#define _BPF_CGROUP_H

#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/jump_label.h>
#include <linux/percpu.h>
#include <linux/percpu-refcount.h>
#include <linux/rbtree.h>
#include <uapi/linux/bpf.h>

struct sock;
struct sockaddr;
struct cgroup;
struct sk_buff;
struct bpf_map;
struct bpf_prog;
struct bpf_sock_ops_kern;
struct bpf_cgroup_storage;
struct ctl_table;
struct ctl_table_header;
struct task_struct;

struct bpf_prog;
struct cgroup_bpf {};
static inline int cgroup_bpf_inherit(struct cgroup *cgrp) { return 0; }
static inline void cgroup_bpf_offline(struct cgroup *cgrp) {}

static inline int cgroup_bpf_prog_attach(const union bpf_attr *attr,
					 enum bpf_prog_type ptype,
					 struct bpf_prog *prog)
{
	return -EINVAL;
}

static inline int cgroup_bpf_prog_detach(const union bpf_attr *attr,
					 enum bpf_prog_type ptype)
{
	return -EINVAL;
}

static inline int cgroup_bpf_link_attach(const union bpf_attr *attr,
					 struct bpf_prog *prog)
{
	return -EINVAL;
}

static inline int cgroup_bpf_prog_query(const union bpf_attr *attr,
					union bpf_attr __user *uattr)
{
	return -EINVAL;
}

static inline int bpf_cgroup_storage_set(
	struct bpf_cgroup_storage *storage[MAX_BPF_CGROUP_STORAGE_TYPE]) { return 0; }
static inline void bpf_cgroup_storage_unset(void) {}
static inline int bpf_cgroup_storage_assign(struct bpf_prog_aux *aux,
					    struct bpf_map *map) { return 0; }
static inline struct bpf_cgroup_storage *bpf_cgroup_storage_alloc(
	struct bpf_prog *prog, enum bpf_cgroup_storage_type stype) { return NULL; }
static inline void bpf_cgroup_storage_free(
	struct bpf_cgroup_storage *storage) {}
static inline int bpf_percpu_cgroup_storage_copy(struct bpf_map *map, void *key,
						 void *value) {
	return 0;
}
static inline int bpf_percpu_cgroup_storage_update(struct bpf_map *map,
					void *key, void *value, u64 flags) {
	return 0;
}

#define cgroup_bpf_enabled (0)
#define BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, type, t_ctx) ({ 0; })
#define BPF_CGROUP_PRE_CONNECT_ENABLED(sk) (0)
#define BPF_CGROUP_RUN_PROG_INET_INGRESS(sk,skb) ({ 0; })
#define BPF_CGROUP_RUN_PROG_INET_EGRESS(sk,skb) ({ 0; })
#define BPF_CGROUP_RUN_PROG_INET_SOCK(sk) ({ 0; })
#define BPF_CGROUP_RUN_PROG_INET_SOCK_RELEASE(sk) ({ 0; })
#define BPF_CGROUP_RUN_PROG_INET4_BIND(sk, uaddr) ({ 0; })
#define BPF_CGROUP_RUN_PROG_INET6_BIND(sk, uaddr) ({ 0; })
#define BPF_CGROUP_RUN_PROG_INET4_POST_BIND(sk) ({ 0; })
#define BPF_CGROUP_RUN_PROG_INET6_POST_BIND(sk) ({ 0; })
#define BPF_CGROUP_RUN_PROG_INET4_CONNECT(sk, uaddr) ({ 0; })
#define BPF_CGROUP_RUN_PROG_INET4_CONNECT_LOCK(sk, uaddr) ({ 0; })
#define BPF_CGROUP_RUN_PROG_INET6_CONNECT(sk, uaddr) ({ 0; })
#define BPF_CGROUP_RUN_PROG_INET6_CONNECT_LOCK(sk, uaddr) ({ 0; })
#define BPF_CGROUP_RUN_PROG_UDP4_SENDMSG_LOCK(sk, uaddr, t_ctx) ({ 0; })
#define BPF_CGROUP_RUN_PROG_UDP6_SENDMSG_LOCK(sk, uaddr, t_ctx) ({ 0; })
#define BPF_CGROUP_RUN_PROG_UDP4_RECVMSG_LOCK(sk, uaddr) ({ 0; })
#define BPF_CGROUP_RUN_PROG_UDP6_RECVMSG_LOCK(sk, uaddr) ({ 0; })
#define BPF_CGROUP_RUN_PROG_SOCK_OPS(sock_ops) ({ 0; })
#define BPF_CGROUP_RUN_PROG_DEVICE_CGROUP(type,major,minor,access) ({ 0; })
#define BPF_CGROUP_RUN_PROG_SYSCTL(head,table,write,buf,count,pos) ({ 0; })
#define BPF_CGROUP_GETSOCKOPT_MAX_OPTLEN(optlen) ({ 0; })
#define BPF_CGROUP_RUN_PROG_GETSOCKOPT(sock, level, optname, optval, \
				       optlen, max_optlen, retval) ({ retval; })
#define BPF_CGROUP_RUN_PROG_GETSOCKOPT_KERN(sock, level, optname, optval, \
					    optlen, retval) ({ retval; })
#define BPF_CGROUP_RUN_PROG_SETSOCKOPT(sock, level, optname, optval, optlen, \
				       kernel_optval) ({ 0; })

#define for_each_cgroup_storage_type(stype) for (; false; )

#endif /* _BPF_CGROUP_H */
