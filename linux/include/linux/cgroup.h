/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CGROUP_H
#define _LINUX_CGROUP_H
/*
 *  cgroup interface
 *
 *  Copyright (C) 2003 BULL SA
 *  Copyright (C) 2004-2006 Silicon Graphics, Inc.
 *
 */

#include <linux/sched.h>
#include <linux/cpumask.h>
#include <linux/nodemask.h>
#include <linux/rculist.h>
#include <linux/cgroupstats.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/kernfs.h>
#include <linux/jump_label.h>
#include <linux/types.h>
#include <linux/ns_common.h>
#include <linux/nsproxy.h>
#include <linux/user_namespace.h>
#include <linux/refcount.h>
#include <linux/kernel_stat.h>

#include <linux/cgroup-defs.h>

struct kernel_clone_args;

struct cgroup_subsys_state;
struct cgroup;

static inline u64 cgroup_id(struct cgroup *cgrp) { return 1; }
static inline void css_get(struct cgroup_subsys_state *css) {}
static inline void css_put(struct cgroup_subsys_state *css) {}
static inline int cgroup_attach_task_all(struct task_struct *from,
					 struct task_struct *t) { return 0; }
static inline int cgroupstats_build(struct cgroupstats *stats,
				    struct dentry *dentry) { return -EINVAL; }

static inline void cgroup_fork(struct task_struct *p) {}
static inline int cgroup_can_fork(struct task_struct *p,
				  struct kernel_clone_args *kargs) { return 0; }
static inline void cgroup_cancel_fork(struct task_struct *p,
				      struct kernel_clone_args *kargs) {}
static inline void cgroup_post_fork(struct task_struct *p,
				    struct kernel_clone_args *kargs) {}
static inline void cgroup_exit(struct task_struct *p) {}
static inline void cgroup_release(struct task_struct *p) {}
static inline void cgroup_free(struct task_struct *p) {}

static inline int cgroup_init_early(void) { return 0; }
static inline int cgroup_init(void) { return 0; }
static inline void cgroup_init_kthreadd(void) {}
static inline void cgroup_kthread_ready(void) {}

static inline struct cgroup *cgroup_parent(struct cgroup *cgrp)
{
	return NULL;
}

static inline struct psi_group *cgroup_psi(struct cgroup *cgrp)
{
	return NULL;
}

static inline bool task_under_cgroup_hierarchy(struct task_struct *task,
					       struct cgroup *ancestor)
{
	return true;
}

static inline void cgroup_path_from_kernfs_id(u64 id, char *buf, size_t buflen)
{}

static inline void cgroup_account_cputime(struct task_struct *task,
					  u64 delta_exec) {}
static inline void cgroup_account_cputime_field(struct task_struct *task,
						enum cpu_usage_stat index,
						u64 delta_exec) {}

/*
 * sock->sk_cgrp_data handling.  For more info, see sock_cgroup_data
 * definition in cgroup-defs.h.
 */
#ifdef CONFIG_SOCK_CGROUP_DATA

#if defined(CONFIG_CGROUP_NET_PRIO) || defined(CONFIG_CGROUP_NET_CLASSID)
extern spinlock_t cgroup_sk_update_lock;
#endif

void cgroup_sk_alloc_disable(void);
void cgroup_sk_alloc(struct sock_cgroup_data *skcd);
void cgroup_sk_clone(struct sock_cgroup_data *skcd);
void cgroup_sk_free(struct sock_cgroup_data *skcd);

static inline struct cgroup *sock_cgroup_ptr(struct sock_cgroup_data *skcd)
{
#if defined(CONFIG_CGROUP_NET_PRIO) || defined(CONFIG_CGROUP_NET_CLASSID)
	unsigned long v;

	/*
	 * @skcd->val is 64bit but the following is safe on 32bit too as we
	 * just need the lower ulong to be written and read atomically.
	 */
	v = READ_ONCE(skcd->val);

	if (v & 3)
		return &cgrp_dfl_root.cgrp;

	return (struct cgroup *)(unsigned long)v ?: &cgrp_dfl_root.cgrp;
#else
	return (struct cgroup *)(unsigned long)skcd->val;
#endif
}

#else	/* CONFIG_CGROUP_DATA */

static inline void cgroup_sk_alloc(struct sock_cgroup_data *skcd) {}
static inline void cgroup_sk_clone(struct sock_cgroup_data *skcd) {}
static inline void cgroup_sk_free(struct sock_cgroup_data *skcd) {}

#endif	/* CONFIG_CGROUP_DATA */

struct cgroup_namespace {
	refcount_t		count;
	struct ns_common	ns;
	struct user_namespace	*user_ns;
	struct ucounts		*ucounts;
	struct css_set          *root_cset;
};

extern struct cgroup_namespace init_cgroup_ns;

static inline void free_cgroup_ns(struct cgroup_namespace *ns) { }
static inline struct cgroup_namespace *
copy_cgroup_ns(unsigned long flags, struct user_namespace *user_ns,
	       struct cgroup_namespace *old_ns)
{
	return old_ns;
}

static inline void get_cgroup_ns(struct cgroup_namespace *ns)
{
	if (ns)
		refcount_inc(&ns->count);
}

static inline void put_cgroup_ns(struct cgroup_namespace *ns)
{
	if (ns && refcount_dec_and_test(&ns->count))
		free_cgroup_ns(ns);
}

static inline void cgroup_enter_frozen(void) { }
static inline void cgroup_leave_frozen(bool always_leave) { }
static inline bool cgroup_task_freeze(struct task_struct *task)
{
	return false;
}
static inline bool cgroup_task_frozen(struct task_struct *task)
{
	return false;
}

static inline void cgroup_bpf_get(struct cgroup *cgrp) {}
static inline void cgroup_bpf_put(struct cgroup *cgrp) {}

#endif /* _LINUX_CGROUP_H */
