/* SPDX-License-Identifier: GPL-2.0-or-later */
/* audit.h -- Auditing support
 *
 * Copyright 2003-2004 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * Written by Rickard E. (Rik) Faith <faith@redhat.com>
 */
#ifndef _LINUX_AUDIT_H_
#define _LINUX_AUDIT_H_

#include <linux/sched.h>
#include <linux/ptrace.h>
#include <uapi/linux/audit.h>
#include <uapi/linux/netfilter/nf_tables.h>

#define AUDIT_INO_UNSET ((unsigned long)-1)
#define AUDIT_DEV_UNSET ((dev_t)-1)

struct audit_sig_info {
	uid_t		uid;
	pid_t		pid;
	char		ctx[];
};

struct audit_buffer;
struct audit_context;
struct inode;
struct netlink_skb_parms;
struct path;
struct linux_binprm;
struct mq_attr;
struct mqstat;
struct audit_watch;
struct audit_tree;
struct sk_buff;

struct audit_krule {
	u32			pflags;
	u32			flags;
	u32			listnr;
	u32			action;
	u32			mask[AUDIT_BITMASK_SIZE];
	u32			buflen; /* for data alloc on list rules */
	u32			field_count;
	char			*filterkey; /* ties events to rules */
	struct audit_field	*fields;
	struct audit_field	*arch_f; /* quick access to arch field */
	struct audit_field	*inode_f; /* quick access to an inode field */
	struct audit_watch	*watch;	/* associated watch */
	struct audit_tree	*tree;	/* associated watched tree */
	struct audit_fsnotify_mark	*exe;
	struct list_head	rlist;	/* entry in audit_{watch,tree}.rules list */
	struct list_head	list;	/* for AUDIT_LIST* purposes only */
	u64			prio;
};

/* Flag to indicate legacy AUDIT_LOGINUID unset usage */
#define AUDIT_LOGINUID_LEGACY		0x1

struct audit_field {
	u32				type;
	union {
		u32			val;
		kuid_t			uid;
		kgid_t			gid;
		struct {
			char		*lsm_str;
			void		*lsm_rule;
		};
	};
	u32				op;
};

enum audit_ntp_type {
	AUDIT_NTP_OFFSET,
	AUDIT_NTP_FREQ,
	AUDIT_NTP_STATUS,
	AUDIT_NTP_TAI,
	AUDIT_NTP_TICK,
	AUDIT_NTP_ADJUST,

	AUDIT_NTP_NVALS /* count */
};

struct audit_ntp_data {};

enum audit_nfcfgop {
	AUDIT_XT_OP_REGISTER,
	AUDIT_XT_OP_REPLACE,
	AUDIT_XT_OP_UNREGISTER,
	AUDIT_NFT_OP_TABLE_REGISTER,
	AUDIT_NFT_OP_TABLE_UNREGISTER,
	AUDIT_NFT_OP_CHAIN_REGISTER,
	AUDIT_NFT_OP_CHAIN_UNREGISTER,
	AUDIT_NFT_OP_RULE_REGISTER,
	AUDIT_NFT_OP_RULE_UNREGISTER,
	AUDIT_NFT_OP_SET_REGISTER,
	AUDIT_NFT_OP_SET_UNREGISTER,
	AUDIT_NFT_OP_SETELEM_REGISTER,
	AUDIT_NFT_OP_SETELEM_UNREGISTER,
	AUDIT_NFT_OP_GEN_REGISTER,
	AUDIT_NFT_OP_OBJ_REGISTER,
	AUDIT_NFT_OP_OBJ_UNREGISTER,
	AUDIT_NFT_OP_OBJ_RESET,
	AUDIT_NFT_OP_FLOWTABLE_REGISTER,
	AUDIT_NFT_OP_FLOWTABLE_UNREGISTER,
	AUDIT_NFT_OP_INVALID,
};

extern int is_audit_feature_set(int which);

extern int __init audit_register_class(int class, unsigned *list);
extern int audit_classify_syscall(int abi, unsigned syscall);
extern int audit_classify_arch(int arch);
/* only for compat system calls */
extern unsigned compat_write_class[];
extern unsigned compat_read_class[];
extern unsigned compat_dir_class[];
extern unsigned compat_chattr_class[];
extern unsigned compat_signal_class[];

extern int audit_classify_compat_syscall(int abi, unsigned syscall);

/* audit_names->type values */
#define	AUDIT_TYPE_UNKNOWN	0	/* we don't know yet */
#define	AUDIT_TYPE_NORMAL	1	/* a "normal" audit record */
#define	AUDIT_TYPE_PARENT	2	/* a parent audit record */
#define	AUDIT_TYPE_CHILD_DELETE 3	/* a child being deleted */
#define	AUDIT_TYPE_CHILD_CREATE 4	/* a child being created */

/* maximized args number that audit_socketcall can process */
#define AUDITSC_ARGS		6

/* bit values for ->signal->audit_tty */
#define AUDIT_TTY_ENABLE	BIT(0)
#define AUDIT_TTY_LOG_PASSWD	BIT(1)

struct filename;

#define AUDIT_OFF	0
#define AUDIT_ON	1
#define AUDIT_LOCKED	2

static inline kuid_t audit_get_loginuid(struct task_struct *tsk)
{
	return INVALID_UID;
}

static inline unsigned int audit_get_sessionid(struct task_struct *tsk)
{
	return AUDIT_SID_UNSET;
}

#define audit_enabled AUDIT_OFF

#define audit_is_compat(arch)  false

#define AUDIT_INODE_PARENT	1	/* dentry represents the parent */
#define AUDIT_INODE_HIDDEN	2	/* audit record should be hidden */
#define AUDIT_INODE_NOEVAL	4	/* audit record incomplete */

static inline int audit_sockaddr(int len, void *addr)
{
	return 0;
}
static inline int audit_log_bprm_fcaps(struct linux_binprm *bprm,
				       const struct cred *new,
				       const struct cred *old)
{
	return 0;
}

#define audit_n_rules 0
#define audit_signals 0

static inline bool audit_loginuid_set(struct task_struct *tsk)
{
	return uid_valid(audit_get_loginuid(tsk));
}

#endif
