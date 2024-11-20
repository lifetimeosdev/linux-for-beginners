/* SPDX-License-Identifier: GPL-2.0 */
#ifndef NET_COMPAT_H
#define NET_COMPAT_H


struct sock;

/*
 * To avoid compiler warnings:
 */
#define compat_msghdr	msghdr
#define compat_mmsghdr	mmsghdr

int __get_compat_msghdr(struct msghdr *kmsg, struct compat_msghdr __user *umsg,
			struct sockaddr __user **save_addr, compat_uptr_t *ptr,
			compat_size_t *len);
int get_compat_msghdr(struct msghdr *, struct compat_msghdr __user *,
		      struct sockaddr __user **, struct iovec **);
int put_cmsg_compat(struct msghdr*, int, int, int, void *);

int cmsghdr_from_user_compat_to_kern(struct msghdr *, struct sock *,
				     unsigned char *, int);

struct compat_group_req {
	__u32				 gr_interface;
	struct __kernel_sockaddr_storage gr_group
		__aligned(4);
} __packed;

struct compat_group_source_req {
	__u32				 gsr_interface;
	struct __kernel_sockaddr_storage gsr_group
		__aligned(4);
	struct __kernel_sockaddr_storage gsr_source
		__aligned(4);
} __packed;

struct compat_group_filter {
	__u32				 gf_interface;
	struct __kernel_sockaddr_storage gf_group
		__aligned(4);
	__u32				 gf_fmode;
	__u32				 gf_numsrc;
	struct __kernel_sockaddr_storage gf_slist[1]
		__aligned(4);
} __packed;

#endif /* NET_COMPAT_H */
