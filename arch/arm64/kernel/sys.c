// SPDX-License-Identifier: GPL-2.0-only
/*
 * AArch64-specific system calls implementation
 *
 * Copyright (C) 2012 ARM Ltd.
 * Author: Catalin Marinas <catalin.marinas@arm.com>
 */

#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/syscalls.h>

#include <asm/cpufeature.h>
#include <asm/syscall.h>

SYSCALL_DEFINE6(mmap, unsigned long, addr, unsigned long, len,
		unsigned long, prot, unsigned long, flags,
		unsigned long, fd, unsigned long, off)
{
	if (offset_in_page(off) != 0)
		return -EINVAL;

	return ksys_mmap_pgoff(addr, len, prot, flags, fd, off >> PAGE_SHIFT);
}

static inline long __do_sys_arm64_personality(unsigned int personality)
{
	if (personality(personality) == PER_LINUX32 &&
		!system_supports_32bit_el0())
		return -EINVAL;
	return ksys_personality(personality);
}

long __arm64_sys_arm64_personality(const struct pt_regs *regs)
{
	long ret = __do_sys_arm64_personality((unsigned int)regs->regs[0]);
	return ret;
}

asmlinkage long sys_ni_syscall(void);

asmlinkage long __arm64_sys_ni_syscall(const struct pt_regs *__unused)
{
	return sys_ni_syscall();
}

/*
 * Wrappers to pass the pt_regs argument.
 */
#define __arm64_sys_personality		__arm64_sys_arm64_personality

// #undef __SYSCALL
// #define __SYSCALL(nr, sym)	asmlinkage long __arm64_##sym(const struct pt_regs *);
// #include <asm/unistd.h>
// 
// #undef __SYSCALL
// #define __SYSCALL(nr, sym)	[nr] = __arm64_##sym,

// const syscall_fn_t sys_call_table[__NR_syscalls] = {
// 	[0 ... __NR_syscalls - 1] = __arm64_sys_ni_syscall,
// #include <asm/unistd.h>
// };

asmlinkage long __arm64_sys_io_setup(const struct pt_regs *);
asmlinkage long __arm64_sys_io_destroy(const struct pt_regs *);
asmlinkage long __arm64_sys_io_submit(const struct pt_regs *);
asmlinkage long __arm64_sys_io_cancel(const struct pt_regs *);
asmlinkage long __arm64_sys_io_getevents(const struct pt_regs *);
asmlinkage long __arm64_sys_setxattr(const struct pt_regs *);
asmlinkage long __arm64_sys_lsetxattr(const struct pt_regs *);
asmlinkage long __arm64_sys_fsetxattr(const struct pt_regs *);
asmlinkage long __arm64_sys_getxattr(const struct pt_regs *);
asmlinkage long __arm64_sys_lgetxattr(const struct pt_regs *);
asmlinkage long __arm64_sys_fgetxattr(const struct pt_regs *);
asmlinkage long __arm64_sys_listxattr(const struct pt_regs *);
asmlinkage long __arm64_sys_llistxattr(const struct pt_regs *);
asmlinkage long __arm64_sys_flistxattr(const struct pt_regs *);
asmlinkage long __arm64_sys_removexattr(const struct pt_regs *);
asmlinkage long __arm64_sys_lremovexattr(const struct pt_regs *);
asmlinkage long __arm64_sys_fremovexattr(const struct pt_regs *);
asmlinkage long __arm64_sys_getcwd(const struct pt_regs *);
asmlinkage long __arm64_sys_lookup_dcookie(const struct pt_regs *);
asmlinkage long __arm64_sys_eventfd2(const struct pt_regs *);
asmlinkage long __arm64_sys_epoll_create1(const struct pt_regs *);
asmlinkage long __arm64_sys_epoll_ctl(const struct pt_regs *);
asmlinkage long __arm64_sys_epoll_pwait(const struct pt_regs *);
asmlinkage long __arm64_sys_dup(const struct pt_regs *);
asmlinkage long __arm64_sys_dup3(const struct pt_regs *);
asmlinkage long __arm64_sys_fcntl(const struct pt_regs *);
asmlinkage long __arm64_sys_inotify_init1(const struct pt_regs *);
asmlinkage long __arm64_sys_inotify_add_watch(const struct pt_regs *);
asmlinkage long __arm64_sys_inotify_rm_watch(const struct pt_regs *);
asmlinkage long __arm64_sys_ioctl(const struct pt_regs *);
asmlinkage long __arm64_sys_ioprio_set(const struct pt_regs *);
asmlinkage long __arm64_sys_ioprio_get(const struct pt_regs *);
asmlinkage long __arm64_sys_flock(const struct pt_regs *);
asmlinkage long __arm64_sys_mknodat(const struct pt_regs *);
asmlinkage long __arm64_sys_mkdirat(const struct pt_regs *);
asmlinkage long __arm64_sys_unlinkat(const struct pt_regs *);
asmlinkage long __arm64_sys_symlinkat(const struct pt_regs *);
asmlinkage long __arm64_sys_linkat(const struct pt_regs *);
asmlinkage long __arm64_sys_umount(const struct pt_regs *);
asmlinkage long __arm64_sys_mount(const struct pt_regs *);
asmlinkage long __arm64_sys_pivot_root(const struct pt_regs *);
asmlinkage long __arm64_sys_ni_syscall(const struct pt_regs *);
asmlinkage long __arm64_sys_statfs(const struct pt_regs *);
asmlinkage long __arm64_sys_fstatfs(const struct pt_regs *);
asmlinkage long __arm64_sys_truncate(const struct pt_regs *);
asmlinkage long __arm64_sys_ftruncate(const struct pt_regs *);
asmlinkage long __arm64_sys_fallocate(const struct pt_regs *);
asmlinkage long __arm64_sys_faccessat(const struct pt_regs *);
asmlinkage long __arm64_sys_chdir(const struct pt_regs *);
asmlinkage long __arm64_sys_fchdir(const struct pt_regs *);
asmlinkage long __arm64_sys_chroot(const struct pt_regs *);
asmlinkage long __arm64_sys_fchmod(const struct pt_regs *);
asmlinkage long __arm64_sys_fchmodat(const struct pt_regs *);
asmlinkage long __arm64_sys_fchownat(const struct pt_regs *);
asmlinkage long __arm64_sys_fchown(const struct pt_regs *);
asmlinkage long __arm64_sys_openat(const struct pt_regs *);
asmlinkage long __arm64_sys_close(const struct pt_regs *);
asmlinkage long __arm64_sys_vhangup(const struct pt_regs *);
asmlinkage long __arm64_sys_pipe2(const struct pt_regs *);
asmlinkage long __arm64_sys_quotactl(const struct pt_regs *);
asmlinkage long __arm64_sys_getdents64(const struct pt_regs *);
asmlinkage long __arm64_sys_lseek(const struct pt_regs *);
asmlinkage long __arm64_sys_read(const struct pt_regs *);
asmlinkage long __arm64_sys_write(const struct pt_regs *);
asmlinkage long __arm64_sys_readv(const struct pt_regs *);
asmlinkage long __arm64_sys_writev(const struct pt_regs *);
asmlinkage long __arm64_sys_pread64(const struct pt_regs *);
asmlinkage long __arm64_sys_pwrite64(const struct pt_regs *);
asmlinkage long __arm64_sys_preadv(const struct pt_regs *);
asmlinkage long __arm64_sys_pwritev(const struct pt_regs *);
asmlinkage long __arm64_sys_sendfile64(const struct pt_regs *);
asmlinkage long __arm64_sys_pselect6(const struct pt_regs *);
asmlinkage long __arm64_sys_ppoll(const struct pt_regs *);
asmlinkage long __arm64_sys_signalfd4(const struct pt_regs *);
asmlinkage long __arm64_sys_vmsplice(const struct pt_regs *);
asmlinkage long __arm64_sys_splice(const struct pt_regs *);
asmlinkage long __arm64_sys_tee(const struct pt_regs *);
asmlinkage long __arm64_sys_readlinkat(const struct pt_regs *);
asmlinkage long __arm64_sys_newfstatat(const struct pt_regs *);
asmlinkage long __arm64_sys_newfstat(const struct pt_regs *);
asmlinkage long __arm64_sys_sync(const struct pt_regs *);
asmlinkage long __arm64_sys_fsync(const struct pt_regs *);
asmlinkage long __arm64_sys_fdatasync(const struct pt_regs *);
asmlinkage long __arm64_sys_sync_file_range(const struct pt_regs *);
asmlinkage long __arm64_sys_timerfd_create(const struct pt_regs *);
asmlinkage long __arm64_sys_timerfd_settime(const struct pt_regs *);
asmlinkage long __arm64_sys_timerfd_gettime(const struct pt_regs *);
asmlinkage long __arm64_sys_utimensat(const struct pt_regs *);
asmlinkage long __arm64_sys_acct(const struct pt_regs *);
asmlinkage long __arm64_sys_capget(const struct pt_regs *);
asmlinkage long __arm64_sys_capset(const struct pt_regs *);
asmlinkage long __arm64_sys_personality(const struct pt_regs *);
asmlinkage long __arm64_sys_exit(const struct pt_regs *);
asmlinkage long __arm64_sys_exit_group(const struct pt_regs *);
asmlinkage long __arm64_sys_waitid(const struct pt_regs *);
asmlinkage long __arm64_sys_set_tid_address(const struct pt_regs *);
asmlinkage long __arm64_sys_unshare(const struct pt_regs *);
asmlinkage long __arm64_sys_futex(const struct pt_regs *);
asmlinkage long __arm64_sys_set_robust_list(const struct pt_regs *);
asmlinkage long __arm64_sys_get_robust_list(const struct pt_regs *);
asmlinkage long __arm64_sys_nanosleep(const struct pt_regs *);
asmlinkage long __arm64_sys_getitimer(const struct pt_regs *);
asmlinkage long __arm64_sys_setitimer(const struct pt_regs *);
asmlinkage long __arm64_sys_kexec_load(const struct pt_regs *);
asmlinkage long __arm64_sys_init_module(const struct pt_regs *);
asmlinkage long __arm64_sys_delete_module(const struct pt_regs *);
asmlinkage long __arm64_sys_timer_create(const struct pt_regs *);
asmlinkage long __arm64_sys_timer_gettime(const struct pt_regs *);
asmlinkage long __arm64_sys_timer_getoverrun(const struct pt_regs *);
asmlinkage long __arm64_sys_timer_settime(const struct pt_regs *);
asmlinkage long __arm64_sys_timer_delete(const struct pt_regs *);
asmlinkage long __arm64_sys_clock_settime(const struct pt_regs *);
asmlinkage long __arm64_sys_clock_gettime(const struct pt_regs *);
asmlinkage long __arm64_sys_clock_getres(const struct pt_regs *);
asmlinkage long __arm64_sys_clock_nanosleep(const struct pt_regs *);
asmlinkage long __arm64_sys_syslog(const struct pt_regs *);
asmlinkage long __arm64_sys_ptrace(const struct pt_regs *);
asmlinkage long __arm64_sys_sched_setparam(const struct pt_regs *);
asmlinkage long __arm64_sys_sched_setscheduler(const struct pt_regs *);
asmlinkage long __arm64_sys_sched_getscheduler(const struct pt_regs *);
asmlinkage long __arm64_sys_sched_getparam(const struct pt_regs *);
asmlinkage long __arm64_sys_sched_setaffinity(const struct pt_regs *);
asmlinkage long __arm64_sys_sched_getaffinity(const struct pt_regs *);
asmlinkage long __arm64_sys_sched_yield(const struct pt_regs *);
asmlinkage long __arm64_sys_sched_get_priority_max(const struct pt_regs *);
asmlinkage long __arm64_sys_sched_get_priority_min(const struct pt_regs *);
asmlinkage long __arm64_sys_sched_rr_get_interval(const struct pt_regs *);
asmlinkage long __arm64_sys_restart_syscall(const struct pt_regs *);
asmlinkage long __arm64_sys_kill(const struct pt_regs *);
asmlinkage long __arm64_sys_tkill(const struct pt_regs *);
asmlinkage long __arm64_sys_tgkill(const struct pt_regs *);
asmlinkage long __arm64_sys_sigaltstack(const struct pt_regs *);
asmlinkage long __arm64_sys_rt_sigsuspend(const struct pt_regs *);
asmlinkage long __arm64_sys_rt_sigaction(const struct pt_regs *);
asmlinkage long __arm64_sys_rt_sigprocmask(const struct pt_regs *);
asmlinkage long __arm64_sys_rt_sigpending(const struct pt_regs *);
asmlinkage long __arm64_sys_rt_sigtimedwait(const struct pt_regs *);
asmlinkage long __arm64_sys_rt_sigqueueinfo(const struct pt_regs *);
asmlinkage long __arm64_sys_rt_sigreturn(const struct pt_regs *);
asmlinkage long __arm64_sys_setpriority(const struct pt_regs *);
asmlinkage long __arm64_sys_getpriority(const struct pt_regs *);
asmlinkage long __arm64_sys_reboot(const struct pt_regs *);
asmlinkage long __arm64_sys_setregid(const struct pt_regs *);
asmlinkage long __arm64_sys_setgid(const struct pt_regs *);
asmlinkage long __arm64_sys_setreuid(const struct pt_regs *);
asmlinkage long __arm64_sys_setuid(const struct pt_regs *);
asmlinkage long __arm64_sys_setresuid(const struct pt_regs *);
asmlinkage long __arm64_sys_getresuid(const struct pt_regs *);
asmlinkage long __arm64_sys_setresgid(const struct pt_regs *);
asmlinkage long __arm64_sys_getresgid(const struct pt_regs *);
asmlinkage long __arm64_sys_setfsuid(const struct pt_regs *);
asmlinkage long __arm64_sys_setfsgid(const struct pt_regs *);
asmlinkage long __arm64_sys_times(const struct pt_regs *);
asmlinkage long __arm64_sys_setpgid(const struct pt_regs *);
asmlinkage long __arm64_sys_getpgid(const struct pt_regs *);
asmlinkage long __arm64_sys_getsid(const struct pt_regs *);
asmlinkage long __arm64_sys_setsid(const struct pt_regs *);
asmlinkage long __arm64_sys_getgroups(const struct pt_regs *);
asmlinkage long __arm64_sys_setgroups(const struct pt_regs *);
asmlinkage long __arm64_sys_newuname(const struct pt_regs *);
asmlinkage long __arm64_sys_sethostname(const struct pt_regs *);
asmlinkage long __arm64_sys_setdomainname(const struct pt_regs *);
asmlinkage long __arm64_sys_getrlimit(const struct pt_regs *);
asmlinkage long __arm64_sys_setrlimit(const struct pt_regs *);
asmlinkage long __arm64_sys_getrusage(const struct pt_regs *);
asmlinkage long __arm64_sys_umask(const struct pt_regs *);
asmlinkage long __arm64_sys_prctl(const struct pt_regs *);
asmlinkage long __arm64_sys_getcpu(const struct pt_regs *);
asmlinkage long __arm64_sys_gettimeofday(const struct pt_regs *);
asmlinkage long __arm64_sys_settimeofday(const struct pt_regs *);
asmlinkage long __arm64_sys_adjtimex(const struct pt_regs *);
asmlinkage long __arm64_sys_getpid(const struct pt_regs *);
asmlinkage long __arm64_sys_getppid(const struct pt_regs *);
asmlinkage long __arm64_sys_getuid(const struct pt_regs *);
asmlinkage long __arm64_sys_geteuid(const struct pt_regs *);
asmlinkage long __arm64_sys_getgid(const struct pt_regs *);
asmlinkage long __arm64_sys_getegid(const struct pt_regs *);
asmlinkage long __arm64_sys_gettid(const struct pt_regs *);
asmlinkage long __arm64_sys_sysinfo(const struct pt_regs *);
asmlinkage long __arm64_sys_mq_open(const struct pt_regs *);
asmlinkage long __arm64_sys_mq_unlink(const struct pt_regs *);
asmlinkage long __arm64_sys_mq_timedsend(const struct pt_regs *);
asmlinkage long __arm64_sys_mq_timedreceive(const struct pt_regs *);
asmlinkage long __arm64_sys_mq_notify(const struct pt_regs *);
asmlinkage long __arm64_sys_mq_getsetattr(const struct pt_regs *);
asmlinkage long __arm64_sys_msgget(const struct pt_regs *);
asmlinkage long __arm64_sys_msgctl(const struct pt_regs *);
asmlinkage long __arm64_sys_msgrcv(const struct pt_regs *);
asmlinkage long __arm64_sys_msgsnd(const struct pt_regs *);
asmlinkage long __arm64_sys_semget(const struct pt_regs *);
asmlinkage long __arm64_sys_semctl(const struct pt_regs *);
asmlinkage long __arm64_sys_semtimedop(const struct pt_regs *);
asmlinkage long __arm64_sys_semop(const struct pt_regs *);
asmlinkage long __arm64_sys_shmget(const struct pt_regs *);
asmlinkage long __arm64_sys_shmctl(const struct pt_regs *);
asmlinkage long __arm64_sys_shmat(const struct pt_regs *);
asmlinkage long __arm64_sys_shmdt(const struct pt_regs *);
asmlinkage long __arm64_sys_socket(const struct pt_regs *);
asmlinkage long __arm64_sys_socketpair(const struct pt_regs *);
asmlinkage long __arm64_sys_bind(const struct pt_regs *);
asmlinkage long __arm64_sys_listen(const struct pt_regs *);
asmlinkage long __arm64_sys_accept(const struct pt_regs *);
asmlinkage long __arm64_sys_connect(const struct pt_regs *);
asmlinkage long __arm64_sys_getsockname(const struct pt_regs *);
asmlinkage long __arm64_sys_getpeername(const struct pt_regs *);
asmlinkage long __arm64_sys_sendto(const struct pt_regs *);
asmlinkage long __arm64_sys_recvfrom(const struct pt_regs *);
asmlinkage long __arm64_sys_setsockopt(const struct pt_regs *);
asmlinkage long __arm64_sys_getsockopt(const struct pt_regs *);
asmlinkage long __arm64_sys_shutdown(const struct pt_regs *);
asmlinkage long __arm64_sys_sendmsg(const struct pt_regs *);
asmlinkage long __arm64_sys_recvmsg(const struct pt_regs *);
asmlinkage long __arm64_sys_readahead(const struct pt_regs *);
asmlinkage long __arm64_sys_brk(const struct pt_regs *);
asmlinkage long __arm64_sys_munmap(const struct pt_regs *);
asmlinkage long __arm64_sys_mremap(const struct pt_regs *);
asmlinkage long __arm64_sys_add_key(const struct pt_regs *);
asmlinkage long __arm64_sys_request_key(const struct pt_regs *);
asmlinkage long __arm64_sys_keyctl(const struct pt_regs *);
asmlinkage long __arm64_sys_clone(const struct pt_regs *);
asmlinkage long __arm64_sys_execve(const struct pt_regs *);
asmlinkage long __arm64_sys_mmap(const struct pt_regs *);
asmlinkage long __arm64_sys_fadvise64_64(const struct pt_regs *);
asmlinkage long __arm64_sys_swapon(const struct pt_regs *);
asmlinkage long __arm64_sys_swapoff(const struct pt_regs *);
asmlinkage long __arm64_sys_mprotect(const struct pt_regs *);
asmlinkage long __arm64_sys_msync(const struct pt_regs *);
asmlinkage long __arm64_sys_mlock(const struct pt_regs *);
asmlinkage long __arm64_sys_munlock(const struct pt_regs *);
asmlinkage long __arm64_sys_mlockall(const struct pt_regs *);
asmlinkage long __arm64_sys_munlockall(const struct pt_regs *);
asmlinkage long __arm64_sys_mincore(const struct pt_regs *);
asmlinkage long __arm64_sys_madvise(const struct pt_regs *);
asmlinkage long __arm64_sys_remap_file_pages(const struct pt_regs *);
asmlinkage long __arm64_sys_mbind(const struct pt_regs *);
asmlinkage long __arm64_sys_get_mempolicy(const struct pt_regs *);
asmlinkage long __arm64_sys_set_mempolicy(const struct pt_regs *);
asmlinkage long __arm64_sys_migrate_pages(const struct pt_regs *);
asmlinkage long __arm64_sys_move_pages(const struct pt_regs *);
asmlinkage long __arm64_sys_rt_tgsigqueueinfo(const struct pt_regs *);
asmlinkage long __arm64_sys_perf_event_open(const struct pt_regs *);
asmlinkage long __arm64_sys_accept4(const struct pt_regs *);
asmlinkage long __arm64_sys_recvmmsg(const struct pt_regs *);
asmlinkage long __arm64_sys_wait4(const struct pt_regs *);
asmlinkage long __arm64_sys_prlimit64(const struct pt_regs *);
asmlinkage long __arm64_sys_fanotify_init(const struct pt_regs *);
asmlinkage long __arm64_sys_fanotify_mark(const struct pt_regs *);
asmlinkage long __arm64_sys_name_to_handle_at(const struct pt_regs *);
asmlinkage long __arm64_sys_open_by_handle_at(const struct pt_regs *);
asmlinkage long __arm64_sys_clock_adjtime(const struct pt_regs *);
asmlinkage long __arm64_sys_syncfs(const struct pt_regs *);
asmlinkage long __arm64_sys_setns(const struct pt_regs *);
asmlinkage long __arm64_sys_sendmmsg(const struct pt_regs *);
asmlinkage long __arm64_sys_process_vm_readv(const struct pt_regs *);
asmlinkage long __arm64_sys_process_vm_writev(const struct pt_regs *);
asmlinkage long __arm64_sys_kcmp(const struct pt_regs *);
asmlinkage long __arm64_sys_finit_module(const struct pt_regs *);
asmlinkage long __arm64_sys_sched_setattr(const struct pt_regs *);
asmlinkage long __arm64_sys_sched_getattr(const struct pt_regs *);
asmlinkage long __arm64_sys_renameat2(const struct pt_regs *);
asmlinkage long __arm64_sys_seccomp(const struct pt_regs *);
asmlinkage long __arm64_sys_getrandom(const struct pt_regs *);
asmlinkage long __arm64_sys_memfd_create(const struct pt_regs *);
asmlinkage long __arm64_sys_bpf(const struct pt_regs *);
asmlinkage long __arm64_sys_execveat(const struct pt_regs *);
asmlinkage long __arm64_sys_userfaultfd(const struct pt_regs *);
asmlinkage long __arm64_sys_membarrier(const struct pt_regs *);
asmlinkage long __arm64_sys_mlock2(const struct pt_regs *);
asmlinkage long __arm64_sys_copy_file_range(const struct pt_regs *);
asmlinkage long __arm64_sys_preadv2(const struct pt_regs *);
asmlinkage long __arm64_sys_pwritev2(const struct pt_regs *);
asmlinkage long __arm64_sys_pkey_mprotect(const struct pt_regs *);
asmlinkage long __arm64_sys_pkey_alloc(const struct pt_regs *);
asmlinkage long __arm64_sys_pkey_free(const struct pt_regs *);
asmlinkage long __arm64_sys_statx(const struct pt_regs *);
asmlinkage long __arm64_sys_io_pgetevents(const struct pt_regs *);
asmlinkage long __arm64_sys_rseq(const struct pt_regs *);
asmlinkage long __arm64_sys_kexec_file_load(const struct pt_regs *);
asmlinkage long __arm64_sys_pidfd_send_signal(const struct pt_regs *);
asmlinkage long __arm64_sys_io_uring_setup(const struct pt_regs *);
asmlinkage long __arm64_sys_io_uring_enter(const struct pt_regs *);
asmlinkage long __arm64_sys_io_uring_register(const struct pt_regs *);
asmlinkage long __arm64_sys_open_tree(const struct pt_regs *);
asmlinkage long __arm64_sys_move_mount(const struct pt_regs *);
asmlinkage long __arm64_sys_fsopen(const struct pt_regs *);
asmlinkage long __arm64_sys_fsconfig(const struct pt_regs *);
asmlinkage long __arm64_sys_fsmount(const struct pt_regs *);
asmlinkage long __arm64_sys_fspick(const struct pt_regs *);
asmlinkage long __arm64_sys_pidfd_open(const struct pt_regs *);
asmlinkage long __arm64_sys_clone3(const struct pt_regs *);
asmlinkage long __arm64_sys_close_range(const struct pt_regs *);
asmlinkage long __arm64_sys_openat2(const struct pt_regs *);
asmlinkage long __arm64_sys_pidfd_getfd(const struct pt_regs *);
asmlinkage long __arm64_sys_faccessat2(const struct pt_regs *);
asmlinkage long __arm64_sys_process_madvise(const struct pt_regs *);

const syscall_fn_t sys_call_table[__NR_syscalls] = {
	[0 ... __NR_syscalls - 1] = __arm64_sys_ni_syscall,
	[__NR_io_setup] = __arm64_sys_io_setup,
	[__NR_io_destroy] = __arm64_sys_io_destroy,
	[__NR_io_submit] = __arm64_sys_io_submit,
	[__NR_io_cancel] = __arm64_sys_io_cancel,
	[__NR_io_getevents] = __arm64_sys_io_getevents,
	[__NR_setxattr] = __arm64_sys_setxattr,
	[__NR_lsetxattr] = __arm64_sys_lsetxattr,
	[__NR_fsetxattr] = __arm64_sys_fsetxattr,
	[__NR_getxattr] = __arm64_sys_getxattr,
	[__NR_lgetxattr] = __arm64_sys_lgetxattr,
	[__NR_fgetxattr] = __arm64_sys_fgetxattr,
	[__NR_listxattr] = __arm64_sys_listxattr,
	[__NR_llistxattr] = __arm64_sys_llistxattr,
	[__NR_flistxattr] = __arm64_sys_flistxattr,
	[__NR_removexattr] = __arm64_sys_removexattr,
	[__NR_lremovexattr] = __arm64_sys_lremovexattr,
	[__NR_fremovexattr] = __arm64_sys_fremovexattr,
	[__NR_getcwd] = __arm64_sys_getcwd,
	[__NR_lookup_dcookie] = __arm64_sys_lookup_dcookie,
	[__NR_eventfd2] = __arm64_sys_eventfd2,
	[__NR_epoll_create1] = __arm64_sys_epoll_create1,
	[__NR_epoll_ctl] = __arm64_sys_epoll_ctl,
	[__NR_epoll_pwait] = __arm64_sys_epoll_pwait,
	[__NR_dup] = __arm64_sys_dup,
	[__NR_dup3] = __arm64_sys_dup3,
	[__NR3264_fcntl] = __arm64_sys_fcntl,
	[__NR_inotify_init1] = __arm64_sys_inotify_init1,
	[__NR_inotify_add_watch] = __arm64_sys_inotify_add_watch,
	[__NR_inotify_rm_watch] = __arm64_sys_inotify_rm_watch,
	[__NR_ioctl] = __arm64_sys_ioctl,
	[__NR_ioprio_set] = __arm64_sys_ioprio_set,
	[__NR_ioprio_get] = __arm64_sys_ioprio_get,
	[__NR_flock] = __arm64_sys_flock,
	[__NR_mknodat] = __arm64_sys_mknodat,
	[__NR_mkdirat] = __arm64_sys_mkdirat,
	[__NR_unlinkat] = __arm64_sys_unlinkat,
	[__NR_symlinkat] = __arm64_sys_symlinkat,
	[__NR_linkat] = __arm64_sys_linkat,
	[__NR_umount2] = __arm64_sys_umount,
	[__NR_mount] = __arm64_sys_mount,
	[__NR_pivot_root] = __arm64_sys_pivot_root,
	[__NR_nfsservctl] = __arm64_sys_ni_syscall,
	[__NR3264_statfs] = __arm64_sys_statfs,
	[__NR3264_fstatfs] = __arm64_sys_fstatfs,
	[__NR3264_truncate] = __arm64_sys_truncate,
	[__NR3264_ftruncate] = __arm64_sys_ftruncate,
	[__NR_fallocate] = __arm64_sys_fallocate,
	[__NR_faccessat] = __arm64_sys_faccessat,
	[__NR_chdir] = __arm64_sys_chdir,
	[__NR_fchdir] = __arm64_sys_fchdir,
	[__NR_chroot] = __arm64_sys_chroot,
	[__NR_fchmod] = __arm64_sys_fchmod,
	[__NR_fchmodat] = __arm64_sys_fchmodat,
	[__NR_fchownat] = __arm64_sys_fchownat,
	[__NR_fchown] = __arm64_sys_fchown,
	[__NR_openat] = __arm64_sys_openat,
	[__NR_close] = __arm64_sys_close,
	[__NR_vhangup] = __arm64_sys_vhangup,
	[__NR_pipe2] = __arm64_sys_pipe2,
	[__NR_quotactl] = __arm64_sys_quotactl,
	[__NR_getdents64] = __arm64_sys_getdents64,
	[__NR3264_lseek] = __arm64_sys_lseek,
	[__NR_read] = __arm64_sys_read,
	[__NR_write] = __arm64_sys_write,
	[__NR_readv] = __arm64_sys_readv,
	[__NR_writev] = __arm64_sys_writev,
	[__NR_pread64] = __arm64_sys_pread64,
	[__NR_pwrite64] = __arm64_sys_pwrite64,
	[__NR_preadv] = __arm64_sys_preadv,
	[__NR_pwritev] = __arm64_sys_pwritev,
	[__NR3264_sendfile] = __arm64_sys_sendfile64,
	[__NR_pselect6] = __arm64_sys_pselect6,
	[__NR_ppoll] = __arm64_sys_ppoll,
	[__NR_signalfd4] = __arm64_sys_signalfd4,
	[__NR_vmsplice] = __arm64_sys_vmsplice,
	[__NR_splice] = __arm64_sys_splice,
	[__NR_tee] = __arm64_sys_tee,
	[__NR_readlinkat] = __arm64_sys_readlinkat,
	[__NR3264_fstatat] = __arm64_sys_newfstatat,
	[__NR3264_fstat] = __arm64_sys_newfstat,
	[__NR_sync] = __arm64_sys_sync,
	[__NR_fsync] = __arm64_sys_fsync,
	[__NR_fdatasync] = __arm64_sys_fdatasync,
	[__NR_sync_file_range] = __arm64_sys_sync_file_range,
	[__NR_timerfd_create] = __arm64_sys_timerfd_create,
	[__NR_timerfd_settime] = __arm64_sys_timerfd_settime,
	[__NR_timerfd_gettime] = __arm64_sys_timerfd_gettime,
	[__NR_utimensat] = __arm64_sys_utimensat,
	[__NR_acct] = __arm64_sys_acct,
	[__NR_capget] = __arm64_sys_capget,
	[__NR_capset] = __arm64_sys_capset,
	[__NR_personality] = __arm64_sys_personality,
	[__NR_exit] = __arm64_sys_exit,
	[__NR_exit_group] = __arm64_sys_exit_group,
	[__NR_waitid] = __arm64_sys_waitid,
	[__NR_set_tid_address] = __arm64_sys_set_tid_address,
	[__NR_unshare] = __arm64_sys_unshare,
	[__NR_futex] = __arm64_sys_futex,
	[__NR_set_robust_list] = __arm64_sys_set_robust_list,
	[__NR_get_robust_list] = __arm64_sys_get_robust_list,
	[__NR_nanosleep] = __arm64_sys_nanosleep,
	[__NR_getitimer] = __arm64_sys_getitimer,
	[__NR_setitimer] = __arm64_sys_setitimer,
	[__NR_kexec_load] = __arm64_sys_kexec_load,
	[__NR_init_module] = __arm64_sys_init_module,
	[__NR_delete_module] = __arm64_sys_delete_module,
	[__NR_timer_create] = __arm64_sys_timer_create,
	[__NR_timer_gettime] = __arm64_sys_timer_gettime,
	[__NR_timer_getoverrun] = __arm64_sys_timer_getoverrun,
	[__NR_timer_settime] = __arm64_sys_timer_settime,
	[__NR_timer_delete] = __arm64_sys_timer_delete,
	[__NR_clock_settime] = __arm64_sys_clock_settime,
	[__NR_clock_gettime] = __arm64_sys_clock_gettime,
	[__NR_clock_getres] = __arm64_sys_clock_getres,
	[__NR_clock_nanosleep] = __arm64_sys_clock_nanosleep,
	[__NR_syslog] = __arm64_sys_syslog,
	[__NR_ptrace] = __arm64_sys_ptrace,
	[__NR_sched_setparam] = __arm64_sys_sched_setparam,
	[__NR_sched_setscheduler] = __arm64_sys_sched_setscheduler,
	[__NR_sched_getscheduler] = __arm64_sys_sched_getscheduler,
	[__NR_sched_getparam] = __arm64_sys_sched_getparam,
	[__NR_sched_setaffinity] = __arm64_sys_sched_setaffinity,
	[__NR_sched_getaffinity] = __arm64_sys_sched_getaffinity,
	[__NR_sched_yield] = __arm64_sys_sched_yield,
	[__NR_sched_get_priority_max] = __arm64_sys_sched_get_priority_max,
	[__NR_sched_get_priority_min] = __arm64_sys_sched_get_priority_min,
	[__NR_sched_rr_get_interval] = __arm64_sys_sched_rr_get_interval,
	[__NR_restart_syscall] = __arm64_sys_restart_syscall,
	[__NR_kill] = __arm64_sys_kill,
	[__NR_tkill] = __arm64_sys_tkill,
	[__NR_tgkill] = __arm64_sys_tgkill,
	[__NR_sigaltstack] = __arm64_sys_sigaltstack,
	[__NR_rt_sigsuspend] = __arm64_sys_rt_sigsuspend,
	[__NR_rt_sigaction] = __arm64_sys_rt_sigaction,
	[__NR_rt_sigprocmask] = __arm64_sys_rt_sigprocmask,
	[__NR_rt_sigpending] = __arm64_sys_rt_sigpending,
	[__NR_rt_sigtimedwait] = __arm64_sys_rt_sigtimedwait,
	[__NR_rt_sigqueueinfo] = __arm64_sys_rt_sigqueueinfo,
	[__NR_rt_sigreturn] = __arm64_sys_rt_sigreturn,
	[__NR_setpriority] = __arm64_sys_setpriority,
	[__NR_getpriority] = __arm64_sys_getpriority,
	[__NR_reboot] = __arm64_sys_reboot,
	[__NR_setregid] = __arm64_sys_setregid,
	[__NR_setgid] = __arm64_sys_setgid,
	[__NR_setreuid] = __arm64_sys_setreuid,
	[__NR_setuid] = __arm64_sys_setuid,
	[__NR_setresuid] = __arm64_sys_setresuid,
	[__NR_getresuid] = __arm64_sys_getresuid,
	[__NR_setresgid] = __arm64_sys_setresgid,
	[__NR_getresgid] = __arm64_sys_getresgid,
	[__NR_setfsuid] = __arm64_sys_setfsuid,
	[__NR_setfsgid] = __arm64_sys_setfsgid,
	[__NR_times] = __arm64_sys_times,
	[__NR_setpgid] = __arm64_sys_setpgid,
	[__NR_getpgid] = __arm64_sys_getpgid,
	[__NR_getsid] = __arm64_sys_getsid,
	[__NR_setsid] = __arm64_sys_setsid,
	[__NR_getgroups] = __arm64_sys_getgroups,
	[__NR_setgroups] = __arm64_sys_setgroups,
	[__NR_uname] = __arm64_sys_newuname,
	[__NR_sethostname] = __arm64_sys_sethostname,
	[__NR_setdomainname] = __arm64_sys_setdomainname,
	[__NR_getrlimit] = __arm64_sys_getrlimit,
	[__NR_setrlimit ] = __arm64_sys_setrlimit,
	[__NR_getrusage] = __arm64_sys_getrusage,
	[__NR_umask] = __arm64_sys_umask,
	[__NR_prctl] = __arm64_sys_prctl,
	[__NR_getcpu] = __arm64_sys_getcpu,
	[__NR_gettimeofday] = __arm64_sys_gettimeofday,
	[__NR_settimeofday] = __arm64_sys_settimeofday,
	[__NR_adjtimex] = __arm64_sys_adjtimex,
	[__NR_getpid] = __arm64_sys_getpid,
	[__NR_getppid] = __arm64_sys_getppid,
	[__NR_getuid] = __arm64_sys_getuid,
	[__NR_geteuid] = __arm64_sys_geteuid,
	[__NR_getgid] = __arm64_sys_getgid,
	[__NR_getegid] = __arm64_sys_getegid,
	[__NR_gettid] = __arm64_sys_gettid,
	[__NR_sysinfo] = __arm64_sys_sysinfo,
	[__NR_mq_open] = __arm64_sys_mq_open,
	[__NR_mq_unlink] = __arm64_sys_mq_unlink,
	[__NR_mq_timedsend] = __arm64_sys_mq_timedsend,
	[__NR_mq_timedreceive] = __arm64_sys_mq_timedreceive,
	[__NR_mq_notify] = __arm64_sys_mq_notify,
	[__NR_mq_getsetattr] = __arm64_sys_mq_getsetattr,
	[__NR_msgget] = __arm64_sys_msgget,
	[__NR_msgctl] = __arm64_sys_msgctl,
	[__NR_msgrcv] = __arm64_sys_msgrcv,
	[__NR_msgsnd] = __arm64_sys_msgsnd,
	[__NR_semget] = __arm64_sys_semget,
	[__NR_semctl] = __arm64_sys_semctl,
	[__NR_semtimedop] = __arm64_sys_semtimedop,
	[__NR_semop] = __arm64_sys_semop,
	[__NR_shmget] = __arm64_sys_shmget,
	[__NR_shmctl] = __arm64_sys_shmctl,
	[__NR_shmat] = __arm64_sys_shmat,
	[__NR_shmdt] = __arm64_sys_shmdt,
	[__NR_socket] = __arm64_sys_socket,
	[__NR_socketpair] = __arm64_sys_socketpair,
	[__NR_bind] = __arm64_sys_bind,
	[__NR_listen] = __arm64_sys_listen,
	[__NR_accept] = __arm64_sys_accept,
	[__NR_connect] = __arm64_sys_connect,
	[__NR_getsockname] = __arm64_sys_getsockname,
	[__NR_getpeername] = __arm64_sys_getpeername,
	[__NR_sendto] = __arm64_sys_sendto,
	[__NR_recvfrom] = __arm64_sys_recvfrom,
	[__NR_setsockopt] = __arm64_sys_setsockopt,
	[__NR_getsockopt] = __arm64_sys_getsockopt,
	[__NR_shutdown] = __arm64_sys_shutdown,
	[__NR_sendmsg] = __arm64_sys_sendmsg,
	[__NR_recvmsg] = __arm64_sys_recvmsg,
	[__NR_readahead] = __arm64_sys_readahead,
	[__NR_brk] = __arm64_sys_brk,
	[__NR_munmap] = __arm64_sys_munmap,
	[__NR_mremap] = __arm64_sys_mremap,
	[__NR_add_key] = __arm64_sys_add_key,
	[__NR_request_key] = __arm64_sys_request_key,
	[__NR_keyctl] = __arm64_sys_keyctl,
	[__NR_clone] = __arm64_sys_clone,
	[__NR_execve] = __arm64_sys_execve,
	[__NR3264_mmap] = __arm64_sys_mmap,
	[__NR3264_fadvise64] = __arm64_sys_fadvise64_64,
	[__NR_swapon] = __arm64_sys_swapon,
	[__NR_swapoff] = __arm64_sys_swapoff,
	[__NR_mprotect] = __arm64_sys_mprotect,
	[__NR_msync] = __arm64_sys_msync,
	[__NR_mlock] = __arm64_sys_mlock,
	[__NR_munlock] = __arm64_sys_munlock,
	[__NR_mlockall] = __arm64_sys_mlockall,
	[__NR_munlockall] = __arm64_sys_munlockall,
	[__NR_mincore] = __arm64_sys_mincore,
	[__NR_madvise] = __arm64_sys_madvise,
	[__NR_remap_file_pages] = __arm64_sys_remap_file_pages,
	[__NR_mbind] = __arm64_sys_mbind,
	[__NR_get_mempolicy] = __arm64_sys_get_mempolicy,
	[__NR_set_mempolicy] = __arm64_sys_set_mempolicy,
	[__NR_migrate_pages] = __arm64_sys_migrate_pages,
	[__NR_move_pages] = __arm64_sys_move_pages,
	[__NR_rt_tgsigqueueinfo] = __arm64_sys_rt_tgsigqueueinfo,
	[__NR_perf_event_open] = __arm64_sys_perf_event_open,
	[__NR_accept4] = __arm64_sys_accept4,
	[__NR_recvmmsg] = __arm64_sys_recvmmsg,
	[__NR_wait4] = __arm64_sys_wait4,
	[__NR_prlimit64] = __arm64_sys_prlimit64,
	[__NR_fanotify_init] = __arm64_sys_fanotify_init,
	[__NR_fanotify_mark] = __arm64_sys_fanotify_mark,
	[__NR_name_to_handle_at] = __arm64_sys_name_to_handle_at,
	[__NR_open_by_handle_at] = __arm64_sys_open_by_handle_at,
	[__NR_clock_adjtime] = __arm64_sys_clock_adjtime,
	[__NR_syncfs] = __arm64_sys_syncfs,
	[__NR_setns] = __arm64_sys_setns,
	[__NR_sendmmsg] = __arm64_sys_sendmmsg,
	[__NR_process_vm_readv] = __arm64_sys_process_vm_readv,
	[__NR_process_vm_writev] = __arm64_sys_process_vm_writev,
	[__NR_kcmp] = __arm64_sys_kcmp,
	[__NR_finit_module] = __arm64_sys_finit_module,
	[__NR_sched_setattr] = __arm64_sys_sched_setattr,
	[__NR_sched_getattr] = __arm64_sys_sched_getattr,
	[__NR_renameat2] = __arm64_sys_renameat2,
	[__NR_seccomp] = __arm64_sys_seccomp,
	[__NR_getrandom] = __arm64_sys_getrandom,
	[__NR_memfd_create] = __arm64_sys_memfd_create,
	[__NR_bpf] = __arm64_sys_bpf,
	[__NR_execveat] = __arm64_sys_execveat,
	[__NR_userfaultfd] = __arm64_sys_userfaultfd,
	[__NR_membarrier] = __arm64_sys_membarrier,
	[__NR_mlock2] = __arm64_sys_mlock2,
	[__NR_copy_file_range] = __arm64_sys_copy_file_range,
	[__NR_preadv2] = __arm64_sys_preadv2,
	[__NR_pwritev2] = __arm64_sys_pwritev2,
	[__NR_pkey_mprotect] = __arm64_sys_pkey_mprotect,
	[__NR_pkey_alloc] = __arm64_sys_pkey_alloc,
	[__NR_pkey_free] = __arm64_sys_pkey_free,
	[__NR_statx] = __arm64_sys_statx,
	[__NR_io_pgetevents] = __arm64_sys_io_pgetevents,
	[__NR_rseq] = __arm64_sys_rseq,
	[__NR_kexec_file_load] = __arm64_sys_kexec_file_load,
	[__NR_pidfd_send_signal] = __arm64_sys_pidfd_send_signal,
	[__NR_io_uring_setup] = __arm64_sys_io_uring_setup,
	[__NR_io_uring_enter] = __arm64_sys_io_uring_enter,
	[__NR_io_uring_register] = __arm64_sys_io_uring_register,
	[__NR_open_tree] = __arm64_sys_open_tree,
	[__NR_move_mount] = __arm64_sys_move_mount,
	[__NR_fsopen] = __arm64_sys_fsopen,
	[__NR_fsconfig] = __arm64_sys_fsconfig,
	[__NR_fsmount] = __arm64_sys_fsmount,
	[__NR_fspick] = __arm64_sys_fspick,
	[__NR_pidfd_open] = __arm64_sys_pidfd_open,
	[__NR_clone3] = __arm64_sys_clone3,
	[__NR_close_range] = __arm64_sys_close_range,
	[__NR_openat2] = __arm64_sys_openat2,
	[__NR_pidfd_getfd] = __arm64_sys_pidfd_getfd,
	[__NR_faccessat2] = __arm64_sys_faccessat2,
	[__NR_process_madvise] = __arm64_sys_process_madvise,
};
