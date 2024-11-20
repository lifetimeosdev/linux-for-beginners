/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KHUGEPAGED_H
#define _LINUX_KHUGEPAGED_H

#include <linux/sched/coredump.h> /* MMF_VM_HUGEPAGE */
#include <linux/shmem_fs.h>


static inline int khugepaged_fork(struct mm_struct *mm, struct mm_struct *oldmm)
{
	return 0;
}
static inline void khugepaged_exit(struct mm_struct *mm)
{
}
static inline int khugepaged_enter(struct vm_area_struct *vma,
				   unsigned long vm_flags)
{
	return 0;
}
static inline int khugepaged_enter_vma_merge(struct vm_area_struct *vma,
					     unsigned long vm_flags)
{
	return 0;
}
static inline void collapse_pte_mapped_thp(struct mm_struct *mm,
					   unsigned long addr)
{
}

static inline void khugepaged_min_free_kbytes_update(void)
{
}

#endif /* _LINUX_KHUGEPAGED_H */
