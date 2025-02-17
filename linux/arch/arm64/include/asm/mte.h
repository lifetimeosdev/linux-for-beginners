/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 ARM Ltd.
 */
#ifndef __ASM_MTE_H
#define __ASM_MTE_H

#define MTE_GRANULE_SIZE	UL(16)
#define MTE_GRANULE_MASK	(~(MTE_GRANULE_SIZE - 1))
#define MTE_TAG_SHIFT		56
#define MTE_TAG_SIZE		4

#ifndef __ASSEMBLY__

#include <linux/page-flags.h>

#include <asm/pgtable-types.h>

void mte_clear_page_tags(void *addr);
unsigned long mte_copy_tags_from_user(void *to, const void __user *from,
				      unsigned long n);
unsigned long mte_copy_tags_to_user(void __user *to, void *from,
				    unsigned long n);
int mte_save_tags(struct page *page);
void mte_save_page_tags(const void *page_addr, void *tag_storage);
bool mte_restore_tags(swp_entry_t entry, struct page *page);
void mte_restore_page_tags(void *page_addr, const void *tag_storage);
void mte_invalidate_tags(int type, pgoff_t offset);
void mte_invalidate_tags_area(int type);
void *mte_allocate_tag_storage(void);
void mte_free_tag_storage(char *storage);

/* unused if !CONFIG_ARM64_MTE, silence the compiler */
#define PG_mte_tagged	0

static inline void mte_sync_tags(pte_t *ptep, pte_t pte)
{
}
static inline void mte_copy_page_tags(void *kto, const void *kfrom)
{
}
static inline void flush_mte_state(void)
{
}
static inline void mte_thread_switch(struct task_struct *next)
{
}
static inline void mte_suspend_exit(void)
{
}
static inline long set_mte_ctrl(struct task_struct *task, unsigned long arg)
{
	return 0;
}
static inline long get_mte_ctrl(struct task_struct *task)
{
	return 0;
}
static inline int mte_ptrace_copy_tags(struct task_struct *child,
				       long request, unsigned long addr,
				       unsigned long data)
{
	return -EIO;
}

#endif

#endif /* __ASSEMBLY__ */
