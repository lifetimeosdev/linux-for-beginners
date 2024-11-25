/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KASAN_H
#define _LINUX_KASAN_H

#include <linux/types.h>

struct kmem_cache;
struct page;
struct vm_struct;
struct task_struct;

static inline void kasan_unpoison_shadow(const void *address, size_t size) {}

static inline void kasan_unpoison_task_stack(struct task_struct *task) {}

static inline void kasan_enable_current(void) {}
static inline void kasan_disable_current(void) {}

static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
static inline void kasan_free_pages(struct page *page, unsigned int order) {}

static inline void kasan_cache_create(struct kmem_cache *cache,
				      unsigned int *size,
				      slab_flags_t *flags) {}

static inline void kasan_poison_slab(struct page *page) {}
static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
					void *object) {}
static inline void kasan_poison_object_data(struct kmem_cache *cache,
					void *object) {}
static inline void *kasan_init_slab_obj(struct kmem_cache *cache,
				const void *object)
{
	return (void *)object;
}

static inline void *kasan_kmalloc_large(void *ptr, size_t size, gfp_t flags)
{
	return ptr;
}
static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
static inline void kasan_poison_kfree(void *ptr, unsigned long ip) {}
static inline void *kasan_kmalloc(struct kmem_cache *s, const void *object,
				size_t size, gfp_t flags)
{
	return (void *)object;
}
static inline void *kasan_krealloc(const void *object, size_t new_size,
				 gfp_t flags)
{
	return (void *)object;
}

static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
				   gfp_t flags)
{
	return object;
}
static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
				   unsigned long ip)
{
	return false;
}

static inline int kasan_module_alloc(void *addr, size_t size) { return 0; }
static inline void kasan_free_shadow(const struct vm_struct *vm) {}

static inline int kasan_add_zero_shadow(void *start, unsigned long size)
{
	return 0;
}
static inline void kasan_remove_zero_shadow(void *start,
					unsigned long size)
{}

static inline void kasan_unpoison_slab(const void *ptr) { }
static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }

static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
static inline void kasan_record_aux_stack(void *ptr) {}

static inline void kasan_init_tags(void) { }

static inline void *kasan_reset_tag(const void *addr)
{
	return (void *)addr;
}

static inline int kasan_populate_vmalloc(unsigned long start,
					unsigned long size)
{
	return 0;
}

static inline void kasan_poison_vmalloc(const void *start, unsigned long size)
{ }
static inline void kasan_unpoison_vmalloc(const void *start, unsigned long size)
{ }
static inline void kasan_release_vmalloc(unsigned long start,
					 unsigned long end,
					 unsigned long free_region_start,
					 unsigned long free_region_end) {}

static inline void kasan_non_canonical_hook(unsigned long addr) { }

#endif /* LINUX_KASAN_H */
