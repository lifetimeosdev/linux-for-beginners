/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KASAN_H
#define _LINUX_KASAN_H

#include <linux/types.h>

struct kmem_cache;
struct page;
struct vm_struct;
struct task_struct;

static inline void *kasan_init_slab_obj(struct kmem_cache *cache,
				const void *object)
{
	return (void *)object;
}

static inline void *kasan_kmalloc_large(void *ptr, size_t size, gfp_t flags)
{
	return ptr;
}
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

static inline int kasan_add_zero_shadow(void *start, unsigned long size)
{
	return 0;
}
static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }

static inline void *kasan_reset_tag(const void *addr)
{
	return (void *)addr;
}

static inline int kasan_populate_vmalloc(unsigned long start,
					unsigned long size)
{
	return 0;
}

#endif /* LINUX_KASAN_H */
