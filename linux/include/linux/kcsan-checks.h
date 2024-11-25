/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_KCSAN_CHECKS_H
#define _LINUX_KCSAN_CHECKS_H

/* Note: Only include what is already included by compiler.h. */
#include <linux/compiler_attributes.h>
#include <linux/types.h>

/* Access types -- if KCSAN_ACCESS_WRITE is not set, the access is a read. */
#define KCSAN_ACCESS_WRITE	(1 << 0) /* Access is a write. */
#define KCSAN_ACCESS_COMPOUND	(1 << 1) /* Compounded read-write instrumentation. */
#define KCSAN_ACCESS_ATOMIC	(1 << 2) /* Access is atomic. */
/* The following are special, and never due to compiler instrumentation. */
#define KCSAN_ACCESS_ASSERT	(1 << 3) /* Access is an assertion. */
#define KCSAN_ACCESS_SCOPED	(1 << 4) /* Access is a scoped access. */


struct kcsan_scoped_access { };
#define __kcsan_cleanup_scoped __maybe_unused
static inline struct kcsan_scoped_access *
kcsan_begin_scoped_access(const volatile void *ptr, size_t size, int type,
			  struct kcsan_scoped_access *sa) { return sa; }

/*
 * Helper macros for implementation of for ASSERT_EXCLUSIVE_*_SCOPED(). @id is
 * expected to be unique for the scope in which instances of kcsan_scoped_access
 * are declared.
 */
#define __kcsan_scoped_name(c, suffix) __kcsan_scoped_##c##suffix
#define __ASSERT_EXCLUSIVE_SCOPED(var, type, id)                               \
	struct kcsan_scoped_access __kcsan_scoped_name(id, _)                  \
		__kcsan_cleanup_scoped;                                        \
	struct kcsan_scoped_access *__kcsan_scoped_name(id, _dummy_p)          \
		__maybe_unused = kcsan_begin_scoped_access(                    \
			&(var), sizeof(var), KCSAN_ACCESS_SCOPED | (type),     \
			&__kcsan_scoped_name(id, _))

/**
 * ASSERT_EXCLUSIVE_WRITER_SCOPED - assert no concurrent writes to @var in scope
 *
 * Scoped variant of ASSERT_EXCLUSIVE_WRITER().
 *
 * Assert that there are no concurrent writes to @var for the duration of the
 * scope in which it is introduced. This provides a better way to fully cover
 * the enclosing scope, compared to multiple ASSERT_EXCLUSIVE_WRITER(), and
 * increases the likelihood for KCSAN to detect racing accesses.
 *
 * For example, it allows finding race-condition bugs that only occur due to
 * state changes within the scope itself:
 *
 * .. code-block:: c
 *
 *	void writer(void) {
 *		spin_lock(&update_foo_lock);
 *		{
 *			ASSERT_EXCLUSIVE_WRITER_SCOPED(shared_foo);
 *			WRITE_ONCE(shared_foo, 42);
 *			...
 *			// shared_foo should still be 42 here!
 *		}
 *		spin_unlock(&update_foo_lock);
 *	}
 *	void buggy(void) {
 *		if (READ_ONCE(shared_foo) == 42)
 *			WRITE_ONCE(shared_foo, 1); // bug!
 *	}
 *
 * @var: variable to assert on
 */
#define ASSERT_EXCLUSIVE_WRITER_SCOPED(var)                                    \
	__ASSERT_EXCLUSIVE_SCOPED(var, KCSAN_ACCESS_ASSERT, __COUNTER__)

/**
 * ASSERT_EXCLUSIVE_ACCESS_SCOPED - assert no concurrent accesses to @var in scope
 *
 * Scoped variant of ASSERT_EXCLUSIVE_ACCESS().
 *
 * Assert that there are no concurrent accesses to @var (no readers nor writers)
 * for the entire duration of the scope in which it is introduced. This provides
 * a better way to fully cover the enclosing scope, compared to multiple
 * ASSERT_EXCLUSIVE_ACCESS(), and increases the likelihood for KCSAN to detect
 * racing accesses.
 *
 * @var: variable to assert on
 */
#define ASSERT_EXCLUSIVE_ACCESS_SCOPED(var)                                    \
	__ASSERT_EXCLUSIVE_SCOPED(var, KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT, __COUNTER__)


#endif /* _LINUX_KCSAN_CHECKS_H */
