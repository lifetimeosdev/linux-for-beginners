/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LINUX_KEXEC_H
#define LINUX_KEXEC_H

#define IND_DESTINATION_BIT 0
#define IND_INDIRECTION_BIT 1
#define IND_DONE_BIT        2
#define IND_SOURCE_BIT      3

#define IND_DESTINATION  (1 << IND_DESTINATION_BIT)
#define IND_INDIRECTION  (1 << IND_INDIRECTION_BIT)
#define IND_DONE         (1 << IND_DONE_BIT)
#define IND_SOURCE       (1 << IND_SOURCE_BIT)
#define IND_FLAGS (IND_DESTINATION | IND_INDIRECTION | IND_DONE | IND_SOURCE)

#if !defined(__ASSEMBLY__)

#include <linux/crash_core.h>
#include <asm/io.h>

#include <uapi/linux/kexec.h>

struct pt_regs;
struct task_struct;
static inline int kexec_should_crash(struct task_struct *p) { return 0; }
static inline int kexec_crash_loaded(void) { return 0; }
#define kexec_in_progress false

#ifdef CONFIG_KEXEC_SIG
void set_kexec_sig_enforced(void);
#else
static inline void set_kexec_sig_enforced(void) {}
#endif

#endif /* !defined(__ASSEBMLY__) */

#endif /* LINUX_KEXEC_H */
