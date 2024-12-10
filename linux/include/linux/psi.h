#ifndef _LINUX_PSI_H
#define _LINUX_PSI_H

#include <linux/jump_label.h>
#include <linux/psi_types.h>
#include <linux/sched.h>
#include <linux/poll.h>

struct seq_file;
struct css_set;

#ifdef CONFIG_PSI

extern struct static_key_false psi_disabled;
extern struct psi_group psi_system;

void psi_init(void);

void psi_task_change(struct task_struct *task, int clear, int set);
void psi_task_switch(struct task_struct *prev, struct task_struct *next,
		     bool sleep);

void psi_memstall_tick(struct task_struct *task, int cpu);
void psi_memstall_enter(unsigned long *flags);
void psi_memstall_leave(unsigned long *flags);

int psi_show(struct seq_file *s, struct psi_group *group, enum psi_res res);

#else /* CONFIG_PSI */

static inline void psi_init(void) {}

static inline void psi_memstall_enter(unsigned long *flags) {}
static inline void psi_memstall_leave(unsigned long *flags) {}

#endif /* CONFIG_PSI */

#endif /* _LINUX_PSI_H */
