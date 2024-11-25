/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_TOPOLOGY_H
#define __ASM_TOPOLOGY_H

#include <linux/cpumask.h>

#include <linux/arch_topology.h>

#ifdef CONFIG_ARM64_AMU_EXTN
/*
 * Replace task scheduler's default counter-based
 * frequency-invariance scale factor setting.
 */
void topology_scale_freq_tick(void);
#define arch_scale_freq_tick topology_scale_freq_tick
#endif /* CONFIG_ARM64_AMU_EXTN */

/* Replace task scheduler's default frequency-invariant accounting */
#define arch_set_freq_scale topology_set_freq_scale
#define arch_scale_freq_capacity topology_get_freq_scale
#define arch_scale_freq_invariant topology_scale_freq_invariant

/* Replace task scheduler's default cpu-invariant accounting */
#define arch_scale_cpu_capacity topology_get_cpu_scale

/* Enable topology flag updates */
#define arch_update_cpu_topology topology_update_cpu_topology

/* Replace task scheduler's default thermal pressure API */
#define arch_scale_thermal_pressure topology_get_thermal_pressure
#define arch_set_thermal_pressure   topology_set_thermal_pressure

#include <asm-generic/topology.h>

#endif /* _ASM_ARM_TOPOLOGY_H */
