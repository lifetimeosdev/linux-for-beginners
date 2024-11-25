/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_NUMA_H
#define __ASM_NUMA_H

#include <asm/topology.h>


static inline void numa_store_cpu_info(unsigned int cpu) { }
static inline void numa_add_cpu(unsigned int cpu) { }
static inline void numa_remove_cpu(unsigned int cpu) { }
static inline void arm64_numa_init(void) { }
static inline void early_map_cpu_to_node(unsigned int cpu, int nid) { }

#endif	/* __ASM_NUMA_H */
