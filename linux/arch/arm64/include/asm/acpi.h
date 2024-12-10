/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *  Copyright (C) 2013-2014, Linaro Ltd.
 *	Author: Al Stone <al.stone@linaro.org>
 *	Author: Graeme Gregory <graeme.gregory@linaro.org>
 *	Author: Hanjun Guo <hanjun.guo@linaro.org>
 */

#ifndef _ASM_ACPI_H
#define _ASM_ACPI_H

#include <linux/efi.h>
#include <linux/memblock.h>
#include <linux/psci.h>
#include <linux/stddef.h>

#include <asm/cputype.h>
#include <asm/io.h>
#include <asm/ptrace.h>
#include <asm/smp_plat.h>
#include <asm/tlbflush.h>

/* Macros for consistency checks of the GICC subtable of MADT */

/*
 * MADT GICC minimum length refers to the MADT GICC structure table length as
 * defined in the earliest ACPI version supported on arm64, ie ACPI 5.1.
 *
 * The efficiency_class member was added to the
 * struct acpi_madt_generic_interrupt to represent the MADT GICC structure
 * "Processor Power Efficiency Class" field, added in ACPI 6.0 whose offset
 * is therefore used to delimit the MADT GICC structure minimum length
 * appropriately.
 */
#define ACPI_MADT_GICC_MIN_LENGTH   offsetof(  \
	struct acpi_madt_generic_interrupt, efficiency_class)

#define BAD_MADT_GICC_ENTRY(entry, end)					\
	(!(entry) || (entry)->header.length < ACPI_MADT_GICC_MIN_LENGTH || \
	(unsigned long)(entry) + (entry)->header.length > (end))

#define ACPI_MADT_GICC_SPE  (offsetof(struct acpi_madt_generic_interrupt, \
	spe_interrupt) + sizeof(u16))

/* Basic configuration for ACPI */
static inline int apei_claim_sea(struct pt_regs *regs) { return -ENOENT; }

static inline bool acpi_parking_protocol_valid(int cpu) { return false; }
static inline void
acpi_set_mailbox_entry(int cpu, struct acpi_madt_generic_interrupt *processor)
{}

static inline const char *acpi_get_enable_method(int cpu)
{
	if (acpi_psci_present())
		return "psci";

	if (acpi_parking_protocol_valid(cpu))
		return "parking-protocol";

	return NULL;
}

static inline int arm64_acpi_numa_init(void) { return -ENOSYS; }
static inline int acpi_numa_get_nid(unsigned int cpu) { return NUMA_NO_NODE; }

#define ACPI_TABLE_UPGRADE_MAX_PHYS MEMBLOCK_ALLOC_ACCESSIBLE

#endif /*_ASM_ACPI_H*/
