/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *  intel-nhlt.h - Intel HDA Platform NHLT header
 *
 *  Copyright (c) 2015-2019 Intel Corporation
 */

#ifndef __INTEL_NHLT_H__
#define __INTEL_NHLT_H__

#include <linux/acpi.h>

struct nhlt_acpi_table;

static inline struct nhlt_acpi_table *intel_nhlt_init(struct device *dev)
{
	return NULL;
}

static inline void intel_nhlt_free(struct nhlt_acpi_table *addr)
{
}

static inline int intel_nhlt_get_dmic_geo(struct device *dev,
					  struct nhlt_acpi_table *nhlt)
{
	return 0;
}

#endif
