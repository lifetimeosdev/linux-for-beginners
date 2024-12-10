/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *  acpi_bus.h - ACPI Bus Driver ($Revision: 22 $)
 *
 *  Copyright (C) 2001, 2002 Andy Grover <andrew.grover@intel.com>
 *  Copyright (C) 2001, 2002 Paul Diefenbaugh <paul.s.diefenbaugh@intel.com>
 */

#ifndef __ACPI_BUS_H__
#define __ACPI_BUS_H__

#include <linux/device.h>
#include <linux/property.h>

/* TBD: Make dynamic */
#define ACPI_MAX_HANDLES	10
struct acpi_handle_list {
	u32 count;
	acpi_handle handles[ACPI_MAX_HANDLES];
};

/* acpi_utils.h */
acpi_status
acpi_extract_package(union acpi_object *package,
		     struct acpi_buffer *format, struct acpi_buffer *buffer);
acpi_status
acpi_evaluate_integer(acpi_handle handle,
		      acpi_string pathname,
		      struct acpi_object_list *arguments, unsigned long long *data);
acpi_status
acpi_evaluate_reference(acpi_handle handle,
			acpi_string pathname,
			struct acpi_object_list *arguments,
			struct acpi_handle_list *list);
acpi_status
acpi_evaluate_ost(acpi_handle handle, u32 source_event, u32 status_code,
		  struct acpi_buffer *status_buf);

acpi_status
acpi_get_physical_device_location(acpi_handle handle, struct acpi_pld_info **pld);

bool acpi_has_method(acpi_handle handle, char *name);
acpi_status acpi_execute_simple_method(acpi_handle handle, char *method,
				       u64 arg);
acpi_status acpi_evaluate_ej0(acpi_handle handle);
acpi_status acpi_evaluate_lck(acpi_handle handle, int lock);
acpi_status acpi_evaluate_reg(acpi_handle handle, u8 space_id, u32 function);
bool acpi_ata_match(acpi_handle handle);
bool acpi_bay_match(acpi_handle handle);
bool acpi_dock_match(acpi_handle handle);

bool acpi_check_dsm(acpi_handle handle, const guid_t *guid, u64 rev, u64 funcs);
union acpi_object *acpi_evaluate_dsm(acpi_handle handle, const guid_t *guid,
			u64 rev, u64 func, union acpi_object *argv4);

static inline union acpi_object *
acpi_evaluate_dsm_typed(acpi_handle handle, const guid_t *guid, u64 rev,
			u64 func, union acpi_object *argv4,
			acpi_object_type type)
{
	union acpi_object *obj;

	obj = acpi_evaluate_dsm(handle, guid, rev, func, argv4);
	if (obj && obj->type != type) {
		ACPI_FREE(obj);
		obj = NULL;
	}

	return obj;
}

#define	ACPI_INIT_DSM_ARGV4(cnt, eles)			\
	{						\
	  .package.type = ACPI_TYPE_PACKAGE,		\
	  .package.count = (cnt),			\
	  .package.elements = (eles)			\
	}

bool acpi_dev_found(const char *hid);
bool acpi_dev_present(const char *hid, const char *uid, s64 hrv);

static inline int register_acpi_bus_type(void *bus) { return 0; }
static inline int unregister_acpi_bus_type(void *bus) { return 0; }

#endif /*__ACPI_BUS_H__*/
