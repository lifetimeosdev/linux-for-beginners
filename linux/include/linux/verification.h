/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Signature verification
 *
 * Copyright (C) 2014 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#ifndef _LINUX_VERIFICATION_H
#define _LINUX_VERIFICATION_H

/*
 * Indicate that both builtin trusted keys and secondary trusted keys
 * should be used.
 */
#define VERIFY_USE_SECONDARY_KEYRING ((struct key *)1UL)
#define VERIFY_USE_PLATFORM_KEYRING  ((struct key *)2UL)

/*
 * The use to which an asymmetric key is being put.
 */
enum key_being_used_for {
	VERIFYING_MODULE_SIGNATURE,
	VERIFYING_FIRMWARE_SIGNATURE,
	VERIFYING_KEXEC_PE_SIGNATURE,
	VERIFYING_KEY_SIGNATURE,
	VERIFYING_KEY_SELF_SIGNATURE,
	VERIFYING_UNSPECIFIED_SIGNATURE,
	NR__KEY_BEING_USED_FOR
};
extern const char *const key_being_used_for[NR__KEY_BEING_USED_FOR];

#endif /* _LINUX_VERIFY_PEFILE_H */
