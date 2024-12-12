/* SPDX-License-Identifier: GPL-2.0-or-later */
/* System keyring containing trusted public keys.
 *
 * Copyright (C) 2013 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#ifndef _KEYS_SYSTEM_KEYRING_H
#define _KEYS_SYSTEM_KEYRING_H

#include <linux/key.h>

#define restrict_link_by_builtin_trusted restrict_link_reject

#define restrict_link_by_builtin_and_secondary_trusted restrict_link_by_builtin_trusted

extern struct pkcs7_message *pkcs7;
static inline int is_hash_blacklisted(const u8 *hash, size_t hash_len,
				      const char *type)
{
	return 0;
}

static inline int is_binary_blacklisted(const u8 *hash, size_t hash_len)
{
	return 0;
}

#ifdef CONFIG_SYSTEM_REVOCATION_LIST
extern int add_key_to_revocation_list(const char *data, size_t size);
extern int is_key_on_revocation_list(struct pkcs7_message *pkcs7);
#else
static inline int add_key_to_revocation_list(const char *data, size_t size)
{
	return 0;
}
static inline int is_key_on_revocation_list(struct pkcs7_message *pkcs7)
{
	return -ENOKEY;
}
#endif

#ifdef CONFIG_IMA_BLACKLIST_KEYRING
extern struct key *ima_blacklist_keyring;

static inline struct key *get_ima_blacklist_keyring(void)
{
	return ima_blacklist_keyring;
}
#else
static inline struct key *get_ima_blacklist_keyring(void)
{
	return NULL;
}
#endif /* CONFIG_IMA_BLACKLIST_KEYRING */

#endif /* _KEYS_SYSTEM_KEYRING_H */
