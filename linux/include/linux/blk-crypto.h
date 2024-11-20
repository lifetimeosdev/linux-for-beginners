/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2019 Google LLC
 */

#ifndef __LINUX_BLK_CRYPTO_H
#define __LINUX_BLK_CRYPTO_H

#include <linux/types.h>

enum blk_crypto_mode_num {
	BLK_ENCRYPTION_MODE_INVALID,
	BLK_ENCRYPTION_MODE_AES_256_XTS,
	BLK_ENCRYPTION_MODE_AES_128_CBC_ESSIV,
	BLK_ENCRYPTION_MODE_ADIANTUM,
	BLK_ENCRYPTION_MODE_MAX,
};

#define BLK_CRYPTO_MAX_KEY_SIZE		64
/**
 * struct blk_crypto_config - an inline encryption key's crypto configuration
 * @crypto_mode: encryption algorithm this key is for
 * @data_unit_size: the data unit size for all encryption/decryptions with this
 *	key.  This is the size in bytes of each individual plaintext and
 *	ciphertext.  This is always a power of 2.  It might be e.g. the
 *	filesystem block size or the disk sector size.
 * @dun_bytes: the maximum number of bytes of DUN used when using this key
 */
struct blk_crypto_config {
	enum blk_crypto_mode_num crypto_mode;
	unsigned int data_unit_size;
	unsigned int dun_bytes;
};

/**
 * struct blk_crypto_key - an inline encryption key
 * @crypto_cfg: the crypto configuration (like crypto_mode, key size) for this
 *		key
 * @data_unit_size_bits: log2 of data_unit_size
 * @size: size of this key in bytes (determined by @crypto_cfg.crypto_mode)
 * @raw: the raw bytes of this key.  Only the first @size bytes are used.
 *
 * A blk_crypto_key is immutable once created, and many bios can reference it at
 * the same time.  It must not be freed until all bios using it have completed
 * and it has been evicted from all devices on which it may have been used.
 */
struct blk_crypto_key {
	struct blk_crypto_config crypto_cfg;
	unsigned int data_unit_size_bits;
	unsigned int size;
	u8 raw[BLK_CRYPTO_MAX_KEY_SIZE];
};

#define BLK_CRYPTO_MAX_IV_SIZE		32
#define BLK_CRYPTO_DUN_ARRAY_SIZE	(BLK_CRYPTO_MAX_IV_SIZE / sizeof(u64))

/**
 * struct bio_crypt_ctx - an inline encryption context
 * @bc_key: the key, algorithm, and data unit size to use
 * @bc_dun: the data unit number (starting IV) to use
 *
 * A bio_crypt_ctx specifies that the contents of the bio will be encrypted (for
 * write requests) or decrypted (for read requests) inline by the storage device
 * or controller, or by the crypto API fallback.
 */
struct bio_crypt_ctx {
	const struct blk_crypto_key	*bc_key;
	u64				bc_dun[BLK_CRYPTO_DUN_ARRAY_SIZE];
};

#include <linux/blk_types.h>
#include <linux/blkdev.h>

struct request;
struct request_queue;

static inline bool bio_has_crypt_ctx(struct bio *bio)
{
	return false;
}

int __bio_crypt_clone(struct bio *dst, struct bio *src, gfp_t gfp_mask);
/**
 * bio_crypt_clone - clone bio encryption context
 * @dst: destination bio
 * @src: source bio
 * @gfp_mask: memory allocation flags
 *
 * If @src has an encryption context, clone it to @dst.
 *
 * Return: 0 on success, -ENOMEM if out of memory.  -ENOMEM is only possible if
 *	   @gfp_mask doesn't include %__GFP_DIRECT_RECLAIM.
 */
static inline int bio_crypt_clone(struct bio *dst, struct bio *src,
				  gfp_t gfp_mask)
{
	// if (bio_has_crypt_ctx(src))
	// 	return __bio_crypt_clone(dst, src, gfp_mask);
	return 0;
}

#endif /* __LINUX_BLK_CRYPTO_H */
