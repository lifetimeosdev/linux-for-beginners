/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/fs.h>

#define DEVCG_ACC_MKNOD 1
#define DEVCG_ACC_READ  2
#define DEVCG_ACC_WRITE 4
#define DEVCG_ACC_MASK (DEVCG_ACC_MKNOD | DEVCG_ACC_READ | DEVCG_ACC_WRITE)

#define DEVCG_DEV_BLOCK 1
#define DEVCG_DEV_CHAR  2
#define DEVCG_DEV_ALL   4  /* this represents all devices */


static inline int devcgroup_check_permission(short type, u32 major, u32 minor,
			       short access)
{ return 0; }
static inline int devcgroup_inode_permission(struct inode *inode, int mask)
{ return 0; }
static inline int devcgroup_inode_mknod(int mode, dev_t dev)
{ return 0; }
