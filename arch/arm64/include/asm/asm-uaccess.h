/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_ASM_UACCESS_H
#define __ASM_ASM_UACCESS_H

#include <asm/alternative.h>
#include <asm/kernel-pgtable.h>
#include <asm/mmu.h>
#include <asm/sysreg.h>
#include <asm/assembler.h>

/*
 * User access enabling/disabling macros.
 */
	.macro	uaccess_ttbr0_disable, tmp1, tmp2
	.endm

	.macro	uaccess_ttbr0_enable, tmp1, tmp2, tmp3
	.endm

#endif
