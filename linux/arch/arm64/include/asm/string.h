/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2013 ARM Ltd.
 */
#ifndef __ASM_STRING_H
#define __ASM_STRING_H

// #define __HAVE_ARCH_STRRCHR
extern char *strrchr(const char *, int c);

// #define __HAVE_ARCH_STRCHR
extern char *strchr(const char *, int c);

// #define __HAVE_ARCH_STRCMP
extern int strcmp(const char *, const char *);

// #define __HAVE_ARCH_STRNCMP
extern int strncmp(const char *, const char *, __kernel_size_t);

// #define __HAVE_ARCH_STRLEN
extern __kernel_size_t strlen(const char *);

// #define __HAVE_ARCH_STRNLEN
extern __kernel_size_t strnlen(const char *, __kernel_size_t);

// #define __HAVE_ARCH_MEMCMP
extern int memcmp(const void *, const void *, size_t);

// #define __HAVE_ARCH_MEMCHR
extern void *memchr(const void *, int, __kernel_size_t);

// #define __HAVE_ARCH_MEMCPY
extern void *memcpy(void *, const void *, __kernel_size_t);
extern void *__memcpy(void *, const void *, __kernel_size_t);

// #define __HAVE_ARCH_MEMMOVE
extern void *memmove(void *, const void *, __kernel_size_t);
extern void *__memmove(void *, const void *, __kernel_size_t);

// #define __HAVE_ARCH_MEMSET
extern void *memset(void *, int, __kernel_size_t);
extern void *__memset(void *, int, __kernel_size_t);

#endif
