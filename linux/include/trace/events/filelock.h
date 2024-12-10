/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Events for filesystem locks
 *
 * Copyright 2013 Jeff Layton <jlayton@poochiereds.net>
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM filelock

#if !defined(_TRACE_FILELOCK_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_FILELOCK_H

#include <linux/tracepoint.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/kdev_t.h>

#define show_fl_flags(val)						\
	__print_flags(val, "|", 					\
		{ FL_POSIX,		"FL_POSIX" },			\
		{ FL_FLOCK,		"FL_FLOCK" },			\
		{ FL_DELEG,		"FL_DELEG" },			\
		{ FL_ACCESS,		"FL_ACCESS" },			\
		{ FL_EXISTS,		"FL_EXISTS" },			\
		{ FL_LEASE,		"FL_LEASE" },			\
		{ FL_CLOSE,		"FL_CLOSE" },			\
		{ FL_SLEEP,		"FL_SLEEP" },			\
		{ FL_DOWNGRADE_PENDING,	"FL_DOWNGRADE_PENDING" },	\
		{ FL_UNLOCK_PENDING,	"FL_UNLOCK_PENDING" },		\
		{ FL_OFDLCK,		"FL_OFDLCK" })

#define show_fl_type(val)				\
	__print_symbolic(val,				\
			{ F_RDLCK, "F_RDLCK" },		\
			{ F_WRLCK, "F_WRLCK" },		\
			{ F_UNLCK, "F_UNLCK" })

#endif /* _TRACE_FILELOCK_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
