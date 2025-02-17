/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CONTEXT_TRACKING_STATE_H
#define _LINUX_CONTEXT_TRACKING_STATE_H

#include <linux/percpu.h>
#include <linux/static_key.h>

struct context_tracking {
	/*
	 * When active is false, probes are unset in order
	 * to minimize overhead: TIF flags are cleared
	 * and calls to user_enter/exit are ignored. This
	 * may be further optimized using static keys.
	 */
	bool active;
	int recursion;
	enum ctx_state {
		CONTEXT_DISABLED = -1,	/* returned by ct_state() if unknown */
		CONTEXT_KERNEL = 0,
		CONTEXT_USER,
		CONTEXT_GUEST,
	} state;
};

static inline bool context_tracking_in_user(void) { return false; }
static inline bool context_tracking_enabled(void) { return false; }
static inline bool context_tracking_enabled_cpu(int cpu) { return false; }
static inline bool context_tracking_enabled_this_cpu(void) { return false; }

#endif
