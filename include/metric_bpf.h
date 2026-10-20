/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef METRIC_BPF_H
#define METRIC_BPF_H
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "sched_delay.h"

/* Reporting drains these counters after disabling collection and detaching.
 * Increment BEFORE reading config; decrement AFTER the last metric-map write.
 * Atomic updates also cover nested hard/soft IRQ callbacks on the same CPU.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, sd_u32);
	__type(value, sd_u64);
} active SEC(".maps");

static __always_inline sd_u64 *metric_enter(void)
{
	sd_u32 zero = 0;
	sd_u64 *writers = bpf_map_lookup_elem(&active, &zero);

	if (writers)
		__sync_fetch_and_add(writers, 1);
	return writers;
}

#define METRIC_PROBE(name, section, expression) \
	SEC(section) int name(struct bpf_raw_tracepoint_args *ctx) \
	{ \
		sd_u64 *writers = metric_enter(); \
		int result; \
		if (!writers) \
			return 0; \
		result = (expression); \
		__sync_fetch_and_sub(writers, 1); \
		return result; \
	}
#endif
