/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SCHED_DELAY_H
#define SCHED_DELAY_H

#ifdef __BPF__
typedef unsigned long long sd_u64;
typedef unsigned int sd_u32;
#else
#include <stdint.h>
typedef uint64_t sd_u64;
typedef uint32_t sd_u32;
#endif

#define SD_BUCKETS 32
#define SD_MAX_PENDING 65536

enum sd_kind {
	SD_WAKEUP,
	SD_RUNNABLE,
	SD_KINDS,
};

struct sd_config {
	sd_u64 start_ns;
	sd_u64 end_ns;
	sd_u32 tgid;
	sd_u32 tid;
};

struct sd_pending {
	sd_u64 start_ns;
	sd_u32 kind;
	sd_u32 tgid;
};

struct sd_stats {
	sd_u64 count;
	sd_u64 total_ns;
	sd_u64 max_ns;
	sd_u64 insert_errors;
	sd_u64 duplicate_starts;
	sd_u64 cancelled;
	sd_u64 histogram[SD_BUCKETS];
};

static __inline__ __attribute__((always_inline)) int
sd_in_window(const struct sd_config *cfg, sd_u64 now)
{
	return now >= cfg->start_ns && now < cfg->end_ns;
}

/* log2 of whole microseconds, saturating at the last bucket. */
static __inline__ __attribute__((always_inline)) sd_u32
sd_bucket(sd_u64 ns)
{
	sd_u64 us = ns / 1000;
	sd_u32 bucket = 0;

#ifdef __BPF__
#pragma unroll
#endif
	for (int i = 0; i < SD_BUCKETS - 1; ++i) {
		if (us > 1) {
			us >>= 1;
			++bucket;
		}
	}
	return bucket;
}

#ifndef __BPF__
_Static_assert(sizeof(struct sd_config) == 24, "config ABI");
_Static_assert(sizeof(struct sd_pending) == 16, "pending ABI");
_Static_assert(sizeof(struct sd_stats) == 304, "per-CPU stats ABI");

static inline void sd_merge_stats(struct sd_stats *total,
				  const struct sd_stats *part)
{
	total->count += part->count;
	total->total_ns += part->total_ns;
	if (part->max_ns > total->max_ns)
		total->max_ns = part->max_ns;
	total->insert_errors += part->insert_errors;
	total->duplicate_starts += part->duplicate_starts;
	total->cancelled += part->cancelled;
	for (int i = 0; i < SD_BUCKETS; ++i)
		total->histogram[i] += part->histogram[i];
}
#endif
#endif
