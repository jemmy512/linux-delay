/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef IRQ_DELAY_H
#define IRQ_DELAY_H

#include "sched_delay.h"

#define IRQ_STACK_DEPTH 8
#define IRQ_MAX_STATS 4096

enum irq_kind {
	IRQ_HARD = 0,
	IRQ_SOFT = 1,
	IRQ_KINDS = 2,
};

struct irq_frame {
	sd_u64 start_ns;
	/* Opaque hard-IRQ irqaction identity, never dereferenced; softirq: 0. */
	sd_u64 action;
	sd_u32 id;
	sd_u32 pad;
};

struct irq_key {
	sd_u32 cpu;
	sd_u32 kind;
	sd_u32 id;
	sd_u32 reserved;
};

struct irq_stats {
	sd_u64 entries;
	sd_u64 count;
	sd_u64 total_ns;
	sd_u64 max_ns;
	sd_u64 histogram[SD_BUCKETS];
};

struct irq_state {
	sd_u32 depth;
	sd_u32 overflow_depth;
	sd_u64 entries;
	sd_u64 overflows;
	sd_u64 unmatched_exits;
	sd_u64 mismatches;
	sd_u64 discarded_frames;
	sd_u64 map_errors;
	sd_u64 missing_stats;
	struct irq_frame frames[IRQ_STACK_DEPTH];
};

_Static_assert(sizeof(struct irq_frame) == 24, "IRQ frame ABI");
_Static_assert(sizeof(struct irq_key) == 16, "IRQ key ABI");
_Static_assert(sizeof(struct irq_stats) == 288, "IRQ stats ABI");
_Static_assert(sizeof(struct irq_state) == 256, "IRQ state ABI");
_Static_assert(IRQ_STACK_DEPTH > 0 &&
	       (IRQ_STACK_DEPTH & (IRQ_STACK_DEPTH - 1)) == 0,
	       "IRQ stack depth must be a power of two");

/* Keep a local, unconditional bound in the generated BPF instructions.
 * Some verifiers lose depth != 0 when merging 32-bit comparison ranges, so
 * depth - 1 can appear to wrap to UINT32_MAX despite the earlier checks.
 * The barrier prevents LLVM from removing the mask as redundant in C.
 * Callers must still validate depth: this is NOT permission to wrap the stack.
 */
static __inline__ __attribute__((always_inline)) sd_u32
irq_bounded_index(sd_u32 index)
{
#ifdef __BPF__
	__asm__ __volatile__("" : "+r" (index));
#endif
	return index & (IRQ_STACK_DEPTH - 1);
}

/*
 * Call only for events inside the collection window. Every entry is counted,
 * including entries for which there is no frame or stats-map capacity.
 * Return 1 if stored, 0 if tracked only through overflow_depth.
 */
static __inline__ __attribute__((always_inline)) int
irq_push(struct irq_state *state, sd_u64 now, sd_u32 id, sd_u64 action)
{
	sd_u32 depth = state->depth;

	state->entries++;
	if (state->overflow_depth || depth >= IRQ_STACK_DEPTH) {
		state->overflows++;
		state->overflow_depth++;
		return 0;
	}
	state->frames[depth].start_ns = now;
	state->frames[depth].action = action;
	state->frames[depth].id = id;
	state->frames[depth].pad = 0;
	state->depth = depth + 1;
	return 1;
}

/*
 * Return 1 and copy the matching frame to out; otherwise leave out untouched.
 * Unstored overflow entries consume exits before any stored frame is examined.
 * A mismatch loses synchronization: discard ALL stored frames, not just the
 * top frame. Later exits then count as unmatched until another entry arrives.
 */
static __inline__ __attribute__((always_inline)) int
irq_pop(struct irq_state *state, sd_u32 id, sd_u64 action,
	struct irq_frame *out)
{
	sd_u32 depth = state->depth;
	struct irq_frame *frame;

	if (state->overflow_depth) {
		state->overflow_depth--;
		return 0;
	}
	if (!depth) {
		state->unmatched_exits++;
		return 0;
	}
	/* Explicit bound keeps the map-value array access verifier-friendly. */
	if (depth > IRQ_STACK_DEPTH) {
		state->mismatches++;
		state->discarded_frames += depth;
		state->depth = 0;
		return 0;
	}
	depth--;
	frame = &state->frames[irq_bounded_index(depth)];
	if (frame->id != id || frame->action != action) {
		state->mismatches++;
		state->discarded_frames += state->depth;
		state->depth = 0;
		return 0;
	}
	*out = *frame;
	state->depth = depth;
	return 1;
}

/* Elapsed wall-clock duration, inclusive of nested interrupt execution. */
static __inline__ __attribute__((always_inline)) void
irq_account_duration(struct irq_stats *stats, sd_u64 delta)
{
	sd_u32 bucket = sd_bucket(delta);

	stats->count++;
	stats->total_ns += delta;
	if (delta > stats->max_ns)
		stats->max_ns = delta;
	if (bucket < SD_BUCKETS)
		stats->histogram[bucket]++;
}

#ifndef __BPF__
static inline void irq_merge_stats(struct irq_stats *total,
				   const struct irq_stats *part)
{
	total->entries += part->entries;
	total->count += part->count;
	total->total_ns += part->total_ns;
	if (part->max_ns > total->max_ns)
		total->max_ns = part->max_ns;
	for (int i = 0; i < SD_BUCKETS; i++)
		total->histogram[i] += part->histogram[i];
}
#endif
#endif
