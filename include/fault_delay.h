/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FAULT_DELAY_H
#define FAULT_DELAY_H

#include "sched_delay.h"

#define FAULT_STACK_DEPTH 8
#define FAULT_MAX_PENDING 65536
#define FAULT_MAX_THREADS 4096

/* Linux vm_fault_t bits, not hardware exception counts. */
#define FAULT_VM_OOM            0x000001U
#define FAULT_VM_SIGBUS         0x000002U
#define FAULT_VM_MAJOR          0x000004U
#define FAULT_VM_HWPOISON       0x000010U
#define FAULT_VM_HWPOISON_LARGE 0x000020U
#define FAULT_VM_SIGSEGV        0x000040U
#define FAULT_VM_NOPAGE         0x000100U
#define FAULT_VM_LOCKED         0x000200U
#define FAULT_VM_RETRY          0x000400U
#define FAULT_VM_FALLBACK       0x000800U
#define FAULT_VM_DONE_COW       0x001000U
#define FAULT_VM_ERROR (FAULT_VM_OOM | FAULT_VM_SIGBUS | FAULT_VM_SIGSEGV | \
			FAULT_VM_HWPOISON | FAULT_VM_HWPOISON_LARGE | \
			FAULT_VM_FALLBACK)

enum fault_kind {
	FAULT_ALL = 0,
	FAULT_MAJOR = 1,
	FAULT_OTHER = 2,
	FAULT_RETRY = 3,
	FAULT_ERROR = 4,
	FAULT_KINDS = 5,
};

/* Global HASH key is current pid_tgid: the stack survives CPU migration. */
struct fault_pending {
	sd_u64 frames[FAULT_STACK_DEPTH];
	sd_u32 depth;
	sd_u32 overflow_depth;
};

struct fault_stats {
	sd_u64 count;
	sd_u64 total_ns;
	sd_u64 max_ns;
	sd_u64 histogram[SD_BUCKETS];
};

struct fault_thread_stats {
	sd_u64 count;
	sd_u64 total_ns;
	sd_u64 max_ns;
	sd_u64 major;
	sd_u64 retries;
	sd_u64 errors;
	sd_u64 other;
	char comm[16];
};

/* All counters are gated by TGID/TID and [start,end). Rejected returns do
 * not contribute durations. Invalid/overflow returns are distinct from
 * unmatched_returns, and cancelled counts stored plus overflow calls.
 */
struct fault_diag {
	sd_u64 entries;           /* All selected entries, even map failures. */
	sd_u64 returns;           /* All selected returns, even without a frame. */
	sd_u64 unmatched_returns; /* Missing/empty stack or pre-window frame. */
	sd_u64 overflows;         /* Entries tracked only in overflow_depth. */
	sd_u64 pending_errors;    /* Failed insert/relookup or delete operations. */
	sd_u64 thread_errors;     /* Failed thread-map insert/relookup operations. */
	sd_u64 cancelled;         /* Pending calls discarded by in-window exit. */
	sd_u64 invalid_depth;     /* Corrupt depth observed on entry/return/exit. */
	sd_u64 clock_errors;      /* Paired return timestamp precedes entry. */
};

_Static_assert(sizeof(struct fault_pending) == 72, "fault pending ABI");
_Static_assert(sizeof(struct fault_stats) == 280, "fault per-CPU stats ABI");
_Static_assert(sizeof(struct fault_thread_stats) == 72, "fault thread ABI");
_Static_assert(sizeof(struct fault_diag) == 72, "fault diagnostics ABI");
_Static_assert(FAULT_STACK_DEPTH > 0 &&
	       (FAULT_STACK_DEPTH & (FAULT_STACK_DEPTH - 1)) == 0,
	       "fault stack depth must be a power of two");

/* Validate depth first. The barrier retains the mask even when LLVM proves
 * it redundant; Android verifiers can lose the lower bound after depth--.
 */
static __inline__ __attribute__((always_inline)) sd_u32
fault_bounded_index(sd_u32 index)
{
#ifdef __BPF__
	__asm__ __volatile__("" : "+r" (index));
#endif
	return index & (FAULT_STACK_DEPTH - 1);
}

enum fault_push_result {
	FAULT_PUSH_STORED,
	FAULT_PUSH_OVERFLOW,
	FAULT_PUSH_INVALID_DEPTH,
};

enum fault_pop_result {
	FAULT_POP_VALID,
	FAULT_POP_UNMATCHED,
	FAULT_POP_OVERFLOW,
	FAULT_POP_INVALID_DEPTH,
};

/* No diagnostics here: callers count entries before map lookup and account
 * the push result separately. Invalid depth leaves state untouched on push.
 * Overflow never replaces the earliest valid frames. UINT32_MAX overflow is
 * sticky (fail closed): once exact nesting is unrepresentable, no later return
 * may pop an outer frame.
 */
static __inline__ __attribute__((always_inline)) enum fault_push_result
fault_push(struct fault_pending *pending, sd_u64 now)
{
	sd_u32 depth = pending->depth;

	if (depth > FAULT_STACK_DEPTH)
		return FAULT_PUSH_INVALID_DEPTH;
	if (pending->overflow_depth || depth == FAULT_STACK_DEPTH) {
		if (pending->overflow_depth != (sd_u32)-1)
			pending->overflow_depth++;
		return FAULT_PUSH_OVERFLOW;
	}
	pending->frames[fault_bounded_index(depth)] = now;
	pending->depth = depth + 1;
	return FAULT_PUSH_STORED;
}

/* Only VALID writes *start_ns; timestamp zero is valid. Invalid depth resets
 * both depth counters without reading a frame. Overflow returns unwind before
 * stored frames, except the deliberately sticky saturation case above.
 * Caller deletes the key when both depth counters reach zero.
 */
static __inline__ __attribute__((always_inline)) enum fault_pop_result
fault_pop(struct fault_pending *pending, sd_u64 *start_ns)
{
	sd_u32 depth = pending->depth;

	if (depth > FAULT_STACK_DEPTH) {
		pending->depth = 0;
		pending->overflow_depth = 0;
		return FAULT_POP_INVALID_DEPTH;
	}
	if (pending->overflow_depth) {
		if (pending->overflow_depth != (sd_u32)-1)
			pending->overflow_depth--;
		return FAULT_POP_OVERFLOW;
	}
	if (!depth)
		return FAULT_POP_UNMATCHED;
	depth--;
	*start_ns = pending->frames[fault_bounded_index(depth)];
	pending->depth = depth;
	return FAULT_POP_VALID;
}

/* Categories overlap. OTHER means no major/retry/error bits, NOT an exact
 * minor-fault count. A handle_mm_fault call is not one hardware exception.
 */
static __inline__ __attribute__((always_inline)) int
fault_matches(sd_u32 ret, sd_u32 category)
{
	switch (category) {
	case FAULT_ALL:
		return 1;
	case FAULT_MAJOR:
		return !!(ret & FAULT_VM_MAJOR);
	case FAULT_OTHER:
		return !(ret & (FAULT_VM_MAJOR | FAULT_VM_RETRY | FAULT_VM_ERROR));
	case FAULT_RETRY:
		return !!(ret & FAULT_VM_RETRY);
	case FAULT_ERROR:
		return !!(ret & FAULT_VM_ERROR);
	default:
		return 0;
	}
}

/* Inclusive elapsed wall-clock duration for one paired completion. */
static __inline__ __attribute__((always_inline)) void
fault_account(struct fault_stats *stats, sd_u64 delta)
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
static inline void fault_merge_stats(struct fault_stats *total,
				     const struct fault_stats *part)
{
	total->count += part->count;
	total->total_ns += part->total_ns;
	if (part->max_ns > total->max_ns)
		total->max_ns = part->max_ns;
	for (int i = 0; i < SD_BUCKETS; i++)
		total->histogram[i] += part->histogram[i];
}
#endif
#endif
