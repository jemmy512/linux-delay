// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "fault_delay.h"
#include "metric_bpf.h"

/* Compile for exactly one fixed pt_regs layout; no kernel structs or CO-RE.
 * The loader must autoload exactly ONE entry/return pair, plus exit cleanup.
 * fentry/fexit require verified BTF: exactly four parameters, 4-byte return.
 */
#if defined(__TARGET_ARCH_arm64) && !defined(__TARGET_ARCH_x86)
#define FAULT_RETURN_SLOT 0 /* ARM64 pt_regs.regs[0] (x0). */
#elif defined(__TARGET_ARCH_x86) && !defined(__TARGET_ARCH_arm64)
#define FAULT_RETURN_SLOT 10 /* x86_64 pt_regs.ax, byte offset 80. */
#else
#error "fault_delay requires exactly one of __TARGET_ARCH_arm64 or __TARGET_ARCH_x86"
#endif

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, sd_u32);
	__type(value, struct sd_config);
} config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, FAULT_MAX_PENDING);
	__type(key, sd_u64);
	__type(value, struct fault_pending);
} fault_pending SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, FAULT_KINDS);
	__type(key, sd_u32);
	__type(value, struct fault_stats);
} fault_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, sd_u32);
	__type(value, struct fault_diag);
} fault_diag SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, FAULT_MAX_THREADS);
	__type(key, sd_u64);
	__type(value, struct fault_thread_stats);
} fault_threads SEC(".maps");

/* Map initializers live in rodata, not on the limited BPF stack. */
static const struct fault_pending empty_pending;
static const struct fault_thread_stats empty_thread;

static __always_inline int fault_selected(const struct sd_config *cfg,
					 sd_u64 key, sd_u64 now)
{
	return sd_in_window(cfg, now) &&
	       (!cfg->tgid || cfg->tgid == (sd_u32)(key >> 32)) &&
	       (!cfg->tid || cfg->tid == (sd_u32)key);
}

static __always_inline int fault_enter(void)
{
	sd_u32 zero = 0;
	const struct sd_config *cfg = bpf_map_lookup_elem(&config, &zero);
	sd_u64 now = bpf_ktime_get_ns();
	sd_u64 key = bpf_get_current_pid_tgid();
	struct fault_pending *pending;
	struct fault_diag *diag;
	enum fault_push_result result;
	long err;

	if (!cfg || !fault_selected(cfg, key, now))
		return 0;
	diag = bpf_map_lookup_elem(&fault_diag, &zero);
	if (!diag)
		return 0;
	diag->entries++;
	pending = bpf_map_lookup_elem(&fault_pending, &key);
	if (!pending) {
		/* Never replace an existing thread stack or evict another thread. */
		err = bpf_map_update_elem(&fault_pending, &key, &empty_pending,
					  BPF_NOEXIST);
		pending = bpf_map_lookup_elem(&fault_pending, &key);
		if (err || !pending)
			diag->pending_errors++;
		if (!pending)
			return 0;
	}
	result = fault_push(pending, now);
	if (result == FAULT_PUSH_OVERFLOW)
		diag->overflows++;
	else if (result == FAULT_PUSH_INVALID_DEPTH)
		diag->invalid_depth++;
	return 0;
}

static __always_inline void fault_account_thread(sd_u64 key, sd_u32 ret,
						 sd_u64 delta,
						 struct fault_diag *diag)
{
	struct fault_thread_stats *stats;
	long err;

	stats = bpf_map_lookup_elem(&fault_threads, &key);
	if (!stats) {
		err = bpf_map_update_elem(&fault_threads, &key, &empty_thread,
					  BPF_NOEXIST);
		stats = bpf_map_lookup_elem(&fault_threads, &key);
		if (err || !stats)
			diag->thread_errors++;
		if (!stats)
			return;
	}
	stats->count++;
	stats->total_ns += delta;
	if (delta > stats->max_ns)
		stats->max_ns = delta;
	stats->major += fault_matches(ret, FAULT_MAJOR);
	stats->retries += fault_matches(ret, FAULT_RETRY);
	stats->errors += fault_matches(ret, FAULT_ERROR);
	stats->other += fault_matches(ret, FAULT_OTHER);
	bpf_get_current_comm(stats->comm, sizeof(stats->comm));
}

static __always_inline int fault_leave(sd_u32 ret)
{
	sd_u32 zero = 0;
	const struct sd_config *cfg = bpf_map_lookup_elem(&config, &zero);
	sd_u64 now = bpf_ktime_get_ns();
	sd_u64 key = bpf_get_current_pid_tgid();
	sd_u64 start_ns = 0, delta;
	struct fault_pending *pending;
	struct fault_diag *diag;
	enum fault_pop_result result;

	/* Freeze pending state and diagnostics after the deadline; no clipping. */
	if (!cfg || !fault_selected(cfg, key, now))
		return 0;
	diag = bpf_map_lookup_elem(&fault_diag, &zero);
	if (!diag)
		return 0;
	diag->returns++;
	pending = bpf_map_lookup_elem(&fault_pending, &key);
	if (!pending) {
		diag->unmatched_returns++;
		return 0;
	}
	result = fault_pop(pending, &start_ns);
	if (!pending->depth && !pending->overflow_depth) {
		if (bpf_map_delete_elem(&fault_pending, &key))
			diag->pending_errors++;
	}
	if (result == FAULT_POP_UNMATCHED)
		diag->unmatched_returns++;
	else if (result == FAULT_POP_INVALID_DEPTH)
		diag->invalid_depth++;
	if (result != FAULT_POP_VALID)
		return 0;
	if (now < start_ns) {
		diag->clock_errors++;
		return 0;
	}
	/* Fresh maps per run are required; reject stale frames rather than clamp. */
	if (start_ns < cfg->start_ns) {
		diag->unmatched_returns++;
		return 0;
	}
	delta = now - start_ns;
#pragma unroll
	for (sd_u32 kind = 0; kind < FAULT_KINDS; kind++) {
		struct fault_stats *stats;
		sd_u32 category = kind;

		if (!fault_matches(ret, category))
			continue;
		stats = bpf_map_lookup_elem(&fault_stats, &category);
		if (stats)
			fault_account(stats, delta);
	}
	/* A full thread map must not suppress the overall category histograms. */
	fault_account_thread(key, ret, delta, diag);
	return 0;
}

static __always_inline int fault_cleanup(void)
{
	sd_u32 zero = 0;
	const struct sd_config *cfg = bpf_map_lookup_elem(&config, &zero);
	sd_u64 now = bpf_ktime_get_ns();
	sd_u64 key = bpf_get_current_pid_tgid();
	struct fault_pending *pending;
	struct fault_diag *diag;

	/* Raw sched_process_exit runs in the exiting thread; no task fields. */
	if (!cfg || !fault_selected(cfg, key, now))
		return 0;
	diag = bpf_map_lookup_elem(&fault_diag, &zero);
	if (!diag)
		return 0;
	pending = bpf_map_lookup_elem(&fault_pending, &key);
	if (!pending)
		return 0;
	if (pending->depth > FAULT_STACK_DEPTH)
		diag->invalid_depth++; /* A corrupt depth is not a call count. */
	else
		diag->cancelled += (sd_u64)pending->depth + pending->overflow_depth;
	if (bpf_map_delete_elem(&fault_pending, &key))
		diag->pending_errors++;
	return 0;
}

/* Local typed wrappers: never cast pt_regs to raw tracepoint arguments.
 * Writer acquisition precedes every config lookup; all paths release it only
 * after the last metric-map update, exactly as in METRIC_PROBE.
 */
#define FAULT_PROBE(name, section, context_type, expression) \
	SEC(section) int name(context_type ctx) \
	{ \
		sd_u64 *writers = metric_enter(); \
		int result; \
		(void)ctx; \
		if (!writers) \
			return 0; \
		result = (expression); \
		__sync_fetch_and_sub(writers, 1); \
		return result; \
	}

FAULT_PROBE(on_fault_fentry, "fentry/handle_mm_fault", sd_u64 *, fault_enter())
FAULT_PROBE(on_fault_fexit, "fexit/handle_mm_fault", sd_u64 *,
	    fault_leave((sd_u32)ctx[4]))
FAULT_PROBE(on_fault_kprobe, "kprobe/handle_mm_fault", sd_u64 *, fault_enter())
FAULT_PROBE(on_fault_kretprobe, "kretprobe/handle_mm_fault", sd_u64 *,
	    fault_leave((sd_u32)ctx[FAULT_RETURN_SLOT]))
FAULT_PROBE(on_fault_process_exit, "raw_tp/sched_process_exit",
	    struct bpf_raw_tracepoint_args *, fault_cleanup())
