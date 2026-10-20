// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "sched_delay.h"
#include "metric_bpf.h"

/*
 * Minimal CO-RE description, NOT a copy of the kernel's memory layout.
 * Runtime BTF supplies offsets. Support both 5.10's state and newer __state.
 * No generated vmlinux.h or kernel source checkout is needed to build.
 */
struct task_struct {
	int pid;
	int tgid;
	unsigned int __state;
	long state;
} __attribute__((preserve_access_index));

char LICENSE[] SEC("license") = "GPL";

/* Hash replacement publishes a complete configuration atomically (RCU). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, sd_u32);
	__type(value, struct sd_config);
} config SEC(".maps");

/* Must be global: tasks can migrate while waiting to run. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, SD_MAX_PENDING);
	__type(key, sd_u32);
	__type(value, struct sd_pending);
} pending SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, SD_KINDS);
	__type(key, sd_u32);
	__type(value, struct sd_stats);
} stats SEC(".maps");

static __always_inline void start_wait(struct task_struct *task, sd_u32 kind,
				      const struct sd_config *cfg, sd_u64 now)
{
	sd_u32 tid = BPF_CORE_READ(task, pid);
	sd_u32 tgid = BPF_CORE_READ(task, tgid);
	struct sd_pending value = {
		.start_ns = now,
		.kind = kind,
		.tgid = tgid,
	};
	struct sd_stats *s;
	long err;

	/* Filter the SUBJECT task, not the current/waking process. */
	if (!tid || (cfg->tgid && cfg->tgid != tgid) ||
	    (cfg->tid && cfg->tid != tid))
		return;

	/* Never replace the earliest runnable timestamp. */
	err = bpf_map_update_elem(&pending, &tid, &value, BPF_NOEXIST);
	if (!err)
		return;
	s = bpf_map_lookup_elem(&stats, &kind);
	if (!s)
		return;
	if (err == -17) /* EEXIST, same value on supported Linux targets. */
		s->duplicate_starts++;
	else
		s->insert_errors++;
}

static __always_inline void finish_wait(struct task_struct *task,
				       const struct sd_config *cfg, sd_u64 now)
{
	sd_u32 tid = BPF_CORE_READ(task, pid);
	struct sd_pending *p = bpf_map_lookup_elem(&pending, &tid);
	struct sd_pending saved;
	struct sd_stats *s;
	sd_u64 delta;
	sd_u32 bucket;

	if (!p)
		return;
	saved = *p;
	bpf_map_delete_elem(&pending, &tid);

	if (saved.kind >= SD_KINDS || saved.start_ns < cfg->start_ns ||
	    now < saved.start_ns || saved.tgid != (sd_u32)BPF_CORE_READ(task, tgid))
		return;

	s = bpf_map_lookup_elem(&stats, &saved.kind);
	if (!s)
		return;
	delta = now - saved.start_ns;
	s->count++;
	s->total_ns += delta;
	if (delta > s->max_ns)
		s->max_ns = delta;
	bucket = sd_bucket(delta);
	if (bucket < SD_BUCKETS)
		s->histogram[bucket]++;
}

static __always_inline int wakeup(struct bpf_raw_tracepoint_args *ctx)
{
	sd_u32 zero = 0;
	struct sd_config *cfg = bpf_map_lookup_elem(&config, &zero);
	sd_u64 now = bpf_ktime_get_ns();

	if (cfg && sd_in_window(cfg, now))
		start_wait((void *)ctx->args[0], SD_WAKEUP, cfg, now);
	return 0;
}

METRIC_PROBE(on_wakeup, "raw_tp/sched_wakeup", wakeup(ctx))
METRIC_PROBE(on_wakeup_new, "raw_tp/sched_wakeup_new", wakeup(ctx))

static __always_inline int handle_switch(struct bpf_raw_tracepoint_args *ctx)
{
	/* Raw arguments: preempt, prev, next (newer kernels add prev_state). */
	struct task_struct *prev = (void *)ctx->args[1];
	struct task_struct *next = (void *)ctx->args[2];
	sd_u32 zero = 0;
	struct sd_config *cfg = bpf_map_lookup_elem(&config, &zero);
	sd_u64 now = bpf_ktime_get_ns();
	long state;
	sd_u32 prev_tid;

	if (!cfg || !sd_in_window(cfg, now))
		return 0;

	finish_wait(next, cfg, now);
	/* A wakeup can target an already-executing task (wake-before-sleep).
	 * Such a timestamp is not an off-CPU wait. Discard it at switch-out,
	 * including blocking switches, rather than measuring running/sleep time.
	 * Do not filter on on_cpu at wakeup: legitimate switch-out races exist.
	 */
	prev_tid = BPF_CORE_READ(prev, pid);
	bpf_map_delete_elem(&pending, &prev_tid);
	if (bpf_core_field_exists(prev->__state))
		state = BPF_CORE_READ(prev, __state);
	else
		state = BPF_CORE_READ(prev, state);

	/* TASK_RUNNING == 0. Includes yield, not only involuntary preemption. */
	if (ctx->args[0] || state == 0)
		start_wait(prev, SD_RUNNABLE, cfg, now);
	return 0;
}

METRIC_PROBE(on_switch, "raw_tp/sched_switch", handle_switch(ctx))

static __always_inline int handle_exit(struct bpf_raw_tracepoint_args *ctx)
{
	sd_u32 zero = 0;
	struct sd_config *cfg = bpf_map_lookup_elem(&config, &zero);
	struct task_struct *task = (void *)ctx->args[0];
	struct sd_pending *p;
	struct sd_stats *s;
	sd_u32 tid, kind;

	/* Preserve unfinished records after the window for userspace reporting. */
	if (!cfg || !sd_in_window(cfg, bpf_ktime_get_ns()))
		return 0;
	tid = BPF_CORE_READ(task, pid);
	p = bpf_map_lookup_elem(&pending, &tid);
	if (!p)
		return 0;
	kind = p->kind;
	bpf_map_delete_elem(&pending, &tid);
	if (kind < SD_KINDS) {
		s = bpf_map_lookup_elem(&stats, &kind);
		if (s)
			s->cancelled++;
	}
	return 0;
}

METRIC_PROBE(on_exit, "raw_tp/sched_process_exit", handle_exit(ctx))
