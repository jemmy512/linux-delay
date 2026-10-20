// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "irq_delay.h"
#include "metric_bpf.h"

/* Independent object: no kernel structure access, CO-RE, or kernel BTF. */
char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, sd_u32);
	__type(value, struct sd_config);
} config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, IRQ_KINDS);
	__type(key, sd_u32);
	__type(value, struct irq_state);
} irq_state SEC(".maps");

/* CPU is part of the key: records are updated only on their owning CPU. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, IRQ_MAX_STATS);
	__type(key, struct irq_key);
	__type(value, struct irq_stats);
} irq_stats SEC(".maps");

/* Do not put this 288-byte initializer on the BPF stack. */
static const struct irq_stats empty_stats;

static __always_inline int irq_enter(sd_u32 kind, sd_u32 id, sd_u64 action)
{
	sd_u32 zero = 0;
	const struct sd_config *cfg = bpf_map_lookup_elem(&config, &zero);
	sd_u64 now = bpf_ktime_get_ns();
	struct irq_state *state;
	struct irq_stats *stats;
	struct irq_key key = {
		.cpu = bpf_get_smp_processor_id(),
		.kind = kind,
		.id = id,
		.reserved = 0,
	};
	long err;

	/* IRQs are system-wide; cfg->tgid/tid intentionally do not filter them. */
	if (!cfg || !sd_in_window(cfg, now))
		return 0;
	state = bpf_map_lookup_elem(&irq_state, &kind);
	if (!state)
		return 0;

	/* Even overflowing entries must contribute to entry frequency. */
	irq_push(state, now, id, action);
	stats = bpf_map_lookup_elem(&irq_stats, &key);
	if (!stats) {
		err = bpf_map_update_elem(&irq_stats, &key, &empty_stats,
					  BPF_NOEXIST);
		stats = bpf_map_lookup_elem(&irq_stats, &key);
		/* Count failed insertions, even if a record appeared meanwhile. */
		if (err || !stats)
			state->map_errors++;
		if (!stats)
			return 0;
	}
	stats->entries++;
	return 0;
}

static __always_inline int irq_leave(sd_u32 kind, sd_u32 id, sd_u64 action)
{
	sd_u32 zero = 0;
	const struct sd_config *cfg = bpf_map_lookup_elem(&config, &zero);
	sd_u64 now = bpf_ktime_get_ns();
	struct irq_state *state;
	struct irq_stats *stats;
	struct irq_frame frame;
	struct irq_key key = {
		.cpu = bpf_get_smp_processor_id(),
		.kind = kind,
		.id = id,
		.reserved = 0,
	};

	/* No clipping: freeze both stack and diagnostics after the deadline. */
	if (!cfg || !sd_in_window(cfg, now))
		return 0;
	state = bpf_map_lookup_elem(&irq_state, &kind);
	if (!state || !irq_pop(state, id, action, &frame))
		return 0;

	/* Exits never create records or evict other IRQs to make space. */
	stats = bpf_map_lookup_elem(&irq_stats, &key);
	if (!stats) {
		state->missing_stats++;
		return 0;
	}
	irq_account_duration(stats, now - frame.start_ns);
	return 0;
}

/* Hard IRQ: arg0=IRQ number, arg1=opaque irqaction identity; ignore exit ret. */
METRIC_PROBE(on_irq_handler_entry, "raw_tp/irq_handler_entry",
	     irq_enter(IRQ_HARD, (sd_u32)ctx->args[0], ctx->args[1]))
METRIC_PROBE(on_irq_handler_exit, "raw_tp/irq_handler_exit",
	     irq_leave(IRQ_HARD, (sd_u32)ctx->args[0], ctx->args[1]))
METRIC_PROBE(on_softirq_entry, "raw_tp/softirq_entry",
	     irq_enter(IRQ_SOFT, (sd_u32)ctx->args[0], 0))
METRIC_PROBE(on_softirq_exit, "raw_tp/softirq_exit",
	     irq_leave(IRQ_SOFT, (sd_u32)ctx->args[0], 0))
