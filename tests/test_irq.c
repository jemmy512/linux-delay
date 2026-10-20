// SPDX-License-Identifier: GPL-2.0-only
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "irq_delay.h"
#include "cpu_list.h"

static void test_normal_pairs(void)
{
	struct irq_state states[IRQ_KINDS] = {0};
	struct irq_stats stats = {0};
	struct irq_frame frame;

	assert(IRQ_HARD == 0 && IRQ_SOFT == 1 && IRQ_KINDS == 2);
	assert(irq_push(&states[IRQ_HARD], 100, 42, 0x1234));
	assert(irq_push(&states[IRQ_SOFT], 200, 3, 0));
	assert(irq_pop(&states[IRQ_HARD], 42, 0x1234, &frame));
	assert(frame.start_ns == 100 && frame.id == 42);
	assert(frame.action == 0x1234 && frame.pad == 0);
	irq_account_duration(&stats, 3100 - frame.start_ns);
	assert(states[IRQ_SOFT].depth == 1);
	assert(irq_pop(&states[IRQ_SOFT], 3, 0, &frame));
	assert(frame.start_ns == 200 && frame.id == 3 && frame.action == 0);
	irq_account_duration(&stats, 1200 - frame.start_ns);
	assert(stats.count == 2 && stats.total_ns == 4000);
	assert(stats.max_ns == 3000);
	assert(stats.histogram[0] == 1 && stats.histogram[1] == 1);
	for (int kind = 0; kind < IRQ_KINDS; kind++) {
		assert(states[kind].entries == 1);
		assert(states[kind].depth == 0);
		assert(states[kind].overflow_depth == 0);
		assert(states[kind].mismatches == 0);
		assert(states[kind].unmatched_exits == 0);
	}
}

static void test_hard_identity(void)
{
	struct irq_state state = {0};
	struct irq_frame out = {.start_ns = 99};

	assert(irq_push(&state, 10, 7, 0x1000));
	assert(!irq_pop(&state, 7, 0x2000, &out));
	assert(out.start_ns == 99);
	assert(state.mismatches == 1 && state.discarded_frames == 1);
	assert(state.depth == 0 && state.unmatched_exits == 0);
	/* Shared IRQ handlers with the same ID can pair sequentially. */
	assert(irq_push(&state, 20, 7, 0x2000));
	assert(irq_pop(&state, 7, 0x2000, &out));
	assert(out.start_ns == 20);
}

static void test_nested_lifo(void)
{
	struct irq_state state = {0};
	struct irq_frame frame;

	/* Same IRQ ID, different actions; then the exact same ID and action. */
	assert(irq_push(&state, 10, 7, 0x1000));
	assert(irq_push(&state, 20, 7, 0x2000));
	assert(irq_push(&state, 30, 7, 0x2000));
	assert(irq_push(&state, 40, 9, 0x3000));
	assert(irq_pop(&state, 9, 0x3000, &frame));
	assert(frame.start_ns == 40 && state.depth == 3);
	assert(irq_pop(&state, 7, 0x2000, &frame));
	assert(frame.start_ns == 30 && state.depth == 2);
	assert(irq_pop(&state, 7, 0x2000, &frame));
	assert(frame.start_ns == 20 && state.depth == 1);
	assert(irq_pop(&state, 7, 0x1000, &frame));
	assert(frame.start_ns == 10 && state.depth == 0);
	assert(state.entries == 4 && state.mismatches == 0);
}

static void test_overflow(void)
{
	struct irq_state state = {0};
	struct irq_frame frame = {.start_ns = 999};

	for (sd_u32 i = 0; i < IRQ_STACK_DEPTH; i++)
		assert(irq_push(&state, 100 + i, i, 1000 + i));
	assert(!irq_push(&state, 200, 90, 2000));
	assert(!irq_push(&state, 201, 91, 2001));
	assert(state.depth == IRQ_STACK_DEPTH && state.overflow_depth == 2);
	assert(!irq_pop(&state, 91, 2001, &frame));
	assert(state.overflow_depth == 1 && frame.start_ns == 999);
	/* New nesting while unwinding must also remain in overflow mode. */
	assert(!irq_push(&state, 202, 92, 2002));
	assert(!irq_pop(&state, 92, 2002, &frame));
	assert(!irq_pop(&state, 90, 2000, &frame));
	assert(state.overflow_depth == 0 && state.depth == IRQ_STACK_DEPTH);
	assert(frame.start_ns == 999);
	for (sd_u32 i = IRQ_STACK_DEPTH; i > 0; i--) {
		assert(irq_pop(&state, i - 1, 1000 + i - 1, &frame));
		assert(frame.start_ns == 100 + i - 1);
		assert(frame.id == i - 1 && frame.action == 1000 + i - 1);
	}
	assert(state.depth == 0 && state.overflow_depth == 0);
	assert(state.entries == IRQ_STACK_DEPTH + 3 && state.overflows == 3);
	assert(state.mismatches == 0 && state.discarded_frames == 0);
	assert(state.unmatched_exits == 0);
}

static void test_unmatched_and_reset(void)
{
	struct irq_state state = {0};
	struct irq_frame frame = {.start_ns = 999};

	assert(!irq_pop(&state, 1, 0, &frame));
	assert(state.unmatched_exits == 1 && frame.start_ns == 999);
	assert(irq_push(&state, 10, 1, 0));
	assert(irq_push(&state, 20, 2, 0));
	assert(irq_push(&state, 30, 3, 0));
	/* Matching an outer frame must NOT produce a duration. */
	assert(!irq_pop(&state, 1, 0, &frame));
	assert(state.depth == 0 && state.overflow_depth == 0);
	assert(state.mismatches == 1 && state.discarded_frames == 3);
	assert(frame.start_ns == 999);
	assert(!irq_pop(&state, 3, 0, &frame));
	assert(!irq_pop(&state, 2, 0, &frame));
	assert(state.unmatched_exits == 3);
	assert(irq_push(&state, 40, 4, 0));
	assert(irq_pop(&state, 4, 0, &frame));
	assert(frame.start_ns == 40 && state.depth == 0);
	assert(state.entries == 4);
}

/* Mirror the BPF event gate; no state updates are allowed outside [start,end). */
static void window_event(struct irq_state *state, const struct sd_config *cfg,
			 sd_u64 now, int entry)
{
	struct irq_frame frame;

	if (!sd_in_window(cfg, now))
		return;
	if (entry)
		irq_push(state, now, 1, 0);
	else
		irq_pop(state, 1, 0, &frame);
}

static void test_window_and_freeze(void)
{
	const struct sd_config cfg = {.start_ns = 100, .end_ns = 200};
	struct irq_state state = {0};
	struct irq_state frozen;

	window_event(&state, &cfg, 99, 1);
	assert(state.entries == 0);
	window_event(&state, &cfg, 100, 0);
	assert(state.unmatched_exits == 1); /* Entry predates the left boundary. */
	window_event(&state, &cfg, 100, 1);
	assert(state.entries == 1 && state.frames[0].start_ns == 100);
	window_event(&state, &cfg, 101, 0);
	assert(state.depth == 0);
	for (int i = 0; i < IRQ_STACK_DEPTH + 2; i++)
		window_event(&state, &cfg, 199, 1);
	frozen = state;
	window_event(&state, &cfg, 200, 0);
	window_event(&state, &cfg, 200, 1);
	window_event(&state, &cfg, 201, 0);
	assert(memcmp(&state, &frozen, sizeof(state)) == 0);
	assert((sd_u64)state.depth + state.overflow_depth == IRQ_STACK_DEPTH + 2);
}

static void test_duration_and_merge(void)
{
	struct irq_stats a = {.entries = 4};
	struct irq_stats b = {.entries = 2};
	struct irq_stats total = {0};
	sd_u64 count = 0;

	irq_account_duration(&a, 0);
	irq_account_duration(&a, 1999);
	irq_account_duration(&a, 2000);
	irq_account_duration(&b, 4000);
	irq_merge_stats(&total, &a);
	irq_merge_stats(&total, &b);
	assert(total.entries == 6 && total.count == 4);
	assert(total.total_ns == 7999 && total.max_ns == 4000);
	assert(total.histogram[0] == 2 && total.histogram[1] == 1);
	assert(total.histogram[2] == 1);
	for (int i = 0; i < SD_BUCKETS; i++)
		count += total.histogram[i];
	assert(count == total.count);
	b = (struct irq_stats){0};
	irq_account_duration(&b, UINT64_MAX);
	assert(b.histogram[SD_BUCKETS - 1] == 1);
	assert(b.total_ns == UINT64_MAX && b.max_ns == UINT64_MAX);
}

/* Regression for Android's verifier losing the nonzero depth lower bound.
 * C tests establish semantics; emitted BPF must also retain the index mask.
 */
static void test_index_bounds(void)
{
	const sd_u32 invalid[] = {0, IRQ_STACK_DEPTH + 1, UINT32_MAX};

	for (sd_u32 i = 0; i < IRQ_STACK_DEPTH; i++)
		assert(irq_bounded_index(i) == i);
	assert(irq_bounded_index(UINT32_MAX) < IRQ_STACK_DEPTH);
	assert(irq_bounded_index(IRQ_STACK_DEPTH) < IRQ_STACK_DEPTH);
	for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
		struct irq_state state = {.depth = invalid[i]};
		struct irq_frame out = {.start_ns = 999, .id = 42};

		/* Even if a wrapped slot would match, invalid depth must not pop it. */
		for (int j = 0; j < IRQ_STACK_DEPTH; j++) {
			state.frames[j].id = 42;
			state.frames[j].action = 123;
		}
		assert(!irq_pop(&state, 42, 123, &out));
		assert(state.depth == 0);
		assert(out.start_ns == 999 && out.id == 42);
		if (invalid[i] == 0) {
			assert(state.unmatched_exits == 1 && state.mismatches == 0);
		} else {
			assert(state.mismatches == 1);
			assert(state.discarded_frames == invalid[i]);
		}
	}
	/* Every legitimate depth still selects its exact top frame. */
	for (sd_u32 depth = 1; depth <= IRQ_STACK_DEPTH; depth++) {
		struct irq_state state = {.depth = depth};
		struct irq_frame out;

		state.frames[depth - 1] = (struct irq_frame){.start_ns = depth, .id = 42, .action = 123};
		assert(irq_pop(&state, 42, 123, &out));
		assert(out.start_ns == depth && state.depth == depth - 1);
	}
}

static void test_cpu_list(void)
{
	sd_u32 ids[8];
	const char *bad[] = {"", "0,", "-1", "1-0", "0,0", "0-2,1", "2,0", "0junk", "4294967296"};

	assert(parse_cpu_list("0,2", ids, 8) == 2);
	assert(ids[0] == 0 && ids[1] == 2); /* Packed slot 1 is CPU 2, not CPU 1. */
	assert(parse_cpu_list("0-2,5-6\n", ids, 8) == 5);
	assert(ids[0] == 0 && ids[1] == 1 && ids[2] == 2 && ids[3] == 5 && ids[4] == 6);
	assert(parse_cpu_list("0-8", ids, 8) == -1);
	assert(parse_cpu_list("0-4294967295", ids, 8) == -1);
	assert(parse_cpu_list("0", ids, 0) == -1);
	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
		assert(parse_cpu_list(bad[i], ids, 8) == -1);
}

int main(void)
{
	test_normal_pairs();
	test_hard_identity();
	test_nested_lifo();
	test_overflow();
	test_unmatched_and_reset();
	test_window_and_freeze();
	test_duration_and_merge();
	test_index_bounds();
	test_cpu_list();
	puts("PASS: IRQ pairing, identity, nesting, overflow, reset, window, stats, index bounds, sparse CPUs");
	return 0;
}
