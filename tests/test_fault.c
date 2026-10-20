// SPDX-License-Identifier: GPL-2.0-only
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "fault_delay.h"

static void test_categories(void)
{
	const sd_u32 errors[] = {
		FAULT_VM_OOM, FAULT_VM_SIGBUS, FAULT_VM_HWPOISON,
		FAULT_VM_HWPOISON_LARGE, FAULT_VM_SIGSEGV, FAULT_VM_FALLBACK,
	};
	const sd_u32 clean[] = {
		0, FAULT_VM_NOPAGE, FAULT_VM_DONE_COW, FAULT_VM_LOCKED,
		FAULT_VM_NOPAGE | FAULT_VM_DONE_COW | FAULT_VM_LOCKED,
	};

	assert(FAULT_ALL == 0 && FAULT_MAJOR == 1 && FAULT_OTHER == 2);
	assert(FAULT_RETRY == 3 && FAULT_ERROR == 4 && FAULT_KINDS == 5);
	assert(FAULT_VM_ERROR == 0x873U);
	for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
		assert(fault_matches(errors[i], FAULT_ALL));
		assert(fault_matches(errors[i], FAULT_ERROR));
		assert(!fault_matches(errors[i], FAULT_OTHER));
	}
	for (size_t i = 0; i < sizeof(clean) / sizeof(clean[0]); i++) {
		assert(fault_matches(clean[i], FAULT_OTHER));
		assert(!fault_matches(clean[i], FAULT_MAJOR));
		assert(!fault_matches(clean[i], FAULT_RETRY));
		assert(!fault_matches(clean[i], FAULT_ERROR));
	}
	/* Exhaust every combination of the low return bits, including overlap.
	 * Use literal Linux masks independently of the header constants.
	 */
	for (sd_u32 ret = 0; ret < 0x2000U; ret++) {
		assert(fault_matches(ret, FAULT_ALL));
		assert(fault_matches(ret, FAULT_MAJOR) == !!(ret & 0x4U));
		assert(fault_matches(ret, FAULT_RETRY) == !!(ret & 0x400U));
		assert(fault_matches(ret, FAULT_ERROR) == !!(ret & 0x873U));
		assert(fault_matches(ret, FAULT_OTHER) == !(ret & 0xc77U));
	}
	assert(fault_matches(UINT32_MAX, FAULT_MAJOR));
	assert(fault_matches(UINT32_MAX, FAULT_RETRY));
	assert(fault_matches(UINT32_MAX, FAULT_ERROR));
	assert(!fault_matches(UINT32_MAX, FAULT_OTHER));
	assert(!fault_matches(0, FAULT_KINDS));
	assert(!fault_matches(UINT32_MAX, UINT32_MAX));
}

static void test_nested_pairs(void)
{
	struct fault_pending pending = {0};
	sd_u64 out = 999;

	assert(fault_pop(&pending, &out) == FAULT_POP_UNMATCHED);
	assert(out == 999);
	/* Timestamp zero is not a sentinel. Nesting is strictly LIFO. */
	for (sd_u32 i = 0; i < FAULT_STACK_DEPTH; i++)
		assert(fault_push(&pending, i * 100) == FAULT_PUSH_STORED);
	for (sd_u32 i = FAULT_STACK_DEPTH; i > 0; i--) {
		assert(fault_pop(&pending, &out) == FAULT_POP_VALID);
		assert(out == (i - 1) * 100 && pending.depth == i - 1);
	}
	assert(out == 0 && pending.overflow_depth == 0);
	assert(fault_pop(&pending, &out) == FAULT_POP_UNMATCHED);
	assert(out == 0);
	/* Reuse an empty stack without relying on cleared timestamp slots. */
	assert(fault_push(&pending, 1234) == FAULT_PUSH_STORED);
	assert(fault_pop(&pending, &out) == FAULT_POP_VALID && out == 1234);
}

static void test_overflow_unwind(void)
{
	struct fault_pending pending = {0};
	sd_u64 frames[FAULT_STACK_DEPTH];
	sd_u64 out = 999;

	for (sd_u32 i = 0; i < FAULT_STACK_DEPTH; i++)
		assert(fault_push(&pending, i) == FAULT_PUSH_STORED);
	memcpy(frames, pending.frames, sizeof(frames));
	assert(fault_push(&pending, 100) == FAULT_PUSH_OVERFLOW);
	assert(fault_push(&pending, 101) == FAULT_PUSH_OVERFLOW);
	assert(pending.depth == FAULT_STACK_DEPTH && pending.overflow_depth == 2);
	assert(fault_pop(&pending, &out) == FAULT_POP_OVERFLOW);
	assert(out == 999 && pending.overflow_depth == 1);
	/* New nesting during overflow unwind cannot consume an outer slot. */
	assert(fault_push(&pending, 102) == FAULT_PUSH_OVERFLOW);
	assert(fault_pop(&pending, &out) == FAULT_POP_OVERFLOW);
	assert(fault_pop(&pending, &out) == FAULT_POP_OVERFLOW);
	assert(out == 999 && pending.overflow_depth == 0);
	assert(memcmp(frames, pending.frames, sizeof(frames)) == 0);
	for (sd_u32 i = FAULT_STACK_DEPTH; i > 0; i--) {
		assert(fault_pop(&pending, &out) == FAULT_POP_VALID);
		assert(out == i - 1);
	}
	assert(pending.depth == 0 && pending.overflow_depth == 0);
	/* Even an available slot cannot be reused while overflow is active. */
	pending.depth = 1;
	pending.overflow_depth = 1;
	assert(fault_push(&pending, 500) == FAULT_PUSH_OVERFLOW);
	assert(pending.depth == 1 && pending.overflow_depth == 2);
}

static void test_overflow_saturation(void)
{
	struct fault_pending pending = {
		.depth = FAULT_STACK_DEPTH, .overflow_depth = UINT32_MAX - 1,
	};
	sd_u64 out = 999;

	assert(fault_push(&pending, 1) == FAULT_PUSH_OVERFLOW);
	assert(pending.overflow_depth == UINT32_MAX);
	assert(fault_push(&pending, 2) == FAULT_PUSH_OVERFLOW);
	assert(pending.overflow_depth == UINT32_MAX);
	assert(fault_pop(&pending, &out) == FAULT_POP_OVERFLOW);
	assert(pending.overflow_depth == UINT32_MAX);
	assert(pending.depth == FAULT_STACK_DEPTH && out == 999);
}

static void check_invalid_depth(sd_u32 depth)
{
	for (int overflow = 0; overflow < 2; overflow++) {
		struct fault_pending pending = {
			.depth = depth, .overflow_depth = (sd_u32)overflow,
		};
		struct fault_pending before = pending;
		sd_u64 out = 999;

		assert(fault_push(&pending, 42) == FAULT_PUSH_INVALID_DEPTH);
		assert(memcmp(&pending, &before, sizeof(pending)) == 0);
		assert(fault_pop(&pending, &out) == FAULT_POP_INVALID_DEPTH);
		assert(out == 999);
		assert(pending.depth == 0 && pending.overflow_depth == 0);
		assert(fault_pop(&pending, &out) == FAULT_POP_UNMATCHED);
		assert(fault_push(&pending, 0) == FAULT_PUSH_STORED);
		assert(fault_pop(&pending, &out) == FAULT_POP_VALID && out == 0);
	}
}

static void test_index_bounds(void)
{
	/* Cover each real depth and empty, every nearby invalid depth, and all
	 * upper-bit boundaries, especially the wrapped depth-- == UINT32_MAX.
	 */
	for (sd_u32 depth = 0; depth <= FAULT_STACK_DEPTH; depth++) {
		struct fault_pending pending = {.depth = depth};
		sd_u64 out = 999;

		for (sd_u32 i = 0; i < FAULT_STACK_DEPTH; i++) {
			assert(fault_bounded_index(i) == i);
			pending.frames[i] = 100 + i;
		}
		if (!depth) {
			assert(fault_pop(&pending, &out) == FAULT_POP_UNMATCHED);
			assert(out == 999 && pending.depth == 0);
		} else {
			assert(fault_pop(&pending, &out) == FAULT_POP_VALID);
			assert(out == 100 + depth - 1 && pending.depth == depth - 1);
		}
	}
	for (sd_u32 depth = FAULT_STACK_DEPTH + 1; depth < 1024; depth++)
		check_invalid_depth(depth);
	for (sd_u32 bit = 10; bit < 32; bit++) {
		sd_u32 depth = (sd_u32)1 << bit;

		check_invalid_depth(depth - 1);
		check_invalid_depth(depth);
		check_invalid_depth(depth + 1);
	}
	check_invalid_depth(UINT32_MAX - 1);
	check_invalid_depth(UINT32_MAX);
	assert(fault_bounded_index(UINT32_MAX) < FAULT_STACK_DEPTH);
	assert(fault_bounded_index(FAULT_STACK_DEPTH) < FAULT_STACK_DEPTH);
}

static void test_histogram_and_merge(void)
{
	struct fault_stats a = {0}, b = {0}, total = {0};
	sd_u64 count = 0;

	fault_account(&a, 0);
	fault_account(&a, 1999);
	fault_account(&a, 2000);
	fault_account(&b, 4000);
	fault_merge_stats(&total, &b);
	fault_merge_stats(&total, &a); /* Smaller max must not replace larger. */
	assert(total.count == 4 && total.total_ns == 7999);
	assert(total.max_ns == 4000);
	assert(total.histogram[0] == 2 && total.histogram[1] == 1);
	assert(total.histogram[2] == 1);
	for (int i = 0; i < SD_BUCKETS; i++)
		count += total.histogram[i];
	assert(count == total.count);
	b = (struct fault_stats){0};
	fault_account(&b, UINT64_MAX);
	assert(b.histogram[SD_BUCKETS - 1] == 1);
	assert(b.total_ns == UINT64_MAX && b.max_ns == UINT64_MAX);
	/* One completion can contribute to three non-ALL categories. */
	struct fault_stats categories[FAULT_KINDS] = {0};
	sd_u32 ret = FAULT_VM_MAJOR | FAULT_VM_RETRY | FAULT_VM_FALLBACK;

	for (sd_u32 i = 0; i < FAULT_KINDS; i++) {
		if (fault_matches(ret, i))
			fault_account(&categories[i], 5000);
	}
	assert(categories[FAULT_ALL].count == 1);
	assert(categories[FAULT_MAJOR].count == 1);
	assert(categories[FAULT_RETRY].count == 1);
	assert(categories[FAULT_ERROR].count == 1);
	assert(categories[FAULT_OTHER].count == 0);
}

/* Mirror the BPF window/stale/clock gates without requiring a Linux kernel. */
static void window_event(struct fault_pending *pending,
			 const struct sd_config *cfg, struct fault_stats *stats,
			 sd_u64 now, int entry)
{
	sd_u64 start_ns;

	if (!sd_in_window(cfg, now))
		return;
	if (entry)
		fault_push(pending, now);
	else if (fault_pop(pending, &start_ns) == FAULT_POP_VALID &&
		 now >= start_ns && start_ns >= cfg->start_ns)
		fault_account(stats, now - start_ns);
}

static void test_window_and_freeze(void)
{
	const struct sd_config cfg = {.start_ns = 100, .end_ns = 200};
	struct fault_pending pending = {0}, frozen;
	struct fault_stats stats = {0};

	window_event(&pending, &cfg, &stats, 99, 1);
	assert(pending.depth == 0);
	window_event(&pending, &cfg, &stats, 100, 0);
	assert(stats.count == 0);
	window_event(&pending, &cfg, &stats, 100, 1);
	window_event(&pending, &cfg, &stats, 101, 0);
	assert(stats.count == 1 && stats.total_ns == 1);
	/* A stale timestamp is discarded, never clipped to start_ns. */
	assert(fault_push(&pending, 99) == FAULT_PUSH_STORED);
	window_event(&pending, &cfg, &stats, 110, 0);
	assert(stats.count == 1 && pending.depth == 0);
	assert(fault_push(&pending, 120) == FAULT_PUSH_STORED);
	window_event(&pending, &cfg, &stats, 119, 0);
	assert(stats.count == 1 && pending.depth == 0);
	for (int i = 0; i < FAULT_STACK_DEPTH + 2; i++)
		window_event(&pending, &cfg, &stats, 199, 1);
	frozen = pending;
	window_event(&pending, &cfg, &stats, 200, 0);
	window_event(&pending, &cfg, &stats, 200, 1);
	window_event(&pending, &cfg, &stats, 201, 0);
	assert(memcmp(&pending, &frozen, sizeof(pending)) == 0);
	assert((sd_u64)pending.depth + pending.overflow_depth == FAULT_STACK_DEPTH + 2);
}

int main(void)
{
	test_categories();
	test_nested_pairs();
	test_overflow_unwind();
	test_overflow_saturation();
	test_index_bounds();
	test_histogram_and_merge();
	test_window_and_freeze();
	puts("PASS: fault flags, overlap, nesting, overflow, bounds, histogram, window");
	return 0;
}
