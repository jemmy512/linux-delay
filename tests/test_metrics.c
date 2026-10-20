// SPDX-License-Identifier: GPL-2.0-only
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include "sched_delay.h"

static void test_histogram(void)
{
	assert(sd_bucket(0) == 0);
	assert(sd_bucket(999) == 0);
	assert(sd_bucket(1000) == 0);
	assert(sd_bucket(1999) == 0);
	assert(sd_bucket(2000) == 1);
	assert(sd_bucket(3999) == 1);
	assert(sd_bucket(4000) == 2);
	for (unsigned int b = 1; b < SD_BUCKETS; b++) {
		uint64_t edge = (1ULL << b) * 1000;

		assert(sd_bucket(edge - 1) == b - 1);
		assert(sd_bucket(edge) == b);
	}
	assert(sd_bucket(UINT64_MAX) == SD_BUCKETS - 1);
}

static void test_window(void)
{
	struct sd_config cfg = {0};

	assert(!sd_in_window(&cfg, 0));
	assert(!sd_in_window(&cfg, 100));
	cfg.start_ns = 100;
	cfg.end_ns = 200;
	assert(!sd_in_window(&cfg, 99));
	assert(sd_in_window(&cfg, 100));
	assert(sd_in_window(&cfg, 199));
	assert(!sd_in_window(&cfg, 200));
	assert(!sd_in_window(&cfg, UINT64_MAX));
}

static void test_merge(void)
{
	struct sd_stats total = {0};
	struct sd_stats a = {
		.count = 2, .total_ns = 5000, .max_ns = 3000,
		.insert_errors = 1, .duplicate_starts = 2, .cancelled = 3,
	};
	struct sd_stats b = {
		.count = 1, .total_ns = 1000, .max_ns = 1000,
		.insert_errors = 4, .duplicate_starts = 5, .cancelled = 6,
	};
	uint64_t samples = 0;

	a.histogram[1] = 2;
	b.histogram[0] = 1;
	sd_merge_stats(&total, &a);
	sd_merge_stats(&total, &b);
	assert(total.count == 3);
	assert(total.total_ns == 6000);
	assert(total.max_ns == 3000);
	assert(total.insert_errors == 5);
	assert(total.duplicate_starts == 7);
	assert(total.cancelled == 9);
	for (int i = 0; i < SD_BUCKETS; i++)
		samples += total.histogram[i];
	assert(samples == total.count);
	assert(total.histogram[0] == 1);
	assert(total.histogram[1] == 2);
}

int main(void)
{
	test_histogram();
	test_window();
	test_merge();
	puts("PASS: histogram boundaries, collection window, per-CPU aggregation");
	return 0;
}
