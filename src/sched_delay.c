// SPDX-License-Identifier: GPL-2.0-only
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "sched_delay.h"
#include "metric_loader.h"

static int count_pending(int fd, sd_u64 counts[SD_KINDS])
{
	sd_u32 key, next;
	const sd_u32 *previous = NULL;

	/* All links are detached: iteration observes a stable map. */
	while (bpf_map_get_next_key(fd, previous, &next) == 0) {
		struct sd_pending p;

		if (bpf_map_lookup_elem(fd, &next, &p)) {
			perror("read unfinished wait");
			return -1;
		}
		if (p.kind < SD_KINDS)
			counts[p.kind]++;
		key = next;
		previous = &key;
	}
	if (errno != ENOENT) {
		perror("iterate unfinished waits");
		return -1;
	}
	return 0;
}

int report_sched(struct metric_bpf *bpf, double seconds)
{
	static const char *names[SD_KINDS] = {
		"Wakeup -> running", "Runnable switch-out -> running",
	};
	sd_u64 unfinished[SD_KINDS] = {0};
	int cpus = libbpf_num_possible_cpus();
	int pending_fd = metric_map_fd(bpf, "pending");
	int stats_fd = metric_map_fd(bpf, "stats");
	struct sd_stats *values;

	(void)seconds;
	if (cpus <= 0 || pending_fd < 0 || stats_fd < 0) {
		fprintf(stderr, "Cannot read scheduler maps or possible CPU count\n");
		return -1;
	}
	if (count_pending(pending_fd, unfinished))
		return -1;

	/* sizeof(sd_stats) is a multiple of 8: required per-CPU map stride. */
	values = calloc((size_t)cpus, sizeof(*values));
	if (!values) {
		perror("allocate per-CPU statistics");
		return -1;
	}
	for (sd_u32 kind = 0; kind < SD_KINDS; kind++) {
		struct sd_stats total = {0};

		if (bpf_map_lookup_elem(stats_fd, &kind, values)) {
			perror("read statistics");
			free(values);
			return -1;
		}
		for (int cpu = 0; cpu < cpus; cpu++)
			sd_merge_stats(&total, &values[cpu]);

		printf("\n%s\n", names[kind]);
		printf("  samples:          %" PRIu64 "\n", total.count);
		printf("  unfinished:       %" PRIu64 "\n", unfinished[kind]);
		printf("  map insert errors:%" PRIu64 "\n", total.insert_errors);
		printf("  duplicate starts: %" PRIu64 "\n", total.duplicate_starts);
		printf("  cancelled on exit:%" PRIu64 "\n", total.cancelled);
		if (!total.count) {
			printf("  No complete samples observed.\n");
			continue;
		}
		printf("  average: %.3f us\n", (double)total.total_ns / total.count / 1000.0);
		printf("  maximum: %.3f us\n", total.max_ns / 1000.0);
		printf("  histogram (microseconds, upper bound exclusive):\n");
		for (int b = 0; b < SD_BUCKETS; b++) {
			sd_u64 low = b ? (1ULL << b) : 0;

			if (!total.histogram[b])
				continue;
			if (b == SD_BUCKETS - 1)
				printf("    [%" PRIu64 ", infinity): %" PRIu64 "\n",
				       low, total.histogram[b]);
			else
				printf("    [%" PRIu64 ", %" PRIu64 "): %" PRIu64 "\n",
				       low, (sd_u64)(1ULL << (b + 1)), total.histogram[b]);
		}
	}
	free(values);
	if (fflush(stdout) == EOF) {
		perror("stdout");
		return -1;
	}
	return 0;
}
