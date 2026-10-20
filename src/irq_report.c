// SPDX-License-Identifier: GPL-2.0-only
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include "metric_loader.h"
#include "irq_delay.h"
#include "cpu_list.h"

struct irq_row {
	struct irq_key key;
	struct irq_stats stats;
};

static int read_cpu_ids(sd_u32 *ids, int cpus)
{
	FILE *file = fopen("/sys/devices/system/cpu/possible", "r");
	char *line = NULL;
	size_t size = 0;
	int result = -1;

	if (!file) {
		perror("read possible CPU IDs");
		return -1;
	}
	if (getline(&line, &size, file) >= 0 &&
	    parse_cpu_list(line, ids, (size_t)cpus) == cpus)
		result = 0;
	else
		fprintf(stderr, "Invalid/changed possible CPU list; refusing to mislabel CPU statistics\n");
	free(line);
	if (fclose(file) == EOF) {
		perror("close possible CPU list");
		result = -1;
	}
	return result;
}

static const char *softirq_name(sd_u32 vector)
{
	static const char *const names[] = {
		"HI", "TIMER", "NET_TX", "NET_RX", "BLOCK",
		"IRQ_POLL", "TASKLET", "SCHED", "HRTIMER", "RCU",
	};

	return vector < sizeof(names) / sizeof(names[0]) ? names[vector] : "UNKNOWN";
}

static double rate(sd_u64 entries, double seconds)
{
	return seconds > 0 ? (double)entries / seconds : 0;
}

static int compare_rows(const void *left, const void *right)
{
	const struct irq_row *a = left, *b = right;

	if (a->key.kind != b->key.kind)
		return a->key.kind < b->key.kind ? -1 : 1;
	if (a->key.cpu != b->key.cpu)
		return a->key.cpu < b->key.cpu ? -1 : 1;
	return (a->key.id > b->key.id) - (a->key.id < b->key.id);
}

static int read_rows(int fd, struct irq_row *rows, size_t *count)
{
	struct irq_key previous, next;
	const struct irq_key *key = NULL;

	while (bpf_map_get_next_key(fd, key, &next) == 0) {
		if (*count >= IRQ_MAX_STATS || next.kind >= IRQ_KINDS) {
			fprintf(stderr, "Invalid IRQ statistics map contents\n");
			return -1;
		}
		rows[*count].key = next;
		if (bpf_map_lookup_elem(fd, &next, &rows[*count].stats)) {
			perror("read IRQ statistics");
			return -1;
		}
		++*count;
		previous = next;
		key = &previous;
	}
	if (errno != ENOENT) {
		perror("iterate IRQ statistics");
		return -1;
	}
	qsort(rows, *count, sizeof(*rows), compare_rows);
	return 0;
}

static void print_histogram(const struct irq_stats *stats)
{
	puts("  histogram (microseconds, upper bound exclusive):");
	for (int b = 0; b < SD_BUCKETS; b++) {
		sd_u64 low = b ? (1ULL << b) : 0;

		if (!stats->histogram[b])
			continue;
		if (b == SD_BUCKETS - 1)
			printf("    [%" PRIu64 ", infinity): %" PRIu64 "\n",
			       low, stats->histogram[b]);
		else
			printf("    [%" PRIu64 ", %" PRIu64 "): %" PRIu64 "\n",
			       low, (sd_u64)(1ULL << (b + 1)), stats->histogram[b]);
	}
}

int report_irq(struct metric_bpf *bpf, double seconds)
{
	int stats_fd = metric_map_fd(bpf, "irq_stats");
	int state_fd = metric_map_fd(bpf, "irq_state");
	int cpus = libbpf_num_possible_cpus();
	struct irq_row *rows = NULL;
	struct irq_state *states = NULL;
	sd_u32 *cpu_ids = NULL;
	size_t count = 0;
	int result = -1;

	if (stats_fd < 0 || state_fd < 0 || cpus <= 0) {
		fprintf(stderr, "Cannot read IRQ maps or possible CPU count\n");
		return -1;
	}
	rows = calloc(IRQ_MAX_STATS, sizeof(*rows));
	states = calloc((size_t)cpus, sizeof(*states));
	cpu_ids = calloc((size_t)cpus, sizeof(*cpu_ids));
	if (!rows || !states || !cpu_ids) {
		perror("allocate IRQ report");
		goto out;
	}
	if (read_cpu_ids(cpu_ids, cpus) || read_rows(stats_fd, rows, &count))
		goto out;

	puts("IRQ durations are elapsed handler times, NOT hardware interrupt delivery latency.");
	puts("Hard IRQ counts are handler invocations (shared IRQ lines may invoke several handlers).");
	puts("Durations include intervening/nested interrupts; do not add hard and soft totals as CPU utilization.");
	for (sd_u32 kind = 0; kind < IRQ_KINDS; kind++) {
		struct irq_stats total = {0};
		sd_u64 entries = 0, unfinished = 0, overflows = 0, unmatched = 0;
		sd_u64 mismatches = 0, discarded = 0, map_errors = 0, missing_stats = 0;

		if (bpf_map_lookup_elem(state_fd, &kind, states)) {
			perror("read IRQ state");
			goto out;
		}
		for (int cpu = 0; cpu < cpus; cpu++) {
			entries += states[cpu].entries;
			unfinished += (sd_u64)states[cpu].depth + states[cpu].overflow_depth;
			overflows += states[cpu].overflows;
			unmatched += states[cpu].unmatched_exits;
			mismatches += states[cpu].mismatches;
			discarded += states[cpu].discarded_frames;
			map_errors += states[cpu].map_errors;
			missing_stats += states[cpu].missing_stats;
		}
		for (size_t i = 0; i < count; i++)
			if (rows[i].key.kind == kind)
				irq_merge_stats(&total, &rows[i].stats);

		printf("\n%s\n", kind == IRQ_HARD ? "Hard IRQ handler duration" : "Softirq execution duration");
		printf("  entries:          %" PRIu64 " (%.3f /s)\n", entries, rate(entries, seconds));
		printf("  mapped entries:   %" PRIu64 "\n", total.entries);
		printf("  samples:          %" PRIu64 "\n", total.count);
		printf("  unfinished:       %" PRIu64 "\n", unfinished);
		printf("  stack overflows:  %" PRIu64 "\n", overflows);
		printf("  unmatched exits:  %" PRIu64 " (includes start-window boundary)\n", unmatched);
		printf("  pairing mismatch: %" PRIu64 "\n", mismatches);
		printf("  discarded frames: %" PRIu64 "\n", discarded);
		printf("  map errors:       %" PRIu64 "\n", map_errors);
		printf("  missing stats:    %" PRIu64 "\n", missing_stats);
		printf("  total elapsed: %.3f ms\n", total.total_ns / 1e6);
		if (total.count) {
			printf("  average: %.3f us\n", (double)total.total_ns / total.count / 1000.0);
			printf("  maximum: %.3f us\n", total.max_ns / 1000.0);
			print_histogram(&total);
		} else {
			puts("  No complete samples observed.");
		}

		puts("  Per-CPU totals (frequency includes entries whose statistics-map insertion failed):");
		printf("    %5s %12s %12s %12s %13s\n", "CPU", "Entries", "Samples", "Entries/s", "Elapsed(ms)");
		for (int cpu = 0; cpu < cpus; cpu++) {
			struct irq_stats cpu_total = {0};

			if (!states[cpu].entries && !states[cpu].unmatched_exits)
				continue;
			for (size_t i = 0; i < count; i++)
				if (rows[i].key.kind == kind && rows[i].key.cpu == cpu_ids[cpu])
					irq_merge_stats(&cpu_total, &rows[i].stats);
			printf("    %5u %12" PRIu64 " %12" PRIu64 " %12.3f %13.3f\n",
			       cpu_ids[cpu], states[cpu].entries, cpu_total.count,
			       rate(states[cpu].entries, seconds), cpu_total.total_ns / 1e6);
		}
		puts("  Per-CPU / IRQ or vector:");
		printf("    %5s %8s %-9s %10s %10s %12s %12s %10s %10s\n",
		       "CPU", "ID", "Vector", "Entries", "Samples", "Entries/s", "Elapsed(ms)", "Avg(us)", "Max(us)");
		for (size_t i = 0; i < count; i++) {
			const struct irq_row *row = &rows[i];
			const struct irq_stats *s = &row->stats;

			if (row->key.kind != kind)
				continue;
			printf("    %5u %8u %-9s %10" PRIu64 " %10" PRIu64 " %12.3f %12.3f",
			       row->key.cpu, row->key.id,
			       kind == IRQ_SOFT ? softirq_name(row->key.id) : "-",
			       s->entries, s->count, rate(s->entries, seconds), s->total_ns / 1e6);
			if (s->count)
				printf(" %10.3f %10.3f\n", (double)s->total_ns / s->count / 1e3, s->max_ns / 1e3);
			else
				printf(" %10s %10s\n", "N/A", "N/A");
		}
	}
	result = 0;
out:
	free(rows);
	free(states);
	free(cpu_ids);
	return result;
}
