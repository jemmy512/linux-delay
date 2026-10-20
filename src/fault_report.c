// SPDX-License-Identifier: GPL-2.0-only
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include "metric_loader.h"
#include "fault_delay.h"

/* fexit ctx[4] is the return value only for the verified four-argument ABI.
 * Otherwise use the architecture's kretprobe return register instead.
 */
static int fault_fentry_abi(void)
{
	struct btf *btf = btf__load_vmlinux_btf();
	const struct btf_type *function, *proto, *return_type;
	const struct btf_param *params;
	int id, err = -EOPNOTSUPP;

	if (!btf)
		return errno ? -errno : -ENOENT;
	if (libbpf_get_error(btf))
		return (int)libbpf_get_error(btf);
	id = btf__find_by_name_kind(btf, "handle_mm_fault", BTF_KIND_FUNC);
	if (id < 0)
		goto out;
	function = btf__type_by_id(btf, id);
	proto = function ? btf__type_by_id(btf, function->type) : NULL;
	if (!proto || !btf_is_func_proto(proto) || btf_vlen(proto) != 4 ||
	    btf__resolve_size(btf, proto->type) != 4)
		goto out;
	id = btf__resolve_type(btf, proto->type);
	return_type = id > 0 ? btf__type_by_id(btf, id) : NULL;
	if (!return_type || !btf_is_int(return_type))
		goto out;
	params = btf_params(proto);
	for (int i = 0; i < 4; i++) {
		const struct btf_type *type;

		id = btf__resolve_type(btf, params[i].type);
		type = id > 0 ? btf__type_by_id(btf, id) : NULL;
		if (!type)
			goto out;
		if (i == 0 || i == 3) {
			if (!btf_is_ptr(type))
				goto out;
		} else if (!btf_is_int(type) || type->size != (i == 1 ? 8U : 4U)) {
			goto out;
		}
	}
	err = 0;
out:
	btf__free(btf);
	return err;
}

int configure_fault(struct bpf_object *object, bool fallback)
{
	static const char *const primary[] = {"on_fault_fentry", "on_fault_fexit"};
	static const char *const secondary[] = {"on_fault_kprobe", "on_fault_kretprobe"};
	const char *const *names = fallback ? secondary : primary;
	struct bpf_program *program;
	int err;

	if (!fallback) {
		err = fault_fentry_abi();
		if (err)
			return err;
	}
	/* Never attach both pairs: that would double-count and corrupt nesting. */
	bpf_object__for_each_program(program, object) {
		err = bpf_program__set_autoload(program, false);
		if (err)
			return err;
	}
	for (int i = 0; i < 3; i++) {
		const char *name = i == 2 ? "on_fault_process_exit" : names[i];

		program = bpf_object__find_program_by_name(object, name);
		if (!program)
			return -ENOENT;
		err = bpf_program__set_autoload(program, true);
		if (err)
			return err;
	}
	return 0;
}

struct fault_row {
	sd_u64 key;
	struct fault_thread_stats stats;
};

static int compare_threads(const void *left, const void *right)
{
	const struct fault_row *a = left, *b = right;

	if (a->stats.count != b->stats.count)
		return a->stats.count > b->stats.count ? -1 : 1;
	return (a->key > b->key) - (a->key < b->key);
}

static int report_unfinished(int fd)
{
	sd_u64 key, next, calls = 0, threads = 0, invalid = 0;
	const sd_u64 *previous = NULL;

	while (bpf_map_get_next_key(fd, previous, &next) == 0) {
		struct fault_pending pending;

		if (bpf_map_lookup_elem(fd, &next, &pending)) {
			perror("read pending fault calls");
			return -1;
		}
		if (pending.depth > FAULT_STACK_DEPTH)
			invalid++;
		else {
			calls += (sd_u64)pending.depth + pending.overflow_depth;
			threads += pending.depth != 0 || pending.overflow_depth != 0;
		}
		key = next;
		previous = &key;
	}
	if (errno != ENOENT) {
		perror("iterate pending fault calls");
		return -1;
	}
	printf("  unfinished calls:  %" PRIu64 " in %" PRIu64 " threads\n", calls, threads);
	printf("  invalid pending:   %" PRIu64 "\n", invalid);
	return 0;
}

static int report_threads(int fd)
{
	struct fault_row *rows = calloc(FAULT_MAX_THREADS, sizeof(*rows));
	sd_u64 key, next;
	const sd_u64 *previous = NULL;
	size_t count = 0;
	int result = -1;

	if (!rows) {
		perror("allocate fault thread report");
		return -1;
	}
	while (bpf_map_get_next_key(fd, previous, &next) == 0) {
		if (count >= FAULT_MAX_THREADS) {
			fprintf(stderr, "Fault thread map exceeds configured capacity\n");
			goto out;
		}
		rows[count].key = next;
		if (bpf_map_lookup_elem(fd, &next, &rows[count].stats)) {
			perror("read fault thread statistics");
			goto out;
		}
		count++;
		key = next;
		previous = &key;
	}
	if (errno != ENOENT) {
		perror("iterate fault thread statistics");
		goto out;
	}
	qsort(rows, count, sizeof(*rows), compare_threads);
	puts("\nPer-thread paired calls (flag columns may overlap; last observed comm):");
	printf("%8s %8s %-16s %10s %8s %8s %8s %8s %12s %12s %12s\n",
	       "TGID", "TID", "COMM", "Calls", "Major", "Retry", "Error", "Other", "Total(ms)", "Avg(us)", "Max(us)");
	for (size_t i = 0; i < count; i++) {
		const struct fault_thread_stats *s = &rows[i].stats;

		printf("%8u %8u %-16.16s %10" PRIu64 " %8" PRIu64 " %8" PRIu64
		       " %8" PRIu64 " %8" PRIu64 " %12.3f %12.3f %12.3f\n",
		       (sd_u32)(rows[i].key >> 32), (sd_u32)rows[i].key, s->comm,
		       s->count, s->major, s->retries, s->errors, s->other,
		       s->total_ns / 1e6, s->count ? (double)s->total_ns / s->count / 1e3 : 0,
		       s->max_ns / 1e3);
	}
	result = 0;
out:
	free(rows);
	return result;
}

int report_fault(struct metric_bpf *bpf, double seconds)
{
	static const char *const names[FAULT_KINDS] = {
		"All paired handle_mm_fault calls", "Major-flagged calls",
		"Non-major calls without retry/error flags (not exact minor faults)",
		"Retry-flagged calls", "Error/fallback-flagged calls",
	};
	int stats_fd = metric_map_fd(bpf, "fault_stats");
	int diag_fd = metric_map_fd(bpf, "fault_diag");
	int pending_fd = metric_map_fd(bpf, "fault_pending");
	int threads_fd = metric_map_fd(bpf, "fault_threads");
	int cpus = libbpf_num_possible_cpus();
	struct fault_stats *values = NULL;
	struct fault_diag *diags = NULL, total_diag = {0};
	sd_u32 zero = 0;
	int result = -1;

	if (stats_fd < 0 || diag_fd < 0 || pending_fd < 0 || threads_fd < 0 || cpus <= 0)
		return -1;
	values = calloc((size_t)cpus, sizeof(*values));
	diags = calloc((size_t)cpus, sizeof(*diags));
	if (!values || !diags) {
		perror("allocate fault statistics");
		goto out;
	}
	if (bpf_map_lookup_elem(diag_fd, &zero, diags)) {
		perror("read fault diagnostics");
		goto out;
	}
	for (int i = 0; i < cpus; i++) {
		total_diag.entries += diags[i].entries;
		total_diag.returns += diags[i].returns;
		total_diag.unmatched_returns += diags[i].unmatched_returns;
		total_diag.overflows += diags[i].overflows;
		total_diag.pending_errors += diags[i].pending_errors;
		total_diag.thread_errors += diags[i].thread_errors;
		total_diag.cancelled += diags[i].cancelled;
		total_diag.invalid_depth += diags[i].invalid_depth;
		total_diag.clock_errors += diags[i].clock_errors;
	}
	printf("\nPage-fault handler metrics: handle_mm_fault (%s)\n",
	       bpf->fallback ? bpf->definition->fallback_backend : bpf->definition->primary_backend);
	puts("Counts are function calls, NOT page-fault exceptions or perf minor/major counters.");
	puts("Latency includes in-function IO/sleep/scheduling waits; retries are not merged.");
	puts("All includes every paired call. Major/retry/error categories overlap; do not sum them.");
	puts("VM_FAULT_ERROR includes huge-page FALLBACK, not just fatal errors.");
	if (bpf->fallback)
		puts("kretprobe instance limits/recursion can miss returns and affect pairing; zero map errors does not prove losslessness.");
	printf("  observed entries:  %" PRIu64 " (%.3f /s)\n", total_diag.entries,
	       seconds > 0 ? total_diag.entries / seconds : 0);
	printf("  observed returns:  %" PRIu64 "\n", total_diag.returns);
	printf("  unmatched returns: %" PRIu64 " (includes start-window boundary)\n", total_diag.unmatched_returns);
	printf("  stack overflows:   %" PRIu64 "\n", total_diag.overflows);
	printf("  pending map errors:%" PRIu64 "\n", total_diag.pending_errors);
	printf("  thread map errors: %" PRIu64 "\n", total_diag.thread_errors);
	printf("  cancelled on exit: %" PRIu64 "\n", total_diag.cancelled);
	printf("  invalid depth:     %" PRIu64 "\n", total_diag.invalid_depth);
	printf("  clock errors:      %" PRIu64 "\n", total_diag.clock_errors);
	if (report_unfinished(pending_fd))
		goto out;
	for (sd_u32 kind = 0; kind < FAULT_KINDS; kind++) {
		struct fault_stats total = {0};

		if (bpf_map_lookup_elem(stats_fd, &kind, values)) {
			perror("read fault latency statistics");
			goto out;
		}
		for (int cpu = 0; cpu < cpus; cpu++)
			fault_merge_stats(&total, &values[cpu]);
		printf("\n%s\n  samples: %" PRIu64 "\n", names[kind], total.count);
		printf("  total elapsed: %.3f ms\n", total.total_ns / 1e6);
		if (!total.count) {
			puts("  No complete samples observed.");
			continue;
		}
		printf("  average: %.3f us\n  maximum: %.3f us\n",
		       (double)total.total_ns / total.count / 1e3, total.max_ns / 1e3);
		puts("  histogram (microseconds, upper bound exclusive):");
		for (int bucket = 0; bucket < SD_BUCKETS; bucket++) {
			sd_u64 low = bucket ? (1ULL << bucket) : 0;

			if (!total.histogram[bucket])
				continue;
			if (bucket == SD_BUCKETS - 1)
				printf("    [%" PRIu64 ", infinity): %" PRIu64 "\n", low, total.histogram[bucket]);
			else
				printf("    [%" PRIu64 ", %" PRIu64 "): %" PRIu64 "\n",
				       low, (sd_u64)(1ULL << (bucket + 1)), total.histogram[bucket]);
		}
	}
	result = report_threads(threads_fd);
out:
	free(values);
	free(diags);
	return result;
}
