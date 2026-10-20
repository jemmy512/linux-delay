// SPDX-License-Identifier: GPL-2.0-only
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "sched_delay.h"
#include "metric_loader.h"
#include "sched_delay.bytes.h"
#include "irq_delay.bytes.h"
#include "fault_delay.bytes.h"

static volatile sig_atomic_t stopped;
static bool verbose;

/* Add future metrics here, with a separate object and report callback. */
static const struct metric_definition metrics[] = {
	{
		.name = "sched", .description = "Scheduling/runqueue delay (default)",
		.object_bytes = sched_delay_bpf_bytes, .object_size = sizeof(sched_delay_bpf_bytes),
		.task_filters = true, .kernel_btf = true, .report = report_sched,
	},
	{
		.name = "irq", .description = "Hard IRQ/softirq duration and entry frequency",
		.object_bytes = irq_delay_bpf_bytes, .object_size = sizeof(irq_delay_bpf_bytes),
		.task_filters = false, .report = report_irq,
	},
	{
		.name = "fault", .description = "Page-fault handler latency and call/return counts",
		.object_bytes = fault_delay_bpf_bytes, .object_size = sizeof(fault_delay_bpf_bytes),
		.task_filters = true, .report = report_fault, .configure = configure_fault,
		.primary_backend = "fentry/fexit", .fallback_backend = "kprobe/kretprobe",
	},
};

static const struct metric_definition *find_metric(const char *name)
{
	for (size_t i = 0; i < sizeof(metrics) / sizeof(metrics[0]); i++)
		if (strcmp(name, metrics[i].name) == 0)
			return &metrics[i];
	return NULL;
}

static void stop_handler(int signo)
{
	(void)signo;
	stopped = 1;
}

static int libbpf_log(enum libbpf_print_level level, const char *fmt, va_list ap)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, fmt, ap);
}

static int now_ns(sd_u64 *value)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts)) {
		perror("clock_gettime");
		return -1;
	}
	*value = (sd_u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
	return 0;
}

/* Link closure prevents new attachment dispatch, but callbacks may be in flight.
 * Config has already expired/been disabled, and every callback increments active
 * before looking it up. Drain all pre-cutoff writers before reading statistics.
 */
static int wait_for_writers(struct metric_bpf *bpf)
{
	int cpus = libbpf_num_possible_cpus();
	int fd = metric_map_fd(bpf, "active");
	sd_u32 zero = 0;
	sd_u64 *active, start, now;
	int result = -1;

	if (cpus <= 0 || fd < 0 || now_ns(&start))
		return -1;
	active = calloc((size_t)cpus, sizeof(*active));
	if (!active) {
		perror("allocate writer counters");
		return -1;
	}
	for (;;) {
		bool busy = false;
		struct timespec pause = {.tv_nsec = 1000000};

		if (bpf_map_lookup_elem(fd, &zero, active)) {
			perror("read writer counters");
			break;
		}
		for (int cpu = 0; cpu < cpus; cpu++)
			busy |= active[cpu] != 0;
		if (!busy) {
			result = 0;
			break;
		}
		if (now_ns(&now))
			break;
		if (now - start >= 3000000000ULL) {
			fprintf(stderr, "Timed out draining BPF writers; refusing an inconsistent report\n");
			break;
		}
		if (nanosleep(&pause, NULL) && errno != EINTR) {
			perror("wait for BPF writers");
			break;
		}
	}
	free(active);
	return result;
}

static int parse_number(const char *arg, unsigned long max, sd_u32 *value)
{
	char *end;
	unsigned long n;

	if (*arg < '0' || *arg > '9')
		return -1;
	errno = 0;
	n = strtoul(arg, &end, 10);
	if (errno || *end || n > max)
		return -1;
	*value = (sd_u32)n;
	return 0;
}

static void usage(FILE *out, const char *name)
{
	fprintf(out,
		"Usage: %s [-m METRIC] [-p TGID] [-t TID] [-d SECONDS] [-v]\n"
		"  -m, --metric  Select one metric; only its probes are loaded/attached\n"
		"  -p  Process ID; includes all its threads (sched/fault, 0: all)\n"
		"  -t  Thread ID (sched/fault, 0: all); combines with -p if provided\n"
		"  -d  Collection duration, 1..86400 seconds (default: 10)\n"
		"  -v  Show libbpf debug/verifier diagnostics\n"
		"  -h  Show help\n"
		"Ctrl-C stops early. Requires Linux/Android BPF permissions.\n"
		"sched needs kernel BTF; irq uses no kernel structure reads.\n"
		"fault prefers fentry/fexit (BTF); falls back to kprobe/kretprobe.\n"
		"Metrics:\n",
		name);
	for (size_t i = 0; i < sizeof(metrics) / sizeof(metrics[0]); i++)
		fprintf(out, "  %-8s %s\n", metrics[i].name, metrics[i].description);
}

int main(int argc, char **argv)
{
	static const struct option options[] = {
		{"metric", required_argument, NULL, 'm'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0},
	};
	struct sd_config cfg = {0};
	struct metric_bpf *bpf = NULL;
	const struct metric_definition *metric = &metrics[0];
	struct sigaction action = {0};
	struct rlimit limit = {RLIM_INFINITY, RLIM_INFINITY};
	bool task_filter_given = false, metric_given = false;
	sd_u32 duration = 10, zero = 0;
	sd_u64 now;
	int option, err, config_fd, result = EXIT_FAILURE;

	while ((option = getopt_long(argc, argv, "m:p:t:d:vh", options, NULL)) != -1) {
		switch (option) {
		case 'm':
			metric = find_metric(optarg);
			if (!metric || metric_given) {
				fprintf(stderr, "Unknown or repeated metric selection; choose one from the list below\n");
				goto invalid;
			}
			metric_given = true;
			break;
		case 'p':
			task_filter_given = true;
			if (parse_number(optarg, 0x7fffffffUL, &cfg.tgid))
				goto invalid;
			break;
		case 't':
			task_filter_given = true;
			if (parse_number(optarg, 0x7fffffffUL, &cfg.tid))
				goto invalid;
			break;
		case 'd':
			if (parse_number(optarg, 86400, &duration) || !duration)
				goto invalid;
			break;
		case 'v': verbose = true; break;
		case 'h': usage(stdout, argv[0]); return EXIT_SUCCESS;
		default: goto invalid;
		}
	}
	if (optind != argc)
		goto invalid;
	if (!metric->task_filters && task_filter_given) {
		fprintf(stderr, "Metric '%s' is system-wide: -p/-t are not supported\n", metric->name);
		goto invalid;
	}

	action.sa_handler = stop_handler;
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL)) {
		perror("sigaction");
		return EXIT_FAILURE;
	}
	libbpf_set_print(libbpf_log);
	/* Older kernels account BPF maps against RLIMIT_MEMLOCK. */
	if (setrlimit(RLIMIT_MEMLOCK, &limit) && verbose)
		perror("raise memlock limit (may be unnecessary)");

	/* Only the selected metric's object/maps/probes are opened and loaded. */
	bpf = metric_bpf_open(metric);
	if (!bpf) {
		fprintf(stderr, "BPF load failed for '%s'. Check permissions, SELinux, "
			"memlock, kernel support%s; retry with -v.\n", metric->name,
			metric->kernel_btf ? " and kernel BTF" : "");
		goto out;
	}
	err = metric_bpf_attach(bpf);
	if (err) {
		fprintf(stderr, "Attach '%s' probes: %s (%d)\n",
			metric->name, strerror(-err), err);
		goto out;
	}
	/* Attachment fallback can reopen the object: fetch FDs only afterward. */
	config_fd = metric_map_fd(bpf, "config");
	if (config_fd < 0)
		goto out;
	/* Publish before a future start so entry-rate denominators have no blind
	 * activation interval. Refuse to report if arming was delayed too long.
	 */
	if (now_ns(&cfg.start_ns))
		goto out;
	cfg.start_ns += 100000000ULL;
	cfg.end_ns = cfg.start_ns + (sd_u64)duration * 1000000000ULL;
	if (bpf_map_update_elem(config_fd, &zero, &cfg, BPF_ANY)) {
		perror("start collection");
		goto out;
	}
	if (now_ns(&now))
		goto out;
	if (now >= cfg.start_ns) {
		fprintf(stderr, "Missed collection arming deadline; retry on a less busy system\n");
		goto out;
	}
	printf("Collecting for %u s (metric=%s, TGID=%u, TID=%u; 0=all). Ctrl-C stops early.\n",
	       duration, metric->name, cfg.tgid, cfg.tid);
	fflush(stdout);

	for (;;) {
		struct timespec pause;
		sd_u64 remaining;

		if (now_ns(&now))
			goto out;
		if (stopped || now >= cfg.end_ns)
			break;
		remaining = cfg.end_ns - now;
		pause.tv_sec = 0;
		pause.tv_nsec = remaining > 100000000 ? 100000000 : (long)remaining;
		if (nanosleep(&pause, NULL) && errno != EINTR) {
			perror("nanosleep");
			goto out;
		}
	}
	/* Fixed-duration cutoff is enforced in BPF, regardless of polling jitter.
	 * On early interruption, disabling collection defines a best-effort cutoff.
	 */
	if (now < cfg.end_ns) {
		cfg.end_ns = now < cfg.start_ns ? cfg.start_ns : now;
		if (bpf_map_update_elem(config_fd, &zero, &cfg, BPF_ANY)) {
			perror("stop collection");
			goto out;
		}
	}
	metric_bpf_detach(bpf);
	if (wait_for_writers(bpf))
		goto out;
	printf("Collection window: %.6f s\n", (cfg.end_ns - cfg.start_ns) / 1e9);
	if (!metric->report(bpf, (cfg.end_ns - cfg.start_ns) / 1e9)) {
		if (fflush(stdout) == EOF)
			perror("stdout");
		else
			result = EXIT_SUCCESS;
	}
out:
	metric_bpf_destroy(bpf);
	return result;
invalid:
	usage(stderr, argv[0]);
	return EXIT_FAILURE;
}
