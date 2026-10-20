/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef METRIC_LOADER_H
#define METRIC_LOADER_H

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

#define METRIC_MAX_LINKS 16

struct metric_definition;

struct metric_bpf {
	struct bpf_object *object;
	struct bpf_link *links[METRIC_MAX_LINKS];
	const struct metric_definition *definition;
	bool fallback;
};

/* One registry entry per independently embedded BPF object/report backend. */
struct metric_definition {
	const char *name;
	const char *description;
	const unsigned char *object_bytes;
	size_t object_size;
	bool task_filters;
	bool kernel_btf;
	int (*report)(struct metric_bpf *, double seconds);
	/* Optional backend selection before load; only one probe pair autoloads. */
	int (*configure)(struct bpf_object *, bool fallback);
	const char *primary_backend;
	const char *fallback_backend;
};

static inline int metric_map_fd(struct metric_bpf *bpf, const char *name)
{
	struct bpf_map *map = bpf_object__find_map_by_name(bpf->object, name);

	if (!map) {
		fprintf(stderr, "Metric map not found: %s\n", name);
		errno = ENOENT;
		return -1;
	}
	return bpf_map__fd(map);
}

static inline void metric_bpf_detach(struct metric_bpf *bpf)
{
	if (!bpf)
		return;
	for (size_t i = 0; i < METRIC_MAX_LINKS; i++) {
		bpf_link__destroy(bpf->links[i]);
		bpf->links[i] = NULL;
	}
}

static inline void metric_bpf_destroy(struct metric_bpf *bpf)
{
	if (!bpf)
		return;
	metric_bpf_detach(bpf);
	bpf_object__close(bpf->object);
	free(bpf);
}

static inline int metric_bpf_load_backend(struct metric_bpf *bpf, bool fallback)
{
	const struct metric_definition *metric = bpf->definition;
	struct bpf_object *object;
	int err;

	bpf->fallback = fallback;
	object = bpf_object__open_mem(metric->object_bytes, metric->object_size, NULL);
	if (!object)
		return errno ? -errno : -EINVAL;
	err = (int)libbpf_get_error(object);
	if (err)
		return err;
	if (metric->configure) {
		err = metric->configure(object, fallback);
		if (err)
			goto fail;
	}
	err = bpf_object__load(object);
	if (err)
		goto fail;
	bpf->object = object;
	return 0;
fail:
	bpf_object__close(object);
	return err;
}

static inline void metric_fallback_notice(struct metric_bpf *bpf, int err)
{
	fprintf(stderr, "%s: %s unavailable (%d); trying %s\n",
		bpf->definition->name, bpf->definition->primary_backend,
		err, bpf->definition->fallback_backend);
}

static inline struct metric_bpf *metric_bpf_open(const struct metric_definition *metric)
{
	struct metric_bpf *bpf = calloc(1, sizeof(*bpf));
	int err;

	if (!bpf)
		return NULL;
	bpf->definition = metric;
	err = metric_bpf_load_backend(bpf, false);
	if (err && metric->configure && metric->fallback_backend) {
		metric_fallback_notice(bpf, err);
		err = metric_bpf_load_backend(bpf, true);
	}
	if (err) {
		metric_bpf_destroy(bpf);
		return NULL;
	}
	return bpf;
}

static inline int metric_bpf_attach_once(struct metric_bpf *bpf)
{
	struct bpf_program *program;
	size_t index = 0;

	bpf_object__for_each_program(program, bpf->object) {
		struct bpf_link *link;
		int err;

		if (!bpf_program__autoload(program))
			continue;
		if (index == METRIC_MAX_LINKS) {
			metric_bpf_detach(bpf);
			return -E2BIG;
		}
		link = bpf_program__attach(program);
		err = link ? (int)libbpf_get_error(link) : -errno;
		if (err || !link) {
			fprintf(stderr, "Cannot attach %s (%s)\n",
				bpf_program__name(program), bpf_program__section_name(program));
			metric_bpf_detach(bpf);
			return err ? err : -EINVAL;
		}
		bpf->links[index++] = link;
	}
	return index ? 0 : -ENOENT;
}

static inline int metric_bpf_attach(struct metric_bpf *bpf)
{
	int err = metric_bpf_attach_once(bpf);

	if (err && !bpf->fallback && bpf->definition->configure &&
	    bpf->definition->fallback_backend) {
		metric_fallback_notice(bpf, err);
		metric_bpf_detach(bpf);
		bpf_object__close(bpf->object);
		bpf->object = NULL;
		err = metric_bpf_load_backend(bpf, true);
		if (!err)
			err = metric_bpf_attach_once(bpf);
	}
	return err;
}

int report_sched(struct metric_bpf *bpf, double seconds);
int report_irq(struct metric_bpf *bpf, double seconds);
int report_fault(struct metric_bpf *bpf, double seconds);
int configure_fault(struct bpf_object *object, bool fallback);
#endif
