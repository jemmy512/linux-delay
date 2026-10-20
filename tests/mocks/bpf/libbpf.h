/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef TEST_MOCK_LIBBPF_H
#define TEST_MOCK_LIBBPF_H

/* Only the userspace API needed by metric_loader.h and its test callback. */
#include <stdbool.h>
#include <stddef.h>

struct bpf_object;
struct bpf_object_open_opts;
struct bpf_program;
struct bpf_map;
struct bpf_link;

struct bpf_object *bpf_object__open_mem(const void *obj_buf, size_t obj_buf_sz,
				      const struct bpf_object_open_opts *opts);
int bpf_object__load(struct bpf_object *obj);
void bpf_object__close(struct bpf_object *obj);
long libbpf_get_error(const void *ptr);
struct bpf_program *bpf_object__next_program(const struct bpf_object *obj,
					   struct bpf_program *prev);
#define bpf_object__for_each_program(pos, obj) \
	for ((pos) = bpf_object__next_program((obj), NULL); (pos); \
	     (pos) = bpf_object__next_program((obj), (pos)))
bool bpf_program__autoload(const struct bpf_program *prog);
int bpf_program__set_autoload(struct bpf_program *prog, bool autoload);
const char *bpf_program__name(const struct bpf_program *prog);
const char *bpf_program__section_name(const struct bpf_program *prog);
struct bpf_link *bpf_program__attach(const struct bpf_program *prog);
int bpf_link__destroy(struct bpf_link *link);
struct bpf_map *bpf_object__find_map_by_name(const struct bpf_object *obj,
					 const char *name);
int bpf_map__fd(const struct bpf_map *map);

#endif
