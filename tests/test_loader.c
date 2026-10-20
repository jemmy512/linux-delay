// SPDX-License-Identifier: GPL-2.0-only
/* Mocked userspace lifecycle only: no BPF parsing, verification or tracing. */
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "metric_loader.h"

#define FAKE_PROGRAMS (METRIC_MAX_LINKS + 1)
#define ATTEMPTS 2

struct bpf_map {
	int fd;
};

struct bpf_program {
	struct bpf_object *object;
	size_t index;
	bool autoload;
	const char *name;
	const char *section;
};

struct bpf_object {
	unsigned int id;
	bool loaded;
	size_t program_count;
	size_t live_links;
	struct bpf_map config;
	struct bpf_program programs[FAKE_PROGRAMS];
};

struct bpf_link {
	struct bpf_object *object;
};

enum failure {
	SUCCEED,
	ERROR_POINTER,
	NULL_WITH_ERRNO,
	NULL_WITHOUT_ERRNO,
};

static struct {
	size_t program_count;
	enum failure open_failure[ATTEMPTS];
	int configure_error[ATTEMPTS];
	int load_error[ATTEMPTS];
	size_t fail_attach_at[ATTEMPTS];
	enum failure attach_failure[ATTEMPTS];
	bool disable_all;
	unsigned int opens, created, closed, loads, configurations;
	unsigned int links_created, links_destroyed;
	unsigned int live_objects, live_maps, live_links;
	bool configured_fallback[ATTEMPTS];
	unsigned int configured_id[ATTEMPTS];
	size_t attach_calls[ATTEMPTS];
	unsigned int attached[ATTEMPTS][FAKE_PROGRAMS];
	char trace[256];
	size_t trace_length;
} fake;

/* Deliberately not an ELF object: the fake API checks identity, not contents. */
static const unsigned char object_bytes[] = {0x12, 0x34};

static void event(char kind)
{
	assert(fake.trace_length + 1 < sizeof(fake.trace));
	fake.trace[fake.trace_length++] = kind;
	fake.trace[fake.trace_length] = '\0';
}

static void *fail_pointer(enum failure mode)
{
	switch (mode) {
	case ERROR_POINTER:
		return (void *)(intptr_t)-EACCES;
	case NULL_WITH_ERRNO:
		errno = EACCES;
		return NULL;
	case NULL_WITHOUT_ERRNO:
		errno = 0;
		return NULL;
	case SUCCEED:
		break;
	}
	assert(!"failure mode required");
	return NULL;
}

long libbpf_get_error(const void *ptr)
{
	if (!ptr)
		return -errno;
	if ((uintptr_t)ptr >= (uintptr_t)-4095)
		return (long)(intptr_t)ptr;
	return 0;
}

struct bpf_object *bpf_object__open_mem(const void *bytes, size_t size,
				      const struct bpf_object_open_opts *opts)
{
	static const char *const names[] = {
		"primary_entry", "primary_exit", "secondary_entry",
		"secondary_exit", "cleanup",
	};
	static const char *const sections[] = {
		"fentry/fake", "fexit/fake", "kprobe/fake",
		"kretprobe/fake", "tracepoint/sched/sched_process_exit",
	};
	struct bpf_object *obj;
	unsigned int id = fake.opens++;

	assert(bytes == object_bytes && size == sizeof(object_bytes));
	assert(!opts && id < ATTEMPTS);
	/* A retry must detach and close the previous object before reopening. */
	assert(!fake.live_objects && !fake.live_maps && !fake.live_links);
	event('O');
	if (fake.open_failure[id] != SUCCEED)
		return fail_pointer(fake.open_failure[id]);
	obj = calloc(1, sizeof(*obj));
	assert(obj);
	obj->id = id;
	obj->config.fd = -1;
	assert(fake.program_count <= FAKE_PROGRAMS);
	obj->program_count = fake.program_count;
	for (size_t i = 0; i < obj->program_count; i++) {
		obj->programs[i] = (struct bpf_program) {
			.object = obj,
			.index = i,
			.autoload = true,
			.name = i < sizeof(names) / sizeof(names[0]) ? names[i] : "extra",
			.section = i < sizeof(sections) / sizeof(sections[0]) ?
				sections[i] : "tracepoint/fake/extra",
		};
	}
	fake.created++;
	fake.live_objects++;
	fake.live_maps++;
	return obj;
}

int bpf_object__load(struct bpf_object *obj)
{
	assert(obj && !libbpf_get_error(obj) && !obj->loaded);
	assert(obj->id < ATTEMPTS);
	event('L');
	fake.loads++;
	if (fake.load_error[obj->id])
		return fake.load_error[obj->id];
	obj->loaded = true;
	/* Unique synthetic FDs expose stale map references after a retry. */
	obj->config.fd = 100 + (int)obj->id;
	return 0;
}

void bpf_object__close(struct bpf_object *obj)
{
	if (!obj)
		return;
	assert(!libbpf_get_error(obj));
	assert(!obj->live_links && !fake.live_links);
	assert(fake.live_objects && fake.live_maps);
	event('X');
	fake.closed++;
	fake.live_objects--;
	fake.live_maps--;
	free(obj);
}

struct bpf_program *bpf_object__next_program(const struct bpf_object *obj,
					   struct bpf_program *prev)
{
	size_t next = 0;

	assert(obj);
	if (prev) {
		assert(prev->object == obj && prev->index < obj->program_count);
		next = prev->index + 1;
	}
	if (next >= obj->program_count)
		return NULL;
	return (struct bpf_program *)&obj->programs[next];
}

bool bpf_program__autoload(const struct bpf_program *prog)
{
	assert(prog);
	return prog->autoload;
}

int bpf_program__set_autoload(struct bpf_program *prog, bool autoload)
{
	assert(prog && !prog->object->loaded);
	prog->autoload = autoload;
	return 0;
}

const char *bpf_program__name(const struct bpf_program *prog)
{
	assert(prog);
	return prog->name;
}

const char *bpf_program__section_name(const struct bpf_program *prog)
{
	assert(prog);
	return prog->section;
}

struct bpf_link *bpf_program__attach(const struct bpf_program *prog)
{
	struct bpf_link *link;
	unsigned int id;

	assert(prog && prog->object->loaded && prog->autoload);
	id = prog->object->id;
	assert(id < ATTEMPTS && prog->index < FAKE_PROGRAMS);
	event('A');
	fake.attach_calls[id]++;
	if (fake.attach_calls[id] == fake.fail_attach_at[id])
		return fail_pointer(fake.attach_failure[id]);
	link = calloc(1, sizeof(*link));
	assert(link);
	link->object = prog->object;
	link->object->live_links++;
	fake.attached[id][prog->index]++;
	fake.live_links++;
	fake.links_created++;
	return link;
}

int bpf_link__destroy(struct bpf_link *link)
{
	if (!link)
		return 0;
	assert(!libbpf_get_error(link));
	assert(link->object->live_links && fake.live_links);
	event('D');
	link->object->live_links--;
	fake.live_links--;
	fake.links_destroyed++;
	free(link);
	return 0;
}

struct bpf_map *bpf_object__find_map_by_name(const struct bpf_object *obj,
					 const char *name)
{
	assert(obj && name);
	return strcmp(name, "config") == 0 ? (struct bpf_map *)&obj->config : NULL;
}

int bpf_map__fd(const struct bpf_map *map)
{
	assert(map);
	return map->fd;
}

static int configure(struct bpf_object *obj, bool fallback)
{
	struct bpf_program *prog;
	unsigned int call = fake.configurations++;

	assert(obj && !obj->loaded && call < ATTEMPTS);
	assert(obj->id < ATTEMPTS);
	event('C');
	fake.configured_fallback[call] = fallback;
	fake.configured_id[call] = obj->id;
	bpf_object__for_each_program(prog, obj) {
		const char *name = bpf_program__name(prog);
		bool enabled = strcmp(name, "cleanup") == 0 ||
			strcmp(name, fallback ? "secondary_entry" : "primary_entry") == 0 ||
			strcmp(name, fallback ? "secondary_exit" : "primary_exit") == 0;

		assert(bpf_program__set_autoload(prog, enabled && !fake.disable_all) == 0);
	}
	return fake.configure_error[obj->id];
}

static const struct metric_definition default_metric = {
	.name = "defaultmetric",
	.object_bytes = object_bytes,
	.object_size = sizeof(object_bytes),
};

static const struct metric_definition configured_metric = {
	.name = "configuredmetric",
	.object_bytes = object_bytes,
	.object_size = sizeof(object_bytes),
	.configure = configure,
	.primary_backend = "primary",
	.fallback_backend = "secondary",
};

static void no_leaks(void)
{
	assert(!fake.live_objects && !fake.live_maps && !fake.live_links);
	assert(fake.created == fake.closed);
	assert(fake.links_created == fake.links_destroyed);
}

static void reset(void)
{
	no_leaks();
	memset(&fake, 0, sizeof(fake));
	fake.program_count = 5;
	errno = 0;
}

static void finish(struct metric_bpf *bpf, const char *trace)
{
	metric_bpf_destroy(bpf);
	no_leaks();
	if (trace)
		assert(strcmp(fake.trace, trace) == 0);
}

static void check_backend(struct metric_bpf *bpf, bool fallback)
{
	unsigned int id;

	assert(bpf && bpf->fallback == fallback);
	id = bpf->object->id;
	assert(id < ATTEMPTS);
	assert(fake.attach_calls[id] == 3 && fake.live_links == 3);
	assert(fake.attached[id][0] == (unsigned int)!fallback);
	assert(fake.attached[id][1] == (unsigned int)!fallback);
	assert(fake.attached[id][2] == (unsigned int)fallback);
	assert(fake.attached[id][3] == (unsigned int)fallback);
	assert(fake.attached[id][4] == 1);
	for (size_t i = 0; i < METRIC_MAX_LINKS; i++)
		assert((bpf->links[i] != NULL) == (i < 3));
}

static void check_retry(void)
{
	assert(fake.opens == 2 && fake.configurations == 2);
	assert(!fake.configured_fallback[0] && fake.configured_fallback[1]);
	assert(fake.configured_id[0] != fake.configured_id[1]);
}

static void test_default_metric(void)
{
	struct metric_bpf *bpf;

	reset();
	bpf = metric_bpf_open(&default_metric);
	assert(bpf && bpf->definition == &default_metric && !bpf->fallback);
	assert(!fake.configurations);
	assert(metric_map_fd(bpf, "config") == 100);
	assert(metric_map_fd(bpf, "missing") == -1 && errno == ENOENT);
	assert(metric_bpf_attach(bpf) == 0);
	assert(fake.live_links == 5 && fake.attach_calls[0] == 5);
	for (size_t i = 0; i < 5; i++)
		assert(fake.attached[0][i] == 1);
	finish(bpf, "OLAAAAADDDDDX");
}

static void test_primary_success_and_disabled_programs(void)
{
	struct metric_bpf *bpf;

	reset();
	bpf = metric_bpf_open(&configured_metric);
	assert(bpf && fake.configurations == 1 && !fake.configured_fallback[0]);
	assert(metric_bpf_attach(bpf) == 0);
	check_backend(bpf, false);
	metric_bpf_detach(bpf);
	assert(!fake.live_links && fake.live_objects == 1);
	for (size_t i = 0; i < METRIC_MAX_LINKS; i++)
		assert(!bpf->links[i]);
	metric_bpf_detach(bpf); /* Idempotent and safe before destruction. */
	finish(bpf, "OCLAAADDDX");
}

static void test_open_fallbacks(void)
{
	for (int configure_fails = 0; configure_fails < 2; configure_fails++) {
		struct metric_bpf *bpf;

		reset();
		if (configure_fails)
			fake.configure_error[0] = -ENOTSUP;
		else
			fake.load_error[0] = -EINVAL;
		bpf = metric_bpf_open(&configured_metric);
		assert(bpf && bpf->fallback && fake.closed == 1);
		check_retry();
		assert(fake.loads == (configure_fails ? 1U : 2U));
		assert(metric_map_fd(bpf, "config") == 101);
		assert(metric_bpf_attach(bpf) == 0);
		check_backend(bpf, true);
		finish(bpf, configure_fails ? "OCXOCLAAADDDX" : "OCLXOCLAAADDDX");
	}
}

static void fail_second_attach(unsigned int id, enum failure mode)
{
	assert(id < ATTEMPTS);
	fake.fail_attach_at[id] = 2;
	fake.attach_failure[id] = mode;
}

static void test_partial_attach_fallback(void)
{
	for (enum failure mode = ERROR_POINTER; mode <= NULL_WITHOUT_ERRNO; mode++) {
		struct metric_bpf *bpf;
		int old_fd;

		reset();
		fail_second_attach(0, mode);
		bpf = metric_bpf_open(&configured_metric);
		assert(bpf);
		old_fd = metric_map_fd(bpf, "config");
		assert(metric_bpf_attach(bpf) == 0);
		check_retry();
		check_backend(bpf, true);
		assert(fake.closed == 1 && fake.links_destroyed == 1);
		assert(fake.attached[0][0] == 1 && fake.attached[0][1] == 0);
		assert(metric_map_fd(bpf, "config") != old_fd);
		finish(bpf, "OCLAADXOCLAAADDDX");
	}
}

static void test_fallback_load_failure(void)
{
	struct metric_bpf *bpf;

	reset();
	fake.load_error[0] = -EINVAL;
	fake.load_error[1] = -ENOMEM;
	bpf = metric_bpf_open(&configured_metric);
	assert(!bpf);
	check_retry();
	finish(bpf, "OCLXOCLX");

	reset();
	fail_second_attach(0, ERROR_POINTER);
	fake.load_error[1] = -ENOMEM;
	bpf = metric_bpf_open(&configured_metric);
	assert(bpf);
	assert(metric_bpf_attach(bpf) == -ENOMEM);
	assert(bpf->fallback && !bpf->object);
	check_retry();
	finish(bpf, "OCLAADXOCLX");
}

static void test_fallback_attach_failure(void)
{
	for (int primary_attach_fails = 0; primary_attach_fails < 2; primary_attach_fails++) {
		struct metric_bpf *bpf;

		reset();
		if (primary_attach_fails)
			fail_second_attach(0, ERROR_POINTER);
		else
			fake.load_error[0] = -EINVAL;
		fail_second_attach(1, ERROR_POINTER);
		bpf = metric_bpf_open(&configured_metric);
		assert(bpf);
		assert(metric_bpf_attach(bpf) == -EACCES);
		assert(bpf->fallback && !fake.live_links);
		assert(fake.live_objects == 1);
		check_retry(); /* No third attempt, including when already on fallback. */
		for (size_t i = 0; i < METRIC_MAX_LINKS; i++)
			assert(!bpf->links[i]);
		finish(bpf, primary_attach_fails ? "OCLAADXOCLAADX" : "OCLXOCLAADX");
	}
}

static void test_open_errors(void)
{
	for (enum failure mode = ERROR_POINTER; mode <= NULL_WITHOUT_ERRNO; mode++) {
		struct metric_bpf direct = {.definition = &default_metric};
		struct metric_bpf *bpf;

		reset();
		fake.open_failure[0] = mode;
		assert(metric_bpf_load_backend(&direct, false) ==
		       (mode == NULL_WITHOUT_ERRNO ? -EINVAL : -EACCES));
		assert(!direct.object);
		no_leaks();

		reset();
		fake.open_failure[0] = mode;
		bpf = metric_bpf_open(&default_metric);
		assert(!bpf && fake.opens == 1);
		finish(bpf, "O");

		reset();
		fake.open_failure[0] = mode;
		bpf = metric_bpf_open(&configured_metric);
		assert(bpf && bpf->fallback);
		assert(fake.opens == 2 && fake.configurations == 1);
		assert(fake.configured_fallback[0]);
		assert(metric_bpf_attach(bpf) == 0);
		check_backend(bpf, true);
		finish(bpf, "OOCLAAADDDX");
	}
}

static void test_no_fallback(void)
{
	for (enum failure mode = ERROR_POINTER; mode <= NULL_WITHOUT_ERRNO; mode++) {
		struct metric_bpf *bpf;

		reset();
		fail_second_attach(0, mode);
		bpf = metric_bpf_open(&default_metric);
		assert(bpf);
		assert(metric_bpf_attach(bpf) ==
		       (mode == NULL_WITHOUT_ERRNO ? -EINVAL : -EACCES));
		assert(fake.opens == 1 && !fake.live_links);
		finish(bpf, "OLAADX");
	}

	reset();
	fake.load_error[0] = -EINVAL;
	assert(!metric_bpf_open(&default_metric));
	finish(NULL, "OLX");

	/* A configure callback alone must not opt into a fallback. */
	struct metric_definition no_secondary = configured_metric;
	no_secondary.fallback_backend = NULL;
	reset();
	fake.configure_error[0] = -ENOTSUP;
	assert(!metric_bpf_open(&no_secondary));
	assert(fake.opens == 1);
	finish(NULL, "OCX");
}

static void test_link_bounds_and_empty_selection(void)
{
	struct metric_bpf *bpf;

	for (size_t count = METRIC_MAX_LINKS; count <= FAKE_PROGRAMS; count++) {
		reset();
		fake.program_count = count;
		bpf = metric_bpf_open(&default_metric);
		assert(bpf);
		assert(metric_bpf_attach(bpf) == (count == METRIC_MAX_LINKS ? 0 : -E2BIG));
		assert(fake.attach_calls[0] == METRIC_MAX_LINKS);
		assert(fake.live_links == (count == METRIC_MAX_LINKS ? METRIC_MAX_LINKS : 0));
		assert(fake.attached[0][METRIC_MAX_LINKS] == 0);
		if (count > METRIC_MAX_LINKS) {
			for (size_t i = 0; i < METRIC_MAX_LINKS; i++)
				assert(!bpf->links[i]);
		}
		finish(bpf, NULL);
	}

	reset();
	fake.disable_all = true;
	bpf = metric_bpf_open(&configured_metric);
	assert(bpf);
	assert(metric_bpf_attach(bpf) == -ENOENT);
	check_retry();
	assert(!fake.attach_calls[0] && !fake.attach_calls[1]);
	finish(bpf, "OCLXOCLX");

	reset();
	fake.program_count = 0;
	bpf = metric_bpf_open(&default_metric);
	assert(bpf && metric_bpf_attach(bpf) == -ENOENT);
	finish(bpf, "OLX");
}

int main(void)
{
	metric_bpf_detach(NULL);
	metric_bpf_destroy(NULL);
	bpf_object__close(NULL);
	assert(bpf_link__destroy(NULL) == 0);
	test_default_metric();
	test_primary_success_and_disabled_programs();
	test_open_fallbacks();
	test_partial_attach_fallback();
	test_fallback_load_failure();
	test_fallback_attach_failure();
	test_open_errors();
	test_no_fallback();
	test_link_bounds_and_empty_selection();
	no_leaks();
	puts("PASS: mocked metric_loader lifecycle, fallback, link bounds and cleanup");
	puts("Mocked lifecycle only; not runtime fault-tracing tests.");
	return 0;
}
