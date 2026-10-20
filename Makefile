# SPDX-License-Identifier: GPL-2.0-only
.DEFAULT_GOAL := all
.DELETE_ON_ERROR:

CC ?= cc
HOSTCC ?= cc
CLANG ?= clang
PYTHON ?= python3
PKG_CONFIG ?= pkg-config
CFLAGS ?= -O2 -g
HOSTCFLAGS ?= -O2 -g
CPPFLAGS ?=
LDFLAGS ?=
LIBBPF_CFLAGS ?= $(shell $(PKG_CONFIG) --cflags libbpf 2>/dev/null)
LIBBPF_LIBS ?= $(shell $(PKG_CONFIG) --libs libbpf 2>/dev/null || echo -lbpf)
# BPF compilation uses HOST Linux headers, even when CC is the Android NDK.
BPF_CPPFLAGS ?= $(shell $(PKG_CONFIG) --cflags libbpf 2>/dev/null) -I/usr/include/$(shell $(HOSTCC) -dumpmachine)
BPF_TARGET ?= bpfel
TARGET_MACHINE := $(shell $(CC) -dumpmachine)
BPF_ARCH ?= $(if $(filter aarch64% arm64%,$(TARGET_MACHINE)),arm64,$(if $(filter x86_64%,$(TARGET_MACHINE)),x86,unsupported))
WARNINGS := -Wall -Wextra -Werror
METRICS := sched_delay irq_delay fault_delay
BPF_OBJECTS := $(addprefix build/,$(addsuffix .bpf.o,$(METRICS)))
BPF_HEADERS := $(addprefix build/,$(addsuffix .bytes.h,$(METRICS)))
USER_SOURCES := src/main.c src/sched_delay.c src/irq_report.c src/fault_report.c
HEADERS := $(wildcard include/*.h)

.PHONY: all android bpf test smoke clean help
all: build/sched-delay
android:
	$(PYTHON) scripts/build_android.py
bpf: $(BPF_OBJECTS) $(BPF_HEADERS)

build:
	mkdir -p $@

build/%.bpf.o: src/%.bpf.c $(HEADERS) | build
	$(CLANG) -target $(BPF_TARGET) -D__BPF__ -D__TARGET_ARCH_$(BPF_ARCH) -O2 -g $(WARNINGS) $(BPF_CPPFLAGS) -Iinclude -c $< -o $@

build/%.bytes.h: build/%.bpf.o scripts/embed_bpf.py
	$(PYTHON) scripts/embed_bpf.py $< $@ --symbol $*_bpf_bytes

build/sched-delay: $(USER_SOURCES) $(HEADERS) $(BPF_HEADERS)
	$(CC) -std=c11 $(CFLAGS) $(WARNINGS) $(CPPFLAGS) $(LIBBPF_CFLAGS) -Iinclude -Ibuild $(USER_SOURCES) $(LDFLAGS) $(LIBBPF_LIBS) -o $@

build/test_metrics: tests/test_metrics.c include/sched_delay.h | build
	$(HOSTCC) -std=c11 $(HOSTCFLAGS) $(WARNINGS) -Iinclude $< -o $@

build/test_irq: tests/test_irq.c include/irq_delay.h include/sched_delay.h include/cpu_list.h | build
	$(HOSTCC) -std=c11 $(HOSTCFLAGS) $(WARNINGS) -Iinclude $< -o $@

build/test_fault: tests/test_fault.c include/fault_delay.h include/sched_delay.h | build
	$(HOSTCC) -std=c11 $(HOSTCFLAGS) $(WARNINGS) -Iinclude $< -o $@

build/test_loader: tests/test_loader.c tests/mocks/bpf/libbpf.h include/metric_loader.h | build
	$(HOSTCC) -std=c11 $(HOSTCFLAGS) $(WARNINGS) -Itests/mocks -Iinclude $< -o $@

test: build/test_metrics build/test_irq build/test_fault build/test_loader
	./build/test_metrics
	./build/test_irq
	./build/test_fault
	./build/test_loader
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py'

# Run explicitly on a permitted Linux host; never escalates privileges itself.
smoke: all
	$(PYTHON) tests/smoke.py ./build/sched-delay
	$(PYTHON) tests/smoke_irq.py ./build/sched-delay
	$(PYTHON) tests/smoke_fault.py ./build/sched-delay

clean:
	rm -rf build

help:
	@echo 'make          Build Linux collector (clang BPF, Python, libbpf required)'
	@echo 'make android  Build standalone static ARM64 executable on macOS/Linux'
	@echo 'make test     Run portable metric tests (also works on macOS)'
	@echo 'make smoke    Run live Linux/BPF smoke test (requires BPF privileges)'
	@echo 'make bpf      Build BPF object and embedded data header only'
	@echo 'See README.md for Android deployment.'
