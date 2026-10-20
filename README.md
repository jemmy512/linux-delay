# sched-delay

A userspace-controlled **libbpf/eBPF** collector for Linux and Android: select scheduling latency (`sched`, the backward-compatible default), system-wide hard IRQ/softirq duration and entry frequency (`irq`), or `handle_mm_fault` function latency and call/return counts (`fault`). No kernel patch, module, custom Kconfig option, or `/proc/sched_delay` file is needed. All three BPF objects are independently embedded in one executable; only the selected object's maps and probes are loaded and attached. Stopping detaches them.

## Quickstart: standalone Android ARM64

Build directly on macOS or Linux; no Linux VM, NDK or Docker is needed:

````sh
make android
````

The host needs Clang with a BPF backend, GNU make, Python 3, curl and tar. On macOS, if dependencies are missing, install them yourself with `brew install llvm make python`. If Apple Clang is in `PATH`, select Homebrew LLVM explicitly:

````sh
BPF_CLANG="$(brew --prefix llvm)/bin/clang" make android
````

Deploy the single executable using `adb` (installed separately) to a rooted, permitted Android ARM64 device:

````sh
adb push build/android-arm64/sched-delay /data/local/tmp/sched-delay
adb shell su -c 'chmod 755 /data/local/tmp/sched-delay'
adb shell su -c '/data/local/tmp/sched-delay -d 10'
adb shell su -c '/data/local/tmp/sched-delay -m sched -p 1234 -d 10'
adb shell su -c '/data/local/tmp/sched-delay --metric irq -d 10'
adb shell su -c '/data/local/tmp/sched-delay -m fault -d 10'
adb shell su -c '/data/local/tmp/sched-delay -m fault -p 1234 -d 10'
````

Push the newly built binary before using `-m fault`; replace 1234 with the application process ID. This is a **static Linux/musl binary, not an NDK/Bionic build**. No runtime shared libraries or external `.bpf.o` are needed. All metrics require BPF permissions and SELinux access. `sched` requires accessible kernel BTF; `fault` prefers BTF-backed fentry/fexit but can fall back to kprobe/kretprobe without external kernel BTF. See [Requirements](#requirements).

### CLI

| Option | Meaning |
| --- | --- |
| `-m sched\|irq\|fault`, `--metric sched\|irq\|fault` | Select one metric; omitted means `sched`. Unknown or repeated selections fail, even if repeated with the same value. |
| `-p TGID` | `sched` and `fault`: all threads of a process, including new threads; 0 means unfiltered. |
| `-t TID` | `sched` and `fault`: one thread; 0 means unfiltered. Combines with `-p`. |
| `-d SECONDS` | Integer duration, 1–86400 seconds; default 10. |
| `-v` | libbpf debug/verifier diagnostics. |
| `-h`, `--help` | Help. |

IRQ rejects any `-p`/`-t`, **including explicit zero**. It is system-wide: an interrupt is not attributable to the current PID, and IRQ output has no process attribution.

## Measurements

### Scheduling (`-m sched`)

| Category | Start | End |
| --- | --- | --- |
| Wakeup delay | `sched_wakeup` or `sched_wakeup_new` | `sched_switch` selecting that thread |
| Runnable switch-out delay | `sched_switch` switching out a still-runnable thread | Next switch selecting that thread |

The second category includes voluntary yields as well as preemption. These are runnable waiting times, **not sleep duration, mutex blocking time, or context-switch execution cost**. The endpoint is the scheduler tracepoint, just before the actual context switch, not the first userspace instruction.

- `-p TGID` includes all threads of a process, including newly created threads. `-t TID` selects one thread. Specifying both applies both filters; zero means unfiltered.
- Subject-task IDs are read from tracepoint task pointers, not from the waking process.
- A global TID-keyed map preserves waits across CPU migrations; per-CPU maps aggregate completed samples.
- Wake-before-sleep can emit a wakeup for an already-executing task. Its stale start is discarded at that task's next switch-out, so continued execution or subsequent sleep is not counted as scheduling delay.
- Reported data: sample count, mean, maximum, log2 microsecond histogram, unfinished records, insert errors, duplicate starts and exit cancellations. Unfinished means unmatched start records; at the window boundary these can include wake-before-sleep candidates, not exclusively truly off-CPU tasks.
- Histogram bucket 0 is `[0, 2)` microseconds; subsequent buckets are `[2^n, 2^(n+1))`; the last bucket includes everything above its lower bound. Percentiles are not reported as exact values.
- Tasks already waiting at startup are not reconstructed. Unfinished waits at the end are reported separately, not truncated or included in the mean/maximum.
- The pending map holds 65,536 waits. Insert errors signal incomplete coverage; duplicate starts preserve the original timestamp. No per-event printing or ring-buffer streaming is used.

### IRQ (`-m irq`)

| Measurement | Raw tracepoints | Pairing |
| --- | --- | --- |
| Hard IRQ handler duration | `irq_handler_entry` → `irq_handler_exit` | IRQ ID and opaque action pointer (never dereferenced) |
| Softirq execution duration | `softirq_entry` → `softirq_exit` | Vector ID |

Reports separate global hard/soft entry counts and frequency (Hz), completed sample counts, total elapsed milliseconds, mean/max microseconds and log2 microsecond histograms (same buckets as `sched`). Per-CPU totals show entries, samples, Hz and elapsed time; per-CPU/IRQ-ID or vector rows also show average and maximum duration.

- **Not measured:** hardware interrupt delivery latency, softirq raise-to-execution pending delay, IRQ-disabled time, IPI coverage or separate threaded-handler execution. PREEMPT_RT and forced-threaded behavior have not been validated. Counts cover only events emitted by these tracepoints, not full threaded IRQ activity.
- Shared IRQ counts are **handler invocations, not hardware events**. Durations include nested/intervening interrupt time; do not add hard and soft totals as CPU utilization.
- The statistics map holds 4096 distinct `(CPU, kind, ID)` keys. Each CPU has separate hard/soft stacks of depth 8. Overflow depth consumes ignored exits before stored frames; pairing mismatches clear the affected stack and count discarded frames.
- Diagnostics include unfinished frames, stack overflows, unmatched exits (including start-window boundaries), pairing mismatches, discarded frames, map errors and missing statistics. Incomplete durations are not clipped or included in samples.
- Entries include unfinished and overflowing handlers. Global/per-CPU entry counters survive statistics-map insertion failures; consequently **mapped entries may differ**, and sample totals can be incomplete. Sparse possible-CPU map order is resolved through `include/cpu_list.h` using `/sys/devices/system/cpu/possible`.

### Fault handler (`-m fault`)

Measures **function invocations and paired returns of `handle_mm_fault`, not hardware page-fault exceptions**. Each retry invocation is counted separately; retries are not merged. Latency is elapsed wall time inside the function, including I/O, sleep and scheduling waits, but excluding outer architecture-specific exception handling. Neither exact perf minor/major fault counters nor complete architecture-level page-fault latency is implemented.

The preferred backend is `fentry/fexit`. Before loading it, runtime BTF validation requires exactly four parameters `(pointer, 64-bit integer, 32-bit integer, pointer)` and a 32-bit integer return. If primary backend configuration, loading or attachment fails, the loader cleans up partial links and the old object, then reopens a **fresh object and maps** for `kprobe/kretprobe`. Only one entry/return pair plus raw `sched_process_exit` cleanup is loaded at a time; the report names the chosen backend. This automatic fallback does not bypass kernel or permission requirements.

Five categories report paired sample counts, total elapsed milliseconds, average/maximum microseconds and log2 microsecond histograms (same buckets as `sched`):

| Category | Return-value classification |
| --- | --- |
| All paired calls | Every valid paired completion |
| Major-flagged | `VM_FAULT_MAJOR` (`0x4`) is set |
| Other: non-major without retry/error | No major, retry or error/fallback bits; **not exact minor faults** |
| Retry-flagged | `VM_FAULT_RETRY` (`0x400`) is set |
| Error/fallback-flagged | Any OOM, SIGBUS, SIGSEGV, HWPOISON, HWPOISON_LARGE or FALLBACK bit is set |

**Categories overlap:** All includes every other category, and major can overlap retry and error/fallback. Do not sum categories as independent counts or durations. The error mask includes `VM_FAULT_FALLBACK` (huge-page fallback), which is not necessarily fatal. Returns carrying other flags such as NOPAGE, LOCKED or DONE_COW, without major/retry/error bits, belong to Other, not an exact minor-fault category.

- Observed entry and return counters are independently gated by TGID/TID filters and `[start, end)`. They include observations that cannot become paired samples. `-p` and `-t` combine as for `sched`.
- A global `pid_tgid`-keyed map holds up to 65,536 pending thread stacks, preserving pairing across CPU migration. Each stack stores eight timestamps. Depth validation and an inline-assembly compiler barrier retain an explicit `index & 7` bounds mask for the verifier.
- Overflow nesting is tracked separately: overflowing returns unwind before stored frames, without overwriting them. Saturated overflow depth fails closed rather than consuming an outer frame. This balancing assumes the relevant entries/returns are observed.
- The 4096-entry thread statistics map counts completed paired returns, not all observed entries. Rows show TGID, TID, last observed comm, call count, major/retry/error/other counts, total time, average and maximum; rows are sorted by call count. A full thread map does not suppress global category histograms.
- Diagnostics report unmatched returns (including start-window boundaries), stack overflows, pending/thread map errors, calls cancelled on in-window thread exit, invalid depth, clock errors, unfinished calls/threads and invalid pending records. Calls crossing the end boundary remain unfinished; durations are not clipped into samples.
- **kretprobe instance limits and recursion can drop returns and affect pairing. Zero map errors does not prove losslessness.** Unfinished calls are not necessarily only boundary crossings, and diagnostics cannot reconstruct missed events.

### Collection window and overhead (all metrics)

Duration describes `[start, end)` on the same monotonic clock as `bpf_ktime_get_ns()`; both sample endpoints must be inside it. After attachment, start is armed 100 ms in the future. Configuration must be published and confirmed before start or the run fails. Ctrl-C/SIGTERM before start yields a zero-length window; early cutoff remains best-effort with a small control/update race.

The BPF gate expires/disables before detachment. `include/metric_bpf.h` counts active per-CPU writers atomically **before configuration lookup**, through their last metric-map write. After detaching, userspace drains these counters before taking a snapshot; a 3-second drain timeout fails rather than printing an inconsistent report.

Measurement overhead is included. Fault tracing adds entry/return probes, timestamp-stack operations and map aggregation to selected calls; fault-heavy workloads can incur appreciable overhead. No per-event streaming is used. Compare against an uninstrumented run; diagnostic counters cannot detect every unobserved event, and none of the metrics is a lossless recorder.

## Structure and adding metrics

- `src/main.c`: program entry point, CLI, metric registry/dispatch, shared window/drain control and cleanup orchestration.
- `src/sched_delay.c`: scheduler-specific pending-wait counting and reporting.
- `include/metric_loader.h`: generic object/map/probe loader and report interface, with optional pre-load `configure` callback for primary/fallback selection and fresh-object retry; replaces the removed `include/sched_delay_loader.h`. No generated bpftool skeleton is used.
- `src/sched_delay.bpf.c`, `include/sched_delay.h`: scheduler probes, shared configuration/ABI and histogram helpers.
- `src/irq_delay.bpf.c`, `src/irq_report.c`, `include/irq_delay.h`: independent IRQ probes, reporting and pairing/statistics helpers.
- `src/fault_delay.bpf.c`, `include/fault_delay.h`, `src/fault_report.c`: fault entry/return and exit-cleanup probes, stack/flag/statistics helpers, runtime BTF ABI validation, backend selection and reporting.
- `include/metric_bpf.h`, `include/cpu_list.h`: writer tracking and sparse CPU-ID parsing.
- `scripts/embed_bpf.py`, `scripts/build_android.py`, `scripts/verify_static_elf.py`: embedding, standalone build and ELF validation.

For a future metric, add a separate BPF object and report callback, then a registry entry in `src/main.c` declaring its task-filter/BTF requirements and optional backend configuration. Use the shared configuration/window and writer-tracking protocol. Add its object to Makefile `METRICS`, its report source to `USER_SOURCES`, and update `scripts/build_android.py`'s object/source lists and the embedded-header includes in `src/main.c`. Add portable and live tests; unselected metrics must remain unloaded/unattached.

## Requirements

Runtime target: **64-bit, little-endian Linux/Android 5.10+** (arm64 or x86-64), with BPF syscall/tracing support and the selected metric's probes:

- `sched`: raw `sched_wakeup`, `sched_wakeup_new`, `sched_switch`, `sched_process_exit`, plus accessible `/sys/kernel/btf/vmlinux`.
- `irq`: raw `irq_handler_entry`, `irq_handler_exit`, `softirq_entry`, `softirq_exit`, plus readable `/sys/devices/system/cpu/possible`. No kernel structure reads, CO-RE relocations or kernel BTF requirement.
- `fault`: raw `sched_process_exit` and a usable `handle_mm_fault` entry/return backend. Preferred fentry/fexit needs accessible kernel BTF with the verified four-argument ABI, kernel BPF trampolines and architecture/kernel ftrace support. The kprobe/kretprobe fallback needs `CONFIG_KPROBES`, `CONFIG_KPROBE_EVENTS`, a probeable `handle_mm_fault` and permission for perf/probe attachment; it requires no external kernel BTF or CO-RE relocations. Fallback can still fail if probes are unavailable or denied.

Typical relevant configurations include `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_EVENTS`, `CONFIG_TRACEPOINTS` and, for `sched` or fault fentry/fexit, `CONFIG_DEBUG_INFO_BTF`. Fault fentry/fexit also depends on the target's ftrace/dynamic-ftrace support. `CONFIG_SCHEDSTATS` and `CONFIG_SCHED_DELAY_METRICS` are **not required**.

Builds use libbpf 1.x and Clang with a BPF backend; the standalone Android build supplies its own target headers and libraries. Scheduler CO-RE uses a minimal task description, adapts older `state` and newer `__state` fields, and needs no generated `vmlinux.h`. Fault kretprobe return decoding uses a fixed target register layout: ARM64 `x0` (`pt_regs.regs[0]`) or x86-64 `pt_regs.ax` at byte offset 80. The Makefile derives `BPF_ARCH` from the userspace compiler target (`CC -dumpmachine`), not the build host; the standalone Android script explicitly forces arm64. The BPF architecture must match the runtime target. Vendor function/tracepoint semantics may need adaptation; kernel version alone is not a compatibility guarantee.

Root or appropriate BPF/perf privileges are required. Android SELinux may deny access even with root; use a permitted engineering/userdebug environment and targeted policy changes, not a normal unprivileged APK. The tool does not change system security policy. It only attempts to raise its own memlock limit for older kernels.

Run in the host's initial PID/time namespaces: filters use kernel/global task IDs, and deadlines assume an unshifted monotonic clock. Runtime execution inside a PID or offset time namespace is not supported. A container can still be used for building. The live smoke test also assumes initial namespaces.

## Standalone Android build details

`make android` runs `scripts/build_android.py` on macOS (Apple Silicon or Intel) or Linux (AArch64 or x86-64), always targeting `aarch64-linux-musl`. macOS can compile the executable and run portable unit tests, but cannot run the Linux eBPF collector itself. Use a checkout path without whitespace.

The script uses host Clang's BPF backend (Homebrew LLVM on macOS), GNU make, Python 3, curl and tar. It downloads pinned dependencies and verifies each archive against a hardcoded SHA256:

| Component | Pinned version |
| --- | --- |
| Zig cross-toolchain | 0.13.0 |
| libbpf | 1.5.0 |
| arachsys standalone libelf | 0.192.1, commit `b5edd4a1e45d359ec3fccd91f4fde9514635f220` |
| zlib | 1.3.1 |

Downloads, extracted sources, toolchain, target libraries and compiler caches stay under `build/standalone/` (~560 MiB observed). Subsequent builds reuse this directory; `make clean` removes it along with all other build outputs. The script installs no system packages. No NDK, Docker, pahole, bpftool, kernel checkout or build-time BTF download is needed.

All three BPF objects are compiled and independently embedded using `scripts/embed_bpf.py`; the executable includes both `src/irq_report.c` and `src/fault_report.c`, and `include/metric_loader.h` loads only the selected object. The final static executable is checked by `scripts/verify_static_elf.py` with `--min-bpf-objects 3`. Only `build/android-arm64/sched-delay` needs deployment; BPF objects and headers stay on the host.

### Android target checks

Before running, check the selected metric's prerequisites using `adb` (BTF is required for `sched` and fault fentry/fexit, but not the fault kprobe fallback):

````sh
adb shell su -c 'uname -a; ls -l /sys/kernel/btf/vmlinux'
adb shell su -c 'cat /sys/kernel/tracing/available_events | grep -E "sched:(sched_wakeup|sched_wakeup_new|sched_switch|sched_process_exit)$"'
adb shell su -c 'cat /sys/kernel/tracing/available_events | grep -E "irq:(irq_handler_entry|irq_handler_exit|softirq_entry|softirq_exit)$"'
adb shell su -c 'cat /sys/devices/system/cpu/possible'
adb shell su -c 'grep -w handle_mm_fault /sys/kernel/tracing/available_filter_functions'
````

If tracefs is mounted elsewhere, use `/sys/kernel/debug/tracing`. Listing events/functions is diagnostic only, not proof that fault BTF validation or probe attachment will succeed. Scheduler/IRQ and fault exit-cleanup attachment use raw tracepoints, not tracefs event files; fault entry/return attachment uses the selected function-probe backend. Check target kernel configuration and use `-m fault -v` to diagnose backend selection. Static linking does not remove kernel or permission requirements.

An Android application may have multiple processes; one scheduler or fault TGID filter does not select all of them. Add `-v` for loading/attachment diagnostics. No pinned maps or persistent probes remain after exit. A previous scheduler binary ran successfully on Android, but **the new fault metric and its automatic fallback are not device-verified**. The updated IRQ metric and writer-draining backend also still need target validation; see the earlier IRQ verifier rejection below. Verifier acceptance and device/page-size compatibility cannot be inferred from a host build.

## Build and run on Linux

The default `make` remains supported with installed libbpf 1.x headers/library, Python 3, a C compiler and Clang with a BPF backend. On a Debian/Ubuntu Linux build host, install dependencies yourself:

````sh
sudo apt-get install build-essential clang llvm libbpf-dev libelf-dev zlib1g-dev pkg-config python3
make
./build/sched-delay -h
sudo ./build/sched-delay -d 10
sudo ./build/sched-delay -p 1234 -d 30
sudo ./build/sched-delay -t 1235 -d 5
sudo ./build/sched-delay -m irq -d 10
sudo ./build/sched-delay -m fault -d 10
sudo ./build/sched-delay -m fault -p 1234 -d 10
````

`build/sched-delay` embeds all three independent BPF objects using byte-array headers and the generic loader, without bpftool, and compiles the IRQ and fault report sources. No external `.bpf.o` is needed; unlike the standalone Android build, this default build may require runtime shared libraries according to the installed libbpf link flags. Supported build hosts and targets are little-endian (`BPF_TARGET=bpfel`), including arm64 and x86-64. `BPF_ARCH` defaults to `arm64` or `x86` based on `CC -dumpmachine`; any override must match the executable's target, particularly for fault kretprobe register decoding. Big-endian builds are outside the supported workflow.

### Optional Android NDK/Bionic route

Use this secondary route only when an NDK/Bionic build is needed. On a Linux build host with the dependencies above, provide an Android NDK arm64 API 30 compiler and **Android/Bionic arm64 builds** of libbpf 1.x, libelf and zlib with headers. The NDK does not supply libbpf/libelf; this route does not automatically build these dependencies. Do not reuse Linux host or standalone musl archives for a Bionic build. Supply additional Android archives if your libelf depends on other compression libraries.

````sh
export ANDROID_NDK_HOME=/opt/android-ndk
export ANDROID_DEPS=/opt/android-deps
export TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64"

make clean
make \
  CC="$TOOLCHAIN/bin/aarch64-linux-android30-clang" \
  LIBBPF_CFLAGS="-I$ANDROID_DEPS/include" \
  LIBBPF_LIBS="$ANDROID_DEPS/lib/libbpf.a $ANDROID_DEPS/lib/libelf.a $ANDROID_DEPS/lib/libz.a"
````

This uses host Linux headers for BPF compilation and Android headers/libraries for the loader. Override `BPF_CPPFLAGS` if host BPF headers are in a nonstandard location. Deploy `build/sched-delay` instead of `build/android-arm64/sched-delay` using the quickstart commands. Static dependency archives alone do not make this NDK executable fully static; validate its runtime dependencies and page alignment separately.

## Licensing and redistribution

The collector is GPL-2.0-only and the standalone executable statically links arachsys libelf (dual GPL-2.0-or-later/LGPL-3.0-or-later), libbpf (BSD-2-Clause/LGPL-2.1) and permissively licensed zlib and musl. Use the applicable compatible license options, including libelf's GPL-2.0-or-later option for this GPL-2.0 collector. Redistributing static binaries requires applicable license notices and corresponding source under the relevant licenses. Retained downloaded sources under `build/standalone/` are useful for compliance, but preserve the actual sources, modifications and build scripts used, rather than relying on a disposable cache alone.

## Tests and validation

Portable tests (Linux or macOS):

````sh
make test
````

The portable suite covers:

- Scheduler C tests and IRQ C tests (nesting, action identity/pairing, overflow, invalid/empty/maximum depth, reset, window boundaries, aggregation and sparse CPU IDs).
- `tests/test_fault.c`: return flags and overlapping categories, nested timestamp stacks, balanced/saturated overflow, index bounds and invalid depth, histogram aggregation, window boundaries and frozen pending state.
- `tests/test_loader.c`: the actual generic loader with fake libbpf APIs, exercising primary/fallback selection, configuration/load/attachment failures, partial-attachment cleanup, fresh-object/map replacement and resource lifetime. It does **not** parse/load real BPF, run the fault BTF ABI check or test kernel verifier/tracing behavior.
- 13 Python build-tool tests, extended to check three embedded BPF objects and distinct generated symbols/header guards.

**Previously validated on the macOS build host (2026-10-20):** scheduler/IRQ C tests and Python build-tool tests passed; IRQ AddressSanitizer/UndefinedBehaviorSanitizer tests also passed. Portable tests do **not** establish runtime BPF verifier acceptance, live probe behavior or device compatibility for the new fault metric/fallback.

An Android verifier rejected the earlier IRQ exit program with `R3 unbounded memory access`: it lost the nonzero lower bound before a 32-bit `depth - 1`, allowing an apparent unsigned wrap. The updated index helper preserves an explicit `index & 7` using a compiler barrier, after normal depth validation. Disassembly confirms this mask precedes the 24-byte frame-offset multiplication in both hard-IRQ and softirq exit programs. The rebuilt program still requires a target-device load test; `chmod` does not resolve this kind of verifier rejection. The fault stack helper uses the same explicit-bound approach, but is not device-verified.

After rebuilding, validate the current artifact rather than relying on an earlier binary's size or hash:

````sh
python3 scripts/verify_static_elf.py build/android-arm64/sched-delay --min-bpf-objects 3
````

This checks ELF64 little-endian AArch64, no external interpreter or shared-library dependencies, 16-KiB-compatible load-segment alignment and at least three embedded BPF objects; it prints the current size and SHA256. The standalone build remains a static ARM64 executable requiring no runtime shared libraries. Alignment targets 4-KiB/16-KiB Android pages but does not prove runtime compatibility. A previously successful scheduler run does not validate the new fault/fallback or updated IRQ/draining build.

Live integration tests on a permitted Linux target, with BPF privileges already available:

````sh
make smoke
````

This runs all three smoke tests:

- `tests/smoke.py`: scheduler wakeups/contention, histograms, task filters, metric-selector validation and early interruption.
- `tests/smoke_irq.py`: UDP-loopback softirq load, IRQ selection, samples, histogram totals, diagnostics and grouped reports.
- `tests/smoke_fault.py`: repeatedly touches fresh anonymous `mmap` mappings, requires nonzero paired samples (but **not** major-flagged samples), checks category histograms and per-thread output under `-p`, and verifies that a nonexistent TID produces zero samples. It does not force disk I/O or drop caches, and does not force both fault backends to run.

The tests do not escalate privileges themselves. These are smoke tests, not latency calibration, exact perf fault-counter validation or full hardware/threaded-IRQ coverage. **The new fault metric and automatic fallback remain unverified on-device**, and the updated IRQ/draining backend still needs device testing.
