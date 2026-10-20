#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Opt-in Linux fault-probe smoke test. Does not force disk IO or drop caches."""
import mmap
import os
from pathlib import Path
import re
import subprocess
import sys
import threading


def main():
    if sys.platform != "linux":
        raise SystemExit("Live fault/BPF testing requires Linux, not macOS.")
    binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else "build/sched-delay").resolve())
    stop = threading.Event()
    errors = []

    def workload():
        try:
            pagesize = os.sysconf("SC_PAGE_SIZE")
            while not stop.is_set():
                # Repeated fresh anonymous mappings exercise ordinary fault handling.
                # Major flags are not guaranteed (and are NOT required by this test).
                with mmap.mmap(-1, 4 * 1024 * 1024,
                               flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
                               prot=mmap.PROT_READ | mmap.PROT_WRITE) as area:
                    for offset in range(0, len(area), pagesize):
                        area[offset] = 1
                stop.wait(0.002)
        except (OSError, ValueError) as error:
            errors.append(error)

    worker = threading.Thread(target=workload)
    worker.start()
    try:
        result = subprocess.run(
            [binary, "--metric", "fault", "-p", str(os.getpid()), "-d", "2"],
            capture_output=True, text=True, timeout=30,
        )
    finally:
        stop.set()
        worker.join(timeout=5)
    assert not worker.is_alive() and not errors, errors
    print(result.stdout, end="")
    assert result.returncode == 0, result.stderr
    assert "metric=fault" in result.stdout
    assert "Collection window: 2.000000 s" in result.stdout
    assert "Wakeup -> running" not in result.stdout and "Hard IRQ handler duration" not in result.stdout
    assert "Page-fault handler metrics: handle_mm_fault" in result.stdout
    samples = [int(n) for n in re.findall(r"^  samples:\s+(\d+)", result.stdout, re.MULTILINE)]
    assert len(samples) == 5 and samples[0] > 0, samples
    assert all(n <= samples[0] for n in samples[1:])
    entries = int(re.search(r"observed entries:\s+(\d+)", result.stdout).group(1))
    assert entries >= samples[0]
    histogram = sum(int(n) for n in re.findall(r"\[[^\n]+\): (\d+)", result.stdout))
    assert histogram == sum(samples), "Category histogram/sample counts disagree"
    assert "Per-thread paired calls" in result.stdout
    assert re.search(r"^\s*" + str(os.getpid()) + r"\s+\d+\s", result.stdout, re.MULTILINE)

    # A nonexistent global TID must not collect unrelated faults.
    filtered = subprocess.run(
        [binary, "-m", "fault", "-t", "2147483647", "-d", "1"],
        capture_output=True, text=True, timeout=30, check=True,
    )
    assert re.findall(r"^  samples:\s+(\d+)", filtered.stdout, re.MULTILINE) == ["0"] * 5
    print("PASS: fault selection, anonymous faults, category histograms and thread filtering")


if __name__ == "__main__":
    main()
