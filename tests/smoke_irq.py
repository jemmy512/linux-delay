#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Opt-in live Linux IRQ smoke test; requires BPF permissions, not sudo inside the script."""
from pathlib import Path
import re
import socket
import subprocess
import sys
import threading


def main():
    if sys.platform != "linux":
        raise SystemExit("Live IRQ/BPF testing requires Linux, not macOS.")
    binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else "build/sched-delay").resolve())
    stop = threading.Event()
    errors = []

    def workload():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rx:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as tx:
                    rx.bind(("127.0.0.1", 0))
                    rx.settimeout(0.5)
                    while not stop.is_set():
                        tx.sendto(b"irq smoke test", rx.getsockname())
                        try:
                            rx.recv(256)
                        except socket.timeout:
                            pass
                        stop.wait(0.001)
        except OSError as error:
            errors.append(error)

    worker = threading.Thread(target=workload)
    worker.start()
    try:
        result = subprocess.run(
            [binary, "--metric", "irq", "-d", "2"],
            capture_output=True, text=True, timeout=20,
        )
    finally:
        stop.set()
        worker.join(timeout=3)
    assert not worker.is_alive(), "Workload failed to stop"
    assert not errors, errors
    print(result.stdout, end="")
    assert result.returncode == 0, result.stderr
    assert "metric=irq" in result.stdout
    assert "Collection window: 2.000000 s" in result.stdout
    assert "Wakeup -> running" not in result.stdout
    assert "Runnable switch-out -> running" not in result.stdout
    hard, soft = result.stdout.split("Hard IRQ handler duration\n", 1)[1].split("Softirq execution duration\n", 1)
    for section in (hard, soft):
        entries = int(re.search(r"^  entries:\s+(\d+)", section, re.MULTILINE).group(1))
        samples = int(re.search(r"^  samples:\s+(\d+)", section, re.MULTILINE).group(1))
        assert samples <= entries
        histogram = sum(int(n) for n in re.findall(r"\[[^\n]+\): (\d+)", section))
        assert histogram == samples, "Histogram/sample counts disagree"
        assert "Per-CPU totals" in section and "Per-CPU / IRQ or vector" in section
        for label in ("unfinished", "stack overflows", "unmatched exits", "pairing mismatch", "map errors"):
            assert re.search(r"^  " + label + r":\s+\d+", section, re.MULTILINE)
    assert int(re.search(r"^  samples:\s+(\d+)", soft, re.MULTILINE).group(1)) > 0, "No softirq samples under UDP load"
    print("PASS: IRQ selection, softirq samples, histogram counts, diagnostics and grouped reports")


if __name__ == "__main__":
    main()
