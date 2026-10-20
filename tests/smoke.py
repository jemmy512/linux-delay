#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Live Linux smoke test. Run with BPF privileges; never invokes sudo itself."""
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import tempfile
import threading
import time


def main():
    if sys.platform != "linux":
        raise SystemExit("Live BPF smoke testing requires Linux, not macOS.")
    binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else "build/sched-delay").resolve())

    # CLI validation must work without loading any BPF programs.
    for args in (["-d", "0"], ["-d", "-1"], ["-d", "nan"],
                 ["-p", "2147483648"], ["unexpected"], ["-m", "unknown"],
                 ["-m", "sched", "-m", "irq"], ["-m", "irq", "-p", "0"],
                 ["-t", "1", "--metric", "irq"]):
        run = subprocess.run([binary, *args], capture_output=True, text=True, timeout=5)
        assert run.returncode != 0 and "Usage:" in run.stderr, (args, run.stderr)
    subprocess.run([binary, "-h"], check=True, capture_output=True, timeout=5)

    original_affinity = os.sched_getaffinity(0)
    os.sched_setaffinity(0, {min(original_affinity)})
    stop = threading.Event()

    def workload():
        while not stop.is_set():
            # Repeated sleeps create wakeups; CPU bursts exercise runnable waits.
            until = time.monotonic() + 0.003
            while time.monotonic() < until:
                pass
            time.sleep(0.001)

    workers = [threading.Thread(target=workload) for _ in range(3)]
    for worker in workers:
        worker.start()
    competitor = None
    try:
        # A separate process bypasses Python's GIL; inherited one-CPU affinity
        # forces runnable contention on a CPU permitted by the host cpuset.
        competitor = subprocess.Popen([sys.executable, "-c", "while True: pass"])
        result = subprocess.run(
            [binary, "--metric", "sched", "-p", str(os.getpid()), "-d", "2"],
            capture_output=True, text=True, timeout=20,
        )
        print(result.stdout, end="")
        if result.returncode:
            raise RuntimeError(result.stderr)
        assert "metric=sched" in result.stdout
        assert "Hard IRQ handler duration" not in result.stdout
        assert "Collection window: 2.000000 s" in result.stdout
        counts = [int(n) for n in re.findall(r"samples:\s+(\d+)", result.stdout)]
        assert len(counts) == 2 and all(n > 0 for n in counts), counts
        histogram_count = sum(int(n) for n in re.findall(r"\[[^\n]+\): (\d+)", result.stdout))
        assert histogram_count == sum(counts), "Histogram/sample counts disagree"
        assert all(int(n) == 0 for n in re.findall(r"map insert errors:\s*(\d+)", result.stdout))

        result = subprocess.run(
            [binary, "-p", str(os.getpid()), "-t", str(workers[0].native_id), "-d", "1"],
            capture_output=True, text=True, timeout=15, check=True,
        )
        counts = [int(n) for n in re.findall(r"samples:\s+(\d+)", result.stdout)]
        assert len(counts) == 2 and counts[0] > 0, "Positive thread filter failed"
        result = subprocess.run(
            [binary, "-p", "2147483647", "-t", str(workers[0].native_id), "-d", "1"],
            capture_output=True, text=True, timeout=15, check=True,
        )
        assert re.findall(r"samples:\s+(\d+)", result.stdout) == ["0", "0"]

        # A nonexistent kernel TID must not collect unrelated threads.
        result = subprocess.run(
            [binary, "-t", "2147483647", "-d", "1"],
            capture_output=True, text=True, timeout=15, check=True,
        )
        assert re.findall(r"samples:\s+(\d+)", result.stdout) == ["0", "0"]

        # Wait for the flushed startup message rather than guessing load time.
        # Redirect diagnostics to a file so a full stderr pipe cannot deadlock.
        with tempfile.TemporaryFile(mode="w+t") as errors:
            with subprocess.Popen(
                [binary, "-p", str(os.getpid()), "-d", "30"],
                stdout=subprocess.PIPE, stderr=errors, text=True,
            ) as process:
                try:
                    with selectors.DefaultSelector() as ready:
                        ready.register(process.stdout, selectors.EVENT_READ)
                        assert ready.select(timeout=15), "Collector startup timed out"
                        line = process.stdout.readline()
                        assert line.startswith("Collecting for"), line
                    process.send_signal(signal.SIGINT)
                    output, _ = process.communicate(timeout=15)
                    errors.seek(0)
                    assert process.returncode == 0, errors.read()
                    match = re.search(r"Collection window: ([0-9.]+) s", output)
                    assert match and float(match.group(1)) < 30, output
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait()
    finally:
        stop.set()
        for worker in workers:
            worker.join()
        if competitor is not None:
            competitor.kill()
            competitor.wait()
        os.sched_setaffinity(0, original_affinity)
    print("PASS: live wakeups/runnable waits, filtering, histograms, CLI and interruption")


if __name__ == "__main__":
    main()
