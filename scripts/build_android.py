#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build a fully static ARM64 Linux/musl executable for rooted Android.

Uses host Clang's BPF backend plus a pinned Zig cross-toolchain. No NDK,
Docker, pahole, bpftool, kernel checkout or system-wide installs are needed.
All downloads, extracted sources and caches stay under build/standalone/.
"""
import hashlib
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
WORK = ROOT / "build/standalone"
DOWNLOADS = WORK / "downloads"
SOURCES = WORK / "src"
PREFIX = WORK / "prefix"
OUTPUT = ROOT / "build/android-arm64"
ZIG_HASHES = {
    ("Darwin", "arm64"): ("macos-aarch64", "46fae219656545dfaf4dce12fb4e8685cec5b51d721beee9389ab4194d43394c"),
    ("Darwin", "x86_64"): ("macos-x86_64", "8b06ed1091b2269b700b3b07f8e3be3b833000841bae5aa6a09b1a8b4773effd"),
    ("Linux", "aarch64"): ("linux-aarch64", "041ac42323837eb5624068acd8b00cd5777dac4cf91179e8dad7a7e90dd0c556"),
    ("Linux", "x86_64"): ("linux-x86_64", "d45312e61ebcc48032b77bc4cf7fd6915c11fa16e4aad116b66c9468211230ea"),
}


def run(args, cwd=ROOT, env=None):
    print("+ " + shlex.join(map(str, args)), flush=True)
    subprocess.run(list(map(str, args)), cwd=cwd, env=env, check=True)


def fetch(name, url, checksum):
    destination = DOWNLOADS / name
    if not destination.exists():
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        run(["curl", "-fL", "--retry", "2", "--connect-timeout", "20", url, "-o", temporary])
        temporary.replace(destination)
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    if digest != checksum:
        raise RuntimeError(f"SHA256 mismatch for {destination}; remove it and retry")
    return destination


def unpack(archive, directory):
    destination = SOURCES / directory
    if not destination.exists():
        run(["tar", "-xf", archive, "-C", SOURCES])
    if not destination.is_dir():
        raise RuntimeError(f"Archive did not contain {directory}")
    return destination


def wrapper(name, args):
    path = WORK / name
    text = "#!/bin/sh\nexec " + shlex.join(map(str, args)) + ' "$@"\n'
    path.write_text(text)
    path.chmod(0o755)
    return str(path)


def main():
    if any(c.isspace() for c in str(ROOT)):
        raise RuntimeError("Dependency makefiles require a checkout path without whitespace")
    host = (platform.system(), platform.machine())
    if host not in ZIG_HASHES:
        raise RuntimeError(f"Unsupported build host: {host}")
    make = shutil.which("gmake") or shutil.which("make")
    clang = shutil.which(os.environ.get("BPF_CLANG", "clang"))
    if not make or not clang or not shutil.which("curl") or not shutil.which("tar"):
        raise RuntimeError("Need GNU make, curl, tar, and Clang with the BPF backend")
    version = subprocess.check_output([make, "--version"], text=True)
    if "GNU Make" not in version:
        raise RuntimeError("Install GNU make (gmake)")
    targets = subprocess.check_output([clang, "--print-targets"], text=True)
    if "bpfel" not in targets:
        raise RuntimeError("Clang has no BPF backend; on macOS use Homebrew llvm, not Apple clang")
    jobs = str(max(1, int(os.environ.get("JOBS", "4"))))
    for directory in (DOWNLOADS, SOURCES, PREFIX / "include/bpf", PREFIX / "lib", OUTPUT):
        directory.mkdir(parents=True, exist_ok=True)

    zig_platform, zig_hash = ZIG_HASHES[host]
    zig_name = f"zig-{zig_platform}-0.13.0"
    zig_source = unpack(fetch(
        "zig-0.13.0.tar.xz", f"https://ziglang.org/download/0.13.0/{zig_name}.tar.xz", zig_hash,
    ), zig_name)
    zig = zig_source / "zig"
    zlib = unpack(fetch(
        "zlib-1.3.1.tar.gz", "https://zlib.net/fossils/zlib-1.3.1.tar.gz",
        "9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23",
    ), "zlib-1.3.1")
    elf_commit = "b5edd4a1e45d359ec3fccd91f4fde9514635f220"
    libelf = unpack(fetch(
        "libelf-0.192.1.tar.gz", f"https://codeload.github.com/arachsys/libelf/tar.gz/{elf_commit}",
        "2bf3123cde2f40198cc3dae235ba084c1a663b39b6e52f46cbaea27f11493fa3",
    ), f"libelf-{elf_commit}")
    libbpf = unpack(fetch(
        "libbpf-1.5.0.tar.gz", "https://codeload.github.com/libbpf/libbpf/tar.gz/refs/tags/v1.5.0",
        "53492aff6dd47e4da04ef5e672d753b9743848bdb38e9d90eafbe190b7983c44",
    ), "libbpf-1.5.0")

    env = os.environ.copy()
    # Do not let Homebrew include/link flags leak into Linux target builds.
    for key in ("CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS", "CPATH",
                "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "LIBRARY_PATH", "SDKROOT",
                "MACOSX_DEPLOYMENT_TARGET", "MAKEFLAGS", "MFLAGS"):
        env.pop(key, None)
    env["ZIG_GLOBAL_CACHE_DIR"] = str(WORK / "zig-global-cache")
    env["ZIG_LOCAL_CACHE_DIR"] = str(WORK / "zig-local-cache")
    cc = wrapper("cc", [zig, "cc", "-target", "aarch64-linux-musl"])
    ar = wrapper("ar", [zig, "ar"])
    ranlib = wrapper("ranlib", [zig, "ranlib"])

    zenv = dict(env, CC=cc, AR=ar, RANLIB=ranlib, CHOST="aarch64-linux-musl", CFLAGS="-O2")
    configured = zlib / ".configured-aarch64-musl"
    if not configured.exists():
        run(["./configure", "--static"], cwd=zlib, env=zenv)
        configured.touch()
    run([make, f"-j{jobs}", "libz.a"], cwd=zlib, env=zenv)
    for header in ("zlib.h", "zconf.h"):
        shutil.copy2(zlib / header, PREFIX / "include" / header)
    shutil.copy2(zlib / "libz.a", PREFIX / "lib/libz.a")

    # The standalone libelf defaults to zstd; this build only needs zlib.
    config_path = libelf / "src/config.h"
    config = config_path.read_text()
    patched = config.replace("#define USE_ZSTD 1\n", "").replace("#define USE_ZSTD_COMPRESS 1\n", "")
    if patched != config:
        config_path.write_text(patched)
    run([
        make, f"-j{jobs}", "libelf.a", f"CC={cc}", f"AR={ar}",
        f"CFLAGS=-O2 -std=gnu11 -DHAVE_MREMAP=1 -I{PREFIX / 'include'}",
        "SOURCES=$(filter-out src/crc32.c src/next_prime.c,$(wildcard src/*.c))", "LDLIBS=-lz",
    ], cwd=libelf, env=env)
    for header in (libelf / "include").glob("*.h"):
        shutil.copy2(header, PREFIX / "include" / header.name)
    shutil.copy2(libelf / "libelf.a", PREFIX / "lib/libelf.a")

    run([
        make, f"-j{jobs}", "libbpf.a", "BUILD_STATIC_ONLY=1", "NO_PKG_CONFIG=1",
        f"CC={cc}", f"AR={ar}", f"CFLAGS=-O2 -g -I{PREFIX / 'include'}", "LDFLAGS=", "CPPFLAGS=",
    ], cwd=libbpf / "src", env=env)
    for header in (libbpf / "src").glob("*.h"):
        shutil.copy2(header, PREFIX / "include/bpf" / header.name)
    shutil.copy2(libbpf / "src/libbpf.a", PREFIX / "lib/libbpf.a")

    metric_objects = ("sched_delay", "irq_delay", "fault_delay")
    for metric in metric_objects:
        obj = OUTPUT / f"{metric}.bpf.o"
        run([
            clang, "-target", "bpfel", "-D__BPF__", "-D__TARGET_ARCH_arm64", "-O2", "-g", "-Wall", "-Wextra", "-Werror",
            "-I" + str(PREFIX / "include"), "-I" + str(libbpf / "include/uapi"),
            "-I" + str(zig_source / "lib/libc/include/aarch64-linux-any"),
            "-I" + str(zig_source / "lib/libc/include/any-linux-any"), "-Iinclude",
            "-c", f"src/{metric}.bpf.c", "-o", obj,
        ], env=env)
        run([sys.executable, "scripts/embed_bpf.py", obj, OUTPUT / f"{metric}.bytes.h",
             "--symbol", f"{metric}_bpf_bytes"], env=env)
    run([
        cc, "-std=c11", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-static", "-pthread",
        "-Wl,-z,max-page-size=16384", "-Iinclude", "-I" + str(OUTPUT),
        "-I" + str(PREFIX / "include"), "-I" + str(libbpf / "include/uapi"),
        "src/main.c", "src/sched_delay.c", "src/irq_report.c", "src/fault_report.c", PREFIX / "lib/libbpf.a",
        PREFIX / "lib/libelf.a", PREFIX / "lib/libz.a", "-o", OUTPUT / "sched-delay",
    ], env=env)
    run([sys.executable, "scripts/verify_static_elf.py", OUTPUT / "sched-delay",
         "--min-bpf-objects", str(len(metric_objects))])
    print(f"\nReady to adb push: {OUTPUT / 'sched-delay'}")
    print("Static Linux/musl ARM64 binary. Use -m sched, -m irq, or -m fault.")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.CalledProcessError, OSError) as error:
        raise SystemExit(str(error)) from error
