#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Verify ARM64 static ELF and Android 16-KiB load-segment alignment."""
import argparse
import hashlib
from pathlib import Path
import struct


def verify(path, min_bpf_objects=1):
    data = path.read_bytes()
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("not a little-endian ELF64 executable")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    if header[1] not in (2, 3) or header[2] != 183:
        raise ValueError("not an AArch64 executable")
    phoff, phsize, phcount = header[5], header[9], header[10]
    if phsize < 56 or not phcount or phoff + phsize * phcount > len(data):
        raise ValueError("invalid program header table")
    loads = 0
    for index in range(phcount):
        kind, _, offset, vaddr, _, filesz, _, align = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + index * phsize,
        )
        if offset + filesz > len(data):
            raise ValueError("segment exceeds file size")
        if kind == 3:
            raise ValueError("PT_INTERP found: executable needs an external loader")
        if kind == 2:
            if filesz % 16:
                raise ValueError("invalid dynamic table")
            for pos in range(offset, offset + filesz, 16):
                tag, _ = struct.unpack_from("<qQ", data, pos)
                if tag == 0:
                    break
                if tag == 1:
                    raise ValueError("DT_NEEDED found: executable needs a shared library")
        if kind == 1:
            loads += 1
            if align < 16384 or (vaddr - offset) % 16384:
                raise ValueError("load segment is not Android 16-KiB compatible")
    if not loads:
        raise ValueError("no load segments")
    embedded_count = 0
    position = 64
    while True:
        position = data.find(b"\x7fELF\x02\x01", position)
        if position == -1:
            break
        if data[position + 18:position + 20] == b"\xf7\x00":
            embedded_count += 1
        position += 4
    if min_bpf_objects < 1 or embedded_count < min_bpf_objects:
        raise ValueError(f"embedded BPF ELF objects: found {embedded_count}, need {min_bpf_objects}")
    print(f"PASS: ARM64 ELF, no external loader/shared libraries, {loads} aligned load segments, {embedded_count} embedded BPF objects")
    print(f"Size: {len(data):,} bytes")
    print(f"SHA256: {hashlib.sha256(data).hexdigest()}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--min-bpf-objects", type=int, default=1)
    args = parser.parse_args()
    try:
        verify(args.binary, args.min_bpf_objects)
    except (OSError, ValueError, struct.error) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
