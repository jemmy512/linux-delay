# SPDX-License-Identifier: GPL-2.0-only
"""Portable tests for BPF embedding and static executable validation."""
import contextlib
import importlib.util
import io
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("verify_static_elf", ROOT / "scripts/verify_static_elf.py")
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


def elf_header(machine, phcount=0):
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    return struct.pack("<16sHHIQQQIHHHHHH", ident, 2, machine, 1,
                       0x100000, 64, 0, 0, 64, 56, phcount, 0, 0, 0)


def static_fixture(extra_type=None, needed=False, align=16384):
    # Minimal program headers suffice: these tests do not execute the fixture.
    count = 1 + (extra_type is not None)
    data = bytearray(elf_header(183, count))
    data += struct.pack("<IIQQQQQQ", 1, 5, 0, 0x100000, 0x100000, 512, 512, align)
    if extra_type is not None:
        data += struct.pack("<IIQQQQQQ", extra_type, 4, 256, 0, 0, 32, 32, 8)
    data += bytes(512 - len(data))
    if needed:
        struct.pack_into("<qQ", data, 256, 1, 1)
    data[384:448] = elf_header(247)
    return data


class BuildToolsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def verify(self, data, min_bpf_objects=1):
        binary = self.directory / "binary"
        binary.write_bytes(data)
        with contextlib.redirect_stdout(io.StringIO()):
            VERIFY.verify(binary, min_bpf_objects)

    def test_static_arm64(self):
        self.verify(static_fixture())

    def test_dynamic_without_dependencies(self):
        self.verify(static_fixture(extra_type=2))

    def test_external_loader_rejected(self):
        with self.assertRaisesRegex(ValueError, "PT_INTERP"):
            self.verify(static_fixture(extra_type=3))

    def test_shared_library_rejected(self):
        with self.assertRaisesRegex(ValueError, "DT_NEEDED"):
            self.verify(static_fixture(extra_type=2, needed=True))

    def test_small_page_alignment_rejected(self):
        with self.assertRaisesRegex(ValueError, "16-KiB"):
            self.verify(static_fixture(align=4096))

    def test_wrong_architecture_rejected(self):
        data = static_fixture()
        struct.pack_into("<H", data, 18, 62)
        with self.assertRaisesRegex(ValueError, "AArch64"):
            self.verify(data)

    def test_truncated_binary_rejected(self):
        with self.assertRaisesRegex(ValueError, "header table"):
            self.verify(elf_header(183, 1))

    def test_missing_embedded_object_rejected(self):
        data = static_fixture()
        data[384:448] = bytes(64)
        with self.assertRaisesRegex(ValueError, "embedded BPF"):
            self.verify(data)

    def test_embed_preserves_bytes(self):
        obj = self.directory / "input.o"
        header = self.directory / "output.h"
        data = elf_header(247) + bytes(range(256))
        obj.write_bytes(data)
        subprocess.run([sys.executable, ROOT / "scripts/embed_bpf.py", obj, header], check=True)
        actual = bytes(int(value, 16) for value in re.findall(r"0x([0-9a-f]{2})", header.read_text()))
        self.assertEqual(actual, data)

    def test_embed_rejects_non_bpf(self):
        obj = self.directory / "input.o"
        header = self.directory / "output.h"
        obj.write_bytes(elf_header(183))
        result = subprocess.run(
            [sys.executable, ROOT / "scripts/embed_bpf.py", obj, header], capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(header.exists())

    def test_multiple_embedded_objects(self):
        with self.assertRaisesRegex(ValueError, "need 2"):
            self.verify(static_fixture(), min_bpf_objects=2)
        data = static_fixture()
        data[448:512] = elf_header(247)
        self.verify(data, min_bpf_objects=2)
        with self.assertRaisesRegex(ValueError, "need 3"):
            self.verify(data, min_bpf_objects=3)
        data[320:384] = elf_header(247)
        self.verify(data, min_bpf_objects=3)

    def test_distinct_symbol_and_guard(self):
        obj = self.directory / "input.o"
        obj.write_bytes(elf_header(247))
        guards = []
        for name in ("sched_delay", "irq_delay", "fault_delay"):
            header = self.directory / f"{name}.h"
            subprocess.run(
                [sys.executable, ROOT / "scripts/embed_bpf.py", obj, header,
                 "--symbol", f"{name}_bpf_bytes"], check=True,
            )
            text = header.read_text()
            self.assertIn(f"unsigned char {name}_bpf_bytes[]", text)
            guards.append(re.search(r"#ifndef (\w+)", text).group(1))
        self.assertEqual(len(set(guards)), 3)

    def test_invalid_symbol_rejected(self):
        obj = self.directory / "input.o"
        obj.write_bytes(elf_header(247))
        header = self.directory / "output.h"
        result = subprocess.run(
            [sys.executable, ROOT / "scripts/embed_bpf.py", obj, header, "--symbol", "bad;code"],
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(header.exists())


if __name__ == "__main__":
    unittest.main()
