"""Verify cached-package integrity and selective static-emulator extraction."""
import hashlib
import importlib.util
import io
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("qemu_setup", Path(__file__).parents[1] / "setup_qemu.py")
qemu = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qemu)


def executable(interpreter=False):
    data = bytearray(128)
    data[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<HH", data, 16, 2, 62)
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<HH", data, 54, 56, 1)
    struct.pack_into("<I", data, 64, 3 if interpreter else 1)
    return data


def archive(members):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w") as output:
        for name, payload, symlink in members:
            info = tarfile.TarInfo(name)
            if symlink:
                info.type = tarfile.SYMTYPE; info.linkname = "/outside"
                output.addfile(info)
            else:
                info.size = len(payload)
                output.addfile(info, io.BytesIO(payload))
    data.seek(0)
    return data


class QemuSetupTests(unittest.TestCase):
    def test_only_reviewed_emulators_are_accepted(self):
        for name in ("qemu-mips", "qemu-ppc64"):
            self.assertEqual(qemu.checked_emulator(name), name)
        for name in ("qemu-mipsel", "../../qemu-mips", "qemu-ppc64\n"):
            with self.subTest(name=name), self.assertRaises(ValueError):qemu.checked_emulator(name)

    def test_corrupt_cached_package_fails_without_network(self):
        expected = hashlib.sha256(b"valid").hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            (directory / qemu.PACKAGE).write_bytes(b"wrong")
            with patch.object(qemu, "SIZE", 5), patch.object(qemu, "SHA256", expected), patch.object(qemu.urllib.request, "urlopen") as network:
                with self.assertRaisesRegex(ValueError, "SHA-256"):
                    qemu.download(directory)
                network.assert_not_called()

    def test_extracts_only_selected_regular_member_not_other_paths(self):
        expected = bytes(executable())
        stream = archive([("../escape", b"ignored", False), ("./usr/bin/qemu-mips", expected, False),
                          ("./usr/bin/qemu-ppc64", b"not selected", False)])
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            target = directory / "selected"
            qemu.extract_emulator(stream, target, "qemu-mips")
            self.assertEqual(target.read_bytes(), expected)
            self.assertEqual({p.name for p in directory.iterdir()}, {"selected"})
            qemu.verify_static_x64(target)

    def test_selected_symlink_duplicate_or_missing_member_is_rejected(self):
        cases = [[("./usr/bin/qemu-mips", b"", True)],
                 [("usr/bin/qemu-mips", b"one", False), ("./usr/bin/qemu-mips", b"two", False)],
                 [("usr/bin/qemu-mipsel", b"other", False)]]
        for members in cases:
            with self.subTest(members=members), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(ValueError):
                    qemu.extract_emulator(archive(members), Path(directory) / "selected", "qemu-mips")

    def test_dynamic_wrong_cpu_and_unbounded_program_headers_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "qemu"
            candidates = [executable(True)]
            bad_cpu = executable(); struct.pack_into("<H", bad_cpu, 18, 183); candidates.append(bad_cpu)
            bad_table = executable(); struct.pack_into("<Q", bad_table, 32, 2**64 - 1); candidates.append(bad_table)
            for data in candidates:
                path.write_bytes(data)
                with self.assertRaises(ValueError):qemu.verify_static_x64(path)

    def test_environment_overrides_only_executable_and_rejects_newlines(self):
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / "env"
            env.write_text("EXISTING=keep\nDRCOM_QEMU_CPU=24Kc\n")
            qemu.github_environment(env, "/private/qemu-mips")
            self.assertEqual(env.read_text(), "EXISTING=keep\nDRCOM_QEMU_CPU=24Kc\nDRCOM_QEMU_EXECUTABLE=/private/qemu-mips\n")
            with self.assertRaises(ValueError):qemu.github_environment(env, "bad\nINJECTED=value")
            self.assertNotIn("INJECTED", env.read_text())


if __name__ == "__main__":
    unittest.main()
