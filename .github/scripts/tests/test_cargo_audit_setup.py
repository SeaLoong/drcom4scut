"""Keep pinned audit installation verified before executing or exporting a tool."""
import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("cargo_audit_setup", Path(__file__).parents[1] / "setup_cargo_audit.py")
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


def write_archive(path, members):
    with tarfile.open(path, "w:gz") as archive:
        for name, symlink in members:
            member = tarfile.TarInfo(name)
            if symlink:
                member.type = tarfile.SYMTYPE
                member.linkname = "/outside"
                archive.addfile(member)
            else:
                member.size = 128
                archive.addfile(member, io.BytesIO(b"x" * member.size))


class CargoAuditSetupTests(unittest.TestCase):
    def setUp(self):
        host = patch.object(audit.sys, "platform", "linux")
        machine = patch.object(audit.platform, "machine", return_value="x86_64")
        host.start()
        machine.start()
        self.addCleanup(host.stop)
        self.addCleanup(machine.stop)

    def test_corrupt_cache_fails_before_network_or_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            (directory / audit.PACKAGE).write_bytes(b"wrong")
            with patch.object(audit, "SIZE", 5), patch.object(audit, "SHA256", hashlib.sha256(b"right").hexdigest()), \
                    patch.object(audit.urllib.request, "urlopen") as network, patch.object(audit.subprocess, "check_output") as execute:
                with self.assertRaisesRegex(ValueError, "SHA-256"):
                    audit.setup(directory / "bin", directory)
                network.assert_not_called()
                execute.assert_not_called()

    def test_cached_symlink_and_invalid_download_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            payload = b"valid"
            real = directory / "outside-cache"
            real.write_bytes(payload)
            cached = directory / audit.PACKAGE
            cached.symlink_to(real)
            with patch.object(audit, "SIZE", len(payload)), patch.object(audit, "SHA256", hashlib.sha256(payload).hexdigest()), \
                    patch.object(audit.urllib.request, "urlopen", return_value=io.BytesIO(b"wrong")) as network:
                with self.assertRaisesRegex(ValueError, "file type"):
                    audit.download(directory)
                network.assert_not_called()
                cached.unlink()
                with self.assertRaisesRegex(ValueError, "SHA-256"):
                    audit.download(directory)
                self.assertFalse(cached.exists())
                self.assertFalse(cached.with_suffix(".partial").exists())

    def test_only_the_expected_regular_executable_is_extracted(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            archive = directory / "source.tgz"
            write_archive(archive, [("../escape", False), (audit.MEMBER, False), ("other/cargo-audit", False)])
            selected = directory / "selected"
            audit.extract_binary(archive, selected)
            self.assertEqual(selected.read_bytes(), b"x" * 128)
            self.assertEqual({path.name for path in directory.iterdir()}, {"source.tgz", "selected"})

    def test_missing_duplicate_and_symlink_binary_are_rejected(self):
        cases = [[("other/cargo-audit", False)], [(audit.MEMBER, False), (audit.MEMBER, False)], [(audit.MEMBER, True)]]
        for members in cases:
            with self.subTest(members=members), tempfile.TemporaryDirectory() as directory:
                directory = Path(directory)
                archive = directory / "source.tgz"
                write_archive(archive, members)
                with self.assertRaises(ValueError):
                    audit.extract_binary(archive, directory / "selected")

    def test_only_exact_version_is_installed_and_path_is_appended_after_success(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            archive = directory / "source.tgz"
            write_archive(archive, [(audit.MEMBER, False)])
            path = directory / "github-path"
            path.write_text("existing-path\n")
            prefix = directory / "bin"
            with patch.object(audit, "download", return_value=archive), patch.object(audit.subprocess, "check_output", return_value="cargo-audit 99.0.0\n"):
                with self.assertRaisesRegex(ValueError, "another version"):
                    audit.setup(prefix, directory, path)
            self.assertFalse((prefix / "cargo-audit").exists())
            self.assertEqual(path.read_text(), "existing-path\n")
            with patch.object(audit, "download", return_value=archive), patch.object(audit.subprocess, "check_output", return_value=f"cargo-audit {audit.VERSION}\n"):
                installed = audit.setup(prefix, directory, path)
            self.assertEqual(installed, prefix / "cargo-audit")
            self.assertTrue(installed.stat().st_mode & 0o111)
            self.assertEqual(path.read_text(), f"existing-path\n{prefix}\n")

    def test_unsupported_host_and_newline_directory_never_download(self):
        with patch.object(audit.platform, "machine", return_value="aarch64"), patch.object(audit, "download") as download:
            with self.assertRaisesRegex(ValueError, "Linux x86-64"):
                audit.setup(Path("bin"), Path("downloads"))
            download.assert_not_called()
        with patch.object(audit, "download") as download:
            with self.assertRaisesRegex(ValueError, "one environment line"):
                audit.setup(Path("bad\npath"), Path("downloads"))
            download.assert_not_called()


if __name__ == "__main__":
    unittest.main()
