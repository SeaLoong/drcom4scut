"""Protect source integrity, stable bootstrap selection and host sysroot isolation."""
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import tarfile
import tempfile
import tomllib
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("setup_mips_toolchain", Path(__file__).parents[1] / "setup_mips_toolchain.py")
toolchain = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(toolchain)


class MipsToolchainTests(unittest.TestCase):
    def test_only_reviewed_targets_are_accepted(self):
        self.assertEqual(toolchain.checked_target("mips-unknown-linux-musl"), "mips")
        self.assertEqual(toolchain.checked_target("mipsel-unknown-linux-musl"), "mipsel")
        for target in ("mips64-unknown-linux-muslabi64", "mips-unknown-linux-gnu", "--help", "mips-unknown-linux-musl\n"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                toolchain.checked_target(target)

    def test_corrupted_archive_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "archive.tar.gz"
            archive.write_bytes(b"corrupt data")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                toolchain.verify_archive(archive, hashlib.sha256(b"expected data").hexdigest())

    def test_corrupted_cached_download_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            (cache / "musl-1.2.5.tar.gz").write_bytes(b"corrupt cached bytes")
            with patch.object(toolchain.urllib.request, "urlopen") as network:
                with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                    toolchain.download_source("musl", cache)
                network.assert_not_called()

    def test_archive_cannot_escape_its_expected_source_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "source.tar.gz"
            with tarfile.open(archive, "w:gz") as output:
                info = tarfile.TarInfo("../escape")
                info.size = 3
                output.addfile(info, io.BytesIO(b"bad"))
            expected = hashlib.sha256(archive.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, "Unexpected source archive root"):
                toolchain.unpack(archive, root / "extract", "source", expected)
            self.assertFalse((root / "escape").exists())

    def test_matching_top_level_still_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "source.tar.gz"
            with tarfile.open(archive, "w:gz") as output:
                info = tarfile.TarInfo("source/../../escape")
                info.size = 3
                output.addfile(info, io.BytesIO(b"bad"))
            expected = hashlib.sha256(archive.read_bytes()).hexdigest()
            with self.assertRaises(tarfile.FilterError):
                toolchain.unpack(archive, root / "extract", "source", expected)
            self.assertFalse((root / "escape").exists())

    def test_unmarked_existing_sources_are_not_silently_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "source.tar.gz"
            archive.write_bytes(b"verified bytes")
            (root / "source").mkdir()
            with self.assertRaisesRegex(ValueError, "unverified source directory"):
                toolchain.unpack(archive, root, "source", hashlib.sha256(archive.read_bytes()).hexdigest())

    def test_bootstrap_uses_exact_stable_compiler_and_cross_stage_zero(self):
        values = toolchain.bootstrap_config(Path("/work"), Path("/stable"), "mipsel-unknown-linux-musl",
                                             Path("/musl"), Path("/cc"), Path("/cxx"), Path("/ar"), Path("/ranlib"), 2)
        config = tomllib.loads(values)
        self.assertEqual(config["build"]["rustc"], "/stable/bin/rustc")
        self.assertEqual(config["build"]["cargo"], "/stable/bin/cargo")
        self.assertTrue(config["build"]["local-rebuild"])
        self.assertFalse(config["rust"]["download-rustc"])
        self.assertEqual(config["rust"]["channel"], "stable")
        self.assertEqual(config["target"]["mipsel-unknown-linux-musl"]["llvm-libunwind"], "in-tree")

    def test_compiler_rejects_wrong_release_or_host(self):
        for info in ("release: 1.99.1-nightly\nhost: x86_64-unknown-linux-gnu\n",
                     "release: 1.98.0\nhost: x86_64-unknown-linux-gnu\n",
                     "release: 1.99.1\nhost: aarch64-unknown-linux-gnu\n"):
            with self.subTest(info=info), patch.object(toolchain, "run", return_value=info):
                with self.assertRaisesRegex(ValueError, "official stable"):
                    toolchain.compiler_sysroot()

    def test_compiler_selection_prefers_pinned_official_version(self):
        responses = ["1.99.1-x86_64-unknown-linux-gnu\ndrcom-mips-1.99.1\n",
                     "release: 1.99.1\nhost: x86_64-unknown-linux-gnu\n", "/official/pinned\n"]
        with patch.object(toolchain, "run", side_effect=responses) as run:
            self.assertEqual(toolchain.compiler_sysroot(), Path("/official/pinned"))
        self.assertEqual(run.call_args_list[1].args[0][:3], ["rustup", "run", "1.99.1"])

    def test_bootstrap_isolates_application_flags_and_retains_proxy_trust(self):
        environment = {"RUSTFLAGS": "-C linker=rust-lld", "CARGO_TARGET_DIR": "/application/build",
                       "CARGO_ENCODED_RUSTFLAGS": "application flags", "CARGO_BUILD_TARGET": "application-target",
                       "HTTPS_PROXY": "policy-proxy", "SSL_CERT_FILE": "/configured-ca"}
        self.assertEqual(toolchain.bootstrap_environment(environment),
                         {"HTTPS_PROXY": "policy-proxy", "SSL_CERT_FILE": "/configured-ca"})
        self.assertIn("RUSTFLAGS", environment)

    @unittest.skipUnless(os.name == "posix", "Linux cross sysroot uses POSIX symlinks")
    def test_isolated_compiler_does_not_copy_other_cross_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stable, isolated = root / "stable", root / "isolated"
            (stable / "bin").mkdir(parents=True)
            (stable / "bin/rustc").write_bytes(b"compiler")
            (stable / "lib/rustlib" / toolchain.HOST).mkdir(parents=True)
            (stable / "lib/rustlib/another-target").mkdir()
            (stable / "lib/driver.so").write_bytes(b"immutable driver")
            (stable / "lib/librustc_driver-probe.so").write_bytes(b"compiler driver")
            toolchain.isolated_compiler(stable, isolated)
            self.assertFalse((isolated / "bin/rustc").is_symlink())
            self.assertEqual((isolated / "bin/rustc").read_bytes(), b"compiler")
            self.assertTrue((isolated / "lib/driver.so").is_symlink())
            self.assertFalse((isolated / "lib/librustc_driver-probe.so").is_symlink())
            self.assertFalse((isolated / "lib/rustlib/another-target").exists())
            self.assertNotEqual((isolated / "lib/rustlib").resolve(), (stable / "lib/rustlib").resolve())

    def test_installation_cannot_target_original_host_sysroot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "separate"):
                toolchain.isolated_compiler(root, root)

    def test_environment_preserves_prior_settings_and_rejects_injection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "github-env"
            path.write_text("EXISTING=keep\n")
            toolchain.github_environment(path, {"RUSTUP_TOOLCHAIN": "drcom-mips-1.99.1"})
            self.assertEqual(path.read_text(), "EXISTING=keep\nRUSTUP_TOOLCHAIN=drcom-mips-1.99.1\n")
            with self.assertRaisesRegex(ValueError, "one line"):
                toolchain.github_environment(path, {"RUSTUP_TOOLCHAIN": "good\nINJECTED=bad"})
            self.assertNotIn("INJECTED", path.read_text())


if __name__ == "__main__":
    unittest.main()
