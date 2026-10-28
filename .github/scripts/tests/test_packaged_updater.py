"""Keep exact-archive update checks active for native and emulator toolchains."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("packaged_updater", Path(__file__).parents[1] / "test_update_package.py")
driver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(driver)


class PackagedUpdaterTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        (self.root / "Cargo.toml").write_text('[package]\nversion = "0.6.1"\n')
        (self.root / "dist").mkdir()
        target = "mips-unknown-linux-musl"
        self.archive = self.root / "dist" / f"drcom4scut-0.6.1-{target}.tar.gz"
        self.archive.write_bytes(b"archive bytes are validated by the invoked Rust test")
        root = patch.object(driver, "ROOT", self.root)
        root.start(); self.addCleanup(root.stop)
        environment = patch.dict(os.environ, {"GITHUB_SHA": "a" * 40,
            "RUSTUP_TOOLCHAIN": "drcom-mips-1.99.1", "DRCOM_TEST_RUNNER": "/private/qemu-wrapper",
            "CARGO_TARGET_MIPS_UNKNOWN_LINUX_MUSL_RUNNER": "/private/qemu-wrapper",
            "DRCOM_QEMU_CPU": "24Kc"})
        environment.start(); self.addCleanup(environment.stop)

    def output(self, *, code=0, text=None):
        passed = f"test {driver.TEST} ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n"
        return subprocess.CompletedProcess(["cargo"], code, stdout=passed if text is None else text)

    def test_exact_archive_features_and_emulator_toolchain_reach_the_real_test(self):
        with patch.object(driver.subprocess, "run", return_value=self.output()) as run:
            driver.test_package("mips-unknown-linux-musl", "log4rs,portal-tls")
        args = run.call_args.args[0]
        self.assertEqual(args[:5], ["cargo", "test", "--locked", "--target", "mips-unknown-linux-musl"])
        self.assertIn("log4rs,portal-tls", args)
        self.assertEqual(args[-4:], ["--lib", driver.TEST, "--", "--exact"])
        env = run.call_args.kwargs["env"]
        self.assertEqual(env["DRCOM_UPDATE_TEST_ARCHIVE"], str(self.archive))
        self.assertEqual(env["DRCOM_UPDATE_TEST_SOURCE"], "a" * 40)
        self.assertEqual(env["RUSTUP_TOOLCHAIN"], "drcom-mips-1.99.1")
        self.assertEqual(env["DRCOM_TEST_RUNNER"], "/private/qemu-wrapper")
        self.assertEqual(env["CARGO_TARGET_MIPS_UNKNOWN_LINUX_MUSL_RUNNER"], "/private/qemu-wrapper")
        self.assertEqual(env["DRCOM_QEMU_CPU"], "24Kc")

    def test_missing_or_symlink_archive_never_starts_cargo(self):
        self.archive.unlink()
        for symlink in (False, True):
            if symlink:
                other = self.root / "wrong-archive"
                other.write_bytes(b"wrong archive")
                self.archive.symlink_to(other)
            with self.subTest(symlink=symlink), patch.object(driver.subprocess, "run") as run:
                with self.assertRaisesRegex(RuntimeError, "exact regular"):
                    driver.test_package("mips-unknown-linux-musl")
                run.assert_not_called()

    def test_invalid_source_identity_never_starts_cargo(self):
        with patch.dict(os.environ, {"GITHUB_SHA": "master"}), patch.object(driver.subprocess, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "full source commit"):
                driver.test_package("mips-unknown-linux-musl")
            run.assert_not_called()

    def test_failed_process_and_zero_or_multiple_tests_fail_validation(self):
        with patch.object(driver.subprocess, "run", return_value=self.output(code=7)):
            with self.assertRaises(subprocess.CalledProcessError):
                driver.test_package("mips-unknown-linux-musl")
        for text in ("test result: ok. 0 passed; 0 failed;\n",
                     f"test {driver.TEST} ... ok\ntest result: ok. 2 passed; 0 failed;\n"):
            with self.subTest(text=text), patch.object(driver.subprocess, "run", return_value=self.output(text=text)):
                with self.assertRaisesRegex(RuntimeError, "exactly once"):
                    driver.test_package("mips-unknown-linux-musl")


if __name__ == "__main__":
    unittest.main()
