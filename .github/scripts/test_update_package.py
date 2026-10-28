"""Run the real updater installer against the exact archive about to be uploaded."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib


ROOT = Path(__file__).resolve().parents[2]
PLATFORMS = {entry["target"]: entry for entry in json.loads((ROOT / ".github/scripts/platforms.json").read_text())}
TEST = "update::tests::native_packaged_archive_install"


def test_package(target, features=""):
    platform = PLATFORMS[target]
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]["version"]
    suffix = "zip" if platform["format"] == "pe" else "tar.gz"
    archive = ROOT / "dist" / f"drcom4scut-{version}-{target}.{suffix}"
    if archive.is_symlink() or not archive.is_file():
        raise RuntimeError("The updater package test requires the exact regular release archive")
    source = os.environ.get("GITHUB_SHA") or subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", source):
        raise RuntimeError("The updater package test requires the full source commit")
    environment = dict(os.environ, DRCOM_UPDATE_TEST_ARCHIVE=str(archive), DRCOM_UPDATE_TEST_SOURCE=source)
    # Respect RUSTUP_TOOLCHAIN, including the verified custom MIPS std sysroot.
    command = ["cargo", "test", "--locked", "--target", target]
    if features:
        command.extend(["--no-default-features", "--features", features])
    command.extend(["--lib", TEST, "--", "--exact"])
    result = subprocess.run(command, cwd=ROOT, env=environment, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", timeout=900)
    print(result.stdout, end="")
    log = ROOT / "artifacts" / f"update-package-{target}.log"
    log.parent.mkdir(exist_ok=True)
    log.write_text(result.stdout, encoding="utf-8")
    result.check_returncode()
    plain = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout)
    if (not re.search(r"^test " + re.escape(TEST) + r" \.\.\. ok$", plain, re.MULTILINE)
            or not re.search(r"test result: ok\. 1 passed; 0 failed;", plain)):
        raise RuntimeError("The packaged updater installer test did not execute exactly once")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=PLATFORMS, required=True)
    parser.add_argument("--features", default="")
    arguments = parser.parse_args()
    test_package(arguments.target, arguments.features)
