"""Install the pinned official cargo-audit binary for Linux x86-64 CI."""
import argparse
import hashlib
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

VERSION = "0.22.2"
PACKAGE = f"cargo-audit-x86_64-unknown-linux-musl-v{VERSION}.tgz"
URL = f"https://github.com/rustsec/rustsec/releases/download/cargo-audit/v{VERSION}/{PACKAGE}"
# Official release metadata, asset ID 439292222:
# https://api.github.com/repos/rustsec/rustsec/releases/assets/439292222
SHA256 = "7fb9497f8594b389e5fce5ef9b92db08432996895b2e0c5a0167a69ed445c428"
SIZE = 6648968
MEMBER = f"cargo-audit-x86_64-unknown-linux-musl-v{VERSION}/cargo-audit"


def verify_archive(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size != SIZE:
        raise ValueError("Pinned cargo-audit archive size or file type mismatch")
    with path.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != SHA256:
            raise ValueError("Pinned cargo-audit archive SHA-256 mismatch")


def download(directory):
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / PACKAGE
    if not path.exists():
        temporary = path.with_suffix(".partial")
        try:
            with urllib.request.urlopen(URL, timeout=60) as response, temporary.open("wb") as output:
                shutil.copyfileobj(response, output, length=1024 * 1024)
            verify_archive(temporary)
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)
    verify_archive(path)  # Reused downloads are always revalidated.
    return path


def extract_binary(archive, output):
    found = False
    with tarfile.open(archive, "r:gz") as package:
        for member in package:
            if member.name != MEMBER:
                continue
            if found or not member.isfile() or not 64 <= member.size <= 64 * 1024 * 1024:
                raise ValueError("Expected exactly one regular cargo-audit executable")
            with package.extractfile(member) as content, output.open("wb") as destination:
                shutil.copyfileobj(content, destination, length=1024 * 1024)
            if output.stat().st_size != member.size:
                raise ValueError("Truncated cargo-audit executable")
            found = True
    if not found:
        raise ValueError("Pinned archive is missing cargo-audit")


def setup(prefix, directory, github_path=None):
    if sys.platform != "linux" or platform.machine().lower() not in ("x86_64", "amd64"):
        raise ValueError("The pinned cargo-audit package requires a Linux x86-64 host")
    prefix = prefix.resolve()
    if "\n" in str(prefix) or "\r" in str(prefix):
        raise ValueError("Tool directory must occupy one environment line")
    archive = download(directory)
    prefix.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="audit-stage-", dir=prefix) as staging:
        executable = Path(staging) / "cargo-audit"
        extract_binary(archive, executable)
        executable.chmod(0o755)
        reported = subprocess.check_output([str(executable), "--version"], text=True, timeout=30).strip()
        if reported != f"cargo-audit {VERSION}":
            raise ValueError("The verified cargo-audit executable reports another version")
        executable.replace(prefix / "cargo-audit")
    if github_path is not None:
        with github_path.open("a") as output:
            output.write(str(prefix) + "\n")
    print(f"Prepared verified official cargo-audit {VERSION}")
    return prefix / "cargo-audit"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--download-dir", type=Path, required=True)
    parser.add_argument("--github-path", type=Path)
    arguments = parser.parse_args()
    setup(arguments.prefix, arguments.download_dir, arguments.github_path)
