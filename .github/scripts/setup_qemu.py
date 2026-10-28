"""Install verified static QEMU for big-endian targets affected by Ubuntu QEMU 8.2.

No apt sources or system packages are changed. The package hash was taken from
Debian's signed trixie Packages index at the pinned snapshot. Its InRelease
signature and index hash were independently verified with the Debian archive
keyring; Packages SHA256: 4f2c68d67001d595fbd343f6dbad44468953a51c4d9dec3a4803249f6e295940.
"""
import argparse
import hashlib
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

PACKAGE = "qemu-user_10.0.13+ds-0+deb13u1_amd64.deb"
URL = "https://snapshot.debian.org/archive/debian/20260925T181338Z/pool/main/q/qemu/" + PACKAGE
SHA256 = "ca6ede739327a20ae5a3498230c8a3a9a072c586e131bc6bcc1201eb1725e336"
SIZE = 71089852
VERSION = "10.0.13"
EMULATORS = {"qemu-mips", "qemu-mips64", "qemu-ppc64"}


def checked_emulator(name):
    if name not in EMULATORS:
        raise ValueError("Only the reviewed big-endian MIPS32, MIPS64 and PPC64 emulators are supported")
    return name


def verify_package(path):
    path = Path(path)
    if path.is_symlink() or path.stat().st_size != SIZE:
        raise ValueError("Pinned QEMU package size or file type mismatch")
    with path.open("rb") as source:
        if hashlib.file_digest(source, "sha256").hexdigest() != SHA256:
            raise ValueError("Pinned QEMU package SHA-256 mismatch")


def download(directory):
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / PACKAGE
    if not path.exists():
        temporary = path.with_suffix(".partial")
        try:
            with urllib.request.urlopen(URL, timeout=120) as response, temporary.open("wb") as output:
                shutil.copyfileobj(response, output, length=1024 * 1024)
            verify_package(temporary)
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)
    verify_package(path)  # Cached packages are never trusted without revalidation.
    return path


def extract_emulator(source, output, emulator):
    """Stream the package tar; copy only one exact regular member to a fixed path."""
    checked_emulator(emulator)
    names = {f"usr/bin/{emulator}", f"./usr/bin/{emulator}"}
    found = False
    with tarfile.open(fileobj=source, mode="r|") as archive:
        for member in archive:
            if member.name not in names:
                continue
            if found or not member.isfile() or not 0 < member.size <= 64 * 1024 * 1024:
                raise ValueError("Expected exactly one regular QEMU executable")
            with archive.extractfile(member) as content, output.open("wb") as destination:
                shutil.copyfileobj(content, destination, length=1024 * 1024)
            if output.stat().st_size != member.size:
                raise ValueError("Truncated QEMU executable")
            found = True
    if not found:
        raise ValueError("Pinned package is missing the selected emulator")


def verify_static_x64(path):
    data = path.read_bytes()
    if (len(data) < 64 or data[:6] != b"\x7fELF\x02\x01"
            or struct.unpack_from("<H", data, 18)[0] != 62
            or struct.unpack_from("<H", data, 16)[0] not in (2, 3)):
        raise ValueError("Expected a Linux x86-64 QEMU executable")
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    if size < 56 or not count or offset + size * count > len(data):
        raise ValueError("Malformed QEMU program header table")
    if any(struct.unpack_from("<I", data, offset + i * size)[0] == 3 for i in range(count)):
        raise ValueError("Pinned QEMU must be static, without a host dynamic-loader dependency")


def github_environment(path, executable):
    value = str(executable)
    if "\r" in value or "\n" in value:
        raise ValueError("Emulator path must occupy one environment line")
    with path.open("a") as output:
        output.write(f"DRCOM_QEMU_EXECUTABLE={value}\n")


def setup(emulator, prefix, directory, github_env=None):
    checked_emulator(emulator)
    if sys.platform != "linux" or platform.machine().lower() not in ("x86_64", "amd64"):
        raise ValueError("The pinned static emulator package requires a Linux x86-64 host")
    archive = download(directory)
    prefix = prefix.resolve()
    prefix.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="qemu-stage-", dir=prefix) as staging:
        temporary = Path(staging) / emulator
        process = subprocess.Popen(["dpkg-deb", "--fsys-tarfile", str(archive)], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        try:
            extract_emulator(process.stdout, temporary, emulator)
            process.communicate(timeout=60)
            if process.returncode:
                raise ValueError("Could not read the verified QEMU package")
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()
        verify_static_x64(temporary)
        temporary.chmod(0o755)
        version = subprocess.check_output([str(temporary), "--version"], text=True, timeout=30)
        if not re.match(r"qemu-\S+ version " + re.escape(VERSION) + r"(?:\s|$)", version):
            raise ValueError("The selected emulator does not report the pinned QEMU version")
        executable = prefix / emulator
        temporary.replace(executable)
    if github_env is not None:
        github_environment(github_env, executable)
    print(f"Prepared verified static QEMU {VERSION} for {emulator}")
    return executable


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emulator", choices=sorted(EMULATORS), required=True)
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--download-dir", type=Path, required=True)
    parser.add_argument("--github-env", type=Path)
    args = parser.parse_args()
    setup(args.emulator, args.prefix, args.download_dir, args.github_env)
