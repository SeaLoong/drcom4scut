"""Check executable ABI/version, then package the exact tested release binary."""

import argparse
import hashlib
import json
import os
import pathlib
import re
import shlex
import shutil
import struct
import subprocess
import tarfile
import tempfile
import tomllib
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
PLATFORMS = {p["target"]: p for p in json.loads((ROOT / ".github/scripts/platforms.json").read_text())}


def verify_abi(binary, platform):
    """Reject mislabeled host binaries before they can become release assets."""
    data = pathlib.Path(binary).read_bytes()
    if platform["format"] == "elf":
        if len(data) < 52 or data[:4] != b"\x7fELF" or data[5] != 1:
            raise ValueError("Expected a little-endian ELF executable")
        if len(data) < (64 if platform["bits"] == 64 else 52):
            raise ValueError("Truncated ELF header")
        if data[4] != {32: 1, 64: 2}[platform["bits"]]:
            raise ValueError("ELF word size does not match target")
        if struct.unpack_from("<H", data, 18)[0] != platform["machine"]:
            raise ValueError("ELF CPU architecture does not match target")
        if platform["openwrt"]:
            # No PT_INTERP means there is no GNU/musl dynamic loader dependency.
            # Static PIE may have PT_DYNAMIC, so inspecting ldd output is weaker.
            if platform["bits"] == 64:
                offset = struct.unpack_from("<Q", data, 32)[0]
                entry_size, count = struct.unpack_from("<HH", data, 54)
            else:
                offset = struct.unpack_from("<I", data, 28)[0]
                entry_size, count = struct.unpack_from("<HH", data, 42)
            if entry_size < 4 or offset + entry_size * count > len(data):
                raise ValueError("Malformed ELF program header table")
            if any(struct.unpack_from("<I", data, offset + i * entry_size)[0] == 3 for i in range(count)):
                raise ValueError("OpenWrt artifacts must be static (unexpected PT_INTERP)")
    elif platform["format"] == "macho":
        # Publish one thin, native executable per CPU. Universal/fat containers
        # cannot establish which slice the --version smoke test actually ran.
        if len(data) < 32 or data[:4] != b"\xcf\xfa\xed\xfe":
            raise ValueError("Expected a thin little-endian Mach-O64 executable")
        if platform["bits"] != 64:
            raise ValueError("Mach-O word size does not match target")
        if struct.unpack_from("<I", data, 4)[0] != platform["machine"]:
            raise ValueError("Mach-O CPU architecture does not match target")
        if struct.unpack_from("<I", data, 12)[0] != 2:  # MH_EXECUTE
            raise ValueError("Mach-O artifact is not an executable")
        count, size = struct.unpack_from("<II", data, 16)
        end = 32 + size
        if end > len(data) or count > size // 8:
            raise ValueError("Malformed Mach-O load command table")
        offset = 32
        for _ in range(count):
            if offset + 8 > end:
                raise ValueError("Malformed Mach-O load command")
            command_size = struct.unpack_from("<I", data, offset + 4)[0]
            if command_size < 8 or command_size % 8 or offset + command_size > end:
                raise ValueError("Malformed Mach-O load command")
            offset += command_size
        if offset != end:
            raise ValueError("Malformed Mach-O load command table")
    elif platform["format"] == "pe":
        if len(data) < 64 or data[:2] != b"MZ":
            raise ValueError("Expected a Windows PE executable")
        offset = struct.unpack_from("<I", data, 60)[0]
        if offset + 6 > len(data) or data[offset:offset + 4] != b"PE\0\0":
            raise ValueError("Malformed PE header")
        if struct.unpack_from("<H", data, offset + 4)[0] != platform["machine"]:
            raise ValueError("PE CPU architecture does not match target")
    else:
        raise ValueError("Unsupported executable format")


def package(root, target, runner=(), target_dir=None):
    platform = PLATFORMS[target]
    version = tomllib.loads((root / "Cargo.toml").read_text())["package"]["version"]
    binary_name = "drcom4scut.exe" if platform["format"] == "pe" else "drcom4scut"
    target_dir = root / "target" if target_dir is None else pathlib.Path(target_dir)
    if not target_dir.is_absolute():
        target_dir = root / target_dir
    binary = target_dir / target / "release" / binary_name
    verify_abi(binary, platform)
    if "arm_arch" in platform:
        # ARMv5TE and ARMv7 share e_machine. Verify attributes too, rather than
        # accepting a wrongly labelled newer-CPU binary which fails on old routers.
        attributes = subprocess.check_output(["readelf", "-A", str(binary)], text=True)
        if not re.search(r"Tag_CPU_arch:\s*" + re.escape(platform["arm_arch"]) + r"\s*$", attributes, re.MULTILINE):
            raise ValueError("ARM CPU baseline does not match target")
        if struct.unpack_from("<I", binary.read_bytes(), 36)[0] & 0x400:
            raise ValueError("Expected ARM soft-float ABI, found hard-float")
    reported = subprocess.check_output([*runner, str(binary), "--version"], text=True).strip()
    if reported != f"drcom4scut {version}":
        raise ValueError(f"Unexpected built version: {reported!r}")
    dist = root / "dist"
    dist.mkdir(exist_ok=True)
    stem = f"drcom4scut-{version}-{target}"
    with tempfile.TemporaryDirectory() as temp:
        contents = pathlib.Path(temp) / stem
        contents.mkdir()
        for source, name in (
            (binary, binary_name), (root / "README.md", "README.md"),
            (root / "LICENSE", "LICENSE"),
            (root / "src/default_config.yml", "config.example.yml"),
        ):
            shutil.copy2(source, contents / name)
        if (root / "docs").is_dir():
            shutil.copytree(root / "docs", contents / "docs", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        if (root / "CHANGELOG.md").is_file():
            shutil.copy2(root / "CHANGELOG.md", contents / "CHANGELOG.md")
        if platform["openwrt"]:
            bundle = root / "packaging/openwrt"
            for required in (
                "files/config.yml", "files/drcom4scut.init", "files/drcom4scut.uci",
                "install.sh", "install-common.sh", "install-luci.sh",
            ):
                if not (bundle / required).is_file():
                    raise ValueError(f"OpenWrt bundle is missing an installation file: {required}")
            shutil.copytree(bundle, contents / "openwrt", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            # Keep the old entry point without moving a document's relative links.
            (contents / "OPENWRT.md").write_text(
                "[OpenWrt 安装与使用](docs/openwrt.md)\n", encoding="utf-8"
            )
        if platform["format"] == "pe":
            archive = dist / f"{stem}.zip"
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
                for item in sorted(contents.rglob("*")):
                    if item.is_file():
                        output.write(item, str(item.relative_to(contents.parent)))
        else:
            archive = dist / f"{stem}.tar.gz"
            with tarfile.open(archive, "w:gz") as output:
                def root_owned(member):
                    # Privileged OpenWrt extraction must not assign executable
                    # bundle ownership to the build runner's unprivileged UID.
                    member.uid = member.gid = 0
                    member.uname = member.gname = "root"
                    return member
                output.add(contents, arcname=stem, filter=root_owned)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix(archive.suffix + ".sha256").write_text(f"{digest}  {archive.name}\n")
    return archive


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", choices=PLATFORMS)
    parser.add_argument("--runner", default="", help="Emulator command for foreign-CPU executables, e.g. qemu-arm")
    parser.add_argument("--target-dir", default=os.environ.get("CARGO_TARGET_DIR"), help="Cargo target directory (defaults to CARGO_TARGET_DIR or target)")
    args = parser.parse_args()
    try:
        archive = package(ROOT, args.target, shlex.split(args.runner), args.target_dir)
    except (ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from error
    print(f"Created {archive.name}")


if __name__ == "__main__":
    main()
