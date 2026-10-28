"""Check executable ABI/version, then package the exact tested profile binary."""

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
    verify_abi_bytes(data, platform)


def number(data, offset, size, endian="little"):
    if offset < 0 or offset + size > len(data):
        raise ValueError("Truncated executable metadata")
    return int.from_bytes(data[offset:offset + size], endian)


def verify_arm_attributes(data, expected, hard_float):
    """Check EABI file attributes directly, including during release aggregation."""
    offset, size, count = number(data, 32, 4), number(data, 46, 2), number(data, 48, 2)
    if size < 40 or not count or offset + size * count > len(data):
        raise ValueError("Missing ARM architecture attributes")
    found_cpu, found_vfp = False, False

    def uleb(payload, position, end):
        value = 0
        for shift in range(0, 64, 7):
            if position >= end:
                raise ValueError("Truncated ARM attribute integer")
            byte = payload[position]
            position += 1
            if shift == 63 and byte > 1:
                raise ValueError("ARM attribute integer overflow")
            value |= (byte & 0x7f) << shift
            if not byte & 0x80:
                return value, position
        raise ValueError("ARM attribute integer overflow")

    def string_end(payload, position, end):
        stop = payload.find(b"\0", position, end)
        if stop == -1:
            raise ValueError("Unterminated ARM attribute string")
        return stop + 1

    for index in range(count):
        section = offset + size * index
        if number(data, section + 4, 4) != 0x70000003:
            continue
        start, length = number(data, section + 16, 4), number(data, section + 20, 4)
        if start + length > len(data):
            raise ValueError("Truncated ARM attributes")
        payload = data[start:start + length]
        if not payload or payload[0] != ord("A"):
            raise ValueError("Invalid ARM attributes")
        vendor = 1
        while vendor < len(payload):
            length = number(payload, vendor, 4)
            end = vendor + length
            if length < 5 or end > len(payload):
                raise ValueError("Invalid ARM vendor attributes")
            position = vendor + 4
            aeabi = payload[position:position + 6] == b"aeabi\0"
            position = string_end(payload, position, end)
            if aeabi:
                while position < end:
                    subsection = position
                    tag, position = uleb(payload, position, end)
                    length = number(payload, position, 4)
                    position += 4
                    subend = subsection + length
                    if subend > end or subend < position:
                        raise ValueError("Invalid ARM file attributes")
                    if tag == 1:
                        while position < subend:
                            tag, position = uleb(payload, position, subend)
                            if tag in (6, 28):
                                value, position = uleb(payload, position, subend)
                                if tag == 6:
                                    if value != expected:
                                        raise ValueError("ARM CPU baseline does not match target")
                                    found_cpu = True
                                else:
                                    if value != int(hard_float):
                                        raise ValueError("ARM VFP argument ABI does not match target")
                                    found_vfp = True
                            elif tag in (4, 5, 65, 67) or tag >= 32 and tag % 2:
                                position = string_end(payload, position, subend)
                            elif tag == 32:
                                _, position = uleb(payload, position, subend)
                                position = string_end(payload, position, subend)
                            else:
                                _, position = uleb(payload, position, subend)
                    position = subend
            vendor = end
    if not found_cpu:
        raise ValueError("Missing ARM CPU baseline attribute")
    if hard_float and not found_vfp:
        raise ValueError("Missing ARM hard-float VFP argument attribute")


def verify_mips_attributes(data, segments, endian):
    offsets = [(offset, size) for kind, offset, size in segments if kind == 0x70000003]
    if len(offsets) != 1:
        raise ValueError("Expected one MIPS ABI flags segment")
    offset, size = offsets[0]
    if size != 24 or offset + size > len(data):
        raise ValueError("Malformed MIPS ABI flags segment")
    attrs = data[offset:offset + size]
    if (number(attrs, 0, 2, endian) != 0 or attrs[2:8] != bytes([32, 2, 1, 0, 0, 3])
            or number(attrs, 8, 4, endian) != 0 or number(attrs, 12, 4, endian) != 0
            or number(attrs, 16, 4, endian) & ~1 or number(attrs, 20, 4, endian) != 0):
        raise ValueError("Expected MIPS32r2 O32 soft-float ABI without ISA extensions")


def verify_abi_bytes(data, platform):
    if platform["format"] == "elf":
        endian = platform.get("endian", "little")
        if endian not in ("little", "big"):
            raise ValueError("Unknown platform byte order")
        if len(data) < 52 or data[:4] != b"\x7fELF" or data[5] != {"little": 1, "big": 2}[endian]:
            raise ValueError(f"Expected a {endian}-endian ELF executable")
        if len(data) < (64 if platform["bits"] == 64 else 52):
            raise ValueError("Truncated ELF header")
        if data[4] != {32: 1, 64: 2}[platform["bits"]]:
            raise ValueError("ELF word size does not match target")
        if number(data, 18, 2, endian) != platform["machine"]:
            raise ValueError("ELF CPU architecture does not match target")
        if number(data, 16, 2, endian) not in (2, 3):
            raise ValueError("ELF artifact is not an executable")
        if platform["bits"] == 64:
            offset = number(data, 32, 8, endian)
            entry_size, count = number(data, 54, 2, endian), number(data, 56, 2, endian)
        else:
            offset = number(data, 28, 4, endian)
            entry_size, count = number(data, 42, 2, endian), number(data, 44, 2, endian)
        if entry_size < (56 if platform["bits"] == 64 else 32) or not count or offset + entry_size * count > len(data):
            raise ValueError("Malformed ELF program header table")
        segments = []
        for index in range(count):
            header = offset + index * entry_size
            kind = number(data, header, 4, endian)
            if platform["bits"] == 64:
                file_offset, file_size = number(data, header + 8, 8, endian), number(data, header + 32, 8, endian)
            else:
                file_offset, file_size = number(data, header + 4, 4, endian), number(data, header + 16, 4, endian)
            segments.append((kind, file_offset, file_size))
        if platform["openwrt"]:
            # No PT_INTERP means there is no GNU/musl dynamic loader dependency.
            # Static PIE may have PT_DYNAMIC, so inspecting ldd output is weaker.
            if any(kind == 3 for kind, _, _ in segments):
                raise ValueError("OpenWrt artifacts must be static (unexpected PT_INTERP)")
        flags = number(data, 48 if platform["bits"] == 64 else 36, 4, endian)
        if "arm_arch" in platform:
            float_abi = platform.get("arm_float_abi", "soft")
            if float_abi not in ("soft", "hard"):
                raise ValueError("Unknown ARM float ABI")
            hard_float = float_abi == "hard"
            if hard_float and flags & 0x600 != 0x400 or not hard_float and flags & 0x400:
                raise ValueError("ARM float ABI does not match target")
            verify_arm_attributes(data, {"v5TE": 4, "v6": 6, "v7": 10}[platform["arm_arch"]], hard_float)
        elif platform["machine"] == 21 and flags & 3 != 2:
            raise ValueError("Expected PowerPC64 ELFv2 ABI")
        elif platform["machine"] == 258 and flags & 0xc7 != 0x43:
            raise ValueError("Expected LoongArch LP64D object ABI v1")
        elif platform["machine"] == 8:
            if platform["bits"] != 32 or flags & 0xf000f000 != 0x70001000 or flags & 0x0fff0660:
                raise ValueError("Expected MIPS32r2 O32 soft-float ELF flags")
            verify_mips_attributes(data, segments, endian)
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


def source_revision(root):
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    expected = os.environ.get("GITHUB_SHA")
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or (expected and expected != commit):
        raise ValueError("Source checkout does not match the build commit")
    dirty = bool(subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=normal"], cwd=root, text=True
    ).strip())
    return commit, dirty


def package(root, target, runner=(), target_dir=None):
    platform = PLATFORMS[target]
    version = tomllib.loads((root / "Cargo.toml").read_text())["package"]["version"]
    binary_name = "drcom4scut.exe" if platform["format"] == "pe" else "drcom4scut"
    target_dir = root / "target" if target_dir is None else pathlib.Path(target_dir)
    if not target_dir.is_absolute():
        target_dir = root / target_dir
    profile = platform.get("profile", "release")
    binary = target_dir / target / profile / binary_name
    if not binary.is_file():
        raise ValueError(f"Missing {profile} executable for {target}: {binary}")
    verify_abi(binary, platform)
    reported = subprocess.check_output([*runner, str(binary), "--version"], text=True).strip()
    if reported != f"drcom4scut {version}":
        raise ValueError(f"Unexpected built version: {reported!r}")
    commit, dirty = source_revision(root)
    dist = root / "dist"
    dist.mkdir(exist_ok=True)
    stem = f"drcom4scut-{version}-{target}"
    with tempfile.TemporaryDirectory() as temp:
        contents = pathlib.Path(temp) / stem
        contents.mkdir()
        (contents / "BUILD-INFO.json").write_text(json.dumps({
            "version": version, "target": target, "source_commit": commit,
            "source_dirty": dirty, "openwrt": platform["openwrt"], "build_profile": profile,
        }, indent=2) + "\n", encoding="utf-8")
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
