import importlib.util
import hashlib
import json
import io
import zipfile
from pathlib import Path
import struct
import tempfile
import tarfile
from unittest.mock import patch
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("package_release", ROOT / ".github/scripts/package_release.py")
package_release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package_release)
source_revision = package_release.source_revision
spec = importlib.util.spec_from_file_location("verify_release", ROOT / ".github/scripts/verify_release.py")
verify_release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify_release)


def elf(machine=62, bits=64, interpreter=False, *, endian="little", flags=None,
        arm_arch=None, arm_float_abi="soft", vfp_args=None, mips_abi=True, mips_float_abi="hard"):
    order = "<" if endian == "little" else ">"
    data = bytearray(128)
    data[:6] = b"\x7fELF" + bytes([2 if bits == 64 else 1, 1 if endian == "little" else 2])
    struct.pack_into(order + "HH", data, 16, 2, machine)
    if flags is None:
        flags = {8: 0x70001007, 21: 2, 258: 0x43}.get(machine, 0)
        if machine == 8 and bits == 64:
            flags = 0x80000007
        if machine == 40:
            flags = 0x05000400 if arm_float_abi == "hard" else 0x05000200
    struct.pack_into(order + "I", data, 48 if bits == 64 else 36, flags)
    if bits == 64:
        struct.pack_into(order + "Q", data, 32, 64)
        struct.pack_into(order + "HH", data, 54, 56, 1)
    else:
        struct.pack_into(order + "I", data, 28, 64)
        struct.pack_into(order + "HH", data, 42, 32, 1)
    struct.pack_into(order + "I", data, 64, 3 if interpreter else 1)
    if arm_arch is not None:
        attributes = bytes([6, arm_arch])
        if arm_float_abi == "hard" and vfp_args is None:
            vfp_args = 1
        if vfp_args is not None:
            attributes += bytes([28, vfp_args])
        file_section = b"\x01" + struct.pack("<I", len(attributes) + 5) + attributes
        vendor = b"aeabi\0" + file_section
        payload = b"A" + struct.pack("<I", len(vendor) + 4) + vendor
        data.extend(bytes(208 - len(data)) + payload)
        struct.pack_into("<I", data, 32, 128)
        struct.pack_into("<HH", data, 46, 40, 2)
        struct.pack_into("<I", data, 172, 0x70000003)
        struct.pack_into("<II", data, 184, 208, len(payload))
    if machine == 8 and mips_abi:
        if bits == 64:
            data.extend(bytes(max(0, 216 - len(data))))
            struct.pack_into(order + "H", data, 56, 2)
            struct.pack_into(order + "IIQQQQQQ", data, 120, 0x70000003, 4, 192, 0, 0, 24, 24, 8)
            struct.pack_into(order + "H6B4I", data, 192, 0, 64, 2, 2,
                             2 if mips_float_abi == "hard" else 0, 0,
                             1 if mips_float_abi == "hard" else 3, 0, 0, 0, 0)
        else:
            data.extend(bytes(max(0, 184 - len(data))))
            struct.pack_into(order + "H", data, 44, 2)
            struct.pack_into(order + "IIIIIIII", data, 96, 0x70000003, 160, 0, 0, 24, 24, 4, 8)
            struct.pack_into(order + "H6B4I", data, 160, 0, 32, 2, 1, 0, 0, 3, 0, 0, 0, 0)
    return data


def platform_elf(platform, *, wrong_cpu=False):
    return elf(62 if wrong_cpu else platform["machine"], platform["bits"],
               endian=platform.get("endian", "little"),
               arm_arch={"v5TE": 4, "v6": 6, "v7": 10}.get(platform.get("arm_arch")),
               arm_float_abi=platform.get("arm_float_abi", "soft"),
               mips_float_abi=platform.get("mips_float_abi", "hard"))


def macho(machine=16777223, filetype=2):
    # A 64-bit little-endian header and one framed LC_UUID command. The ABI
    # validator inspects metadata; executing the image is a separate smoke test.
    data = bytearray(56)
    struct.pack_into("<IIIIIIII", data, 0, 0xFEEDFACF, machine, 0, filetype, 1, 24, 0, 0)
    struct.pack_into("<II", data, 32, 0x1B, 24)
    return data


class PackagingTests(unittest.TestCase):
    def setUp(self):
        source_patch = patch.object(package_release, "source_revision", return_value=("a" * 40, False))
        source_patch.start()
        self.addCleanup(source_patch.stop)

    def test_source_metadata_rejects_wrong_checkout_and_records_local_changes(self):
        with patch.dict(package_release.os.environ, {"GITHUB_SHA": "a" * 40}):
            with patch.object(package_release.subprocess, "check_output", side_effect=["b" * 40]):
                with self.assertRaisesRegex(ValueError, "build commit"):
                    source_revision(ROOT)
            for status, dirty in (("", False), (" M src/main.rs\n", True), ("?? untracked.rs\n", True)):
                with self.subTest(status=status), patch.object(
                    package_release.subprocess, "check_output", side_effect=["a" * 40, status]
                ):
                    self.assertEqual(source_revision(ROOT), ("a" * 40, dirty))

    def write_archive(self, archive, platform, *, commit="a" * 40, dirty=False, wrong_cpu=False):
        prefix = f'drcom4scut-0.4.1-{platform["target"]}/'
        name = "drcom4scut.exe" if platform["format"] == "pe" else "drcom4scut"
        if platform["format"] == "elf":
            data = platform_elf(platform, wrong_cpu=wrong_cpu)
        elif platform["format"] == "macho":
            data = macho(platform["machine"])
        else:
            data = bytearray(128)
            data[:2] = b"MZ"
            struct.pack_into("<I", data, 60, 64)
            data[64:68] = b"PE\0\0"
            struct.pack_into("<H", data, 68, platform["machine"])
        entries = {
            prefix + name: data,
            prefix + "BUILD-INFO.json": json.dumps({
                "version": "0.4.1", "target": platform["target"], "source_commit": commit,
                "source_dirty": dirty, "openwrt": platform["openwrt"],
            }).encode(),
        }
        if archive.suffix == ".zip":
            with zipfile.ZipFile(archive, "w") as output:
                for name, data in entries.items():
                    output.writestr(name, data)
        else:
            with tarfile.open(archive, "w:gz") as output:
                for name, data in entries.items():
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    output.addfile(member, io.BytesIO(data))
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        archive.with_suffix(archive.suffix + ".sha256").write_text(f"{digest}  {archive.name}\n")
        return digest

    def check_elf(self, target, data):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "binary"
            binary.write_bytes(data)
            package_release.verify_abi(binary, package_release.PLATFORMS[target])

    def write_router_source(self, root):
        for name, contents in {
            "Cargo.toml": '[package]\nversion = "0.4.0"\n',
            "README.md": "OpenWrt fixture",
            "LICENSE": "Fixture license",
            "src/default_config.yml": "username: ''\n",
            "packaging/openwrt/files/config.yml": "username: ''\n",
            "packaging/openwrt/files/drcom4scut.init": "Fixture service",
            "packaging/openwrt/files/drcom4scut.uci": "Fixture service configuration",
            "packaging/openwrt/install.sh": "Fixture installer",
            "packaging/openwrt/install-common.sh": "Fixture installer helper",
            "packaging/openwrt/install-luci.sh": "Fixture LuCI installer",
        }.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents)

    def test_router_package_uses_selected_profile_and_never_the_release_decoy(self):
        target = "x86_64-unknown-linux-musl"
        platform = dict(package_release.PLATFORMS[target], profile="router")
        with tempfile.TemporaryDirectory() as directory, patch.dict(package_release.PLATFORMS, {target: platform}):
            root = Path(directory)
            self.write_router_source(root)
            binary = root / "build-cache" / target / "router/drcom4scut"
            decoy = root / "build-cache" / target / "release/drcom4scut"
            binary.parent.mkdir(parents=True)
            decoy.parent.mkdir(parents=True)
            binary.write_bytes(elf() + b"selected small router executable")
            decoy.write_bytes(elf() + b"stale default release executable")
            with patch.object(package_release.subprocess, "check_output", return_value="drcom4scut 0.4.0\n") as version:
                archive = package_release.package(root, target, target_dir="build-cache")
            version.assert_called_once_with([str(binary), "--version"], text=True)
            with tarfile.open(archive) as output:
                prefix = f"drcom4scut-0.4.0-{target}/"
                self.assertEqual(output.extractfile(prefix + "drcom4scut").read(), binary.read_bytes())
                info = json.load(output.extractfile(prefix + "BUILD-INFO.json"))
                self.assertEqual(info["build_profile"], "router")

    def test_missing_router_output_fails_without_falling_back_to_release(self):
        target = "x86_64-unknown-linux-musl"
        platform = dict(package_release.PLATFORMS[target], profile="router")
        with tempfile.TemporaryDirectory() as directory, patch.dict(package_release.PLATFORMS, {target: platform}):
            root = Path(directory)
            self.write_router_source(root)
            decoy = root / "target" / target / "release/drcom4scut"
            decoy.parent.mkdir(parents=True)
            decoy.write_bytes(elf())
            with patch.object(package_release.subprocess, "check_output") as version:
                with self.assertRaisesRegex(ValueError, "Missing router executable"):
                    package_release.package(root, target)
            version.assert_not_called()
            self.assertFalse((root / "dist").exists())

    def test_every_published_elf_matches_its_target(self):
        for target, platform in package_release.PLATFORMS.items():
            if platform["format"] == "elf":
                with self.subTest(target=target):
                    self.check_elf(target, platform_elf(platform))

    def test_mislabeled_host_binary_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "architecture"):
            self.check_elf("aarch64-unknown-linux-musl", elf())
        with self.assertRaisesRegex(ValueError, "word size"):
            self.check_elf("armv7-unknown-linux-musleabi", elf(machine=40))

    def test_openwrt_rejects_dynamic_loader_dependency(self):
        with self.assertRaisesRegex(ValueError, "static"):
            self.check_elf("x86_64-unknown-linux-musl", elf(interpreter=True))
        self.check_elf("x86_64-unknown-linux-gnu", elf(interpreter=True))

    def test_additional_router_cpu_endian_and_float_variants(self):
        variants = [
            {"machine": 3, "bits": 32},
            {"machine": 40, "bits": 32, "arm_arch": "v6", "arm_float_abi": "soft"},
            {"machine": 40, "bits": 32, "arm_arch": "v6", "arm_float_abi": "hard"},
            {"machine": 40, "bits": 32, "arm_arch": "v7", "arm_float_abi": "hard"},
            {"machine": 258, "bits": 64},
            {"machine": 21, "bits": 64, "endian": "big"},
            {"machine": 21, "bits": 64, "endian": "little"},
            {"machine": 8, "bits": 32, "endian": "big"},
            {"machine": 8, "bits": 32, "endian": "little"},
        ]
        for variant in variants:
            platform = dict(variant, format="elf", openwrt=True)
            with self.subTest(platform=platform):
                data = platform_elf(platform)
                package_release.verify_abi_bytes(data, platform)
                opposite = "big" if platform.get("endian", "little") == "little" else "little"
                with self.assertRaisesRegex(ValueError, "endian"):
                    package_release.verify_abi_bytes(data, dict(platform, endian=opposite))

    def test_non_executable_and_malformed_program_tables_are_rejected_for_both_endians(self):
        for endian in ("little", "big"):
            order = "<" if endian == "little" else ">"
            platform = {"machine": 21, "bits": 64, "endian": endian, "format": "elf", "openwrt": True}
            data = elf(machine=21, endian=endian)
            for offset, format, value in ((16, "H", 1), (32, "Q", 2**64 - 1), (54, "H", 4), (56, "H", 0)):
                bad = bytearray(data)
                struct.pack_into(order + format, bad, offset, value)
                with self.subTest(endian=endian, offset=offset), self.assertRaises(ValueError):
                    package_release.verify_abi_bytes(bad, platform)
            with self.assertRaisesRegex(ValueError, "static"):
                package_release.verify_abi_bytes(elf(machine=21, endian=endian, interpreter=True), platform)

    def test_powerpc_elfv1_and_loongarch_wrong_float_or_object_abi_are_rejected(self):
        for endian in ("little", "big"):
            platform = {"machine": 21, "bits": 64, "endian": endian, "format": "elf", "openwrt": True}
            for flags in (0, 1, 3):
                with self.subTest(endian=endian, flags=flags), self.assertRaisesRegex(ValueError, "ELFv2"):
                    package_release.verify_abi_bytes(elf(machine=21, endian=endian, flags=flags), platform)
        platform = {"machine": 258, "bits": 64, "format": "elf", "openwrt": True}
        for flags in (0x41, 0x42, 0x03, 0x83):
            with self.subTest(flags=flags), self.assertRaisesRegex(ValueError, "LP64D"):
                package_release.verify_abi_bytes(elf(machine=258, flags=flags), platform)

    def test_arm_cpu_and_vfp_arguments_are_checked_in_archive_abi_validation(self):
        soft = {"machine": 40, "bits": 32, "format": "elf", "openwrt": True, "arm_arch": "v6"}
        hard = dict(soft, arm_float_abi="hard")
        for arch in (4, 10):
            with self.subTest(arch=arch), self.assertRaisesRegex(ValueError, "CPU baseline"):
                package_release.verify_abi_bytes(elf(machine=40, bits=32, arm_arch=arch), soft)
        with self.assertRaisesRegex(ValueError, "attributes"):
            package_release.verify_abi_bytes(elf(machine=40, bits=32), soft)
        with self.assertRaisesRegex(ValueError, "VFP argument"):
            package_release.verify_abi_bytes(elf(machine=40, bits=32, arm_arch=6, vfp_args=1), soft)
        for flags in (0x05000200, 0x05000600):
            with self.subTest(flags=flags), self.assertRaisesRegex(ValueError, "float ABI"):
                package_release.verify_abi_bytes(elf(machine=40, bits=32, flags=flags, arm_arch=6, arm_float_abi="hard"), hard)
        with self.assertRaisesRegex(ValueError, "Missing ARM hard-float"):
            package_release.verify_abi_bytes(elf(machine=40, bits=32, flags=0x05000400, arm_arch=6), hard)
        for value in (0, 3):
            with self.subTest(vfp=value), self.assertRaisesRegex(ValueError, "VFP argument"):
                package_release.verify_abi_bytes(elf(machine=40, bits=32, arm_arch=6, arm_float_abi="hard", vfp_args=value), hard)
        malformed = elf(machine=40, bits=32, arm_arch=6)
        struct.pack_into("<I", malformed, 209, 0)
        with self.assertRaisesRegex(ValueError, "vendor attributes"):
            package_release.verify_abi_bytes(malformed, soft)

    def test_mips_requires_o32_mips32r2_soft_float_without_extensions(self):
        for endian in ("little", "big"):
            order = "<" if endian == "little" else ">"
            platform = {"machine": 8, "bits": 32, "endian": endian, "format": "elf", "openwrt": True}
            for flags in (0x50001007, 0x70003007, 0x70001027, 0x70001047,
                          0x70001207, 0x70001407, 0x71001007, 0x70011007):
                with self.subTest(endian=endian, flags=flags), self.assertRaisesRegex(ValueError, "MIPS32r2"):
                    package_release.verify_abi_bytes(elf(machine=8, bits=32, endian=endian, flags=flags), platform)
            for offset, format, value in ((0, "H", 1), (2, "B", 64), (3, "B", 1), (4, "B", 2),
                                          (5, "B", 1), (6, "B", 1), (7, "B", 1), (8, "I", 1),
                                          (12, "I", 1), (16, "I", 2), (20, "I", 1)):
                bad = elf(machine=8, bits=32, endian=endian)
                struct.pack_into(order + format, bad, 160 + offset, value)
                with self.subTest(endian=endian, offset=offset), self.assertRaisesRegex(ValueError, "soft-float ABI"):
                    package_release.verify_abi_bytes(bad, platform)

    def test_mips_allows_defined_oddspreg_metadata_with_soft_float(self):
        # LLVM emits ODDSPREG even for O32 soft-float with no CP1 registers.
        for endian in ("little", "big"):
            order = "<" if endian == "little" else ">"
            platform = {"machine": 8, "bits": 32, "endian": endian, "format": "elf", "openwrt": True}
            data = elf(machine=8, bits=32, endian=endian)
            struct.pack_into(order + "I", data, 176, 1)
            package_release.verify_abi_bytes(data, platform)

    def test_mips_missing_duplicate_truncated_or_unbounded_abi_flags_are_rejected(self):
        for endian in ("little", "big"):
            order = "<" if endian == "little" else ">"
            platform = {"machine": 8, "bits": 32, "endian": endian, "format": "elf", "openwrt": True}
            with self.assertRaisesRegex(ValueError, "one MIPS"):
                package_release.verify_abi_bytes(elf(machine=8, bits=32, endian=endian, mips_abi=False), platform)
            duplicate = elf(machine=8, bits=32, endian=endian)
            duplicate[64:96] = duplicate[96:128]
            with self.assertRaisesRegex(ValueError, "one MIPS"):
                package_release.verify_abi_bytes(duplicate, platform)
            for offset, value in ((100, 2**32 - 1), (112, 23), (112, 25)):
                bad = elf(machine=8, bits=32, endian=endian)
                struct.pack_into(order + "I", bad, offset, value)
                with self.subTest(endian=endian, offset=offset, value=value), self.assertRaisesRegex(ValueError, "Malformed MIPS"):
                    package_release.verify_abi_bytes(bad, platform)
            with self.assertRaisesRegex(ValueError, "Malformed MIPS"):
                package_release.verify_abi_bytes(elf(machine=8, bits=32, endian=endian)[:-1], platform)

    def test_mips64_requires_n64_mips64r2_hard_double_float_without_extensions(self):
        for endian in ("little", "big"):
            order = "<" if endian == "little" else ">"
            platform = {"machine": 8, "bits": 64, "endian": endian, "format": "elf", "openwrt": True}
            good = elf(machine=8, bits=64, endian=endian)
            package_release.verify_abi_bytes(good, platform)
            struct.pack_into(order + "I", good, 208, 1)
            package_release.verify_abi_bytes(good, platform)
            for flags in (0x70001007, 0xa0000007, 0x80001007, 0x80002007, 0x80000027,
                          0x80000047, 0x80000107, 0x80000207, 0x80000407, 0x81000007):
                with self.subTest(endian=endian, flags=flags), self.assertRaisesRegex(ValueError, "MIPS64r2"):
                    package_release.verify_abi_bytes(elf(machine=8, bits=64, endian=endian, flags=flags), platform)
            for offset, format, value in ((0, "H", 1), (2, "B", 32), (3, "B", 6), (4, "B", 1),
                                          (5, "B", 0), (5, "B", 1), (6, "B", 1), (7, "B", 2), (7, "B", 3),
                                          (8, "I", 1), (12, "I", 1), (16, "I", 2), (20, "I", 1)):
                bad = elf(machine=8, bits=64, endian=endian)
                struct.pack_into(order + format, bad, 192 + offset, value)
                with self.subTest(endian=endian, offset=offset, value=value), self.assertRaisesRegex(ValueError, "MIPS64r2"):
                    package_release.verify_abi_bytes(bad, platform)
            with self.assertRaises(ValueError):
                package_release.verify_abi_bytes(elf(machine=8, bits=32, endian=endian), platform)

    def test_mips64_requires_unique_bounded_full_width_abi_segment(self):
        for endian in ("little", "big"):
            order = "<" if endian == "little" else ">"
            platform = {"machine": 8, "bits": 64, "endian": endian, "format": "elf", "openwrt": True}
            with self.assertRaisesRegex(ValueError, "one MIPS"):
                package_release.verify_abi_bytes(elf(machine=8, bits=64, endian=endian, mips_abi=False), platform)
            duplicate = elf(machine=8, bits=64, endian=endian)
            duplicate[64:120] = duplicate[120:176]
            with self.assertRaisesRegex(ValueError, "one MIPS"):
                package_release.verify_abi_bytes(duplicate, platform)
            for offset, value in ((128, 2**32 + 192), (128, 2**64 - 1), (152, 23),
                                  (152, 25), (152, 2**32 + 24)):
                bad = elf(machine=8, bits=64, endian=endian)
                struct.pack_into(order + "Q", bad, offset, value)
                with self.subTest(endian=endian, offset=offset, value=value), self.assertRaisesRegex(ValueError, "Malformed MIPS"):
                    package_release.verify_abi_bytes(bad, platform)
            with self.assertRaisesRegex(ValueError, "Malformed MIPS"):
                package_release.verify_abi_bytes(elf(machine=8, bits=64, endian=endian)[:-1], platform)

    def test_mips64_soft_float_and_hard_float_are_not_interchangeable(self):
        for endian in ("little", "big"):
            platform = {"machine": 8, "bits": 64, "endian": endian, "format": "elf", "openwrt": True}
            for float_abi, other in (("soft", "hard"), ("hard", "soft")):
                expected = platform | {"mips_float_abi": float_abi}
                data = elf(machine=8, bits=64, endian=endian, mips_float_abi=float_abi)
                package_release.verify_abi_bytes(data, expected)
                with self.subTest(endian=endian, float_abi=float_abi), self.assertRaisesRegex(ValueError, "MIPS64r2"):
                    package_release.verify_abi_bytes(data, platform | {"mips_float_abi": other})
            with self.assertRaisesRegex(ValueError, "Unknown MIPS float ABI"):
                package_release.verify_abi_bytes(data, platform | {"mips_float_abi": "single"})

    def test_truncated_or_wrong_endian_header_is_rejected(self):
        for data in [b"", b"\x7fELF", bytes(128), elf()[:60]]:
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                self.check_elf("x86_64-unknown-linux-musl", data)
        data = elf()
        data[5] = 2
        with self.assertRaises(ValueError):
            self.check_elf("x86_64-unknown-linux-musl", data)

    def test_windows_pe_machine_must_match_x64(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "client.exe"
            data = bytearray(128)
            data[:2] = b"MZ"
            struct.pack_into("<I", data, 60, 64)
            data[64:68] = b"PE\0\0"
            struct.pack_into("<H", data, 68, 34404)
            binary.write_bytes(data)
            platform = package_release.PLATFORMS["x86_64-pc-windows-msvc"]
            package_release.verify_abi(binary, platform)
            struct.pack_into("<H", data, 68, 43620)
            binary.write_bytes(data)
            with self.assertRaisesRegex(ValueError, "architecture"):
                package_release.verify_abi(binary, platform)
            binary.write_bytes(data[:65])
            with self.assertRaisesRegex(ValueError, "PE header"):
                package_release.verify_abi(binary, platform)

    def test_windows_arm64_rejects_the_x64_imported_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "client.exe"
            data = bytearray(128)
            data[:2] = b"MZ"
            struct.pack_into("<I", data, 60, 64)
            data[64:68] = b"PE\0\0"
            struct.pack_into("<H", data, 68, 43620)
            binary.write_bytes(data)
            platform = package_release.PLATFORMS["aarch64-pc-windows-msvc"]
            package_release.verify_abi(binary, platform)
            struct.pack_into("<H", data, 68, 34404)
            binary.write_bytes(data)
            with self.assertRaisesRegex(ValueError, "architecture"):
                package_release.verify_abi(binary, platform)

    def test_macos_native_cpu_and_executable_type_are_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "client"
            for target in ("x86_64-apple-darwin", "aarch64-apple-darwin"):
                platform = package_release.PLATFORMS[target]
                with self.subTest(target=target):
                    binary.write_bytes(macho(platform["machine"]))
                    package_release.verify_abi(binary, platform)
                    other = 16777228 if platform["machine"] == 16777223 else 16777223
                    binary.write_bytes(macho(other))
                    with self.assertRaisesRegex(ValueError, "architecture"):
                        package_release.verify_abi(binary, platform)
                    for filetype in (1, 6):  # MH_OBJECT and MH_DYLIB are not applications.
                        binary.write_bytes(macho(platform["machine"], filetype))
                        with self.assertRaisesRegex(ValueError, "not an executable"):
                            package_release.verify_abi(binary, platform)

    def test_macos_rejects_fat_32_bit_wrong_endian_and_truncated_images(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "client"
            platform = package_release.PLATFORMS["x86_64-apple-darwin"]
            for data in (b"", macho()[:31], b"\xca\xfe\xba\xbe" + bytes(60),
                         b"\xce\xfa\xed\xfe" + bytes(60), b"\xfe\xed\xfa\xcf" + bytes(60)):
                with self.subTest(header=data[:4]):
                    binary.write_bytes(data)
                    with self.assertRaisesRegex(ValueError, "Mach-O64"):
                        package_release.verify_abi(binary, platform)

    def test_macos_rejects_malformed_load_command_frames(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "client"
            platform = package_release.PLATFORMS["x86_64-apple-darwin"]
            for offset, value in ((16, 100), (20, 40), (20, 16), (36, 0), (36, 10), (36, 32)):
                data = macho()
                struct.pack_into("<I", data, offset, value)
                with self.subTest(offset=offset, value=value):
                    binary.write_bytes(data)
                    with self.assertRaisesRegex(ValueError, "load command"):
                        package_release.verify_abi(binary, platform)

    def test_desktop_targets_have_native_runners_and_matching_executable_formats(self):
        native = {
            "x86_64-unknown-linux-gnu": ("ubuntu-24.04", "elf"),
            "aarch64-unknown-linux-gnu": ("ubuntu-24.04-arm", "elf"),
            "x86_64-apple-darwin": ("macos-15-intel", "macho"),
            "aarch64-apple-darwin": ("macos-15", "macho"),
            "x86_64-pc-windows-msvc": ("windows-latest", "pe"),
            "aarch64-pc-windows-msvc": ("windows-11-arm", "pe"),
        }
        for target, (runner, format) in native.items():
            with self.subTest(target=target):
                platform = package_release.PLATFORMS[target]
                self.assertEqual((platform["runner"], platform["format"]), (runner, format))
                self.assertFalse(platform.get("emulator"))
                self.assertFalse(platform["openwrt"])
        self.assertEqual({p["target"] for p in package_release.PLATFORMS.values() if not p["openwrt"]}, set(native))
        self.assertEqual(package_release.PLATFORMS["x86_64-pc-windows-msvc"]["npcap_arch"], "x64")
        self.assertEqual(package_release.PLATFORMS["aarch64-pc-windows-msvc"]["npcap_arch"], "ARM64")

    def test_macos_release_is_a_tar_archive_with_the_executable_and_offline_docs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "docs").mkdir()
            (root / "Cargo.toml").write_text('[package]\nversion = "0.4.1"\n')
            (root / "README.md").write_text("[macOS](docs/macos.md)")
            (root / "LICENSE").write_text("Fixture license")
            (root / "src/default_config.yml").write_text("username: ''\n")
            (root / "docs/macos.md").write_text("macOS permissions and use")
            target = "aarch64-apple-darwin"
            binary = root / "target" / target / "release/drcom4scut"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(macho(16777228))
            binary.chmod(0o755)
            decoy = root / "target" / target / "router/drcom4scut"
            decoy.parent.mkdir(parents=True)
            decoy.write_bytes(macho(16777228) + b"unused router profile")
            with patch.object(package_release.subprocess, "check_output", return_value="drcom4scut 0.4.1\n") as version:
                archive = package_release.package(root, target)
            version.assert_called_once_with([str(binary), "--version"], text=True)
            self.assertTrue(archive.name.endswith(".tar.gz"))
            with tarfile.open(archive) as output:
                prefix = f"drcom4scut-0.4.1-{target}/"
                self.assertEqual(output.extractfile(prefix + "drcom4scut").read(), binary.read_bytes())
                self.assertEqual(output.getmember(prefix + "drcom4scut").mode & 0o111, 0o111)
                self.assertEqual(output.extractfile(prefix + "docs/macos.md").read(), b"macOS permissions and use")
                self.assertFalse(any("openwrt/" in member.name for member in output.getmembers()))
                self.assertEqual(json.load(output.extractfile(prefix + "BUILD-INFO.json"))["build_profile"], "release")

    def test_release_verification_requires_every_native_and_router_platform(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".github/scripts").mkdir(parents=True)
            (root / "Cargo.toml").write_text('[package]\nversion = "0.4.1"\n')
            manifest = ROOT / ".github/scripts/platforms.json"
            (root / ".github/scripts/platforms.json").write_bytes(manifest.read_bytes())
            dist = root / "dist"
            dist.mkdir()
            expected = {}
            for platform in json.loads(manifest.read_text()):
                suffix = ".zip" if platform["format"] == "pe" else ".tar.gz"
                archive = dist / f'drcom4scut-0.4.1-{platform["target"]}{suffix}'
                digest = self.write_archive(archive, platform)
                expected[archive.name] = digest
                archive.with_suffix(archive.suffix + ".sha256").write_text(f"{digest}  {archive.name}\n")
            missing = dist / "drcom4scut-0.4.1-aarch64-apple-darwin.tar.gz"
            contents = missing.read_bytes()
            missing.unlink()
            with self.assertRaisesRegex(SystemExit, "Missing regular"):
                verify_release.verify(root, source_commit="a" * 40)
            self.assertFalse((dist / "SHA256SUMS").exists())
            missing.write_bytes(contents)
            verify_release.verify(root, source_commit="a" * 40)
            actual = {name: digest for digest, name in (
                line.split("  ", 1) for line in (dist / "SHA256SUMS").read_text().splitlines()
            )}
            self.assertEqual(actual, expected)
            self.assertEqual(len(actual), len(json.loads(manifest.read_text())))
            affected = json.loads(manifest.read_text())[2]
            invalid = dist / f'drcom4scut-0.4.1-{affected["target"]}.tar.gz'
            original = invalid.read_bytes()
            original_sum = invalid.with_suffix(".gz.sha256").read_bytes()
            for changes, message in (({"commit": "b" * 40}, "validated source"),
                                     ({"dirty": True}, "modified source"),
                                     ({"wrong_cpu": True}, "architecture")):
                with self.subTest(changes=changes):
                    self.write_archive(invalid, affected, **changes)
                    with self.assertRaisesRegex(SystemExit, message):
                        verify_release.verify(root, source_commit="a" * 40)
            invalid.write_bytes(original)
            invalid.with_suffix(".gz.sha256").write_bytes(original_sum)
            missing.write_bytes(b"changed after validation")
            with self.assertRaisesRegex(SystemExit, "Checksum"):
                verify_release.verify(root, source_commit="a" * 40)

    def test_release_contains_offline_linked_docs_changelog_and_root_owned_members(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "docs").mkdir()
            (root / "Cargo.toml").write_text('[package]\nversion = "0.4.0"\n')
            (root / "README.md").write_text('[Development](docs/development.md)')
            (root / "LICENSE").write_text('fixture license')
            (root / "src/default_config.yml").write_text('username: ""')
            (root / "docs/development.md").write_text('Offline developer guide')
            (root / "CHANGELOG.md").write_text('Version 0.4.0 changes')
            target = "x86_64-unknown-linux-gnu"
            binary = root / "target" / target / "release/drcom4scut"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(elf())
            with patch.object(package_release.subprocess, "check_output", return_value="drcom4scut 0.4.0\n"):
                archive = package_release.package(root, target)
            with tarfile.open(archive) as output:
                members = output.getmembers()
                prefix = f"drcom4scut-0.4.0-{target}/"
                names = {item.name for item in members}
                self.assertIn(prefix + "docs/development.md", names)
                self.assertIn(prefix + "CHANGELOG.md", names)
                self.assertTrue(all(item.uid == 0 and item.gid == 0 for item in members))
                self.assertEqual(output.extractfile(prefix + "docs/development.md").read(), b"Offline developer guide")
            self.assertTrue(archive.with_suffix(archive.suffix + ".sha256").is_file())

    def test_router_manifest_selects_static_musl_profile_and_explicit_float_abi(self):
        supported = [p for p in json.loads((ROOT / ".github/scripts/platforms.json").read_text()) if p["openwrt"]]
        self.assertTrue(supported)
        for platform in supported:
            with self.subTest(target=platform["target"]):
                self.assertIn("musl", platform["target"])
                self.assertEqual(platform["profile"], "router")
                if platform["target"].endswith("eabihf"):
                    self.assertEqual(platform["arm_float_abi"], "hard")
                elif platform["machine"] == 40:
                    self.assertEqual(platform.get("arm_float_abi", "soft"), "soft")
                self.assertIn(platform.get("endian", "little"), ("little", "big"))

    def test_openwrt_bundle_requires_and_ships_the_default_installation_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, contents in {
                "Cargo.toml": '[package]\nversion = "0.4.0"\n',
                "README.md": "[OpenWrt](docs/openwrt.md)",
                "LICENSE": "Fixture license",
                "src/default_config.yml": "username: ''\n",
                "docs/openwrt.md": "[Configuration](configuration.md)",
                "docs/configuration.md": "Configuration guide",
            }.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents)
            bundle = root / "packaging/openwrt"
            for name in (
                "files/drcom4scut.init", "files/drcom4scut.uci",
                "install.sh", "install-common.sh", "install-luci.sh",
            ):
                path = bundle / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("Fixture installation resource")
            target = "x86_64-unknown-linux-musl"
            profile = package_release.PLATFORMS[target].get("profile", "release")
            binary = root / "target" / target / profile / "drcom4scut"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(elf())
            with patch.object(package_release.subprocess, "check_output", return_value="drcom4scut 0.4.0\n"):
                with self.assertRaisesRegex(ValueError, "files/config.yml"):
                    package_release.package(root, target)
                (bundle / "files/config.yml").write_text("username: ''\n")
                archive = package_release.package(root, target)
            with tarfile.open(archive) as output:
                prefix = f"drcom4scut-0.4.0-{target}/"
                self.assertEqual(output.extractfile(prefix + "openwrt/files/config.yml").read(), b"username: ''\n")
                self.assertEqual(output.extractfile(prefix + "docs/openwrt.md").read(), b"[Configuration](configuration.md)")
                self.assertIn(b"docs/openwrt.md", output.extractfile(prefix + "OPENWRT.md").read())


if __name__ == "__main__":
    unittest.main()
