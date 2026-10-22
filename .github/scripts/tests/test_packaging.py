import importlib.util
import json
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


def elf(machine=62, bits=64, interpreter=False):
    data = bytearray(128)
    data[:6] = b"\x7fELF" + bytes([2 if bits == 64 else 1, 1])
    struct.pack_into("<H", data, 18, machine)
    if bits == 64:
        struct.pack_into("<Q", data, 32, 64)
        struct.pack_into("<HH", data, 54, 56, 1)
    else:
        struct.pack_into("<I", data, 28, 64)
        struct.pack_into("<HH", data, 42, 32, 1)
    struct.pack_into("<I", data, 64, 3 if interpreter else 1)
    return data


class PackagingTests(unittest.TestCase):
    def check_elf(self, target, data):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "binary"
            binary.write_bytes(data)
            package_release.verify_abi(binary, package_release.PLATFORMS[target])

    def test_every_published_elf_matches_its_target(self):
        for target, platform in package_release.PLATFORMS.items():
            if platform["format"] == "elf":
                with self.subTest(target=target):
                    self.check_elf(target, elf(platform["machine"], platform["bits"]))

    def test_mislabeled_host_binary_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "architecture"):
            self.check_elf("aarch64-unknown-linux-musl", elf())
        with self.assertRaisesRegex(ValueError, "word size"):
            self.check_elf("armv7-unknown-linux-musleabi", elf(machine=40))

    def test_openwrt_rejects_dynamic_loader_dependency(self):
        with self.assertRaisesRegex(ValueError, "static"):
            self.check_elf("x86_64-unknown-linux-musl", elf(interpreter=True))
        self.check_elf("x86_64-unknown-linux-gnu", elf(interpreter=True))

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

    def test_all_openwrt_arches_are_official_musl_targets(self):
        supported = {p["target"] for p in json.loads((ROOT / ".github/scripts/platforms.json").read_text()) if p["openwrt"]}
        self.assertEqual(len(supported), 5)
        self.assertTrue(all("musl" in target for target in supported))
        self.assertFalse(any("mips" in target for target in supported))

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
            binary = root / "target" / target / "release/drcom4scut"
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
