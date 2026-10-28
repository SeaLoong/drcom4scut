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
            data = elf(62 if wrong_cpu else platform["machine"], platform["bits"])
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
            self.assertEqual(len(actual), 11)
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
