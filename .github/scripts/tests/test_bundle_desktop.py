"""Exercise counterpart selection, hostile archives, native layouts and release gates."""
import copy
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parent if HERE.name == "tests" else HERE
spec = importlib.util.spec_from_file_location("bundle_desktop", SCRIPTS / "bundle_desktop.py")
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)
SHA = "a" * 40
OTHER = "b" * 40


def binary(runtime):
    data = bytearray(128)
    kind, machine = bundle.PLATFORMS[runtime][2:4]
    if kind == "pe":
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 60, 64)
        data[64:68] = b"PE\0\0"
        struct.pack_into("<H", data, 68, machine)
        struct.pack_into("<H", data, 88, 0x20b)
    elif kind == "elf":
        data[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<HH", data, 16, 3, machine)
    else:
        data[:4] = b"\xcf\xfa\xed\xfe"
        struct.pack_into("<I", data, 4, machine)
        struct.pack_into("<I", data, 12, 2)
    return bytes(data)


def component(parent, repository, runtime, sha):
    version = "0.5.1" if repository == bundle.CORE else "3.1.1"
    root = parent / repository.split("/")[1]
    root.mkdir(parents=True)
    metadata = {"version": version, "source_commit": sha, "source_dirty": False}
    exe = ("drcom4scut" if repository == bundle.CORE else "drcom4scutGUI") + (".exe" if runtime.startswith("win-") else "")
    payload = root
    if repository == bundle.CORE:
        metadata.update(target=bundle.PLATFORMS[runtime][1], openwrt=False)
        (root / "config.example.yml").write_text("username: ''\npassword: ''\n")
    else:
        metadata.update(runtime=runtime, minimum_core_version="0.5.0", self_contained=True, core_included=False)
        payload = bundle.payload_path(root, runtime)
        payload.mkdir(parents=True, exist_ok=True)
        for name in ("drcom4scutGUI.Core.dll", "drcom4scutGUI.dll", "drcom4scutGUI.runtimeconfig.json", "drcom4scutGUI.deps.json"):
            (payload / name).write_bytes(b"managed runtime payload")
        if runtime.startswith("osx-"):
            launcher = root / "drcom4scutGUI.app/Contents/MacOS/drcom4scutGUI"
            launcher.parent.mkdir(parents=True)
            launcher.write_bytes(binary(runtime)); launcher.chmod(0o755)
            (root / "drcom4scutGUI.app/Contents/sealed-resource").write_bytes(b"retain signature bytes")
    (payload / exe).write_bytes(binary(runtime)); (payload / exe).chmod(0o755)
    (root / "docs").mkdir(); (root / "docs/help.md").write_text("offline help")
    bundle.json_write(root / "BUILD-INFO.json", metadata)
    return root, metadata


def make_bundle(parent, runtime, owner=bundle.CORE, release_id=17):
    roots, provenance = {}, {}
    for repository, key in ((bundle.CORE, "core"), (bundle.GUI, "gui")):
        sha = SHA if repository == owner else OTHER
        root, metadata = component(parent / "components", repository, runtime, sha)
        roots[repository] = root
        provenance[key] = {"repository": repository, "source_commit": sha, "build": metadata,
                           "archive": bundle.archive_name(repository, metadata["version"], runtime), "sha256": "c" * 64}
        if repository != owner:
            provenance[key]["release"] = {"release_id": release_id, "tag": f"preview-{release_id}-1-bbbbbbbb", "published_at": "2026-10-23T12:00:00Z", "prerelease": True}
    return bundle.assemble(roots[bundle.CORE], roots[bundle.GUI], parent / "combined", runtime, provenance), provenance


class DesktopBundleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_latest_uses_publication_time_including_prereleases_not_tag_or_api_order(self):
        old = {"id": 50, "draft": False, "published_at": "2026-10-21T00:00:00Z", "prerelease": False, "tag_name": "v99.0.0"}
        new = dict(old, id=12, published_at="2026-10-23T00:00:00Z", prerelease=True, tag_name="preview-1")
        draft = dict(new, id=100, draft=True, published_at="2027-01-01T00:00:00Z")
        self.assertEqual(bundle.latest_published([draft, old, new]), new)
        self.assertEqual(bundle.latest_published([new, old]), new)
        with self.assertRaises(ValueError): bundle.latest_published([draft])
        with self.assertRaises(ValueError): bundle.latest_published([dict(new, published_at="2026-10-23")])

    def release(self, repository=bundle.GUI):
        version = "3.1.1" if repository == bundle.GUI else "0.5.1"
        names = [bundle.archive_name(repository, version, runtime) for runtime in bundle.PLATFORMS] + ["SHA256SUMS"]
        return {"id": 17, "draft": False, "prerelease": True, "published_at": "2026-10-23T00:00:00Z", "tag_name": "preview-17-1-bbbbbbbb",
                "assets": [{"id": i+1, "name": name, "size": 123, "state": "uploaded", "digest": "sha256:" + "c" * 64} for i,name in enumerate(names)]}

    def test_resolve_pins_all_six_standalone_assets_and_annotated_tag_commit(self):
        for owner, counterpart in ((bundle.CORE, bundle.GUI), (bundle.GUI, bundle.CORE)):
            with self.subTest(owner=owner), patch.object(bundle.subprocess, "check_output", return_value=json.dumps([[self.release(counterpart)]]).encode()), patch.object(bundle, "query", side_effect=[{"object": {"type": "tag", "sha": "c" * 40}}, {"object": {"type": "commit", "sha": OTHER}}]):
                lock = bundle.resolve(owner, self.root / "lock.json")
            self.assertEqual(lock["repository"], counterpart)
            self.assertEqual(lock["source_commit"], OTHER)
            self.assertEqual(len(lock["assets"]), 7)
            self.assertTrue(lock["prerelease"])
            self.assertFalse(any("-desktop-" in name for name in lock["assets"]))

    def test_newest_incomplete_or_undigested_release_never_falls_back(self):
        old = self.release(); old.update(id=16, published_at="2026-10-22T00:00:00Z")
        for change in ("missing", "digest", "duplicate", "bundle-only"):
            new = self.release()
            if change == "missing": new["assets"].pop(0)
            elif change == "digest": new["assets"][0]["digest"] = None
            elif change == "duplicate": new["assets"].append(copy.deepcopy(new["assets"][0]))
            else: new["assets"] = [{"name": "drcom4scut-desktop-core-0.5.1-gui-3.1.1-win-x64.zip"}]
            with self.subTest(change=change), patch.object(bundle.subprocess, "check_output", return_value=json.dumps([[old], [new]]).encode()), self.assertRaises((ValueError, TypeError)):
                bundle.resolve(bundle.CORE, self.root / "lock.json")
        self.assertFalse((self.root / "lock.json").exists())

    def test_download_requires_pinned_size_and_digest(self):
        data = b"counterpart content"
        lock = {"repository": bundle.GUI, "assets": {"x.zip": {"id": 9, "size": len(data), "digest": "sha256:" + "0" * 64}}}
        def download(*args, **kwargs): kwargs["stdout"].write(data)
        with patch.object(bundle.subprocess, "run", side_effect=download), self.assertRaisesRegex(ValueError, "pinned digest"):
            bundle.fetch_asset(lock, "x.zip", self.root / "x.zip")

    def test_tar_and_zip_reject_escaping_reserved_and_case_colliding_paths(self):
        for extension in ("zip", "tar.gz"):
            for names in (("../outside",), ("/absolute",), ("root/C:\\escape",), ("root/CON.txt",), ("root/file.",), ("root/Foo", "root/foo")):
                archive = self.root / ("bad." + extension)
                if extension == "zip":
                    with zipfile.ZipFile(archive, "w") as stream:
                        for name in names: stream.writestr(name, b"data")
                else:
                    with tarfile.open(archive, "w:gz") as stream:
                        for name in names:
                            item = tarfile.TarInfo(name); item.size = 4
                            stream.addfile(item, io.BytesIO(b"data"))
                with self.subTest(extension=extension, names=names), self.assertRaises(ValueError):
                    bundle.unpack(archive, self.root / "extracted")
                shutil.rmtree(self.root / "extracted")
        self.assertFalse((self.root / "outside").exists())

    def test_tar_rejects_oversized_header_before_reading_the_file_body(self):
        header = tarfile.TarInfo("root/bomb"); header.size = bundle.MAX_EXTRACTED + 1
        archive = self.root / "oversized.tar.gz"
        # Deliberately omit the giant body: the size guard must run before tar
        # attempts to read it (which would otherwise raise a truncated ReadError).
        archive.write_bytes(gzip.compress(header.tobuf() + b"\0" * 1024))
        with self.assertRaisesRegex(ValueError, "size limit"):
            bundle.unpack(archive, self.root / "extracted")

    def test_tar_links_and_zip_symlinks_and_expansion_are_rejected(self):
        archive = self.root / "link.tar.gz"
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE):
            with tarfile.open(archive, "w:gz") as stream:
                item = tarfile.TarInfo("root/link"); item.type = kind; item.linkname = "../../outside"
                stream.addfile(item)
            with self.assertRaisesRegex(ValueError, "special"):
                bundle.unpack(archive, self.root / "extracted")
            shutil.rmtree(self.root / "extracted")
        archive = self.root / "link.zip"
        with zipfile.ZipFile(archive, "w") as stream:
            item = zipfile.ZipInfo("root/link"); item.external_attr = (stat.S_IFLNK | 0o777) << 16
            stream.writestr(item, "../../outside")
        with self.assertRaisesRegex(ValueError, "special"): bundle.unpack(archive, self.root / "extracted")
        shutil.rmtree(self.root / "extracted")
        with zipfile.ZipFile(archive, "w") as stream: stream.writestr("root/file", b"x" * 10)
        with patch.object(bundle, "MAX_EXTRACTED", 5), self.assertRaisesRegex(ValueError, "size limit"):
            bundle.unpack(archive, self.root / "extracted")

    def test_six_native_layouts_roundtrip_and_preserve_mac_app_bytes(self):
        for runtime in bundle.PLATFORMS:
            if os.name == "nt" and not runtime.startswith("win-"):
                continue  # Windows cannot round-trip POSIX executable bits.
            with self.subTest(runtime=runtime):
                root, info = make_bundle(self.root / runtime, runtime)
                self.assertTrue((root / "开始使用.txt").is_file())
                self.assertTrue((root / "config.example.yml").is_file())
                core = root / ("drcom4scut.exe" if runtime.startswith("win-") else "drcom4scut")
                self.assertTrue(core.is_file())
                self.assertFalse((root / "core-help" / core.name).exists())
                if runtime.startswith("osx-"):
                    self.assertEqual((root / "drcom4scutGUI.app/Contents/sealed-resource").read_bytes(), b"retain signature bytes")
                    self.assertFalse((bundle.payload_path(root, runtime) / "drcom4scut").exists())
                archive = bundle.pack(root, self.root / "dist", runtime)
                extracted = bundle.unpack(archive, self.root / ("roundtrip-" + runtime))
                self.assertEqual(bundle.inspect_bundle(extracted, bundle.CORE, SHA, runtime)["core"], info["core"])

    @unittest.skipIf(os.name == "nt", "POSIX archive execute bits are tested on Linux and macOS")
    def test_component_source_architecture_executability_and_runtime_metadata_are_checked(self):
        root, metadata = component(self.root, bundle.GUI, "linux-x64", OTHER)
        self.assertEqual(bundle.inspect_component(root, bundle.GUI, "3.1.1", OTHER, "linux-x64"), metadata)
        for field,value in (("source_dirty", True), ("runtime", "linux-arm64"), ("core_included", True), ("self_contained", False), ("source_commit", SHA)):
            bundle.json_write(root / "BUILD-INFO.json", dict(metadata, **{field:value}))
            with self.subTest(field=field), self.assertRaises(ValueError): bundle.inspect_component(root, bundle.GUI, "3.1.1", OTHER, "linux-x64")
        bundle.json_write(root / "BUILD-INFO.json", metadata)
        (root / "drcom4scutGUI").write_bytes(binary("linux-arm64"))
        with self.assertRaisesRegex(ValueError, "architecture"): bundle.inspect_component(root, bundle.GUI, "3.1.1", OTHER, "linux-x64")
        (root / "drcom4scutGUI").write_bytes(binary("linux-x64")); (root / "drcom4scutGUI").chmod(0o644)
        with self.assertRaisesRegex(ValueError, "permission"): bundle.inspect_component(root, bundle.GUI, "3.1.1", OTHER, "linux-x64")

    def test_incompatible_latest_core_is_not_reinterpreted_or_downgraded(self):
        for version in ("0.3.1", "0.5.0-rc.1"):
            with self.subTest(version=version), self.assertRaisesRegex(ValueError, "refusing an older fallback"):
                bundle.compatible({"version": version}, {"minimum_core_version": "0.5.0"})
        bundle.compatible({"version": "0.5.1"}, {"minimum_core_version": "0.5.0"})

    def test_bundle_rejects_altered_files_and_wrong_workflow_source(self):
        root, _ = make_bundle(self.root, "linux-x64")
        with self.assertRaisesRegex(ValueError, "workflow"): bundle.inspect_bundle(root, bundle.CORE, OTHER, "linux-x64")
        (root / "drcom4scutGUI.Core.dll").write_bytes(b"replaced managed integration assembly")
        with self.assertRaisesRegex(ValueError, "verified component contents"): bundle.inspect_bundle(root, bundle.CORE, SHA, "linux-x64")

    def make_matrix(self, mixed=False):
        dist = self.root / "dist"; dist.mkdir()
        standalone = dist / "standalone.tar.gz"; standalone.write_bytes(b"already validated standalone")
        (dist / "SHA256SUMS").write_text(f"{bundle.digest(standalone)}  {standalone.name}\n")
        for i,runtime in enumerate(bundle.PLATFORMS):
            root, _ = make_bundle(self.root / runtime, runtime, release_id=18 if mixed and i == 5 else 17)
            bundle.pack(root, dist, runtime)
        return dist

    @unittest.skipIf(os.name == "nt", "POSIX archive execute bits are tested on Linux and macOS")
    def test_aggregate_requires_six_pinned_bundles_and_keeps_standalone_assets(self):
        dist = self.make_matrix()
        index = bundle.aggregate(bundle.CORE, SHA, dist)
        self.assertEqual(set(index), set(bundle.PLATFORMS))
        self.assertEqual(len(bundle.read_checksums(dist / "SHA256SUMS")), 7)
        self.assertEqual(json.loads((dist / "BUNDLE-INDEX.json").read_text()), index)

    @unittest.skipIf(os.name == "nt", "POSIX archive execute bits are tested on Linux and macOS")
    def test_aggregate_rejects_mixed_counterpart_releases(self):
        with self.assertRaisesRegex(ValueError, "different counterpart"): bundle.aggregate(bundle.CORE, SHA, self.make_matrix(mixed=True))

    @unittest.skipIf(os.name == "nt", "POSIX archive execute bits are tested on Linux and macOS")
    def test_aggregate_rejects_missing_runtime_and_corrupt_archive(self):
        dist = self.make_matrix()
        archive = next(dist.glob("*-win-x64.zip"))
        original = archive.read_bytes(); archive.unlink()
        with self.assertRaisesRegex(ValueError, "exactly one bundle"): bundle.aggregate(bundle.CORE, SHA, dist)
        archive.write_bytes(original + b"changed")
        with self.assertRaisesRegex(ValueError, "checksum"): bundle.aggregate(bundle.CORE, SHA, dist)

    @unittest.skipIf(os.name == "nt", "POSIX archive execute bits are tested on Linux and macOS")
    def test_build_verifies_both_asset_hashes_before_merging(self):
        runtime = "linux-x64"
        own, _ = component(self.root / "own", bundle.CORE, runtime, SHA)
        remote, _ = component(self.root / "remote", bundle.GUI, runtime, OTHER)
        own.rename(own.with_name("drcom4scut-0.5.1-x86_64-unknown-linux-gnu")); own = own.with_name("drcom4scut-0.5.1-x86_64-unknown-linux-gnu")
        remote.rename(remote.with_name("drcom4scutGUI-3.1.1-linux-x64")); remote = remote.with_name("drcom4scutGUI-3.1.1-linux-x64")
        bundle.pack(own, self.root / "own-dist", runtime)
        remote_archive = bundle.pack(remote, self.root / "remote-dist", runtime)
        lock = {"schema": 1, "repository": bundle.GUI, "version": "3.1.1", "source_commit": OTHER,
                "release_id": 17, "tag": "preview-17-1-bbbbbbbb", "published_at": "2026-10-23T00:00:00Z", "prerelease": True}
        bundle.json_write(self.root / "lock.json", lock)
        def fetch(_lock, name, output):
            if name == "SHA256SUMS": output.write_text(f"{bundle.digest(remote_archive)}  {remote_archive.name}\n")
            else: shutil.copyfile(remote_archive, output)
        with patch.object(bundle, "own_version", return_value="0.5.1"), patch.object(bundle, "fetch_asset", side_effect=fetch):
            archive = bundle.build(bundle.CORE, SHA, runtime, self.root / "own-dist", self.root / "lock.json", self.root / "output")
        extracted = bundle.unpack(archive, self.root / "result")
        self.assertEqual(bundle.inspect_bundle(extracted, bundle.CORE, SHA, runtime)["gui"]["release"]["release_id"], 17)


if __name__ == "__main__":
    unittest.main()
