"""Verify every supported platform archive before generating aggregate checksums."""

import hashlib
import importlib.util
import os
import re
import tarfile
import zipfile
import json
from pathlib import Path, PurePosixPath
import tomllib


ROOT = Path(__file__).resolve().parents[2]


spec = importlib.util.spec_from_file_location("core_release_packager", Path(__file__).with_name("package_release.py"))
packager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packager)


def read_members(archive, names):
    """Inspect archives in place; never extract paths supplied by an artifact."""
    try:
        if archive.suffix == ".zip":
            with zipfile.ZipFile(archive) as package:
                entries = package.infolist()
                if len({item.filename for item in entries}) != len(entries):
                    raise ValueError("Duplicate ZIP entries")
                for item in entries:
                    name = PurePosixPath(item.filename)
                    if name.is_absolute() or ".." in name.parts or "\\" in item.filename or (item.external_attr >> 16) & 0o170000 == 0o120000:
                        raise ValueError("Unsafe ZIP entry")
                return {name: package.read(name) for name in names}
        with tarfile.open(archive, "r:gz") as package:
            entries = package.getmembers()
            if len({item.name for item in entries}) != len(entries):
                raise ValueError("Duplicate tar entries")
            for item in entries:
                name = PurePosixPath(item.name)
                if name.is_absolute() or ".." in name.parts or "\\" in item.name or not (item.isfile() or item.isdir()):
                    raise ValueError("Unsafe tar entry")
            result = {}
            for name in names:
                item = package.getmember(name)
                if not item.isfile():
                    raise ValueError("Expected a regular archive member")
                with package.extractfile(item) as file:
                    result[name] = file.read()
            return result
    except (zipfile.BadZipFile, tarfile.TarError, KeyError, ValueError, OSError) as error:
        raise SystemExit("Invalid core package or build metadata") from error


def verify(root=ROOT, dist=None, source_commit=None):
    source_commit = os.environ.get("GITHUB_SHA") if source_commit is None else source_commit
    if not isinstance(source_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise SystemExit("A complete validated source commit is required")
    root = Path(root)
    dist = root / "dist" if dist is None else Path(dist)
    version = tomllib.loads((root / "Cargo.toml").read_text())["package"]["version"]
    platforms = json.loads((root / ".github/scripts/platforms.json").read_text())
    targets = [platform["target"] for platform in platforms]
    if not targets or len(set(targets)) != len(targets):
        raise SystemExit("Release platform targets must be nonempty and unique")
    expected = set()
    lines = []
    for platform in platforms:
        extension = "zip" if platform["format"] == "pe" else "tar.gz"
        name = f'drcom4scut-{version}-{platform["target"]}.{extension}'
        archive = dist / name
        checksum = archive.with_suffix(archive.suffix + ".sha256")
        if any(path.is_symlink() or not path.is_file() for path in (archive, checksum)):
            raise SystemExit(f"Missing regular release archive or checksum: {name}")
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        line = f"{digest}  {name}"
        if checksum.read_text(encoding="utf-8").strip() != line:
            raise SystemExit(f"Checksum or filename mismatch: {name}")
        prefix = f'drcom4scut-{version}-{platform["target"]}/'
        binary_name = "drcom4scut.exe" if platform["format"] == "pe" else "drcom4scut"
        metadata_name = prefix + "BUILD-INFO.json"
        members = read_members(archive, (metadata_name, prefix + binary_name))
        try:
            metadata = json.loads(members[metadata_name])
            if not isinstance(metadata, dict) or (
                metadata.get("version") != version or metadata.get("target") != platform["target"]
                or metadata.get("source_commit") != source_commit
                or metadata.get("openwrt") is not platform["openwrt"]
            ):
                raise ValueError("Core package does not match the validated source")
            if metadata.get("source_dirty") is not False:
                raise ValueError("Refusing a release package built from a modified source checkout")
            packager.verify_abi_bytes(members[prefix + binary_name], platform)
        except (ValueError, UnicodeError) as error:
            raise SystemExit(str(error)) from error
        expected.update((name, checksum.name))
        lines.append(line)
    entries = list(dist.iterdir())
    if any(path.is_symlink() or not path.is_file() for path in entries):
        raise SystemExit("Release artifacts must be regular files")
    actual = {path.name for path in entries if path.name != "SHA256SUMS"}
    if actual != expected:
        raise SystemExit(f"Unexpected release artifact set: {actual ^ expected}")
    (dist / "SHA256SUMS").write_text("".join(line + "\n" for line in sorted(lines, key=lambda line: line.split("  ", 1)[1])), encoding="utf-8")


if __name__ == "__main__":
    verify()
