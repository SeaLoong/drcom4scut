"""Verify every supported platform archive before generating aggregate checksums."""

import hashlib
import json
from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[2]


def verify(root=ROOT, dist=None):
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
