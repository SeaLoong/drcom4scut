"""Verify the complete platform matrix, then generate aggregate checksums."""
import hashlib
import json
from pathlib import Path
import tomllib

root = Path(__file__).resolve().parents[2]
version = tomllib.loads((root / "Cargo.toml").read_text())["package"]["version"]
dist = root / "dist"
platforms = json.loads((root / ".github/scripts/platforms.json").read_text())
expected = set()
for platform in platforms:
    extension = "zip" if platform["format"] == "pe" else "tar.gz"
    name = f'drcom4scut-{version}-{platform["target"]}.{extension}'
    archive = dist / name
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    checksum = archive.with_suffix(archive.suffix + ".sha256")
    if checksum.read_text().strip() != f"{digest}  {name}":
        raise SystemExit(f"Checksum or filename mismatch: {name}")
    expected.update((name, checksum.name))
actual = {item.name for item in dist.iterdir() if item.is_file() and item.name != "SHA256SUMS"}
if actual != expected:
    raise SystemExit(f"Unexpected release artifact set: {actual ^ expected}")
(dist / "SHA256SUMS").write_text("".join((dist / name).read_text() for name in sorted(expected) if name.endswith(".sha256")))
