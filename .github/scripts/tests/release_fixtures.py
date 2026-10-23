"""Small upload fixtures; archive extraction is exercised separately."""
import hashlib
import json
from pathlib import Path
import tomllib
import xml.etree.ElementTree as ET


def add_bundles(directory, repository, root):
    versions = {"core": "0.5.1", "gui": "3.1.1"}
    versions["gui" if repository.endswith("GUI") else "core"] = (ET.parse(root / "Directory.Build.props").findtext(".//Version") if repository.endswith("GUI") else tomllib.loads((root / "Cargo.toml").read_text())["package"]["version"])
    index = {}
    for runtime in ("win-x64", "win-arm64", "osx-x64", "osx-arm64", "linux-x64", "linux-arm64"):
        extension = "zip" if runtime.startswith("win-") else "tar.gz"
        name = f"drcom4scut-desktop-core-{versions['core']}-gui-{versions['gui']}-{runtime}.{extension}"
        path = Path(directory) / name
        path.write_bytes(b"archive already verified by the aggregation job")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        index[runtime] = {"filename": name, "sha256": digest, "core_version": versions["core"], "gui_version": versions["gui"],
                          "counterpart": {"source_commit": "b" * 40, "release": {"release_id": 17, "tag": "preview-17-1-bbbbbbbb", "published_at": "2026-10-23T00:00:00Z", "prerelease": True}}}
        with (Path(directory) / "SHA256SUMS").open("a") as stream:
            stream.write(f"{digest}  {name}\n")
    (Path(directory) / "BUNDLE-INDEX.json").write_text(json.dumps(index))
    return index
