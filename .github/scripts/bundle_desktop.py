"""Build a native desktop bundle from one local build and one pinned public release.

The same file lives in both repositories. Counterpart selection happens once per
workflow, before the native matrix. A missing or incompatible newest release is
an error; this never silently falls back to an older release or bundles a bundle.
"""
import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
import tomllib
from urllib.parse import quote
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape
import zipfile

ROOT = Path(__file__).resolve().parents[2]
CORE = "SeaLoong/drcom4scut"
GUI = "SeaLoong/drcom4scutGUI"
SHA = re.compile(r"[0-9a-f]{40}")
VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?")
MAX_ARCHIVE = 512 * 1024 * 1024
MAX_EXTRACTED = 1024 * 1024 * 1024
PLATFORMS = {
    "win-x64": ("windows-latest", "x86_64-pc-windows-msvc", "pe", 34404, "zip"),
    "win-arm64": ("windows-11-arm", "aarch64-pc-windows-msvc", "pe", 43620, "zip"),
    "linux-x64": ("ubuntu-24.04", "x86_64-unknown-linux-gnu", "elf", 62, "tar.gz"),
    "linux-arm64": ("ubuntu-24.04-arm", "aarch64-unknown-linux-gnu", "elf", 183, "tar.gz"),
    "osx-x64": ("macos-15-intel", "x86_64-apple-darwin", "macho", 16777223, "tar.gz"),
    "osx-arm64": ("macos-15", "aarch64-apple-darwin", "macho", 16777228, "tar.gz"),
}


def json_write(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def query(endpoint):
    return json.loads(subprocess.check_output(["gh", "api", endpoint], timeout=90))


def own_repository(root=ROOT):
    return CORE if (Path(root) / "Cargo.toml").is_file() else GUI


def own_version(repository, root=ROOT):
    value = (tomllib.loads((Path(root) / "Cargo.toml").read_text())["package"]["version"] if repository == CORE
             else ET.parse(Path(root) / "Directory.Build.props").findtext(".//Version"))
    version_tuple(value)
    return value


def version_tuple(value):
    if not isinstance(value, str) or not (match := VERSION.fullmatch(value)):
        raise ValueError("Invalid component version")
    # The current GUI accepts production numeric core versions only. Do not
    # reinterpret an incompatible prerelease version as its future stable base.
    return tuple(map(int, match.groups()[:3]))


def latest_published(releases):
    candidates = []
    for release in releases:
        if release.get("draft") is not False:
            continue
        published = release.get("published_at")
        if not isinstance(published, str):
            raise ValueError("Published release has no publication timestamp")
        timestamp = datetime.fromisoformat(published.replace("Z", "+00:00"))
        if timestamp.tzinfo is None or type(release.get("id")) is not int or release["id"] <= 0:
            raise ValueError("Invalid published release identity")
        candidates.append((timestamp, release["id"], release))
    if not candidates:
        raise ValueError("Counterpart repository has no published release")
    return max(candidates, key=lambda item: item[:2])[2]


def resolve_commit(repository, tag):
    target = query(f"repos/{repository}/git/ref/tags/{quote(tag, safe='')}").get("object", {})
    for _ in range(6):
        if target.get("type") == "commit" and SHA.fullmatch(target.get("sha", "")):
            return target["sha"]
        if target.get("type") != "tag" or not SHA.fullmatch(target.get("sha", "")):
            break
        target = query(f"repos/{repository}/git/tags/{target['sha']}").get("object", {})
    raise ValueError("Counterpart release tag does not resolve to a commit")


def resolve(repository, output):
    if repository not in (CORE, GUI):
        raise ValueError("Unexpected bundle repository")
    counterpart = GUI if repository == CORE else CORE
    pages = json.loads(subprocess.check_output([
        "gh", "api", "--paginate", "--slurp", f"repos/{counterpart}/releases?per_page=100"
    ], timeout=90))
    if not isinstance(pages, list) or any(not isinstance(page, list) for page in pages):
        raise ValueError("Invalid release listing")
    latest = latest_published([release for page in pages for release in page])
    tag = latest.get("tag_name", "")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", tag):
        raise ValueError("Unsafe counterpart release tag")
    assets = latest.get("assets", [])
    if len({asset.get("name") for asset in assets}) != len(assets):
        raise ValueError("Duplicate counterpart asset name")
    pattern = (r"drcom4scutGUI-(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)-(?:win|linux|osx)-(?:x64|arm64)\.(?:zip|tar\.gz)" if counterpart == GUI
               else r"drcom4scut-(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)-(?:x86_64|aarch64)-(?:pc-windows-msvc|unknown-linux-gnu|apple-darwin)\.(?:zip|tar\.gz)")
    versions = {match[1] for asset in assets if (match := re.fullmatch(pattern, asset.get("name", "")))}
    if len(versions) != 1:
        raise ValueError("Newest counterpart release must contain one complete standalone desktop version")
    version = versions.pop()
    required = {archive_name(counterpart, version, runtime) for runtime in PLATFORMS} | {"SHA256SUMS"}
    selected = {}
    for name in required:
        matches = [asset for asset in assets if asset.get("name") == name]
        if len(matches) != 1:
            raise ValueError(f"Newest counterpart release is missing {name}; refusing an older fallback")
        asset = matches[0]
        if (asset.get("state") != "uploaded" or type(asset.get("id")) is not int or asset["id"] <= 0
                or type(asset.get("size")) is not int or not 0 < asset["size"] <= MAX_ARCHIVE
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", asset.get("digest", ""))):
            raise ValueError("Counterpart asset metadata is incomplete")
        selected[name] = {key: asset[key] for key in ("id", "size", "digest")}
    record = {"schema": 1, "repository": counterpart, "release_id": latest["id"], "tag": tag,
              "published_at": latest["published_at"], "prerelease": latest.get("prerelease"),
              "source_commit": resolve_commit(counterpart, tag), "version": version, "assets": selected}
    json_write(output, record)
    print(f"Pinned {counterpart} {tag} ({version}) from {record['published_at']}")
    return record


def archive_name(repository, version, runtime):
    version_tuple(version)
    _, target, _, _, extension = PLATFORMS[runtime]
    return f"{repository.split('/')[1]}-{version}-{runtime if repository == GUI else target}.{extension}"


def fetch_asset(lock, name, destination):
    asset = lock["assets"][name]
    destination = Path(destination)
    if destination.exists():
        raise ValueError("Download destination already exists")
    with destination.open("xb") as stream:
        subprocess.run(["gh", "api", "-H", "Accept: application/octet-stream",
                        f"repos/{lock['repository']}/releases/assets/{asset['id']}"], stdout=stream,
                       check=True, timeout=300)
    if destination.stat().st_size != asset["size"] or "sha256:" + digest(destination) != asset["digest"]:
        raise ValueError("Downloaded counterpart asset differs from its pinned digest")


def read_checksums(path):
    result = {}
    if Path(path).stat().st_size > 1024 * 1024:
        raise ValueError("Oversized checksum manifest")
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*\.(?:zip|tar\.gz))", line)
        if not match or match[2] in result:
            raise ValueError("Invalid checksum manifest")
        result[match[2]] = match[1]
    return result


def safe_path(raw):
    name = PurePosixPath(raw)
    if (not raw or not name.parts or name.is_absolute() or ".." in name.parts or "\\" in raw or ":" in raw
            or any(part.rstrip(" .") != part or re.fullmatch(r"(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", part) for part in name.parts)):
        raise ValueError("Unsafe archive path")
    return name


def unpack(archive, destination):
    """Extract only bounded, unique regular files/directories into a new directory."""
    archive, destination = Path(archive), Path(destination)
    if archive.is_symlink() or not archive.is_file() or archive.stat().st_size > MAX_ARCHIVE:
        raise ValueError("Invalid archive file")
    destination.mkdir()
    seen, total = set(), 0
    with (zipfile.ZipFile(archive) if archive.suffix == ".zip" else tarfile.open(archive, "r:gz")) as source:
        # Tar headers must be checked before advancing over their bodies.
        # getmembers() would first decompress every declared file to seek ahead.
        entries = source.infolist() if isinstance(source, zipfile.ZipFile) else source
        for count, item in enumerate(entries, 1):
            if count > 10000:
                raise ValueError("Too many archive entries")
            zipped = isinstance(source, zipfile.ZipFile)
            raw = item.filename if zipped else item.name
            name = safe_path(raw)
            key = name.as_posix().casefold()
            if key in seen:
                raise ValueError("Duplicate or case-colliding archive path")
            seen.add(key)
            mode = item.external_attr >> 16 if zipped else item.mode
            directory = item.is_dir() if zipped else item.isdir()
            if (zipped and stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)
                    or not zipped and not (item.isfile() or directory)):
                raise ValueError("Archive links and special files are not permitted")
            size = item.file_size if zipped else item.size
            total += size
            if size < 0 or total > MAX_EXTRACTED:
                raise ValueError("Archive expands beyond the size limit")
            target = destination.joinpath(*name.parts)
            if directory:
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with (source.open(item) if zipped else source.extractfile(item)) as incoming, target.open("xb") as outgoing:
                copied = 0
                while block := incoming.read(1024 * 1024):
                    copied += len(block)
                    if copied > size:
                        raise ValueError("Archive file exceeded its declared size")
                    outgoing.write(block)
            if copied != size:
                raise ValueError("Truncated archive file")
            target.chmod(0o755 if mode & 0o111 else 0o644)
    roots = list(destination.iterdir())
    if len(roots) != 1 or not roots[0].is_dir():
        raise ValueError("Component archive must contain exactly one root directory")
    return roots[0]


def abi(data, runtime):
    _, _, format, machine, _ = PLATFORMS[runtime]
    if format == "pe":
        if len(data) < 64 or data[:2] != b"MZ": raise ValueError("Expected PE executable")
        offset = struct.unpack_from("<I", data, 60)[0]
        if offset + 26 > len(data) or data[offset:offset + 4] != b"PE\0\0" or struct.unpack_from("<H", data, offset + 4)[0] != machine or struct.unpack_from("<H", data, offset + 24)[0] != 0x20b:
            raise ValueError("PE architecture does not match bundle")
    elif format == "elf":
        if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", data, 18)[0] != machine or struct.unpack_from("<H", data, 16)[0] not in (2, 3):
            raise ValueError("ELF architecture does not match bundle")
    elif len(data) < 32 or data[:4] != b"\xcf\xfa\xed\xfe" or struct.unpack_from("<I", data, 4)[0] != machine or struct.unpack_from("<I", data, 12)[0] != 2:
        raise ValueError("Mach-O architecture does not match bundle")


def payload_path(root, runtime):
    return root / "drcom4scutGUI.app/Contents/Resources/publish" if runtime.startswith("osx-") else root


def inspect_component(root, repository, version, sha, runtime):
    metadata = json.loads((root / "BUILD-INFO.json").read_text(encoding="utf-8"))
    if (metadata.get("version") != version or metadata.get("source_commit") != sha
            or metadata.get("source_dirty") is not False):
        raise ValueError("Component metadata does not match the pinned clean source")
    if repository == CORE:
        if metadata.get("target") != PLATFORMS[runtime][1] or metadata.get("openwrt") is not False:
            raise ValueError("Core target does not match the desktop runtime")
        executable = root / ("drcom4scut.exe" if runtime.startswith("win-") else "drcom4scut")
    else:
        if metadata.get("runtime") != runtime or metadata.get("self_contained") is not True or metadata.get("core_included") is not False:
            raise ValueError("Expected a standalone self-contained GUI archive")
        version_tuple(metadata.get("minimum_core_version"))
        directory = payload_path(root, runtime)
        required = ["drcom4scutGUI.Core.dll", "drcom4scutGUI.dll", "drcom4scutGUI.runtimeconfig.json", "drcom4scutGUI.deps.json"]
        if any(not (directory / name).is_file() for name in required):
            raise ValueError("GUI payload is missing runtime or core integration files")
        executable = directory / ("drcom4scutGUI.exe" if runtime.startswith("win-") else "drcom4scutGUI")
        if runtime.startswith("osx-"):
            abi((root / "drcom4scutGUI.app/Contents/MacOS/drcom4scutGUI").read_bytes(), runtime)
    abi(executable.read_bytes(), runtime)
    if not runtime.startswith("win-") and not executable.stat().st_mode & 0o111:
        raise ValueError("Component executable has lost its execute permission")
    return metadata


def compatible(core, gui):
    minimum = gui["minimum_core_version"]
    if VERSION.fullmatch(core["version"])[4] is not None or version_tuple(core["version"]) < version_tuple(minimum):
        raise ValueError(f"Newest core {core['version']} is incompatible with GUI minimum {minimum}; refusing an older fallback")


def bundle_stem(core_version, gui_version, runtime):
    version_tuple(core_version); version_tuple(gui_version)
    if runtime not in PLATFORMS: raise ValueError("Unsupported desktop runtime")
    return f"drcom4scut-desktop-core-{core_version}-gui-{gui_version}-{runtime}"


def assemble(core_root, gui_root, destination, runtime, provenance):
    core_meta, gui_meta = provenance["core"]["build"], provenance["gui"]["build"]
    compatible(core_meta, gui_meta)
    stem = bundle_stem(core_meta["version"], gui_meta["version"], runtime)
    target = Path(destination) / stem
    shutil.copytree(gui_root, target)
    core_name = "drcom4scut.exe" if runtime.startswith("win-") else "drcom4scut"
    if (target / core_name).exists(): raise ValueError("Standalone GUI unexpectedly contains a core")
    shutil.copy2(core_root / core_name, target / core_name)
    if (core_root / "config.example.yml").is_file():
        shutil.copy2(core_root / "config.example.yml", target / "config.example.yml")
    shutil.copytree(core_root, target / "core-help", ignore=shutil.ignore_patterns(core_name))
    # Keep original component metadata intact, including sealed macOS resources.
    (target / "BUILD-INFO.json").rename(target / "GUI-BUILD-INFO.json")
    metadata = {"schema": 1, "runtime": runtime, "core_included": True, "self_contained": True,
                "core": provenance["core"], "gui": provenance["gui"]}
    (target / "开始使用.txt").write_text(
        "这是图形界面与核心的一体包。\n\n"
        "1. 完整解压这个文件夹。\n"
        "2. Windows 打开 drcom4scutGUI.exe；Linux 打开 drcom4scutGUI；Mac 打开 drcom4scutGUI.app。\n"
        "3. 选择连接方式，填写校园网账号和密码，点击“连接”。\n\n"
        "Windows 有线连接需要 Npcap。Linux/macOS 有线连接按帮助文档准备网卡权限。\n"
        "图形界面帮助在 docs，命令行帮助在 core-help/docs。\n"
        "官网与完整帮助：https://sealoong.github.io/drcom4scut/\n",
        encoding="utf-8")
    metadata["files"] = {path.relative_to(target).as_posix(): digest(path) for path in sorted(target.rglob("*")) if path.is_file()}
    json_write(target / "BUNDLE-INFO.json", metadata)
    return target


def pack(contents, output, runtime):
    output = Path(output); output.mkdir(parents=True, exist_ok=True)
    archive = output / (contents.name + "." + PLATFORMS[runtime][4])
    if archive.exists(): raise ValueError("Bundle output already exists")
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as target:
            for path in sorted(contents.rglob("*")):
                if path.is_file(): target.write(path, path.relative_to(contents.parent).as_posix())
    else:
        with tarfile.open(archive, "w:gz") as target:
            def portable(item):
                item.uid = item.gid = 0; item.uname = item.gname = "root"
                return item
            target.add(contents, arcname=contents.name, filter=portable)
    archive.with_name(archive.name + ".sha256").write_text(f"{digest(archive)}  {archive.name}\n", encoding="utf-8")
    return archive


def build(repository, sha, runtime, own_dist, lock_path, output):
    if repository not in (CORE, GUI) or not SHA.fullmatch(sha): raise ValueError("Invalid local source identity")
    lock = json.loads(Path(lock_path).read_text(encoding="utf-8"))
    counterpart = GUI if repository == CORE else CORE
    if lock.get("schema") != 1 or lock.get("repository") != counterpart or not SHA.fullmatch(lock.get("source_commit", "")):
        raise ValueError("Counterpart lock belongs to another repository or source")
    version = own_version(repository)
    local = Path(own_dist) / archive_name(repository, version, runtime)
    local_sum = local.with_name(local.name + ".sha256")
    if local_sum.is_symlink() or local_sum.read_text(encoding="utf-8").strip() != f"{digest(local)}  {local.name}":
        raise ValueError("Local component checksum mismatch")
    with tempfile.TemporaryDirectory(prefix="desktop-components-") as directory:
        directory = Path(directory)
        remote = directory / archive_name(counterpart, lock["version"], runtime)
        sums = directory / "SHA256SUMS"
        fetch_asset(lock, "SHA256SUMS", sums)
        fetch_asset(lock, remote.name, remote)
        if read_checksums(sums).get(remote.name) != digest(remote): raise ValueError("Counterpart checksum manifest mismatch")
        roots = {repository: unpack(local, directory / "own"), counterpart: unpack(remote, directory / "counterpart")}
        metadata = {repository: inspect_component(roots[repository], repository, version, sha, runtime),
                    counterpart: inspect_component(roots[counterpart], counterpart, lock["version"], lock["source_commit"], runtime)}
        own_info = {"repository": repository, "source_commit": sha, "build": metadata[repository],
                    "archive": local.name, "sha256": digest(local)}
        other_info = {"repository": counterpart, "source_commit": lock["source_commit"], "build": metadata[counterpart],
                      "archive": remote.name, "sha256": digest(remote),
                      "release": {key: lock[key] for key in ("release_id", "tag", "published_at", "prerelease")}}
        provenance = {"core": own_info if repository == CORE else other_info, "gui": own_info if repository == GUI else other_info}
        contents = assemble(roots[CORE], roots[GUI], directory / "bundle", runtime, provenance)
        archive = pack(contents, output, runtime)
    print(f"Created {archive.name}")
    return archive


def inspect_bundle(root, repository, sha, runtime):
    info = json.loads((root / "BUNDLE-INFO.json").read_text(encoding="utf-8"))
    if info.get("schema") != 1 or info.get("runtime") != runtime or info.get("core_included") is not True or info.get("self_contained") is not True:
        raise ValueError("Invalid desktop bundle metadata")
    for key, repo in (("core", CORE), ("gui", GUI)):
        component = info[key]; metadata = component["build"]
        if component.get("repository") != repo or component.get("source_commit") != metadata.get("source_commit") or not SHA.fullmatch(component.get("source_commit", "")):
            raise ValueError("Bundle component provenance mismatch")
        if metadata.get("source_dirty") is not False or not re.fullmatch(r"[0-9a-f]{64}", component.get("sha256", "")):
            raise ValueError("Unverified bundle component")
        if repo == repository and component["source_commit"] != sha:
            raise ValueError("Bundle does not contain this workflow's source build")
        if component.get("archive") != archive_name(repo, metadata["version"], runtime):
            raise ValueError("Bundle provenance did not use standalone component archives")
        if repo != repository:
            release = component.get("release", {})
            if type(release.get("release_id")) is not int or not isinstance(release.get("published_at"), str):
                raise ValueError("Counterpart release was not pinned")
    files = {path.relative_to(root).as_posix(): digest(path) for path in root.rglob("*") if path.is_file() and path != root / "BUNDLE-INFO.json"}
    if files != info.get("files"):
        raise ValueError("Bundle files differ from the verified component contents")
    compatible(info["core"]["build"], info["gui"]["build"])
    if info["core"]["build"].get("target") != PLATFORMS[runtime][1] or info["gui"]["build"].get("runtime") != runtime:
        raise ValueError("Bundled components target different platforms")
    core = root / ("drcom4scut.exe" if runtime.startswith("win-") else "drcom4scut")
    gui = payload_path(root, runtime) / ("drcom4scutGUI.exe" if runtime.startswith("win-") else "drcom4scutGUI")
    abi(core.read_bytes(), runtime); abi(gui.read_bytes(), runtime)
    if runtime.startswith("osx-"):
        abi((root / "drcom4scutGUI.app/Contents/MacOS/drcom4scutGUI").read_bytes(), runtime)
    if json.loads((root / "GUI-BUILD-INFO.json").read_text()) != info["gui"]["build"] or json.loads((root / "core-help/BUILD-INFO.json").read_text()) != info["core"]["build"]:
        raise ValueError("Original component metadata changed")
    if not runtime.startswith("win-") and any(not p.stat().st_mode & 0o111 for p in (core, gui)):
        raise ValueError("Bundled executable lost execute permission")
    return info


def aggregate(repository, sha, dist):
    dist = Path(dist)
    previous = read_checksums(dist / "SHA256SUMS")
    bundles, counterparts = {}, []
    for runtime in PLATFORMS:
        matches = list(dist.glob(f"drcom4scut-desktop-core-*-gui-*-{runtime}.{PLATFORMS[runtime][4]}"))
        if len(matches) != 1: raise ValueError(f"Expected exactly one bundle for {runtime}")
        archive = matches[0]
        checksum = archive.with_name(archive.name + ".sha256")
        if checksum.read_text().strip() != f"{digest(archive)}  {archive.name}": raise ValueError("Bundle checksum mismatch")
        with tempfile.TemporaryDirectory() as directory:
            root = unpack(archive, Path(directory) / "contents")
            info = inspect_bundle(root, repository, sha, runtime)
        expected = bundle_stem(info["core"]["build"]["version"], info["gui"]["build"]["version"], runtime) + "." + PLATFORMS[runtime][4]
        if archive.name != expected: raise ValueError("Bundle filename does not match its components")
        other = info["gui" if repository == CORE else "core"]
        counterparts.append({k:other[k] for k in ("source_commit", "release")})
        bundles[runtime] = {"filename": archive.name, "sha256": digest(archive), "core_version": info["core"]["build"]["version"], "gui_version": info["gui"]["build"]["version"], "counterpart": counterparts[-1]}
        previous[archive.name] = digest(archive)
    if any(value != counterparts[0] for value in counterparts): raise ValueError("Matrix selected different counterpart releases")
    actual = {path.name for path in dist.iterdir() if path.name.endswith((".zip", ".tar.gz"))}
    if actual != set(previous): raise ValueError("Unexpected release archive set after bundling")
    json_write(dist / "BUNDLE-INDEX.json", bundles)
    (dist / "SHA256SUMS").write_text("".join(f"{value}  {name}\n" for name,value in sorted(previous.items())), encoding="utf-8")
    return bundles


def smoke(archive, runtime, repository, sha):
    with tempfile.TemporaryDirectory(prefix="desktop-smoke-") as directory:
        directory = Path(directory)
        root = unpack(archive, directory / "extracted")
        info = inspect_bundle(root, repository, sha, runtime)
        payload = payload_path(root, runtime)
        core = root / ("drcom4scut.exe" if runtime.startswith("win-") else "drcom4scut")
        gui = (root / "drcom4scutGUI.app/Contents/MacOS/drcom4scutGUI" if runtime.startswith("osx-") else payload / ("drcom4scutGUI.exe" if runtime.startswith("win-") else "drcom4scutGUI"))
        if runtime.startswith("osx-"):
            subprocess.run(["codesign", "--verify", "--deep", "--strict", str(root / "drcom4scutGUI.app")], check=True, timeout=90)
        # Exercise the exact integration assembly shipped in this bundle. The
        # tiny probe has no NuGet dependencies, credentials or network session.
        project = directory / "probe"; project.mkdir()
        (project / "Probe.csproj").write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework><OutputType>Exe</OutputType><ImplicitUsings>enable</ImplicitUsings></PropertyGroup><ItemGroup><Reference Include="drcom4scutGUI.Core"><HintPath>' + escape(str(payload / "drcom4scutGUI.Core.dll")) + '</HintPath></Reference></ItemGroup></Project>')
        (project / "NuGet.Config").write_text('<configuration><packageSources><clear /></packageSources></configuration>')
        (project / "Program.cs").write_text('''using drcom4scutGUI;
string found = PlatformPaths.ResolveCoreExecutablePath(args[0], OperatingSystem.IsWindows(), OperatingSystem.IsMacOS());
if (Path.GetFullPath(found) != Path.GetFullPath(args[1])) throw new Exception("Bundled core was not discovered automatically");
using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(25));
string reported = await new CoreProcessSession(found).VerifyCoreAsync(deadline.Token);
if (reported != "drcom4scut " + args[2]) throw new Exception("Bundled core reported another version");
Console.WriteLine("Packaged GUI.Core discovered and verified " + reported);
''', encoding="utf-8")
        subprocess.run(["dotnet", "run", "--project", str(project / "Probe.csproj"), "--configuration", "Release", "--", str(payload), str(core), info["core"]["build"]["version"]], cwd=project, check=True, timeout=180)
        subprocess.run([str(gui), "--smoke-test"], cwd=gui.parent, check=True, timeout=45)
        print(f"Native bundle launch and GUI/core integration passed: {runtime}")


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("resolve", "build", "aggregate", "smoke"):
        p = sub.add_parser(command); p.add_argument("--repository", choices=(CORE, GUI), default=own_repository())
        if command != "resolve": p.add_argument("--sha", default=os.environ.get("GITHUB_SHA"), required=not os.environ.get("GITHUB_SHA"))
        if command in ("build", "smoke"): p.add_argument("--runtime", choices=PLATFORMS, required=True)
        if command == "resolve": p.add_argument("--output", type=Path, required=True)
        if command == "build":
            p.add_argument("--own-dist", type=Path, default=Path("own-dist")); p.add_argument("--lock", type=Path, required=True); p.add_argument("--output", type=Path, default=Path("bundles"))
        if command == "aggregate": p.add_argument("--dist", type=Path, default=Path("dist"))
        if command == "smoke": p.add_argument("--archive", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "resolve": resolve(args.repository, args.output)
    elif args.command == "build": build(args.repository, args.sha, args.runtime, args.own_dist, args.lock, args.output)
    elif args.command == "aggregate": aggregate(args.repository, args.sha, args.dist)
    else: smoke(args.archive, args.runtime, args.repository, args.sha)


if __name__ == "__main__":
    main()
