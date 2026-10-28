"""Render download links only for checked, complete desktop bundles."""
import argparse
import json
from pathlib import Path
import re
import tomllib
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
RUNTIMES = ("win-x64", "win-arm64", "osx-x64", "osx-arm64", "linux-x64", "linux-arm64")
LABELS = {
    "win-x64": "Windows · Intel / AMD 64 位", "win-arm64": "Windows · ARM64",
    "osx-x64": "macOS · Intel", "osx-arm64": "macOS · Apple 芯片",
    "linux-x64": "Linux · Intel / AMD 64 位", "linux-arm64": "Linux · ARM64",
    "x86_64-unknown-linux-musl": "OpenWrt · x86-64",
    "i686-unknown-linux-musl": "OpenWrt · x86 32 位（i686，需 SSE2）",
    "aarch64-unknown-linux-musl": "OpenWrt · ARM64",
    "armv5te-unknown-linux-musleabi": "OpenWrt · ARMv5TE（软浮点）",
    "arm-unknown-linux-musleabi": "OpenWrt · ARMv6（软浮点）",
    "arm-unknown-linux-musleabihf": "OpenWrt · ARMv6（硬浮点）",
    "armv7-unknown-linux-musleabi": "OpenWrt · ARMv7（软浮点）",
    "armv7-unknown-linux-musleabihf": "OpenWrt · ARMv7（硬浮点）",
    "riscv64gc-unknown-linux-musl": "OpenWrt · RISC-V 64 位",
    "loongarch64-unknown-linux-musl": "OpenWrt · LoongArch64（LP64D、LSX）",
    "powerpc64-unknown-linux-musl": "OpenWrt · PowerPC64（大端、ELFv2）",
    "powerpc64le-unknown-linux-musl": "OpenWrt · PowerPC64（小端、ELFv2）",
    "mips-unknown-linux-musl": "OpenWrt · MIPS32r2（大端、O32 软浮点）",
    "mipsel-unknown-linux-musl": "OpenWrt · MIPS32r2（小端、O32 软浮点）",
    "mips64-unknown-linux-muslabi64": "OpenWrt · MIPS64r2（大端、N64 硬浮点）",
    "mips64el-unknown-linux-muslabi64": "OpenWrt · MIPS64r2（小端、N64 硬浮点）",
    "mips64-openwrt-linux-musl": "OpenWrt · MIPS64r2（大端、N64 软浮点）",
}


def validate_index(bundles):
    if not isinstance(bundles, dict) or set(bundles) != set(RUNTIMES):
        raise ValueError("Release requires all six verified desktop bundles")
    identities = set()
    for runtime, item in bundles.items():
        versions = [item.get(key, "") for key in ("core_version", "gui_version")]
        if any(not re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", value) for value in versions):
            raise ValueError("Invalid bundled component version")
        extension = "zip" if runtime.startswith("win-") else "tar.gz"
        expected = f"drcom4scut-desktop-core-{versions[0]}-gui-{versions[1]}-{runtime}.{extension}"
        if item.get("filename") != expected or not re.fullmatch(r"[0-9a-f]{64}", item.get("sha256", "")):
            raise ValueError("Invalid desktop download identity")
        counterpart = item.get("counterpart", {})
        release = counterpart.get("release", {})
        if (not re.fullmatch(r"[0-9a-f]{40}", counterpart.get("source_commit", ""))
                or not re.fullmatch(r"[A-Za-z0-9._-]+", release.get("tag", ""))
                or type(release.get("release_id")) is not int or release["release_id"] <= 0):
            raise ValueError("Missing counterpart release provenance")
        identities.add((tuple(versions), json.dumps(counterpart, sort_keys=True)))
    if len(identities) != 1:
        raise ValueError("Desktop downloads contain different counterpart releases or versions")
    return bundles


def load_index(directory, assets):
    directory = Path(directory)
    path = directory / "BUNDLE-INDEX.json"
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
        raise ValueError("Missing verified desktop bundle index")
    bundles = validate_index(json.loads(path.read_text(encoding="utf-8")))
    names = {asset.name for asset in assets}
    manifest = dict(line.split("  ", 1)[::-1] for line in (directory / "SHA256SUMS").read_text().splitlines())
    for item in bundles.values():
        if item["filename"] not in names or manifest.get(item["filename"]) != item["sha256"]:
            raise ValueError("Desktop download is missing from the verified upload set")
    return bundles


def render(repository, sha, tag, *, bundles, preview=False, root=ROOT):
    if repository not in ("SeaLoong/drcom4scut", "SeaLoong/drcom4scutGUI"):
        raise ValueError("Unexpected release repository")
    if not re.fullmatch(r"[0-9a-f]{40}", sha) or not re.fullmatch(r"[A-Za-z0-9._-]+", tag):
        raise ValueError("Invalid release identity")
    validate_index(bundles)
    gui = repository.endswith("GUI")
    version = (ET.parse(root / "Directory.Build.props").findtext(".//Version") if gui else
               tomllib.loads((root / "Cargo.toml").read_text())["package"]["version"])
    sample = bundles[RUNTIMES[0]]
    if sample["gui_version" if gui else "core_version"] != version:
        raise ValueError("Desktop bundle version differs from this source version")
    source = f"https://github.com/{repository}/blob/{sha}/"
    download = f"https://github.com/{repository}/releases/download/{tag}/"
    lines = ["## 校园网客户端" + (" · 预发布" if preview else ""), "",
             "下载与你的电脑对应的一体包，完整解压后即可打开图形界面；命令行程序也已放在同一个文件夹中。", "",
             f"包含图形界面 {sample['gui_version']} 和核心 {sample['core_version']}。", "",
             "### 电脑下载", "", "| 系统 / 设备 | 下载 |", "| --- | --- |"]
    for runtime in RUNTIMES:
        name = bundles[runtime]["filename"]
        lines.append(f"| {LABELS[runtime]} | [`{name}`]({download}{name}) |")
    lines += ["", "### 开始使用", "",
              "1. 下载上表的一体包，完整解压到一个文件夹。",
              "2. Windows 打开 `drcom4scutGUI.exe`，Linux 打开 `drcom4scutGUI`，Mac 打开 `drcom4scutGUI.app`。",
              "3. 选择连接方式，填写校园网账号和密码，点击“连接”。", "",
              "Windows 有线连接先安装 [Npcap](https://npcap.com/#download)。macOS 桌面版适用于 macOS 15 或更新系统。",
              "网页登录方式与网卡权限设置见[完整使用指南](https://sealoong.github.io/drcom4scut/)。",
              "压缩包中的 `开始使用.txt`、`docs/` 和 `core-help/docs/` 提供离线帮助。", "",
              f"[本版使用说明]({source}{'docs/usage.md' if gui else 'docs/getting-started.md'}) · [本版改进]({source}{'docs/changes.md' if gui else 'CHANGELOG.md'})"]
    if not gui:
        lines += ["", "### OpenWrt 路由器下载", "", "路由器使用专用安装包，包内附带服务与 LuCI 管理页面。", "",
                  "| 设备处理器 | 下载 |", "| --- | --- |"]
        for platform in json.loads((root / ".github/scripts/platforms.json").read_text()):
            if platform.get("openwrt"):
                target = platform["target"]
                name = f"drcom4scut-{version}-{target}.tar.gz"
                lines.append(f"| {LABELS[target]} | [`{name}`]({download}{name}) |")
        lines += ["", f"[OpenWrt 安装与使用]({source}docs/openwrt.md)"]
    other = "SeaLoong/drcom4scut" if gui else "SeaLoong/drcom4scutGUI"
    provenance = sample["counterpart"]
    lines += ["", f"下载完整性校验：[SHA256SUMS]({download}SHA256SUMS)。",
              "", f"本仓库构建来源：[`{sha[:8]}`](https://github.com/{repository}/commit/{sha})。",
              f"配套{'核心' if gui else '图形界面'}采用打包时最新发布的 [{provenance['release']['tag']}](https://github.com/{other}/releases/tag/{provenance['release']['tag']})，"
              f"源码 [`{provenance['source_commit'][:8]}`](https://github.com/{other}/commit/{provenance['source_commit']})。", ""]
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--bundle-index", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--preview", action="store_true")
    args = parser.parse_args()
    args.output.write_text(render(args.repository, args.commit, args.tag,
                                 bundles=json.loads(args.bundle_index.read_text()), preview=args.preview), encoding="utf-8")
