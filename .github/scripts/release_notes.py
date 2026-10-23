"""Generate user-facing download and setup notes from the release manifests."""
import argparse
import json
from pathlib import Path
import re
import tomllib
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]


def render(repository, sha, tag, *, preview=False, root=ROOT):
    if repository not in ("SeaLoong/drcom4scut", "SeaLoong/drcom4scutGUI"):
        raise ValueError("Unexpected release repository")
    if not re.fullmatch(r"[0-9a-f]{40}", sha) or not re.fullmatch(r"[A-Za-z0-9._-]+", tag):
        raise ValueError("Invalid release identity")
    gui = repository.endswith("GUI")
    version = (ET.parse(root / "Directory.Build.props").findtext(".//Version") if gui else
               tomllib.loads((root / "Cargo.toml").read_text())["package"]["version"])
    source = f"https://github.com/{repository}/blob/{sha}/"
    download = f"https://github.com/{repository}/releases/download/{tag}/"
    platforms = json.loads((root / ".github/scripts/platforms.json").read_text())
    title = ("桌面客户端" if gui else "校园网客户端") + " " + version
    lines = [f"## {title}" + (" · 预发布" if preview else ""), "",
             "选择与你的电脑或路由器对应的压缩包，解压后按使用指南连接校园网。", "",
             "### 下载", "", "| 系统 / 设备 | 下载 |", "| --- | --- |"]
    labels = {
        "win-x64": "Windows · Intel / AMD 64 位", "win-arm64": "Windows · ARM64",
        "osx-x64": "macOS · Intel", "osx-arm64": "macOS · Apple 芯片",
        "linux-x64": "Linux · Intel / AMD 64 位", "linux-arm64": "Linux · ARM64",
        "x86_64-pc-windows-msvc": "Windows · Intel / AMD 64 位",
        "aarch64-pc-windows-msvc": "Windows · ARM64",
        "x86_64-apple-darwin": "macOS · Intel", "aarch64-apple-darwin": "macOS · Apple 芯片",
        "x86_64-unknown-linux-gnu": "Linux · Intel / AMD 64 位",
        "aarch64-unknown-linux-gnu": "Linux · ARM64",
        "x86_64-unknown-linux-musl": "OpenWrt · x86-64",
        "aarch64-unknown-linux-musl": "OpenWrt · ARM64",
        "armv5te-unknown-linux-musleabi": "OpenWrt · ARMv5TE（软浮点）",
        "armv7-unknown-linux-musleabi": "OpenWrt · ARMv7（软浮点）",
        "riscv64gc-unknown-linux-musl": "OpenWrt · RISC-V 64 位",
    }
    for platform in platforms:
        target = platform["runtime" if gui else "target"]
        extension = platform["archive"] if gui else ("zip" if platform["format"] == "pe" else "tar.gz")
        name = f"{repository.split('/')[1]}-{version}-{target}.{extension}"
        lines.append(f"| {labels[target]} | [{name}]({download}{name}) |")
    lines += ["", "### 开始使用", ""]
    if gui:
        lines += [
            "1. 下载上表的桌面客户端，再从[核心下载页](https://github.com/SeaLoong/drcom4scut/releases)选择同一系统、同一处理器的核心程序（0.5.0 或更新）。",
            "2. 解压两个文件，把核心程序放在桌面客户端旁边；Mac 上放在 `.app` 旁边。",
            "3. 打开客户端，选择连接方式，填写校园网账号和密码，点击“连接”。",
            "", "macOS 桌面版适用于 macOS 15 或更新系统。Windows 有线连接先安装 [Npcap](https://npcap.com/#download)。",
            f"", f"[完整使用指南]({source}docs/usage.md) · [本版改进]({source}docs/changes.md)",
        ]
    else:
        lines += [
            "1. 下载并解压对应的压缩包；日常桌面使用可以搭配 [图形界面](https://github.com/SeaLoong/drcom4scutGUI/releases)。",
            "2. 按[使用指南](" + source + "README.md)准备网卡权限和账号配置。",
            "3. 运行客户端开始连接；OpenWrt 用户按包内 `docs/openwrt.md` 安装服务。",
            "", f"[Windows / Linux 入门]({source}README.md) · [macOS]({source}docs/macos.md) · [OpenWrt]({source}docs/openwrt.md) · [网页登录]({source}docs/portal.md)",
            "", f"[本版改进]({source}CHANGELOG.md)",
        ]
    lines += ["", f"下载完整性校验：[SHA256SUMS]({download}SHA256SUMS)。压缩包附带离线帮助文档。",
              "", f"构建来源：[`{sha[:8]}`](https://github.com/{repository}/commit/{sha})。", ""]
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--preview", action="store_true")
    args = parser.parse_args()
    args.output.write_text(render(args.repository, args.commit, args.tag, preview=args.preview), encoding="utf-8")
