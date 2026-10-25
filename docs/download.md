# 下载适合你的版本

[返回首页](../README.md)

**电脑下载桌面一体包，路由器下载 OpenWrt 包。** 桌面一体包已包含图形界面和命令行程序，解压后既可以打开窗口连接，也可以在终端运行。

## 1. 打开下载页

进入 [drcom4scut 下载页](https://github.com/SeaLoong/drcom4scut/releases/latest)，展开最新正式版的 **Assets（下载文件）**。桌面一体包的文件名包含 **`desktop`**，结尾是 `.zip` 或 `.tar.gz`。

下载入口直接打开最新正式版（**Latest**）。按下面的表格选择文件；如需预览版或历史版本，可查看[全部发行记录](https://github.com/SeaLoong/drcom4scut/releases)。

`Source code` 是供开发者编译使用的源码，`SHA256SUMS` 是下载校验清单。日常安装选择程序压缩包即可。

## 2. 找到你的系统和处理器

- **Windows**：打开“设置 → 系统 → 关于”，查看“系统类型”。常见 Intel / AMD 电脑选 x64，ARM 电脑选 ARM64。
- **Mac**：打开“苹果菜单 → 关于本机”。Apple M 系列芯片选 ARM64，Intel 处理器选 x64。
- **Linux**：运行 `uname -m`。`x86_64` 选 x64，`aarch64` 选 ARM64。

在文件名包含 `desktop` 的下载文件中，按下表的**结尾**选择。文件名前半部分会列出包内程序的版本：

| 你的电脑 | 桌面一体包的文件名结尾 | 安装步骤 |
| --- | --- | --- |
| Windows，Intel / AMD | `win-x64.zip` | [窗口](https://github.com/SeaLoong/drcom4scutGUI/blob/master/docs/windows.md) · [终端](windows.md) |
| Windows，ARM64 | `win-arm64.zip` | [窗口](https://github.com/SeaLoong/drcom4scutGUI/blob/master/docs/windows.md) · [终端](windows.md) |
| Mac，Apple M 系列 | `osx-arm64.tar.gz` | [窗口](https://github.com/SeaLoong/drcom4scutGUI/blob/master/docs/macos.md) · [终端](macos.md) |
| Mac，Intel | `osx-x64.tar.gz` | [窗口](https://github.com/SeaLoong/drcom4scutGUI/blob/master/docs/macos.md) · [终端](macos.md) |
| Linux，Intel / AMD | `linux-x64.tar.gz` | [窗口](https://github.com/SeaLoong/drcom4scutGUI/blob/master/docs/linux.md) · [终端](linux.md) |
| Linux，ARM64 | `linux-arm64.tar.gz` | [窗口](https://github.com/SeaLoong/drcom4scutGUI/blob/master/docs/linux.md) · [终端](linux.md) |

Mac 图形界面需要 macOS 15 或更新且受支持的系统；Linux 图形界面需要图形桌面。各系统指南包含首次打开、连接前准备和日常操作的完整步骤。

## 3. 完整解压，选择窗口或终端

把一体包完整解压到一个便于找到的文件夹，例如文档目录下的 `drcom4scut`。保留文件夹内的全部文件，移动或备份时也可以直接操作整个文件夹。

**Windows / Linux**：窗口程序和命令行程序已经放在一起：

```text
你的安装文件夹/
├── drcom4scutGUI.exe    ← 窗口程序，Linux 上没有 .exe
├── drcom4scut.exe       ← 命令行程序，Linux 上没有 .exe
├── 开始使用.txt
└── 其余程序文件与帮助文档
```

**Mac**：窗口程序是 `.app`，旁边是命令行程序：

```text
你的安装文件夹/
├── drcom4scutGUI.app
├── drcom4scut
├── 开始使用.txt
└── 帮助文档与配置示例
```

喜欢窗口操作，打开 `drcom4scutGUI`；使用终端或 SSH，在这个文件夹打开终端，运行同包中的 `drcom4scut`。接着按上表中对应的安装指南完成第一次连接。

发布页中的 `SHA256SUMS` 可以帮助核对下载是否完整，[这里有各系统的校验命令](configuration.md#检查下载的文件)。

已经安装后，可按[更新方法](update.md)在窗口或终端中检查新版本。程序内的更新检查只选择最新正式版。

## OpenWrt 路由器怎么选？

OpenWrt 使用专门的路由器包，内含认证程序、开机运行脚本和 LuCI 管理页。支持 x86-64、ARM64、ARMv7、ARMv5TE 和 RISC-V 64 五类设备。

从 [OpenWrt 安装指南](openwrt.md)开始：先确认路由器型号和处理器，再下载对应文件、上传到路由器，选择网页或 SSH 管理连接。

[回到命令行入门](getting-started.md) · [图形界面日常操作](https://github.com/SeaLoong/drcom4scutGUI/blob/master/docs/usage.md) · [遇到问题](troubleshooting.md)
