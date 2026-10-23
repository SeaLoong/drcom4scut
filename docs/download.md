# 下载适合你的版本

[返回首页](../README.md)

电脑用户推荐使用 **drcom4scutGUI 图形界面**，它提供账号输入框、连接按钮和状态显示。图形界面与负责连接的核心程序搭配使用，各下载一份、放在一起即可。OpenWrt 和命令行用户只需要核心。

## 打开下载页面

- **[图形界面下载](https://github.com/SeaLoong/drcom4scutGUI/releases)**：选择含 `3.1.1` 或更新版本、与你的系统匹配的文件。
- **[核心下载](https://github.com/SeaLoong/drcom4scut/releases)**：本指南使用 `0.5.1` 系列；图形界面 3.1.x 至少需要核心 0.5.0。

GitHub 将每个版本放在一条发布记录中。**Pre-release** 表示开发预览版，会随通过检查的新代码更新；正式版由维护者另行发布，页面中的 **Latest** 指正式版。展开相应记录下的 **Assets**，选择程序压缩包。`Source code` 是给开发者使用的源码。

## Windows、Mac、Linux 下载对照

文件名前面还有项目名与版本号，按表格中的**文件名结尾**查找即可。

| 你的电脑 | 图形界面 | 核心 |
| --- | --- | --- |
| Windows，Intel / AMD 处理器 | `win-x64.zip` | `x86_64-pc-windows-msvc.zip` |
| Windows，ARM 处理器 | `win-arm64.zip` | `aarch64-pc-windows-msvc.zip` |
| Mac，Apple M 系列芯片 | `osx-arm64.tar.gz` | `aarch64-apple-darwin.tar.gz` |
| Mac，Intel 处理器 | `osx-x64.tar.gz` | `x86_64-apple-darwin.tar.gz` |
| Linux，Intel / AMD 处理器 | `linux-x64.tar.gz` | `x86_64-unknown-linux-gnu.tar.gz` |
| Linux，ARM64 处理器 | `linux-arm64.tar.gz` | `aarch64-unknown-linux-gnu.tar.gz` |

Windows 在 **设置 → 系统 → 系统信息** 查看处理器；Mac 在 **苹果菜单 → 关于本机** 查看芯片；Linux 可运行 `uname -m`。`x86_64` 对应常见 Intel / AMD 电脑，`aarch64` 对应 ARM64。

Mac 图形界面适用于 macOS 15 及更新的受支持系统。Linux 图形界面需要桌面环境；详细系统要求与安装步骤见[图形界面使用说明](https://github.com/SeaLoong/drcom4scutGUI/blob/master/docs/usage.md)。

## 解压并打开

1. 将图形界面和核心解压到自己有写入权限的文件夹，保留包内其他文件。
2. Windows / Linux 将核心 `drcom4scut.exe` / `drcom4scut` 放在 GUI 程序旁边；Mac 将 `drcom4scut` 放在 `drcom4scutGUI.app` 旁边。
3. 打开图形界面，运行一次“环境自检”，按[使用说明](https://github.com/SeaLoong/drcom4scutGUI/blob/master/docs/usage.md)完成首次配置。

每次发布都提供 `SHA256SUMS` 文件清单，可用它检查下载是否完整：[查看校验方法](configuration.md#检查下载的文件)。Mac 首次打开和有线网卡授权见 [Mac 指南](macos.md)。

## OpenWrt 路由器

核心提供 x86-64、ARM64、ARMv7、ARMv5TE 和 RISC-V 64 的静态程序包。先确认路由器处理器与固件，再按 [OpenWrt 安装指南](openwrt.md#选择程序)选包和安装。

## 接下来

[图形界面开始连接](https://github.com/SeaLoong/drcom4scutGUI/blob/master/docs/usage.md) · [命令行快速开始](getting-started.md) · [路由器安装](openwrt.md) · [遇到问题](troubleshooting.md)
