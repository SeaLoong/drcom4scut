# drcom4scut

[![自动检查](https://github.com/SeaLoong/drcom4scut/actions/workflows/rust.yml/badge.svg?branch=master)](https://github.com/SeaLoong/drcom4scut/actions/workflows/rust.yml)
[![下载预览版](docs/badges/preview.svg)](https://github.com/SeaLoong/drcom4scut/releases)
[![支持平台](docs/badges/platforms.svg)](docs/download.md)
[![许可证](docs/badges/license.svg)](LICENSE)

**让华南理工大学校园网连接更省心。** 接好网线、填好账号密码，即可开始认证；连接中断时自动尝试恢复。

[软件首页与帮助中心](https://SeaLoong.github.io/drcom4scut/) · [下载](docs/download.md) · [连接帮助](docs/troubleshooting.md)

## 我应该从哪里开始？

| 在哪里使用 | 从这里开始 |
| --- | --- |
| **Windows、Mac、Linux 电脑** | 推荐 **[图形界面 drcom4scutGUI](https://github.com/SeaLoong/drcom4scutGUI#readme)**，用窗口和按钮完成操作 |
| **OpenWrt 路由器** | [安装到路由器](docs/openwrt.md)，让路由器持续负责校园网认证 |
| **终端或后台服务** | [命令行快速开始](docs/getting-started.md)；本仓库提供的核心程序适合这种方式 |
| **校园 Wi-Fi** | 连接 Wi-Fi 后在学校网页登录；需要自动填写时，了解[校园网页登录](docs/portal.md) |

## 可以做什么？

- **有线联网**：完成校园网认证，自动保持连接，断线后重新尝试。
- **多平台使用**：Windows、macOS、Linux 电脑和多种 OpenWrt 路由器都有下载包。
- **轻松管理**：图形界面可记住账号、查看连接情况和设置开机后自动连接；路由器可通过 LuCI 页面操作。
- **校园网页登录**：已连接校园 Wi-Fi 时，可自动提交兼容 DrCOM/ePortal 页面的账号密码。当前验证范围见[无线使用说明](docs/portal.md)。
- **后台运行**：支持 Windows 服务、OpenWrt 开机启动，以及终端中的状态和日志查询。

## 下载与安装

电脑用户从 **[图形界面安装说明](https://github.com/SeaLoong/drcom4scutGUI#安装)** 开始。下载图形界面和配套核心，解压到同一文件夹；Mac 将核心放在 `.app` 旁边。

当前跨平台使用指南对应核心 **0.5.1**、图形界面 **3.1.1** 系列。下载页标有 **Pre-release** 的是开发预览版；正式版使用独立的发布记录。选择与你的电脑匹配的程序文件，完整对照表见[下载指南](docs/download.md)。

## 三步开始连接

1. **接好校园网网线。** 在电脑的网络设置里确认以太网已经连接并取得地址。
2. **打开图形界面。** 选择“有线网络”和连接校园网的网卡，填写账号、密码；首次使用运行一次“环境自检”。
3. **点击“连接”。** 等待窗口显示在线。日常可保留程序运行，让它在连接中断时自动恢复；结束时点击“断开”。

Windows 有线认证需要安装 [Npcap](https://npcap.com/#download)；Mac 和 Linux 的首次网卡授权步骤见[图形界面帮助](https://github.com/SeaLoong/drcom4scutGUI/blob/master/docs/usage.md)。使用终端的步骤见[命令行快速开始](docs/getting-started.md)。

## 连接失败怎么办？

先运行“环境自检”，然后按提示核对网卡、地址和账号。完整步骤见[连接与排障](docs/troubleshooting.md)；需要反馈时，附上系统版本、客户端版本和已遮住个人信息的错误提示，到[问题反馈](https://github.com/SeaLoong/drcom4scut/issues)说明。

## 使用帮助

[下载选择](docs/download.md) · [命令行入门](docs/getting-started.md) · [Mac](docs/macos.md) · [OpenWrt](docs/openwrt.md) · [校园网页登录](docs/portal.md) · [Windows 后台服务](docs/windows-service.md) · [配置参考](docs/configuration.md)

参与项目可阅读[开发指南](docs/development.md)、[更新记录](CHANGELOG.md)与[参考来源](docs/references-clients.md)。项目采用 [LGPL-3.0-or-later](LICENSE) 许可证。
