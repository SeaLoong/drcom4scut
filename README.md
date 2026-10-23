# drcom4scut

[![自动检查](https://github.com/SeaLoong/drcom4scut/actions/workflows/rust.yml/badge.svg?branch=master)](https://github.com/SeaLoong/drcom4scut/actions/workflows/rust.yml)
[![下载预览版](docs/badges/preview.svg)](https://github.com/SeaLoong/drcom4scut/releases)
[![支持平台](docs/badges/platforms.svg)](https://github.com/SeaLoong/drcom4scut/releases)
[![许可证](docs/badges/license.svg)](LICENSE)

华南理工大学校园网认证工具。接好校园网网线、填写账号密码后，它可以替你完成认证，并在断线后尝试重新连接。

## 我应该从哪里开始？

| 你的使用场景 | 推荐入口 |
| --- | --- |
| 在 Windows、Mac 或 Linux 电脑上使用，想点按钮操作 | **[下载图形界面 drcom4scutGUI](https://github.com/SeaLoong/drcom4scutGUI#readme)**，按其安装说明放好配套核心 |
| 希望让 OpenWrt 路由器负责认证 | **[OpenWrt 安装指南](docs/openwrt.md)** |
| 熟悉终端，希望直接运行或部署后台服务 | 继续阅读本页的[命令行使用](#命令行使用) |
| 已连接校园 Wi-Fi，平时在网页中输入账号密码 | 先用浏览器完成登录；需要尝试自动登录时，阅读[无线网页登录](docs/portal.md) |

本仓库提供的是“认证核心”，本身没有可点击的窗口。普通电脑用户建议从上面的图形界面开始。

## 可以做什么？

- 连接校园有线网络后，使用账号密码认证；断线、网线重新插入或网卡地址变化后尝试恢复连接。
- 查看当前认证状态和日志，停止时尝试退出本次校园网会话。
- 在 Windows 后台运行，或交给 OpenWrt 路由器管理。
- 对兼容的校园网页登录页面，尝试自动提交账号密码、检查在线状态。

无线自动登录针对特定的 DrCOM/ePortal 登录页面，尚未在校园实网验证；它不会替系统连接 Wi-Fi，也不能登录所有校园网页。网页能手动登录，仍是确认账号和网络可用的第一步。

## 下载与安装

前往 **[下载页面 Releases](https://github.com/SeaLoong/drcom4scut/releases)**，选择标有 **Pre-release** 的最新开发预览。本文的跨平台安装说明对应目前的 `0.5.0` 系列；页面中的 **Latest** 正式版可能仍是较早版本。

展开该条发布记录下的 **Assets**，下载与你的系统、处理器对应的文件。不要下载 `Source code`，那是开发者使用的源码。

| 电脑 | 文件名结尾 |
| --- | --- |
| Windows，常见 Intel / AMD 电脑（x64） | `x86_64-pc-windows-msvc.zip` |
| Windows，ARM 处理器电脑（ARM64） | `aarch64-pc-windows-msvc.zip` |
| Mac，Intel 处理器 | `x86_64-apple-darwin.tar.gz` |
| Mac，Apple M 系列处理器 | `aarch64-apple-darwin.tar.gz` |
| Linux，Intel / AMD 处理器（x64） | `x86_64-unknown-linux-gnu.tar.gz` |
| Linux，ARM64 处理器 | `aarch64-unknown-linux-gnu.tar.gz` |
| OpenWrt 路由器 | 按[路由器指南](docs/openwrt.md#选择程序)选择，不能只按品牌判断 |

`x86_64` 就是常见的 x64；`aarch64` 就是 ARM64。Windows 可在“设置 → 系统 → 系统信息”查看处理器；Mac 可在苹果菜单“关于本机”查看。文件名前面还会带项目名和版本号。

下载后先按[校验文件的方法](docs/configuration.md#检查下载的文件)确认文件完整，再解压到自己有写入权限的目录。包内有程序、配置示例、文档和许可证。

有线认证还需要允许程序使用网卡：Windows 安装 [Npcap](https://npcap.com/#download)；Mac 按 [macOS 指南](docs/macos.md)配置；Linux 按[网卡权限步骤](https://github.com/SeaLoong/drcom4scutGUI/blob/master/docs/usage.md#linux)由管理员授权。无线网页登录不需要这些抓包权限。

## 命令行使用

以下以 Linux / Mac 的终端为例。在 Windows PowerShell 中，把命令开头的 `./drcom4scut` 换成 `.\drcom4scut.exe`。不想编辑配置或使用终端，可以改用[图形界面](https://github.com/SeaLoong/drcom4scutGUI#readme)。

### 1. 接好网线，找出网卡名称

先确认系统已识别以太网网卡，并已取得 IP 地址，然后在解压目录打开终端，执行：

```sh
./drcom4scut --list-interfaces
```

记下连接校园网网线的那张网卡在 `NAME` 一列中的名称。下面用 `eth0` 举例；Mac 上可能叫 `en0` 或 `en5`，请替换成自己的名称。

### 2. 填写账号和密码

生成配置文件：

```sh
./drcom4scut init --config config.yml
```

用文本编辑器打开 `config.yml`，找到并修改下面三项，其他设置先保留默认值：

```yaml
username: '你的校园网账号'
password_file: password
interface: eth0
```

在同一个目录新建名为 `password` 的纯文本文件，只写一行校园网密码。保存时选择“UTF-8”或“UTF-8（无 BOM）”，不要选择“带 BOM”（额外文件头）；Windows 注意不要让文件实际变成 `password.txt`，或把配置中的名字也改为 `password.txt`。

Mac / Linux 还需要执行下面的命令，让密码文件只供自己访问：

```sh
chmod 600 password
```

不要把密码直接写进终端命令、截图或问题反馈。更多文件保存说明见[密码与路径](docs/configuration.md#密码与路径)。

### 3. 检查，然后开始认证

```sh
./drcom4scut --config config.yml --check-config
./drcom4scut doctor --interface eth0
./drcom4scut --config config.yml --status-file status.json
```

第一条检查填写是否有效；第二条检查网卡和访问权限；第三条才开始真正认证。前两条检查通过不等于账号已经登录。

如果提示没有访问网卡的权限：Mac 按[BPF 权限说明](docs/macos.md#有线抓包权限)处理，Linux 按[授权与自检步骤](https://github.com/SeaLoong/drcom4scutGUI/blob/master/docs/usage.md#linux)操作。图形界面始终以普通用户运行。程序不会替系统配置 IP 地址；系统还未取得地址时，先解决网络连接问题。

默认即可完成通常的有线认证。不要为了 Windows、Mac 或 Linux 切换 `profile`；它是给少数网络环境保留的高级兼容设置。

### 4. 查看状态或停止

运行期间保留这个终端窗口。另开一个终端可以查看状态：

```sh
./drcom4scut status --status-file status.json
```

`online` 表示本次校园网认证已完成。它不保证所有网站都能访问。日志可用 `./drcom4scut logs --config config.yml` 查看。

要停止，在运行认证的窗口按 **Ctrl-C**。程序会尝试注销后退出。认证中断后会自行重试，同一网卡请不要同时打开多个客户端。

## 连接失败怎么办？

| 看到的情况 | 下一步 |
| --- | --- |
| 找不到网卡、提示 `capture=unavailable` | 重新检查网卡名称、是否取得 IP，以及 Windows Npcap / Mac 网卡权限 / Linux 管理员权限 |
| 密码文件找不到或被拒绝 | 检查实际文件名、保存位置和格式；Mac / Linux 重新执行 `chmod 600 password` |
| 日志显示前一步通过，但还没有在线 | 有线认证包含多个步骤，等待最终状态；先确认实际连接的是校园网以太网网卡，不要随意改成“仅 EAP” |
| 无线自动登录失败 | 先在浏览器中登录，确认当前网页入口；见[无线常见问题](docs/portal.md#常见问题) |
| 仍不知道哪里出错 | 保留程序版本、系统和错误提示，到[问题反馈](https://github.com/SeaLoong/drcom4scut/issues)说明；先遮住账号、密码和个人网络信息 |

## 按场景查阅

[Mac 安装](docs/macos.md) · [OpenWrt 路由器](docs/openwrt.md) · [无线网页登录](docs/portal.md) · [Windows 后台服务](docs/windows-service.md) · [配置选项](docs/configuration.md)

修改源码或维护项目时，再看[开发与构建](docs/development.md)、[更新记录](CHANGELOG.md)、[派生版本](docs/references-forks.md)和[参考客户端](docs/references-clients.md)。

本项目采用 [LGPL-3.0-or-later 许可证](LICENSE)。
