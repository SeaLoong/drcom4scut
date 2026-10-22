# drcom4scut

华南理工大学校园网认证客户端，可在 Windows、macOS、Linux 和受支持的 OpenWrt 设备上使用。

支持有线 EAP + UDP 认证、仅 EAP 认证，以及无线 DrCOM/ePortal 登录；提供网卡选择、断线重连、连接状态、日志和退出注销。桌面用户可配合 [drcom4scutGUI](https://github.com/SeaLoong/drcom4scutGUI) 使用图形界面，路由器用户可安装 LuCI 管理页。

## 下载与安装

在 [Releases](https://github.com/SeaLoong/drcom4scut/releases) 选择正式版，或标记为 **Pre-release** 的 Preview 测试版；也可从 [Actions](https://github.com/SeaLoong/drcom4scut/actions) 下载构建产物。下载后核对包的 SHA-256，再解压到自己有写入权限的目录。

| 使用环境 | 选择的包 | 运行前准备 |
| --- | --- | --- |
| Windows x64 / ARM64 | `x86_64-pc-windows-msvc.zip` / `aarch64-pc-windows-msvc.zip` | 有线认证需安装对应系统的 [Npcap](https://npcap.com/#download)；无线 Portal 不需要抓包驱动 |
| macOS Intel / Apple Silicon | `x86_64-apple-darwin.tar.gz` / `aarch64-apple-darwin.tar.gz` | 有线认证需要 BPF 访问权限，见 [macOS 使用指南](docs/macos.md) |
| Linux x86_64 / ARM64 | `x86_64-unknown-linux-gnu.tar.gz` / `aarch64-unknown-linux-gnu.tar.gz` | 有线认证需要抓包权限 |
| Linux/OpenWrt 静态程序 | 对应 CPU 的 `linux-musl` / `linux-musleabi` 包 | 按 [OpenWrt 安装指南](docs/openwrt.md) 核对 CPU、ABI 和固件 |

发布包包含程序、`config.example.yml`、文档和许可证。Windows 下使用 `drcom4scut.exe`，以下示例中的 `./drcom4scut` 在 PowerShell 中写作 `.\drcom4scut.exe`。

## 有线网络快速开始

先连接校园网网线，确认网卡已有可用 IPv4。程序负责认证；IP 地址、DHCP 和系统网络设置由操作系统或路由器管理。

1. 列出网卡，记录连接校园网的 `NAME`：

   ```sh
   ./drcom4scut --list-interfaces
   ```

2. 在当前目录创建配置模板：

   ```sh
   ./drcom4scut init --config config.yml
   ```

   编辑 `config.yml` 中的账号、密码文件和网卡。将 `eth0` 换成上一步显示的实际名称；macOS 上可能是 `en0`、`en5` 等名称：

   ```yaml
   username: '你的校园网账号'
   password_file: password
   interface: eth0
   ```

3. 用编辑器创建名为 `password` 的文件，仅写一行密码，保存为不带 BOM 的 UTF-8。Linux、macOS 上限制其权限：

   ```sh
   chmod 600 password
   ```

   Windows 上将配置放在当前用户的私有目录；需要自动保存密码时，推荐使用 GUI。不要把密码放入命令行或环境变量。

4. 检查配置和有线抓包条件，再启动认证：

   ```sh
   ./drcom4scut --config config.yml --check-config
   ./drcom4scut doctor --interface eth0
   ./drcom4scut run --config config.yml --status-file status.json
   ```

   Linux 有线认证需由管理员运行核心，或由管理员授予所需抓包权限。macOS 按 [BPF 权限说明](docs/macos.md#有线抓包权限)配置。使用 GUI 时保持普通用户运行，只向核心授予必要权限。`doctor` 不发送认证报文；它会报告网卡、IPv4 或驱动权限问题。配置检查通过也不表示学校已接受认证。

默认有线模式同时执行 EAP 和 UDP。只需要 EAP 时，在配置中设置 `no_udp: true` 或运行时添加 `--no-udp`。有线报文配置默认即可，一般无需设置 `profile`；只有已知服务端有特定兼容要求时，才按[高级配置说明](docs/configuration.md#有线报文兼容选项)调整，它与本机操作系统无关。

## 日常使用

`run` 可以省略。程序会在认证失败或网卡地址变化后尝试重连；同一网卡上请只运行一个认证客户端。

| 操作 | 命令 |
| --- | --- |
| 正常运行并记录状态 | `./drcom4scut --config config.yml --status-file status.json` |
| 查看上述状态文件 | `./drcom4scut status --status-file status.json` |
| 查看最近 200 行本地日志 | `./drcom4scut logs --config config.yml` |
| 关闭文件日志 | `./drcom4scut --config config.yml --no-log` |
| 测试一次认证流程并退出（不持续保活） | `./drcom4scut --config config.yml --once` |
| 查看全部参数 | `./drcom4scut --help` |

在运行窗口按 Ctrl-C 可停止并尝试注销。Linux、macOS 的 SIGTERM 和服务管理器停止也会触发清理。需要单独发送有线注销时，可使用 `./drcom4scut --config config.yml --logoff --interface eth0`。

状态中的 `online` 表示所选认证模式已完成：EAP + UDP 模式需要 UDP 在线确认，仅 EAP 模式只检查 EAP。完整模式的 UDP 心跳重试耗尽时会暂时下线并继续恢复 UDP，健康的 EAP 会话会保留。`online` 不是对任意互联网地址的连通性保证。读取状态时也要查看 `updated_at`，避免把旧文件当作当前连接。

## 无线、后台与路由器

- **无线门户**：设置 `mode: portal` 并使用学校实际的可信门户地址，见[无线登录指南](docs/portal.md)。它与有线 EAP 是不同接入方式，不会自动切换。
- **桌面 GUI**：使用 [drcom4scutGUI](https://github.com/SeaLoong/drcom4scutGUI) 的 Windows、macOS 或 Linux 包，将对应系统和 CPU 的核心放在 GUI 旁；macOS 放在 `.app` 同级。支持多账号、托盘和按用户选择的登录启动；GUI 3.1.0 需要核心 0.5.0 或更高版本。
- **macOS**：架构选择、BPF 权限和首次打开说明见 [macOS 使用指南](docs/macos.md)。
- **Windows 无人值守运行**：见[后台服务部署](docs/windows-service.md)，由管理员安装和管理。
- **OpenWrt 与 LuCI**：见[路由器安装、配置和管理](docs/openwrt.md)。现有预编译包不包括 MIPS/MIPSEL。

## 常见问题

| 现象 | 先检查 |
| --- | --- |
| 找不到网卡或 `capture=unavailable` | `--list-interfaces` 中的名称、网卡 IPv4，以及 Npcap、macOS BPF 或 Linux 抓包权限 |
| 密码文件被拒绝 | 是否为单行 UTF-8 普通文件；Unix 权限是否为 `0600` / `0400`，且没有硬链接 |
| EAP 成功但 UDP 无法上线 | 选中的有线网卡、本地 IPv4、校园 DNS 和 UDP 服务器；使用[配置参考](docs/configuration.md)核对参数 |
| Portal 接受登录但仍未上线 | 门户地址、AC/客户端 IPv4、学校在线列表是否确认当前设备，见[门户排障](docs/portal.md#常见问题) |
| `logs` 找不到日志 | 是否关闭了文件日志；`log.file_directory` 是否指向运行时实际目录 |
| 断线后仍显示在线 | 状态文件是否属于正在运行的客户端，`updated_at` 是否已停止更新 |

提交问题时请附程序版本、系统、模式和已脱敏的错误信息；不要上传账号配置、密码文件、认证抓包或完整私密日志。

## 更多文档

[配置参考](docs/configuration.md) · [macOS](docs/macos.md) · [OpenWrt](docs/openwrt.md) · [无线门户](docs/portal.md) · [Windows 服务](docs/windows-service.md) · [开发与构建](docs/development.md) · [更新记录](CHANGELOG.md)

本项目使用 [LGPL-3.0-or-later](LICENSE)。协议和兼容性参考见[派生版本记录](docs/references-forks.md)与[相关客户端记录](docs/references-clients.md)。
