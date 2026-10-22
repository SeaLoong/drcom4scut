# drcom4scut 0.4.0

使用稳定版 Rust / Tokio 的华南理工大学网络认证客户端，支持有线 802.1X + DrCOM、仅 EAP，以及显式配置的无线 DrCOM/ePortal。

本次升级对照了原仓库的 11 个直接 fork、GUI 的 1 个 fork、公开分支和问题记录，并检查了其他 SCUT 客户端。来源、提交、许可证、功能处理结果及检索范围见[派生版本调研](docs/references-forks.md)和[相关客户端调研](docs/references-clients.md)。检索结果代表这些公开来源，不代表已穷尽 GitHub 上所有代码。

## 下载和运行

从 GitHub Actions 的构建产物或 Releases 下载与 CPU、ABI 匹配的包。Linux 有 GNU 和静态 musl 产物；OpenWrt 支持的架构、安装和 procd/LuCI 集成见 [OpenWrt 文档](docs/openwrt.md)。Windows 真实有线认证需要安装 [Npcap](https://npcap.com/#download)。

```sh
./drcom4scut --list-interfaces
./drcom4scut init --config /path/to/config.yml
./drcom4scut doctor --interface eth0
./drcom4scut --config /path/to/config.yml --check-config
./drcom4scut run --config /path/to/config.yml --interface eth0
```

`doctor` 检查网卡、IPv4 和抓包权限，不发送认证报文，也不需要账号。Unix 有线认证需要原始抓包权限（例如 `CAP_NET_RAW`）；HTTP 代理不能替代校园侧以太网连接。`run` 可以省略，原有 `-c/-u/-m/-i/-H/-N/-t/-D` 参数保留。

### 密码传递与存储

推荐在配置中使用 `password_file`，路径相对于配置文件；Unix 密码文件必须为普通文件、单链接、权限 `0600` 或 `0400`。Windows 应使用当前用户私有 ACL，Windows 服务则使用管理员/SYSTEM 私有目录。

```yaml
username: '你的学号'
password_file: password
interface: eth0
```

密码文件仅包含一行 UTF-8 密码。不要在 shell 命令、命令行参数或环境变量里拼接密码。GUI 3.0.0 使用 DPAPI CurrentUser 保存密码，再通过 `--password-stdin` 的独立标准输入管道交给核心；发送后关闭管道。核心支持 `--password-file PATH`。旧 `-p/--password` 与 YAML `password` 仅为兼容保留，GUI 不会回退到这些方式；程序启动、诊断与状态文件不输出账号密码。旧版本已经写出的敏感日志不会因升级自动消失，应自行清理。

### 常用能力

- `--interface NAME` 固定有线网卡，DNS 和 UDP 同时绑定真实本地地址及出口接口，避免 Wi-Fi/VPN/多默认路由干扰；不自动修改系统路由、防火墙或其他连接。
- `--no-udp` / `no_udp: true` 仅执行 EAP；`--once` 验证一次完整认证/心跳后退出；`--no-log` 禁用文件日志。
- 网卡丢失、DHCP IPv4 变化和认证失败会重新发现接口并重连。`reconnect` 到 `reconnect_max` 的有上限指数退避避免持续快速重试；UDP 失败不直接销毁健康 EAP 会话。
- 合法初始 EAP 标识符、PAE 组播心跳和重新认证均有回归测试；畸形长度、乱序响应及过期认证结果不会提前进入在线状态。
- `--status-file PATH` 输出无凭据的 JSON 在线状态；`status --status-file PATH` 读取状态；`logs` 显示配置日志的最近 200 行。状态区分 EAP 认证与完整 UDP 在线，文件时间戳用于识别旧状态。
- Ctrl-C、SIGTERM 和 Windows 服务停止会取消会话并有界发送 Logoff。`--logoff --interface NAME` 可主动执行有线注销。
- `hooks.online` / `hooks.offline` 可配置本地命令参数数组；不自动启动 shell、不传递密码，设置 `hooks.timeout` 限制执行时间。

### 报文配置与 Windows 31 兼容

默认 `profile: legacy` 保留原版报文。选择 `profile: windows31` 可启用 260 字节 MiscInfo、启动心跳以及对应 MD5 扩展/版本字段。网关、第二 DNS、源端口及报文中的 IPv4 均可显式设置：

```yaml
profile: windows31
local_port: 61440
server_port: 61440
gateway: 192.0.2.1
# eap_ip: 192.0.2.10   # 可选：报文内 EAP IPv4
# udp_ip: 192.0.2.10   # 可选：报文内 UDP IPv4
```

这里的文档示例地址不能直接用于校园认证。`ip` 用于选择实际本地地址，`eap_ip` / `udp_ip` 只改变协议载荷，不改变路由来源。显式的 `data.*` 设置优先于 profile 默认值。默认 DNS 与原版一致，`--dns IP[:PORT]` 可重复覆盖。完整字段见 [config.example.yml](src/default_config.yml)。

### 无线门户

`mode: portal` 为独立 provider，不依赖原始以太网。显式配置可信门户地址、AC 和客户端地址，只有服务器在线列表确认本机已上线才报告成功。禁止把密码转发到跳转出的其他主机。官方部分门户使用明文 HTTP，必须显式启用 `--allow-insecure-portal`，这不能保护密码在校园网络上的传输；HTTPS 不会自动降级。详情及模拟服务器测试见[无线门户文档](docs/portal.md)。

### Windows GUI 和服务

[drcom4scutGUI](https://github.com/SeaLoong/drcom4scutGUI) 3.0.0 是独立的 .NET 10 WPF 界面，支持多账号、托盘、登录启动、私有密码管道、诊断，以及 EAP+UDP、仅 EAP 和无线门户三种模式。界面包旁边需放置本核心 0.4.0+ 的 `drcom4scut.exe`；真实有线认证仍需 Npcap。

无人值守运行可使用[Windows SCM 服务](docs/windows-service.md)。服务安装/启动/停止/查询/卸载均为显式管理员操作，凭据配置和程序必须预先位于受保护目录，不把 GUI 的当前用户 DPAPI 密文直接拿给 LocalSystem 使用。

## 构建、测试和 CI

`rust-toolchain.toml` 使用 stable，最低 Rust 1.99。本次验证为 Rust 1.99.1。旧的 `is_global()` 仍是不稳定 API，已经替换其用法；不需要 `RUSTC_BOOTSTRAP`。

```sh
cargo build --locked --release
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo clippy --locked --all-targets --no-default-features -- -D warnings
cargo test --locked
cargo test --locked --no-default-features
```

默认特性包括文件日志及支持 HTTPS 的门户。`--no-default-features` 可构建有线精简版；`--no-default-features --features log4rs,portal` 为纯 Rust 静态路由器构建，支持需显式许可的 HTTP 门户，不包含 HTTPS 门户能力。`portal-tls` 使用正常证书校验，原生构建需要 C 工具链。Windows 编译需要官方 Npcap SDK 1.15 的 `Packet.lib`、`wpcap.lib`，设置 `LIB` 和 `LIBPCAP_LIBDIR`。MSVC 通过 `build.rs` 延迟加载驱动 DLL，以便无驱动时也能执行帮助、版本和不抓包的测试。

[CI 平台清单](.github/scripts/platforms.json) 是构建和发布的共同来源，包含 GNU、Windows 及五种静态 OpenWrt 架构。ARMv5TE/ARMv7/RISC-V 使用 QEMU 实际执行测试；原生 Linux/Windows runner 执行对应测试。打包前检查真实 ELF/PE、CPU/ABI/静态属性、版本和文件集合，避免把宿主二进制改名冒充其他架构。

[测试说明](docs/development.md)区分协议单元、模拟 EAP、真实回环 UDP/DNS/门户、CLI 子进程、跨架构 QEMU 和实际校园网测试。前几类成功不能证明学校服务器已接受认证；真实校园网、Npcap 驱动及长期在线需要目标环境验证。

## 手动 Release

先提交更新后的版本、源码和锁文件。工作流进入默认分支后，在 **Actions → Manual release → Run workflow** 选择待发布引用，填写与 `Cargo.toml` 一致的标签（本轮 `v0.4.0`）。默认创建草稿。

流程重新运行测试和平台构建，核对全部包、SHA-256、版本、标签及提交后再创建 Release；不覆盖指向其他提交的标签或既有 Release。用户请求推送代码不等于执行发布，本轮只准备流程。

## 许可证与来源

遵循仓库 [LGPL-3.0](LICENSE)。Cargo 元数据已与现有许可证文件保持一致。调研中的协议行为均有来源记录；未把没有许可证或 AGPL 客户端的实现代码混入本仓库。
