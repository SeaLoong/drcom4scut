# 开发、构建与验证

本页面向源码开发者，命令均在源码仓库根目录执行。使用 `rust-toolchain.toml` 选择的 stable Rust，最低版本见 `Cargo.toml` 的 `rust-version`（当前为 1.99）。维护依赖时同步提交 `Cargo.lock`；普通构建、检查和 CI 使用 `--locked`。开发协作约定见 [AGENTS.md](https://github.com/SeaLoong/drcom4scut/blob/master/AGENTS.md)，用户操作入口见 [README](../README.md)。

## 本机构建与检查

在仓库根目录运行：

```sh
cargo build --locked --release
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo clippy --locked --all-targets --no-default-features -- -D warnings
cargo test --locked
cargo test --locked --no-default-features
./target/release/drcom4scut --version
```

默认构建的 HTTPS 后端需要平台 C 工具链。Windows 还需 [Npcap SDK 1.15](https://npcap.com/dist/npcap-sdk-1.15.zip) 的匹配架构库：x64 使用 `Lib/x64`，ARM64 使用 `Lib/ARM64`，其中均包含 `Packet.lib` 和 `wpcap.lib`。将所选目录加入 `LIB`，并设置 `LIBPCAP_LIBDIR`。CI 使用[固定 SDK 安装步骤](https://github.com/SeaLoong/drcom4scut/blob/master/.github/actions/setup-npcap/action.yml)，保留正常 TLS 校验。MSVC 在 `build.rs` 中延迟加载捕获 DLL；真实抓包仍需安装 Npcap。

macOS 使用 Xcode Command Line Tools 提供的系统 SDK 和链接器；抓包走系统 BPF，不依赖 Npcap。Intel 与 Apple Silicon 分别原生构建、测试及发布，产物是各自架构的 Mach-O，不是通用二进制。核心的操作系统基线参考 [Rust Apple 目标说明](https://doc.rust-lang.org/rustc/platform-support/apple-darwin.html)和实际使用的依赖，不能将 CI runner 系统版本或 GUI 的 .NET 要求直接当作核心最低版本。运行权限见 [macOS 指南](macos.md)。

## 构建特性

| 特性集合 | 命令参数 | 能力 |
| --- | --- | --- |
| 默认 | 无附加参数 | 文件日志、有线 EAP/UDP、HTTP 与 HTTPS Portal |
| 精简 | `--no-default-features` | 有线 EAP/UDP、控制台日志 |
| 路由器 | `--no-default-features --features log4rs,portal` | 文件日志、有线认证、显式允许的 HTTP Portal |
| HTTPS 门户 | `--features portal-tls` | 启用 `portal` 及证书校验；交叉编译需匹配的 TLS C/汇编工具链 |

HTTP-only 产物会拒绝 HTTPS，不能用关闭证书校验或静默降级代替 TLS 支持。`log4rs` 只启用实际使用的日志 appender/编码/滚动功能，不需要其 YAML 配置解析器。

## 模块与运行模型

- `settings` 解析 CLI/YAML、密码源、模式和报文字段；`main` 提供检查、管理命令与退出信号入口。
- `client` 统一管理认证会话、网卡变化、退避、状态、hooks 和清理。EAP 与 UDP 由各自的 Tokio future 持有状态，`watch` 保留最近授权结果，UDP 完成握手后才上报完整在线。
- `device` 隔离抓包接口。Unix 将 pnet 阻塞收发放在有限超时的适配层；macOS BPF 使用非阻塞描述符和有界等待，取消中的读取保留复用。Windows 使用非阻塞 pcap，并通过原生 IP Helper 枚举网卡，使列举与 Portal 不依赖捕获驱动。
- `socket` 为 DNS/UDP 选择真实本地 IPv4 和出口接口，macOS 使用 `IP_BOUND_IF` 约束出口。载荷里的 `eap_ip` / `udp_ip` 与实际源地址分离。未固定 `ip` 的会话周期检查地址变化。
- `portal` 处理显式选择的 ePortal 接入、同主机约束、响应解析和在线会话确认。`control` 提供 Windows 私有命名管道和 Unix 私有 socket 的 GUI 停止通道，停止请求与父进程 EOF 均进入有界清理；`service` 仅对接 Windows SCM。

有线 `legacy` 与 `windows31` 共用 EAP Start、Identity、MD5、Success 的基本过程；后者改变部分扩展字段和 MiscInfo，并增加一次 UDP 启动心跳确认。Identity 扩展仍相同，周期心跳相同。报文参数与依据分别见[配置参考](configuration.md#有线报文兼容选项)及[客户端参考](references-clients.md)。

## 测试层次

| 范围 | 覆盖内容 | 运行条件 |
| --- | --- | --- |
| 协议 | 固定字节、长度、端序、校验和、截断/乱序、两种报文配置 | 普通用户 |
| EAP 状态机 | 任意初始标识符、认证、组播心跳、重认证、重试、取消 | 模拟以太网及虚拟时钟 |
| DNS/UDP | 真实 socket、源绑定、启动/周期心跳、丢包、EAP 状态变化 | 本机 loopback |
| Portal | HTTP/TLS、JSONP、会话归属、地址/跳转约束、超时与注销 | 本机模拟服务器 |
| CLI/生命周期 | 真实子进程、私有密码输入、状态、hooks、信号退出 | 普通用户 |
| Windows 策略 | 服务 ACL、所有者、父路径、外部密码源、无驱动枚举 | Windows runner |
| macOS / Unix | 原生接口绑定与 loopback、私有 socket、停止与父进程 EOF | 原生 macOS / Linux runner |
| OpenWrt | procd/UCI、私有路径、LuCI JS/RPC、安装、ABI 与归档 | Shell、Python、Node fixtures |
| 其他 CPU | 相同协议与子进程测试，发布二进制版本检查 | 对应硬件或 QEMU |

测试应确认实际执行并完成，零测试、跳过和通过分别报告。交叉 `cargo check` 不证明原生 macOS 或 Windows 行为。模拟认证、QEMU 和策略 fixtures 也不能代替校园交换机、实际 Npcap/BPF、路由器网卡、LuCI 浏览器或长期在线验证。

并发测试通过门闩或虚拟时钟安排事件，不依赖主机在几毫秒内调度。ARMv5 测试不得假设存在 64 位原子。跨架构时 `CARGO_TARGET_*_RUNNER` 只启动测试主程序，CLI 子进程另需 `DRCOM_TEST_RUNNER`。

独立脚本检查可在仓库根目录运行：

```sh
python3 -m unittest discover -s .github/scripts/tests -v
python3 -m unittest discover -s packaging/openwrt/luci-app-drcom4scut/tests -v
```

Windows 原生服务策略检查：

```powershell
powershell -NoProfile -NonInteractive -File scripts/test-service-acl.ps1
```

## OpenWrt 交叉构建

当前发布平台和特性以 [platforms.json](https://github.com/SeaLoong/drcom4scut/blob/master/.github/scripts/platforms.json) 为准。静态路由器产物使用 Rust 分发中的 self-contained musl 和 `rust-lld`；例如 ARMv7：

```sh
rustup target add armv7-unknown-linux-musleabi
RUSTFLAGS='-C linker=rust-lld -C target-feature=+crt-static' \
  cargo build --locked --release --target armv7-unknown-linux-musleabi \
    --no-default-features --features log4rs,portal
DRCOM_TEST_RUNNER=qemu-arm \
CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABI_RUNNER=qemu-arm \
RUSTFLAGS='-C linker=rust-lld -C target-feature=+crt-static' \
  cargo test --locked --target armv7-unknown-linux-musleabi \
    --no-default-features --features log4rs,portal
python3 .github/scripts/package_release.py armv7-unknown-linux-musleabi --runner qemu-arm
```

安装对应 QEMU user-mode 程序后执行测试。桌面 GNU Linux、Windows、macOS 的 x64/ARM64 目标使用匹配架构的原生 runner；静态 x64/ARM64 也在对应 Linux runner 上执行，ARMv5TE、ARMv7 和 RISC-V 通过 QEMU 执行。没有提供当前稳定工具链可构建、可测试的 MIPS/MIPSEL 发布目标；平台清单中的产物也不等于任意路由器型号已通过实网验证。

## LuCI 页面包

在对应 OpenWrt SDK 中，将 `packaging/openwrt/luci-app-drcom4scut/` 复制为 `package/luci-app-drcom4scut/`，保留其中的许可证文件，安装 SDK 自带的 LuCI feed，然后运行：

```sh
make package/luci-app-drcom4scut/compile V=s
```

SDK 按其发行版生成 `.ipk` 或 `.apk`。该包只包含 JS、Shell、JSON 等页面资源，依赖 `luci-base`、`rpcd`、`jshn`、`logd`，使用 `Architecture: all`；它不构建或捆绑认证二进制。Shell/JS/API fixtures 的测试见上文，SDK 包安装和真实浏览器交互仍需在对应固件验证。

## CI 与打包

[Rust CI](https://github.com/SeaLoong/drcom4scut/blob/master/.github/workflows/rust.yml) 在 push、pull request 或手动运行时调用[共用验证工作流](https://github.com/SeaLoong/drcom4scut/blob/master/.github/workflows/validate-build.yml)。它运行格式、两组严格 Clippy、默认/精简及目标特性测试、平台构建和脚本回归。清单包含六个桌面目标和五个静态路由器目标，共十一个；runner、模拟器和 Npcap 库架构在同一清单中明确声明。

平台清单同时驱动构建矩阵、[打包器](https://github.com/SeaLoong/drcom4scut/blob/master/.github/scripts/package_release.py)和[发布完整性检查](https://github.com/SeaLoong/drcom4scut/blob/master/.github/scripts/verify_release.py)。Cargo 命令显式指定 target，打包前核对 ELF/PE/Mach-O、CPU、位宽、端序、静态属性、ARM 基线/ABI 和实际版本。包内包含程序、配置示例、文档、许可证及相应 OpenWrt 资源，并生成 SHA-256。

## 自动预发布

推送到本仓库 `master` 后，全部验证和平台清单中的十一个目标构建成功才会自动创建 Preview。它直接使用本次 CI 的产物，不重新构建；PR、其他分支、fork 和手动运行普通 CI 均不发布。

预发布标签为 `preview-运行号-尝试号-提交号前八位`，固定指向本次完整提交号，不覆盖已有标签。程序版本仍采用 `Cargo.toml`，下载时通过预发布标签和说明中的提交号辨认构建。Preview 标记为 Pre-release，且不会替换正式版的 Latest。

[预发布器](https://github.com/SeaLoong/drcom4scut/blob/master/.github/scripts/publish_preview.py)先创建草稿，上传归档与 `SHA256SUMS`，核对远端文件集合、大小和 SHA-256 后才公开。失败上传保留为草稿；旧提交或已被更新运行取代的任务不会重新发布旧产物。仅保留最近十个本流程已公开的 Preview，清理 Release 时保留 Git 标签，正式版、草稿和其他预发布不受影响。

实现参考 [Sensa 的自动预发布与手动发布](https://github.com/SeaLoong/Sensa/tree/9dc7de27645fb484fa52711656bf31b05ff3f84a/.github/workflows)。普通 CI 在主分支不取消正在运行的发布，只有最终发布 job 获得 `contents: write`；发布使用内置 `github.token`，不需要额外 PAT。

## 手动发布

1. 更新 `Cargo.toml`、相关打包元数据和 [CHANGELOG](../CHANGELOG.md)，提交源码及锁文件，确认普通 CI 结果。
2. 在默认分支已有工作流的仓库中打开 **Actions → Manual release → Run workflow**，选择待发布引用，填写与 manifest 一致的标签，如 `v0.5.0`。
3. `draft` 默认开启。保留它会创建草稿；取消后会直接发布。

工作流重新执行共用验证、检查全部平台包与校验和，核对最终标签仍指向已验证提交，然后创建 Release。它拒绝覆盖其他提交的标签及既有 Release。只有最终发布 job 有写权限。正式发布仅接受手动触发，普通 Git 推送只会按上述条件自动创建 Preview。

来源快照、许可证和协议证据见[派生仓库记录](references-forks.md)与[相关客户端记录](references-clients.md)。新增兼容行为应附独立报文样本或可重复的协议测试，并明确实机验证范围。
