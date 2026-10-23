# 开发、构建与验证

[返回首页](../README.md)

使用客户端请从[下载安装](download.md)或[图形界面](https://github.com/SeaLoong/drcom4scutGUI#readme)开始。本页面向希望修改源码、自己构建程序或维护发布的人；开发命令均在源码仓库根目录执行。

| 你的目标 | 从这里开始 |
| --- | --- |
| 在自己的电脑编译一次 | [本机构建与检查](#本机构建与检查) |
| 为路由器生成程序 | [OpenWrt 交叉构建](#openwrt-交叉构建) |
| 修改认证代码，确认没有破坏已有行为 | [模块与运行模型](#模块与运行模型)、[测试层次](#测试层次) |
| 维护测试包或正式版 | [CI 与打包](#ci-与打包)、[自动预发布](#自动预发布)、[手动发布](#手动发布) |

本页几个常用词：**构建/编译**是把源码变成可运行程序；**依赖**是使用的第三方库；**CI** 是 GitHub 自动运行的检查；**交叉构建**是在一台电脑上生成给另一种处理器或系统使用的程序；**模拟测试**使用自建的假服务器检查逻辑，不会真的登录学校网络。

使用 `rust-toolchain.toml` 指定的稳定版 Rust，最低版本见 `Cargo.toml` 的 `rust-version`（当前为 1.99）。`Cargo.lock` 固定第三方库版本，普通命令添加 `--locked` 是为了按已审查的版本构建，避免悄悄更换依赖。维护依赖时同步提交这个文件。协作约定见 [AGENTS.md](https://github.com/SeaLoong/drcom4scut/blob/master/AGENTS.md)。

## 本机构建与检查

先安装稳定版 Rust 和当前系统的 C 编译工具，再在仓库根目录运行。以下示例最后一条用于 Mac / Linux；Windows PowerShell 对应 `.\target\release\drcom4scut.exe --version`：

```sh
cargo build --locked --release
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo clippy --locked --all-targets --no-default-features -- -D warnings
cargo test --locked
cargo test --locked --no-default-features
./target/release/drcom4scut --version
```

上面的命令依次生成发布程序、检查格式、检查代码问题、运行默认和精简测试，最后确认版本。`-D warnings` 表示把代码警告也当作检查失败处理。

默认构建的 HTTPS 加密连接部分需要本机 C 编译工具。Windows 还需 [Npcap SDK 1.15](https://npcap.com/dist/npcap-sdk-1.15.zip) 的匹配架构库：x64 使用 `Lib/x64`，ARM64 使用 `Lib/ARM64`，其中均包含 `Packet.lib` 和 `wpcap.lib`。将所选目录加入 `LIB`，并设置 `LIBPCAP_LIBDIR`。CI 使用[固定 SDK 安装步骤](https://github.com/SeaLoong/drcom4scut/blob/master/.github/actions/setup-npcap/action.yml)，保留正常 TLS 校验。MSVC 在 `build.rs` 中延迟加载捕获 DLL；真实抓包仍需安装 Npcap。

macOS 使用 Xcode Command Line Tools 提供的系统 SDK 和链接器；抓包走系统 BPF，不依赖 Npcap。Intel 与 Apple Silicon 分别原生构建、测试及发布，产物是各自架构的 Mach-O，不是通用二进制。核心的操作系统基线参考 [Rust Apple 目标说明](https://doc.rust-lang.org/rustc/platform-support/apple-darwin.html)和实际使用的依赖，核心最低系统要求独立核对，GUI 则使用对应 .NET 的系统要求。运行权限见 [macOS 指南](macos.md)。

## 构建特性

这些是**编译时决定是否包含某项能力**的开关，不是用户每天认证时要选择的模式。普通桌面发布包已经选好默认能力；路由器包为了便于跨设备构建，采用表中的路由器组合。

| 特性集合 | 命令参数 | 能力 |
| --- | --- | --- |
| 默认 | 无附加参数 | 文件日志、有线 EAP/UDP、HTTP 与 HTTPS Portal |
| 精简 | `--no-default-features` | 有线 EAP/UDP、控制台日志 |
| 路由器 | `--no-default-features --features log4rs,portal-tls` | 文件日志、有线认证、HTTP 与 HTTPS Portal |
| HTTPS 门户 | `--features portal-tls` | 启用 `portal` 及证书校验；交叉编译需匹配的 TLS C/汇编工具链 |

HTTP 是未加密的网页请求，HTTPS 使用 TLS 加密并检查网站证书。HTTPS 入口需要启用 `portal-tls`，以保持加密传输和证书检查。`log4rs` 只启用实际使用的日志 appender/编码/滚动功能，不需要其 YAML 配置解析器。

## 模块与运行模型

修改某个功能前，先定位对应模块。异步任务负责在等待服务器回复时让出执行机会；取消和退出必须一起考虑，避免窗口退出后认证仍在后台运行。

- `settings` 解析 CLI/YAML、密码源、模式和报文字段；`main` 提供检查、管理命令与退出信号入口。
- `client` 统一管理认证会话、网卡变化、退避、状态、hooks 和清理。EAP 与 UDP 由各自的 Tokio future 持有状态，`watch` 保留最近授权结果，UDP 完成握手后才上报完整在线。
- `device` 隔离抓包接口。Unix 将 pnet 阻塞收发放在有限超时的适配层；macOS BPF 使用非阻塞描述符和有界等待，取消中的读取保留复用。Windows 使用非阻塞 pcap，并通过原生 IP Helper 枚举网卡，使列举与 Portal 不依赖捕获驱动。
- `socket` 为 DNS/UDP 选择真实本地 IPv4 和出口接口，macOS 使用 `IP_BOUND_IF` 约束出口。载荷里的 `eap_ip` / `udp_ip` 与实际源地址分离。未固定 `ip` 的会话周期检查地址变化。
- `portal` 处理显式选择的 ePortal 接入、同主机约束、响应解析和在线会话确认。`control` 提供 Windows 私有命名管道和 Unix 私有 socket 的 GUI 停止通道，停止请求与父进程 EOF 均进入有界清理；`service` 仅对接 Windows SCM。
- `update` 检查最新正式版、校验下载并替换当前核心；`update_schedule` 为整个连接生命周期保留一次自动检查计时，重连沿用原来的计时。

有线 `legacy` 与 `windows31` 共用 EAP Start、Identity、MD5、Success 的基本过程；后者改变部分扩展字段和 MiscInfo，并增加一次 UDP 启动心跳确认。Identity 扩展仍相同，周期心跳相同。报文参数与依据分别见[配置参考](configuration.md#有线报文兼容选项)及[客户端参考](references-clients.md)。

## 测试层次

验证分为程序逻辑、目标平台运行和校园实网三层，发布说明分别记录各层结果。`loopback` 指本机回环地址，`fixture` 指专门构造的测试输入或环境，QEMU 是运行其他处理器程序的模拟器。

| 范围 | 覆盖内容 | 运行条件 |
| --- | --- | --- |
| 协议 | 固定字节、长度、端序、校验和、截断/乱序、两种报文配置 | 普通用户 |
| EAP 状态机 | 任意初始标识符、认证、组播心跳、重认证、重试、取消 | 模拟以太网及虚拟时钟 |
| DNS/UDP | 真实 socket、源绑定、启动/周期心跳、丢包、EAP 状态变化 | 本机 loopback |
| Portal | HTTP/TLS、JSONP、会话归属、地址/跳转约束、超时与注销 | 本机模拟服务器 |
| CLI/生命周期 | 真实子进程、私有密码输入、状态、hooks、信号退出 | 普通用户 |
| 更新 | 正式版选择、代理路径、归档与架构校验、实际运行文件替换及回滚、连接后的计时 | 本机模拟服务器、临时程序副本及虚拟时钟 |
| Windows 策略 | 服务 ACL、所有者、父路径、外部密码源、无驱动枚举 | Windows runner |
| macOS / Unix | 原生接口绑定与 loopback、私有 socket、停止与父进程 EOF | 原生 macOS / Linux runner |
| OpenWrt | procd/UCI、私有路径、LuCI JS/RPC、安装、ABI 与归档 | Shell、Python、Node fixtures |
| 其他 CPU | 相同协议与子进程测试，发布二进制版本检查 | 对应硬件或 QEMU |

测试报告分别记录通过、跳过及未运行项。原生行为由对应平台 runner 检查，校园交换机、抓包权限、路由器和长期在线能力则通过真实环境验证。

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

如果只是给路由器安装客户端，使用[现成下载包](openwrt.md)即可。以下步骤供需要自编译的人使用；目标名称同时限定处理器、系统及程序调用方式，请按目标设备选择。

当前发布平台和特性以 [platforms.json](https://github.com/SeaLoong/drcom4scut/blob/master/.github/scripts/platforms.json) 为准。静态路由器产物使用 Rust 分发中的 self-contained musl 和 `rust-lld`；例如 ARMv7：

```sh
rustup target add armv7-unknown-linux-musleabi
RUSTFLAGS='-C linker=rust-lld -C target-feature=+crt-static' \
  cargo build --locked --release --target armv7-unknown-linux-musleabi \
    --no-default-features --features log4rs,portal-tls
DRCOM_TEST_RUNNER=qemu-arm \
CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABI_RUNNER=qemu-arm \
RUSTFLAGS='-C linker=rust-lld -C target-feature=+crt-static' \
  cargo test --locked --target armv7-unknown-linux-musleabi \
    --no-default-features --features log4rs,portal-tls
python3 .github/scripts/package_release.py armv7-unknown-linux-musleabi --runner qemu-arm
```

安装对应 QEMU user-mode 程序后执行测试。桌面 GNU Linux、Windows、macOS 的 x64/ARM64 目标使用匹配架构的原生 runner；静态 x64/ARM64 也在对应 Linux runner 上执行，ARMv5TE、ARMv7 和 RISC-V 通过 QEMU 执行。目前的发布清单覆盖五个静态路由器目标，具体设备兼容性通过真实固件和校园网络验证。

## LuCI 页面包

LuCI 是 OpenWrt 的浏览器管理界面。这里生成的只是“服务 → SCUT DrCOM”页面，不包含负责校园网认证的核心；安装使用见[路由器指南](openwrt.md#luci-管理页)。

在对应 OpenWrt SDK 中，将 `packaging/openwrt/luci-app-drcom4scut/` 复制为 `package/luci-app-drcom4scut/`，保留其中的许可证文件，安装 SDK 自带的 LuCI feed，然后运行：

```sh
make package/luci-app-drcom4scut/compile V=s
```

SDK 按其发行版生成 `.ipk` 或 `.apk`。该包只包含 JS、Shell、JSON 等页面资源，依赖 `luci-base`、`rpcd`、`jshn`、`logd`，使用 `Architecture: all`；它不构建或捆绑认证二进制。Shell/JS/API fixtures 的测试见上文，SDK 包安装和真实浏览器交互仍需在对应固件验证。

## CI 与打包

修改代码后，GitHub 会自动检查格式、代码问题、测试及各平台构建。打包步骤还会确认“文件名说给哪种电脑使用，里面就确实是哪种程序”，并生成供下载者核对的校验值。

[Rust CI](https://github.com/SeaLoong/drcom4scut/blob/master/.github/workflows/rust.yml) 在推送到 `master`、提交 PR 或手动运行时调用[共用验证工作流](https://github.com/SeaLoong/drcom4scut/blob/master/.github/workflows/validate-build.yml)；仅修改 `site/` 或 Pages 工作流的推送与 PR 由网站流程检查，随软件打包的 `docs/` 修改仍执行 Rust CI。它运行格式、两组严格 Clippy、默认/精简及目标特性测试、平台构建和脚本回归。清单包含六个桌面目标和五个静态路由器目标，共十一个；runner、模拟器和 Npcap 库架构在同一清单中明确声明。

平台清单同时驱动构建矩阵、[打包器](https://github.com/SeaLoong/drcom4scut/blob/master/.github/scripts/package_release.py)和[发布完整性检查](https://github.com/SeaLoong/drcom4scut/blob/master/.github/scripts/verify_release.py)。Cargo 命令显式指定 target，打包前核对 ELF/PE/Mach-O、CPU、位宽、端序、静态属性、ARM 基线/ABI 和实际版本。包内包含程序、配置示例、文档、许可证及相应 OpenWrt 资源，并生成 SHA-256。`BUILD-INFO.json` 记录源码版本、提交、工作区状态和目标平台，汇总发布时再次核对。

桌面下载使用包含 GUI 和核心的[一体包](download.md)。验证完成后，[一体包工作流](https://github.com/SeaLoong/drcom4scut/blob/master/.github/workflows/bundle-desktop.yml)先按 `published_at` 选出另一个仓库最新公开的发布，包含预发布，并一次固定该发布与下载文件；本仓库组件采用本次源码的构建结果。六个平台各自在原生 runner 校验、组装，并检查包内 GUI 能发现和启动核心。所选发布缺少平台、校验失败或版本不兼容时，流程会失败并保留错误原因，维护者可据此补齐发布后重新运行。

两仓库的预发布与手动发布均提供这六种一体包。包名包含核心版本、GUI 版本和运行平台；`BUNDLE-INFO.json` 记录双方源码提交、原始归档 SHA-256 和构建信息，以及所选另一仓库的发布编号、标签、发布时间和预发布标记。Windows / Linux 两个程序放在同一目录，Mac 核心放在 `.app` 旁边；打包保留 `.app` 内容和签名。汇总步骤确认六个平台采用同一份对方发布，再生成完整下载校验清单。

## 自动预发布

Preview 是给使用者试用最新代码的开发预览，正式版 Release 仍由维护者手动发布。用户下载说明见[下载指南](download.md)；下面介绍维护流程。

推送到本仓库 `master` 后，全部验证、平台清单中的十一个目标构建，以及六种桌面一体包检查成功才会自动创建 Preview。它直接使用本次 CI 的产物，不重新构建；PR、其他分支、fork 和手动运行普通 CI 均不发布。

预发布标签为 `preview-运行号-尝试号-提交号前八位`，固定指向本次完整提交号，不覆盖已有标签。程序版本仍采用 `Cargo.toml`，下载时通过预发布标签和说明中的提交号辨认构建。Preview 标记为 Pre-release，且不会替换正式版的 Latest。

[预发布器](https://github.com/SeaLoong/drcom4scut/blob/master/.github/scripts/publish_preview.py)先创建草稿，上传归档与 `SHA256SUMS`，核对远端文件集合、大小和 SHA-256 后才公开。失败上传保留为草稿；旧提交或已被更新运行取代的任务不会重新发布旧产物。仅保留最近十个本流程已公开的 Preview，清理 Release 时保留 Git 标签，正式版、草稿和其他预发布不受影响。

实现参考 [Sensa 的自动预发布与手动发布](https://github.com/SeaLoong/Sensa/tree/9dc7de27645fb484fa52711656bf31b05ff3f84a/.github/workflows)。普通 CI 在主分支不取消正在运行的发布，只有最终发布 job 获得 `contents: write`；发布使用内置 `github.token`，不需要额外 PAT。

## 手动发布

1. 更新 `Cargo.toml`、相关打包元数据和 [CHANGELOG](../CHANGELOG.md)，提交源码及锁文件，确认普通 CI 结果。
2. 在 GitHub 打开 **Actions → Manual release → Run workflow**，选择待发布的分支，填写与 `Cargo.toml` 版本一致的标签，如 `v0.6.1`。
3. `draft` 默认开启。保留它会创建草稿；取消后会直接发布。

工作流重新执行共用验证、按上文相同规则选择另一仓库的最新公开版本，生成并检查六种桌面一体包及其余平台包与校验和，核对最终标签仍指向已验证提交，然后上传到草稿。全部远端文件核验完成后，按 `draft` 选项保留草稿或公开发布。它拒绝覆盖其他提交的标签及既有 Release。只有最终发布 job 有写权限。正式发布仅接受手动触发，普通 Git 推送只会按上述条件自动创建 Preview。

来源快照、许可证和协议证据见[派生仓库记录](references-forks.md)与[相关客户端记录](references-clients.md)。新增兼容行为应附独立报文样本或可重复的协议测试，并明确实机验证范围。

## 程序内更新

用户操作见[更新指南](update.md)。核心直接选择当前构建目标的最新正式版，手动检查和安装只读取更新配置，不要求认证配置或校园密码，也不生成配置模板。检查信息、归档及 `SHA256SUMS` 共用指定的 HTTPS 代理，默认 `https://gh-proxy.com/`；精简和路由器构建也包含更新所需的 HTTPS 支持。

安装前核对发布文件摘要、校验清单、构建来源和二进制系统架构，拒绝越界路径、链接和特殊文件，只取出当前核心可执行文件。安装在同目录暂存并替换，保留 Unix 模式、所有者及 Linux capabilities；失败时还原原文件。摘要和校验清单用于核对数据一致性，目前没有独立发布签名，更新代理属于信任范围。

自动检查在所选连接模式完整在线后开始计时，使用 GUI 私有控制通道时由 GUI 统一管理。测试覆盖本地模拟下载、错误校验值、恶意归档、实际运行文件的替换与回滚，以及重连、仅 EAP 和 Portal 的计时；平台工作流另用本次原生发布归档验证安装。模拟更新测试不证明校园认证或目标设备的授权行为。

## 软件首页与帮助中心

网站采用 [VitePress](https://vitepress.dev/) 构建，入口组织参考 [Vite 文档](https://github.com/vitejs/vite/tree/main/docs)、[Syncthing 帮助](https://docs.syncthing.net/) 与 [RustDesk 项目首页](https://github.com/rustdesk/rustdesk)：先选择使用场景，再进入安装和具体任务。

Markdown 是文档的唯一来源。`site/scripts/prepare.mjs` 将本仓库的 README、docs、更新记录和安全说明，以及图形界面仓库的对应文档转换为站点内容；相互引用的帮助链接转为站内导航。图形界面文档固定到 `site/sources.json` 的提交号，Pages 工作流按该提交检出，构建时无需向浏览者请求外部服务。

首次启用网站时，在 GitHub 仓库的 **Settings → Pages → Build and deployment → Source** 选择 **GitHub Actions**。已启用的仓库沿用现有设置；随后运行 **Website and help** 工作流即可发布网站。

本地准备 Node.js 24，并将两个仓库放在同一父目录，执行：

```sh
cd site
npm ci
npx playwright install --with-deps chromium
npm run build
npm run test:browser
npm run preview
```

图形界面放在其他目录时，用 `GUI_DOCS_DIR=/完整路径/drcom4scutGUI` 指定。构建结果为 `site/.vitepress/dist`；构建自动检查文档转换、生成页面的本地链接、图片和标题锚点。浏览器检查覆盖搜索、慢加载入口、手机导航、主题切换、深链接、更新帮助入口和截图展示，Pages 发布前也会执行。本地搜索随静态页面发布，用户输入的搜索词留在浏览器。

VitePress 当前稳定版搭配固定的 Vite 6.4.5 安全修复版本，锁文件保存确切依赖。维护时执行 `npm audit --prefix site`，并同时验证构建、导航和搜索。[Website and help](https://github.com/SeaLoong/drcom4scut/actions/workflows/pages.yml) 在推送时构建页面，PR 只检查构建；master 或手动运行可部署。[Dependency audit](https://github.com/SeaLoong/drcom4scut/actions/workflows/dependency-audit.yml) 每周检查已锁定依赖；正式发布软件仍使用前述手动流程。
