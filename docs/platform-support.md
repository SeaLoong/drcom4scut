# 平台支持与路由器构建

[返回首页](../README.md) · [OpenWrt 安装](openwrt.md) · [开发与验证](development.md)

选择程序需要同时匹配处理器、系统和运行库。`uname -m` 只能说明其中一部分；两个设备都显示 MIPS 或 ARM，并不保证同一个程序可以运行。

MIPS 是处理器架构，musl 是 C 运行库。同一种 musl 既可以静态链接进程序，也可以动态链接到固件已有的共享库。换成 MIPS 需要匹配的 Rust 目标标准库、C 交叉编译器、链接器和目标系统库；只更换 musl 或链接器还不够。

| 要核对的条件 | 含义 |
| --- | --- |
| CPU 与指令集 | x86-64、ARMv5TE、ARMv7、ARM64、RISC-V GC 等；较新指令不能用于不支持它的旧 CPU |
| 位数与字节序 | 32/64 位、大端/小端决定程序和数据的解释方式；MIPS 与 MIPSel 必须分别构建 |
| ABI | 程序调用约定，包括 MIPS O32/N64、ARM 软/硬浮点；同一 CPU 也可能使用不同 ABI |
| 操作系统与运行库 | GNU Linux 使用 glibc，OpenWrt 通常使用 musl；动态程序还需匹配加载器和共享库 |
| 工具链 | Rust 编译器、目标标准库、C 编译器、链接器与目标系统库共同组成构建条件 |

## 源码构建矩阵与下载范围

核心的[平台清单](https://github.com/SeaLoong/drcom4scut/blob/master/.github/scripts/platforms.json)包含 **23 个目标：6 个桌面目标和 17 个静态路由器目标**。这是当前源码的构建与验证范围；已有正式版不会自动增加附件，下载时以所选 Release 实际提供的文件为准。六种桌面 GUI 一体包保持独立，新增路由器目标只生成核心、procd 服务和可选 LuCI 资源，不引入 .NET。

| 桌面系统 | x64 目标 | ARM64 目标 |
| --- | --- | --- |
| Windows | `x86_64-pc-windows-msvc` | `aarch64-pc-windows-msvc` |
| GNU Linux | `x86_64-unknown-linux-gnu` | `aarch64-unknown-linux-gnu` |
| macOS | `x86_64-apple-darwin` | `aarch64-apple-darwin` |

| 静态 OpenWrt 目标 | 处理器条件 |
| --- | --- |
| `x86_64-unknown-linux-musl` | x86-64 |
| `i686-unknown-linux-musl` | 32 位 x86，需 SSE2；不代表仅支持 i586 的旧 CPU |
| `aarch64-unknown-linux-musl` | ARM64 |
| `armv5te-unknown-linux-musleabi` | ARMv5TE，软浮点 ABI |
| `arm-unknown-linux-musleabi` | ARMv6，软浮点 ABI |
| `arm-unknown-linux-musleabihf` | ARMv6，VFP、硬浮点 ABI |
| `armv7-unknown-linux-musleabi` | ARMv7，软浮点 ABI |
| `armv7-unknown-linux-musleabihf` | ARMv7-A，VFPv3-D16、硬浮点 ABI |
| `riscv64gc-unknown-linux-musl` | 64 位 RISC-V，GC 扩展 |
| `loongarch64-unknown-linux-musl` | LoongArch64，LP64D ABI、LSX |
| `powerpc64-unknown-linux-musl` | 64 位 PowerPC，大端、ELFv2 ABI |
| `powerpc64le-unknown-linux-musl` | 64 位 PowerPC，小端、ELFv2 ABI |
| `mips-unknown-linux-musl` | MIPS32r2，大端、O32 软浮点 ABI |
| `mipsel-unknown-linux-musl` | MIPS32r2，小端、O32 软浮点 ABI |
| `mips64-unknown-linux-muslabi64` | MIPS64r2，大端、N64 硬浮点 ABI，需要 FPU 与支持 N64 的 64 位 Linux 内核 |
| `mips64el-unknown-linux-muslabi64` | MIPS64r2，小端、N64 硬浮点 ABI，需要 FPU 与支持 N64 的 64 位 Linux 内核 |
| `mips64-openwrt-linux-musl` | MIPS64r2，大端、N64 软浮点 ABI，需要支持 N64 的 64 位 Linux 内核；可用于兼容的无 FPU 设备 |

静态 musl 程序自带所需的 C 运行库，不依赖固件中的 musl 动态加载器，适合在匹配架构的不同固件间分发。它仍依赖兼容的 Linux 内核、网卡和权限；HTTPS 证书信任还需要可用的证书来源。当前发布与更新校验要求 OpenWrt 程序没有 `PT_INTERP` 动态加载器记录。

## 保留功能的体积优化

路由器使用 `router` 构建配置，在发布配置基础上采用 `opt-level = "z"` 和一个代码生成单元，保留 LTO、去符号和失败时终止进程的设置。它改变编译优化方式，功能仍由 Cargo 特性决定。

在仓库根目录构建已支持的 ARMv7 静态目标，例如：

```sh
rustup target add armv7-unknown-linux-musleabi
CC=clang AR=llvm-ar RUSTFLAGS='-C linker=rust-lld -C target-feature=+crt-static' \
  cargo build --locked --profile router --target armv7-unknown-linux-musleabi \
    --no-default-features --features log4rs,portal-tls
qemu-arm ./target/armv7-unknown-linux-musleabi/router/drcom4scut --version
```

最后一条需先安装 QEMU；也可将产物复制到匹配设备直接执行。C 编译工具和测试步骤见[交叉构建说明](development.md#openwrt-交叉构建)。

这个组合保留有线 EAP/UDP、文件日志、HTTP/HTTPS Portal、证书校验和 HTTPS 在线更新。`--no-default-features` 单独使用会移除可选文件日志和 Portal，仍保留更新需要的 TLS；它是不同的功能组合，不能用来代表完整路由器包的体积。程序大小还取决于目标、工具链和依赖；压缩包大小、解压后文件大小、运行内存和处理速度需要分别测量。

### 同架构的体积实测

2026-10-28 使用 Rust 1.99.1 和平台扩展提交 `1bb0126` 的源码，在同一 x86-64 Linux 主机上对相同完整功能进行比较；musl C 编译工具来自 Debian musl 1.2.5，Rust 标准库来自该工具链的官方目标组件。gzip 使用级别 9，仅压缩单个程序，不包含文档、服务脚本或 GUI：

| 目标与构建配置 | 程序文件 | 单程序 gzip |
| --- | ---: | ---: |
| glibc，`x86_64-unknown-linux-gnu` / `release` | 5.38 MiB | 2.61 MiB |
| 静态 musl，`x86_64-unknown-linux-musl` / `release` | 5.51 MiB | 2.68 MiB |
| 静态 musl，同一目标 / `router` | 3.79 MiB | 1.94 MiB |

本次静态 musl 文件比 glibc 文件大约 2.4%；切换到 `router` 配置后，同一静态目标的文件减小约 31.2%，gzip 减小约 27.8%。前两者还包含目标标准库和链接方式的差异，不能把差额全部归为 libc，也不能推广为所有架构的固定比例。优化后的程序通过 ABI、版本及私有密码输入配置检查，完整功能未删减；文件变小不代表运行内存或速度必然更好，仍需在实际路由器上验证。

桌面 GUI 的 .NET 自包含发布是另一个体积来源；其[平台与发布体积说明](https://github.com/SeaLoong/drcom4scutGUI/blob/master/docs/platform-support.md)单独比较了运行时随包与系统共享两种方式。

## MIPS 与 MIPSel 的稳定工具链

MIPS 系列使用五个独立目标：MIPS32r2 大小端 O32 软浮点、MIPS64r2 大小端 N64 硬浮点，以及 MIPS64r2 大端 N64 软浮点。N64 硬浮点包要求 FPU；无 FPU 的 Octeon 等设备应选择匹配的软浮点包。三种 N64 包均不兼容 N32、O32 或 MIPS r6/NaN2008，不能只看处理器位数互换。N64 还需要支持该 ABI 的 64 位 Linux 内核；64 位 CPU 配合 32 位内核不能运行。

这五个目标均需从源码准备目标标准库；Rust 1.99 没有对应的官方预编译目标标准库，不能直接依赖 `rustup target add`。这仍不覆盖所有 MIPS 固件、指令集和 ABI 组合。

[工具链准备脚本](https://github.com/SeaLoong/drcom4scut/blob/master/.github/scripts/setup_mips_toolchain.py)固定稳定版 Rust **1.99.1** 与 musl **1.2.5** 源码，并校验下载的 SHA-256。它使用 Rust 的 bootstrap `local-rebuild / stage0` 路径构建目标标准库，在独立目录安装交叉工具链；不修改宿主 sysroot，不需要 nightly，也不要求应用构建设置 `RUSTC_BOOTSTRAP`。CI 对这五个目标执行相同准备步骤，并分别检查浮点 ABI。

本地步骤见[开发文档](development.md#mips-与-mipsel-工具链)。准备后仍需验证完整功能、精简功能、ELF 大小端/O32/N64/浮点 ABI、子进程和归档更新。QEMU 测试通过只证明所用模拟器中的行为，不代表具体 OpenWrt 固件的网卡、procd/LuCI、资源占用和校园认证均已实机验证。

i586 也出现在 Rust 的目标列表中，但当前 TLS 依赖的实际构建需要 SSE2，不能把强制启用 SSE2 的产物称为可在旧 i586 CPU 上运行。当前采用明确要求 SSE2 的 i686 包；其他未进入清单的目标同样需要实际构建、ABI 检查和运行验证后再提供。

## SDK 动态包与通用静态包

使用 OpenWrt SDK 可以与指定固件的 CPU、musl、链接器和编译选项保持一致。动态链接复用固件已有的共享库，可能减少程序文件，但仍须计入新增依赖占用，并明确固件、加载器和运行库版本。OpenWrt Rust 配方通常采用动态链接；这类包需要自己的打包和验证约定，当前静态包的安装与自动更新规则不能直接套用。

静态包更便于跨固件分发，体积通常较大，也需要在更新程序时一并更新所包含的库。选择哪一种应依据实际设备的空间、内存和维护方式；两者都应保留 TLS 与证书校验，不能为了缩小文件而默默降低 HTTPS 安全性。

## 小设备可以怎样进一步支持

| 路线 | 适用情况与当前状态 |
| --- | --- |
| 完整功能、体积优化的静态包 | 当前清单中的路由器目标采用 `router` 配置，适合跨匹配架构的固件分发。 |
| 指定固件的 SDK 动态包 | 未来可复用系统库，由固件包管理器安装依赖；需要单独的包身份、ABI 验证和升级规则，尚未发布。 |
| 明确裁剪能力的有线专用包 | 未来可把更新器及其 HTTP/TLS、归档依赖也设为可选，以降低占用；必须明确缺少哪些功能，不能把当前 `--no-default-features` 当成这种包。 |

动态包或裁剪包不能沿用现有静态完整包的附件名和自动更新选择逻辑，否则更新时可能被替换成另一种构建。应先定义变体、依赖和升级策略，再验证并发布；普通用户继续使用功能完整的标准包。

## 怎样理解验证结果

2026-10-28，平台扩展新增的 i686、ARMv6 软/硬浮点、ARMv7 硬浮点、LoongArch64、大小端 PowerPC64、MIPS/MIPSel 共 9 个目标，均已生成完整功能程序，并在清单指定的 QEMU CPU 上通过完整与精简功能测试。MIPS/MIPSel 在平台扩展提交 `1bb0126` 上分别通过完整功能 214 项、精简功能 180 项测试；后续功能修复会增加回归用例，以对应提交的 CI 为准。优化产物通过 ABI、版本和私有配置检查，9 个实际归档也确认只有核心与 OpenWrt 服务/LuCI 资源，没有 GUI 或 .NET 运行时。

本轮新增的三种 MIPS64r2 N64 目标分别通过完整功能 233 项、精简功能 196 项测试；软浮点目标在不提供 FPU 的 `Octeon68XX` CPU 模型上验证，硬浮点目标使用 `MIPS64R2-generic`。程序、真实归档与更新器仍须通过同一套严格 ABI 和安装验证。

CI 为大端 MIPS32、MIPS64 与 PowerPC64 使用固定、校验 SHA-256 的静态 QEMU 10.0.13，见[模拟器准备脚本](https://github.com/SeaLoong/drcom4scut/blob/master/.github/scripts/setup_qemu.py)。Ubuntu 24.04 自带 QEMU 8.2 在上述大端目标上处理跨端序 netlink 响应时，会使网卡枚举挂起；同一程序换用 QEMU 10 后可正常完成。此处通过更新模拟器解决，保留网卡枚举、协议和 CLI 测试。平台清单中各目标的实际发布归档还会通过核心更新器安装，并执行安装后的版本检查；交叉目标的子进程使用相同 CPU runner。

强化后的 ABI 校验还验证了此前正式版的 11 个真实核心组件，均保持兼容；不会为了接受新架构而放松动态加载器、端序或浮点 ABI 检查。这些是构建、模拟器与产物验证结果，尚不代表新增目标已经在具体 OpenWrt 硬件或校园网络上通过验收。

| 已完成的检查 | 能说明什么 |
| --- | --- |
| 交叉编译成功 | 源码和依赖可以生成该目标程序 |
| ELF/ABI 校验和 `--version` 成功 | 产物标记符合预期，能在所用设备或模拟器启动 |
| 目标测试在 QEMU 或原生 runner 通过 | 对应测试覆盖的协议、TLS、子进程和更新逻辑可运行 |
| 对应 OpenWrt 固件实机验证 | 安装、服务、网卡、权限和资源使用在该设备可用 |
| 校园网络验证 | 该学校接入环境下的认证、重连与持续在线结果 |

每次报告应注明目标、工具链、固件、设备或模拟器，以及未运行项。模拟器测试不能替代校园实网；单台设备结果也不能覆盖全部同名 CPU。

## 官方参考

- [Rust 平台支持与 Tier 3 定义](https://doc.rust-lang.org/rustc/platform-support.html#tier-3)
- [Rust 1.99 MIPS musl 目标](https://github.com/rust-lang/rust/blob/1.99.0/compiler/rustc_target/src/spec/targets/mips_unknown_linux_musl.rs)与 [MIPSel musl 目标](https://github.com/rust-lang/rust/blob/1.99.0/compiler/rustc_target/src/spec/targets/mipsel_unknown_linux_musl.rs)
- [Rust bootstrap 构建说明](https://rustc-dev-guide.rust-lang.org/building/bootstrapping/what-bootstrapping-does.html)
- [OpenWrt SDK 使用说明](https://openwrt.org/docs/guide-developer/toolchain/using_the_sdk)
- [OpenWrt Rust 构建配方](https://github.com/openwrt/packages/blob/master/lang/rust/Makefile)与[目标、链接配置](https://github.com/openwrt/packages/blob/master/lang/rust/rust-values.mk)
- [ring 的目标处理](https://github.com/briansmith/ring/blob/2723abbca9e83347d82b056d5b239c6604f786df/include/ring-core/target.h)与[构建实现](https://github.com/briansmith/ring/blob/2723abbca9e83347d82b056d5b239c6604f786df/build.rs)
