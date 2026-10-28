# 平台支持与路由器构建

[返回首页](../README.md) · [OpenWrt 安装](openwrt.md) · [开发与验证](development.md)

选择程序需要同时匹配处理器、系统和运行库。`uname -m` 只能说明其中一部分；两个设备都显示 MIPS 或 ARM，并不保证同一个程序可以运行。

MIPS 是处理器架构，musl 是 C 运行库。同一种 musl 既可以静态链接进程序，也可以动态链接到固件已有的共享库。换成 MIPS 需要匹配的 Rust 目标标准库、C 交叉编译器、链接器和目标系统库；只更换 musl 或链接器还不够。

| 要核对的条件 | 含义 |
| --- | --- |
| CPU 与指令集 | x86-64、ARMv5TE、ARMv7、ARM64、RISC-V GC 等；较新指令不能用于不支持它的旧 CPU |
| 位数与字节序 | 32/64 位、大端/小端决定程序和数据的解释方式；MIPS 与 MIPSel 必须分别构建 |
| ABI | 程序调用约定，包括 MIPS O32、ARM 软/硬浮点；同一 CPU 也可能使用不同 ABI |
| 操作系统与运行库 | GNU Linux 使用 glibc，OpenWrt 通常使用 musl；动态程序还需匹配加载器和共享库 |
| 工具链 | Rust 编译器、目标标准库、C 编译器、链接器与目标系统库共同组成构建条件 |

## 当前发布范围

核心的[平台清单](https://github.com/SeaLoong/drcom4scut/blob/master/.github/scripts/platforms.json)包含 **11 个目标：6 个桌面目标和 5 个静态 OpenWrt 目标**。下载时以该次 Release 实际提供的文件为准。

| 桌面系统 | x64 目标 | ARM64 目标 |
| --- | --- | --- |
| Windows | `x86_64-pc-windows-msvc` | `aarch64-pc-windows-msvc` |
| GNU Linux | `x86_64-unknown-linux-gnu` | `aarch64-unknown-linux-gnu` |
| macOS | `x86_64-apple-darwin` | `aarch64-apple-darwin` |

| 静态 OpenWrt 目标 | 处理器条件 |
| --- | --- |
| `x86_64-unknown-linux-musl` | x86-64 |
| `aarch64-unknown-linux-musl` | ARM64 |
| `armv5te-unknown-linux-musleabi` | ARMv5TE，软浮点 ABI |
| `armv7-unknown-linux-musleabi` | ARMv7，软浮点 ABI |
| `riscv64gc-unknown-linux-musl` | 64 位 RISC-V，支持 GC 扩展 |

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

2026-10-28 使用 Rust 1.99.1，在同一 x86-64 Linux 主机上对相同完整功能进行比较；musl C 编译工具来自 Debian musl 1.2.5，Rust 标准库来自该工具链的官方目标组件。gzip 使用级别 9，仅压缩单个程序，不包含文档、服务脚本或 GUI：

| 目标与构建配置 | 程序文件 | 单程序 gzip |
| --- | ---: | ---: |
| glibc，`x86_64-unknown-linux-gnu` / `release` | 5.37 MiB | 2.61 MiB |
| 静态 musl，`x86_64-unknown-linux-musl` / `release` | 5.50 MiB | 2.68 MiB |
| 静态 musl，同一目标 / `router` | 3.78 MiB | 1.94 MiB |

本次静态 musl 文件比 glibc 文件大约 2.4%；切换到 `router` 配置后，同一静态目标的文件减小约 31.3%，gzip 减小约 27.8%。前两者还包含目标标准库和链接方式的差异，不能把差额全部归为 libc，也不能推广为所有架构的固定比例。优化后的程序通过 ABI、版本及私有密码输入配置检查，完整功能未删减；文件变小不代表运行内存或速度必然更好，仍需在实际路由器上验证。

桌面 GUI 的 .NET 自包含发布是另一个体积来源；其[平台与发布体积说明](https://github.com/SeaLoong/drcom4scutGUI/blob/master/docs/platform-support.md)单独比较了运行时随包与系统共享两种方式。

## MIPS 与 MIPSel 的接入计划

**目前没有发布 MIPS/MIPSel 包。** Rust 1.99 的 `mips-unknown-linux-musl` 与 `mipsel-unknown-linux-musl` 均为 Tier 3：编译器认识这些目标，源码中也有标准库支持，但 Rust 官方不提供预编译标准库。`rustc --print target-list` 能列出目标，不代表 `rustup target add` 可以安装；当前安装会提示没有预编译产物。

这两个目标采用 MIPS32r2、O32 ABI、软浮点，分别为大端与小端，最大原子操作宽度为 32 位。它们不能代表全部 MIPS 设备，更不能直接用于不同 ABI 的 MIPS64。接入前需要：

1. 确定设备型号、CPU/字节序/浮点 ABI、OpenWrt 版本与 target/subtarget，以及可用存储和内存。可提供 `ubus call system board`、`uname -m`、`opkg print-architecture` 或 `apk --print-arch` 的输出，去掉设备标识和个人信息即可，不需要校园账号或密码。
2. 固定匹配的 OpenWrt SDK 和可验证来源的稳定版 Rust 工具链，包含目标标准库；版本需满足 `Cargo.toml` 的最低要求。没有合适的现成工具链时，需要从对应稳定版 Rust 源码构建。OpenWrt 的 Rust 配方提供了这种构建方式，但应核对实际版本和补丁，不能假设下载一个 SDK 就已包含足够新的 Rust。
3. 对齐 C 运行库、Rust 标准库和 `libc` 绑定的时间 ABI，验证时钟、socket 超时与文件信息。目标没有 64 位原子操作，依赖和测试也需使用兼容实现。`ring` 有通用 C 路径，不能仅凭其汇编目标列表断言不支持 MIPS；TLS、随机数和证书校验仍须实际构建、运行验证。
4. 扩展打包器和更新器的 ELF 校验，分别核对大小端、`EM_MIPS`、O32、指令集和浮点 ABI，并增加拒绝错误架构的测试。现有校验只接受小端 ELF，不能仅添加平台名称就开始发布。
5. 用 `qemu-mips`、`qemu-mipsel` 分别执行目标测试和产物检查，再在对应 OpenWrt 设备验证安装、procd/LuCI、抓包、权限和实际认证。通过后才加入发布清单和下载说明。

Cargo 的 `-Zbuild-std` 可以从源码编译标准库，但官方要求 nightly Cargo、nightly rustc 和 `rust-src`。它属于另一个需要单独维护和验证的工具链方案；本项目当前仍使用稳定版，不把 nightly 当作默认补救措施。

## SDK 动态包与通用静态包

使用 OpenWrt SDK 可以与指定固件的 CPU、musl、链接器和编译选项保持一致。动态链接复用固件已有的共享库，可能减少程序文件，但仍须计入新增依赖占用，并明确固件、加载器和运行库版本。OpenWrt Rust 配方通常采用动态链接；这类包需要自己的打包和验证约定，当前静态包的安装与自动更新规则不能直接套用。

静态包更便于跨固件分发，体积通常较大，也需要在更新程序时一并更新所包含的库。选择哪一种应依据实际设备的空间、内存和维护方式；两者都应保留 TLS 与证书校验，不能为了缩小文件而默默降低 HTTPS 安全性。

## 小设备可以怎样进一步支持

| 路线 | 适用情况与当前状态 |
| --- | --- |
| 完整功能、体积优化的静态包 | 当前五个 OpenWrt 目标采用 `router` 配置，适合跨匹配架构的固件分发。 |
| 指定固件的 SDK 动态包 | 未来可复用系统库，由固件包管理器安装依赖；需要单独的包身份、ABI 验证和升级规则，尚未发布。 |
| 明确裁剪能力的有线专用包 | 未来可把更新器及其 HTTP/TLS、归档依赖也设为可选，以降低占用；必须明确缺少哪些功能，不能把当前 `--no-default-features` 当成这种包。 |

动态包或裁剪包不能沿用现有静态完整包的附件名和自动更新选择逻辑，否则更新时可能被替换成另一种构建。应先定义变体、依赖和升级策略，再验证并发布；普通用户继续使用功能完整的标准包。

## 怎样理解验证结果

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
- [Cargo build-std 要求](https://doc.rust-lang.org/cargo/reference/unstable.html#build-std)
- [OpenWrt SDK 使用说明](https://openwrt.org/docs/guide-developer/toolchain/using_the_sdk)
- [OpenWrt Rust 构建配方](https://github.com/openwrt/packages/blob/master/lang/rust/Makefile)与[目标、链接配置](https://github.com/openwrt/packages/blob/master/lang/rust/rust-values.mk)
- [ring 的目标处理](https://github.com/briansmith/ring/blob/2723abbca9e83347d82b056d5b239c6604f786df/include/ring-core/target.h)与[构建实现](https://github.com/briansmith/ring/blob/2723abbca9e83347d82b056d5b239c6604f786df/build.rs)
