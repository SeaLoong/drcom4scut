# OpenWrt 安装、运行与构建

本项目提供静态 musl 可执行程序和 procd/netifd 集成，不依赖路由器上的 glibc、Rust 或动态 musl loader。这里的“支持 OpenWrt”指下列 CPU/ABI，不代表任意路由器型号都能使用同一个包。

| Rust 产物目标 | CPU/ABI | 常见 OpenWrt 架构方向 |
| --- | --- | --- |
| `x86_64-unknown-linux-musl` | x86-64 | x86/64 软路由 |
| `aarch64-unknown-linux-musl` | ARM64 | aarch64_cortex-a53、aarch64_cortex-a72 等 |
| `armv7-unknown-linux-musleabi` | ARMv7，soft-float | ARMv7 设备；不要求硬浮点用户空间 |
| `armv5te-unknown-linux-musleabi` | ARMv5TE，soft-float | ARMv5/ARMv6 设备；先确认 CPU 支持 ARMv5TE |
| `riscv64gc-unknown-linux-musl` | RV64GC | 带 GC 扩展的 64 位 RISC-V 设备 |

使用 `ubus call system board`、`uname -m` 和 `opkg print-architecture`（使用 apk 的固件可执行 `apk --print-arch`） 检查设备，不要仅按固件文件名猜测。ARMv7 包不是 ARMv5 包；RV64GC 也不能用于缺少 C/F/D 扩展的 RISC-V CPU。还应检查该 Rust target 的最低 Linux 内核要求；旧内核设备应先升级仍受维护的固件。

参考[官方 Rust 平台支持表](https://doc.rust-lang.org/rustc/platform-support.html)及当前 `rustup target list --toolchain stable`。MIPS/MIPSEL 是一些旧 OpenWrt 路由器的重要架构，但当前 stable Rust 官方分发中没有对应的 Linux 标准库。新核心依赖 Rust 1.99，不能安全地退回旧编译器或把 ARM 包改名冒充 MIPS 包。本次不提供未经构建验证的 MIPS 产物。将来上游恢复可用 stable target 或提供受维护的稳定交叉工具链后可增加；目前需要 MIPS 的设备请保留原客户端或改用受支持设备。

## 安装

1. 从 Release 下载对应的 `*-linux-musl*.tar.gz`，核对 `SHA256SUMS`，上传到路由器并解压。
2. 进入解压目录执行 `sh openwrt/install.sh`。安装器会先执行 `--version` 拒绝错误 CPU/ABI 的程序，拒绝现有配置目录/文件的符号链接和非 root 所有者，不会覆盖已有账号或密码配置，也不会自动启用认证。
3. 编辑 `/etc/drcom4scut/config.yml` 的 `username`。升级时先删除旧 YAML 中的明文 `password` 字段。密码只写入 `/etc/drcom4scut/password`：推荐在路由器上用编辑器输入，避免把密码写入 shell 历史或命令行。此文件可以有一个结尾换行，不应有多行内容。
4. 执行 `chown root:root /etc/drcom4scut/password; chmod 600 /etc/drcom4scut/password`。服务拒绝组/其他用户可读或非 root 所有的密码文件。不要把密码放入 UCI、启动命令或日志。
5. 通过 `/usr/bin/drcom4scut --list-interfaces` 找到连接学校网线的物理接口。默认服务从 netifd 的 `wan` 网络取得二层设备（认证前尚未取得 DHCP 地址也能启动）；使用 bridge、VLAN、DSA 时请确认它确实能收发学校的 802.1X 以太网帧。需要时配置 `uci set drcom4scut.main.interface='eth0.2'`，并把 `network` 设为对应的逻辑网络。
6. 先执行 `/usr/bin/drcom4scut --check-config --config /etc/drcom4scut/config.yml --password-file /etc/drcom4scut/password`，再执行以下不包含密码的启用命令：

```sh
uci set drcom4scut.main.enabled='1'
uci commit drcom4scut
/etc/init.d/drcom4scut enable
/etc/init.d/drcom4scut start
logread -e drcom4scut
```

procd 在 root 所有的 `0700` 运行目录中维护脱敏状态文件 `/var/run/drcom4scut/status.json`，供本机管理界面读取；密码不会写入状态文件。procd 监控前台进程；netifd 的接口事件触发重启，以便 DHCP 换址、重插网线后重新读取当前接口属性。未取得设备时服务等待 netifd 事件。不要同时启动多个认证客户端。

服务把配置与密码路径限制为 `/etc/drcom4scut/` 下的直接子文件（文件名只含字母、数字、点、下划线、短横线），拒绝路径穿越、软链接和非 root 私有配置。目录必须为 root 所有的 `0700`，文件必须为 root 所有的 `0400` 或 `0600`。这是为了让 LuCI/UCI 操作权限不能变成任意 root 文件读取或临时 YAML hooks 执行；需要其他配置时由 root 管理员先放入该目录。普通 CLI 仍支持显式指定其他私有配置路径。

账号配置目录为 root 私有；示例关闭文件日志，避免持续写路由器闪存。密码文件只能降低存储/进程列表中的泄露风险，root、调试器或已控制设备的攻击者仍可读取认证所需的密码。实际 DrCOM 协议由学校服务端决定，客户端不能单方面把学校认证改为 TLS。

## 可选 LuCI 管理界面

包内提供独立编写的 `luci-app-drcom4scut`。它显示脱敏状态、最近事件分类，支持启停/重新连接、UCI 服务与网络接口设置，以及脱敏诊断 JSON 导出。界面不提供密码输入框，不读取密码文件，也不返回服务端原始日志文本。需要修改密码时由 root 在前述 `0600` 文件中编辑；浏览器只保存该文件的路径。

如果路由器已安装 `luci-base`、`rpcd`、`jshn`、`logd`，可以在解压后的同架构 Release 目录运行：

```sh
sh openwrt/install-luci.sh
```

脚本安装固定的 JS、菜单、ACL 与专用 rpcd 方法，重启 rpcd 后重新登录，在“服务 → SCUT DrCOM”中管理。它不会自动启用认证，不授予通用 `file.read`、`file.exec` 或任意命令权限。只有通过 rpcd ACL 授权的会话可调用 `drcom4scut.status/logs/diagnostics` 或固定的 `start/stop/restart`。UCI 仅开放该服务自己的配置；procd 还会在实际启动时验证私有配置路径，避免仅靠浏览器校验。

也可以将 `openwrt/luci-app-drcom4scut/` 作为包放入对应 OpenWrt SDK 的 `package/`，安装 SDK 自带 LuCI feed 后执行：

```sh
make package/luci-app-drcom4scut/compile V=s
```

这个仅含 JS/shell/JSON 的界面包使用 `Architecture: all`，不包含认证程序；认证程序仍必须选择匹配 CPU/ABI 的产物。不要把界面包的 `all` 误解为核心支持所有 CPU。浏览器/真实 rpcd/procd 交互需在实际 OpenWrt 设备验证；当前自动检查覆盖脚本与 JSON/JS 语法、精确 ACL、路径约束和脱敏逻辑，并未声称已完成真实路由器 UI 测试。

## 门户认证与 TLS 能力

静态路由器产物启用 `log4rs,portal`，包含有线 802.1X/DrCOM 和无线 HTTP 门户模式，但不包含 `portal-tls`。HTTP 门户必须由用户显式允许，不能悄悄降级 HTTPS 或关闭证书验证。请仅在可信的校园网络中按学校公布的地址配置；HTTP 上的应用层密码无法靠本地文件权限变成加密传输。

需要 HTTPS 门户的用户应使用支持 TLS 的 GNU/Windows 产物，或在具备匹配 C/汇编工具链的 SDK 环境中自行启用 `portal-tls` 构建。当前 TLS crypto 后端不是纯 Rust，不把尚未验证的 C 交叉构建结果标为通用 OpenWrt 产物。

## 自行构建与测试

在普通 Linux 开发机上安装当前 stable Rust 和目标标准库，例如：

```sh
rustup target add armv7-unknown-linux-musleabi
RUSTFLAGS='-C linker=rust-lld -C target-feature=+crt-static' \
  cargo build --locked --release --target armv7-unknown-linux-musleabi \
    --no-default-features --features log4rs,portal
```

上述路由器特性集合无需目标 C 编译器；Rust 分发中的 `rust-lld` 和 musl self-contained 文件用于静态链接。CI 使用 QEMU user-mode 执行 ARM/RISC-V 的协议与 CLI 测试，以及目标二进制 `--version`，然后检查 ELF CPU、字长、端序和无 `PT_INTERP`，防止把宿主机或动态链接程序作为路由器产物发布。QEMU 不能代替路由器网卡/内核及校园网实机验证。

```sh
DRCOM_TEST_RUNNER=qemu-arm \
CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABI_RUNNER=qemu-arm \
RUSTFLAGS='-C linker=rust-lld -C target-feature=+crt-static' \
  cargo test --locked --target armv7-unknown-linux-musleabi \
    --no-default-features --features log4rs,portal
python .github/scripts/package_release.py armv7-unknown-linux-musleabi --runner qemu-arm
```

手动 Release 工作流与普通 CI 共用同一平台清单和检查。发布包的 `openwrt/` 目录提供安装器、procd 服务、UCI 示例和账号配置示例，不是与每个 OpenWrt 固件仓库绑定的 `.ipk` 包；没有伪造通用 MIPS 或通用 `.ipk` 架构声明。
