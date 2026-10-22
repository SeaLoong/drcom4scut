# 0.4.0 开发、架构与验证

## 开发入口

使用已有 checkout 和 `rust-toolchain.toml` 的 stable 工具链。任务环境已经隔离，不创建额外 worktree，除非用户明确要求。依赖升级必须同步 `Cargo.lock`，平时使用 `--locked`。命令、特性和平台清单见 [README](../README.md)。

## 运行模型

- EAP 和 UDP 分别由单个 Tokio future 拥有状态；`watch` 保留最新授权和完整 UDP 在线状态。EAP 成功不能代替 UDP 在线。
- `client::run` 统一管理网络变化、退避、在线状态、hooks 和清理；Windows SCM、控制台和 GUI 控制通道共用这一生命周期。
- DNS 和 DrCOM UDP 绑定真实本地 IPv4。Linux 使用 `SO_BINDTODEVICE`，Windows 使用 `IP_UNICAST_IF`，拒绝歧义接口。报文中的 `eap_ip` / `udp_ip` 与传输源地址分开。
- 未固定 `ip` 时，每五秒检查所选网卡的地址；DHCP 地址消失/变化时先注销并重建会话。固定 `ip` 的配置由用户负责维护。
- Unix pnet 的阻塞收发隔离在有限超时的适配层；取消中的读取被保留并复用，不重复排队或丢弃已收到的帧。Windows 使用非阻塞 pcap，避免 pnet 忽略读取超时导致退出挂起。
- Windows 通过 IP Helper 枚举网卡、IPv4 和状态，列出网卡及无线 Portal 不依赖 Npcap。抓包前从受信系统目录加载 Npcap，缺少驱动时返回诊断错误；MSVC 延迟加载允许无驱动执行帮助、版本和不抓包测试。
- GUI 密码只使用 EOF 分帧的私有 stdin；独立随机命名管道只允许固定 `stop\n` 或父进程 EOF。GUI 先请求有界清理，超时才终止所属进程树，不杀其他客户端。
- Portal 为独立 provider。HTTP 必须明确允许，HTTPS 不降级；入口只接受公开网关元数据，不能保存带账号/密码/token 的登录 URL。只有本机 IP 以及已知 MAC 均匹配在线列表才算成功。

`legacy` 报文保持原格式；`windows31` 是显式的另一配置。测试用独立固定字节、校验和和协议录制行为对照，不把某个模拟服务器通过等同于真实校园接受。

## 验证层次

| 层次 | 验证内容 | 运行环境 |
| --- | --- | --- |
| 协议单元 | 字段、端序、长度、校验和、畸形/截断、两个 profile | 普通用户 |
| EAP 状态机 | 完整认证、任意初始标识符、组播心跳、重认证、超时、取消 | 模拟以太网、虚拟时钟 |
| Socket/UDP | 真实回环 DNS/UDP、源绑定、启动心跳、重试、丢包及 EAP 隔离 | 本机 loopback |
| Portal | 真实回环 HTTP、JSONP、会话归属、跳转/URL拒绝、源绑定 | 本机 loopback |
| CLI | 实际子进程、私有 stdin/文件、模式覆盖、注销、SIGTERM、状态/hooks | 普通用户 |
| Windows 安全策略 | SCM 文件/祖先所有者、ACL、null DACL、密码源、重解析点；DPAPI及管道 | Windows runner；部分规则可在其他平台测 |
| OpenWrt 集成 | procd/UCI、私有路径、LuCI ACL/后端、安装器、ELF/ABI和归档 | rootless fixtures、Node、Python |
| 其他 CPU | 相同 Rust 测试及 CLI 子进程、发布程序 `--version` | 原生或 QEMU |
| 真实网络 | 校园认证、驱动实际工作、长时间在线、物理拔插和路由器浏览器 | 目标网卡、系统、网络和账号 |

QEMU 不能替代真实路由器驱动、netifd、LuCI 浏览器和校园交换机测试。Windows 交叉 `cargo check` 也不能替代原生运行；Linux 上 DPAPI 测试应明确标为跳过，而非通过。

跨架构测试中 `CARGO_TARGET_*_RUNNER` 只处理测试主程序；CLI 子进程另用 `DRCOM_TEST_RUNNER` 启动对应 QEMU。临时目录计数使用 `AtomicUsize`，不假设 ARMv5 支持 64 位原子。并发/取消测试使用门闩或虚拟时钟，不用依赖主机调度的毫秒竞速。

## 构建与发布

`.github/scripts/platforms.json` 驱动七目标 CI 和发布完整性检查。五种静态 OpenWrt 构建使用 `log4rs,portal`，不引入需要交叉 C 工具链的 TLS provider；原生 GNU/Windows 默认构建包含 `portal-tls`。架构、feature 与检查命令不能通过重新命名产物替代。

打包检查版本、ELF/PE机器类型、位宽、端序、静态属性、ARM CPU基线与 ABI。发布包包含程序、配置示例、文档/许可证及相应 OpenWrt 集成资源，SHA-256 在最终发布前再次核对。

普通 CI 和手动 Release 复用验证工作流。只有最后发布 job 有写权限；标签必须匹配 manifest 与已验证提交，不强推/覆盖标签，不覆盖现有 Release。Git 推送触发 CI，不等于用户要求执行 Release。

Windows SDK 通过正常 TLS 从官方固定版本地址下载。测试不需要安装或绕过 Npcap 商业静默安装器。真实捕获仍必须安装官方驱动。

## 持续提交

用户已要求每轮完成的改动都提交并推送两个仓库的 `master`。先完成适当检查，使用正常快进推送；遇到远端更新先保留本地工作并合并/重放、验证冲突，不强制覆盖。不得提交账号、密码文件、真实配置、诊断私密数据或构建缓存。
