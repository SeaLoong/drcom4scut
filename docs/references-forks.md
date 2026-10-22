# 直接派生版本调查记录

调查日期：2026-10-23（北京时间）。通过 GitHub REST API 枚举两个仓库当时可见的直接 fork、全部返回的分支引用、PR 与 issue，并按精确提交下载源码检查；不把仓库名称相同或 fork 的自述视为功能已验证。相关独立客户端见同目录的参考项目调查。

覆盖范围：核心仓库 11 个直接 fork、GUI 仓库 1 个直接 fork；列表单页上限 100，实际返回数均小于该上限。每个 fork 的返回元数据 `forks_count` 为 0，未发现下一层公开派生。核心读取 36 个 PR 和 48 个 issue/PR 列表条目，GUI 读取 2 个 issue/PR 条目。私有、已删除、尚未索引的项目不在此范围；这不是对整个 GitHub 的穷尽证明。

## 默认分支快照

| 仓库 | 检查的提交 | 结论 |
| --- | --- | --- |
| [gchh1/drcom4scut](https://github.com/gchh1/drcom4scut) | [`118aea5d3eb3a01057a73376524a4b122b261125`](https://github.com/gchh1/drcom4scut/tree/118aea5d3eb3a01057a73376524a4b122b261125) | Windows 服务、doctor/init/logs、绑定有线源 IPv4、网卡/IP 变化监测；有独立代码变更。 |
| [HarryHuangQi/drcom4scut](https://github.com/HarryHuangQi/drcom4scut) | [`ef20ae5c71744eb9e096f5e586713490ba01f4ee`](https://github.com/HarryHuangQi/drcom4scut/tree/ef20ae5c71744eb9e096f5e586713490ba01f4ee) | 默认分支与上游 ef20ae5c 相同。 |
| [unstartdev/drcom4scut](https://github.com/unstartdev/drcom4scut) | [`ef20ae5c71744eb9e096f5e586713490ba01f4ee`](https://github.com/unstartdev/drcom4scut/tree/ef20ae5c71744eb9e096f5e586713490ba01f4ee) | 默认分支与上游 ef20ae5c 相同。 |
| [AlexBybye/drcom4scut](https://github.com/AlexBybye/drcom4scut) | [`ef20ae5c71744eb9e096f5e586713490ba01f4ee`](https://github.com/AlexBybye/drcom4scut/tree/ef20ae5c71744eb9e096f5e586713490ba01f4ee) | 默认分支与上游 ef20ae5c 相同。 |
| [LuoMuQAQ/drcom4scut](https://github.com/LuoMuQAQ/drcom4scut) | [`b9845c6eaf80dbfc922d90fb7a7c7a530253c190`](https://github.com/LuoMuQAQ/drcom4scut/tree/b9845c6eaf80dbfc922d90fb7a7c7a530253c190) | Rust/Win32 GUI、DPAPI、父进程退出联动、EAPOL-Logoff、UDP 健康监测、托盘/自启、安装卸载。 |
| [Accurio/drcom4scut](https://github.com/Accurio/drcom4scut) | [`ef20ae5c71744eb9e096f5e586713490ba01f4ee`](https://github.com/Accurio/drcom4scut/tree/ef20ae5c71744eb9e096f5e586713490ba01f4ee) | 默认分支与上游相同；device-ip 分支的 MAC+IP 选择修复已由上游 PR #48 合并。 |
| [trv3wood/drcom4scut](https://github.com/trv3wood/drcom4scut) | [`e537b377ef691a4f43400b7daa96be210b4730a9`](https://github.com/trv3wood/drcom4scut/tree/e537b377ef691a4f43400b7daa96be210b4730a9) | master 包含 UDP 指数退避；另外检查了初始 Identifier 修复与 Windows 服务分支。 |
| [AlexLin625/drcom4scut](https://github.com/AlexLin625/drcom4scut) | [`719c6bbb1c47187a94d787cd7449cfb36dbe662c`](https://github.com/AlexLin625/drcom4scut/tree/719c6bbb1c47187a94d787cd7449cfb36dbe662c) | 较早分支，DNS 失败后遍历备用服务器；现有异步 DNS 实现也需保留该行为。 |
| [gdzhht/drcom4scut](https://github.com/gdzhht/drcom4scut) | [`ca7408a0295cee6ffe806f7c4bf8cfc2f6baa81f`](https://github.com/gdzhht/drcom4scut/tree/ca7408a0295cee6ffe806f7c4bf8cfc2f6baa81f) | 较早依赖/CI/格式变更与 DNS 备用服务器遍历，未发现独立新认证协议。 |
| [QvPing/drcom4scut](https://github.com/QvPing/drcom4scut) | [`2b166e91e541218c2a6660984f8cf8ce77dd1db8`](https://github.com/QvPing/drcom4scut/tree/2b166e91e541218c2a6660984f8cf8ce77dd1db8) | 较早版本，增加 EAP-only、禁日志和命令行 DNS 覆盖。 |
| [cq01/drcom4scut](https://github.com/cq01/drcom4scut) | [`ef20ae5c71744eb9e096f5e586713490ba01f4ee`](https://github.com/cq01/drcom4scut/tree/ef20ae5c71744eb9e096f5e586713490ba01f4ee) | 默认分支与上游相同；dev 为旧依赖升级分支。 |
| [Accurio/drcom4scut-gui](https://github.com/Accurio/drcom4scut-gui) | [`91c61d1f12d8ad8573c364c2acbd159eef6d59c5`](https://github.com/Accurio/drcom4scut-gui/tree/91c61d1f12d8ad8573c364c2acbd159eef6d59c5) | 与 GUI 上游 91c61d1f 相同，现有多账户、IP 选择等已在上游。 |

## 其他公开分支

| 仓库 / 分支 | 检查的提交 |
| --- | --- |
| LuoMuQAQ/drcom4scut / `feature/native-heroui-ui` | [`7035ba8f27785a88dcdc267bc25a6629984f628c`](https://github.com/LuoMuQAQ/drcom4scut/tree/7035ba8f27785a88dcdc267bc25a6629984f628c) |
| LuoMuQAQ/drcom4scut / `feature/native-heroui-v3-fidelity` | [`5593bbe6f43c5197e3389c9d06027979c97ea94b`](https://github.com/LuoMuQAQ/drcom4scut/tree/5593bbe6f43c5197e3389c9d06027979c97ea94b) |
| Accurio/drcom4scut / `device-ip` | [`aac20b3129ce40dfba78e196b7b7fec206f4c440`](https://github.com/Accurio/drcom4scut/tree/aac20b3129ce40dfba78e196b7b7fec206f4c440) |
| trv3wood/drcom4scut / `dev` | [`f96ab90bd5e4f4650e082f27fbd16aed523d936c`](https://github.com/trv3wood/drcom4scut/tree/f96ab90bd5e4f4650e082f27fbd16aed523d936c) |
| trv3wood/drcom4scut / `fix-already-login` | [`f20a3027e7e19f557113caa8ae1576042bf27599`](https://github.com/trv3wood/drcom4scut/tree/f20a3027e7e19f557113caa8ae1576042bf27599) |
| trv3wood/drcom4scut / `windows-service` | [`4f9948352f7f299a0e0b9c692c2c5ea451bc7458`](https://github.com/trv3wood/drcom4scut/tree/4f9948352f7f299a0e0b9c692c2c5ea451bc7458) |
| cq01/drcom4scut / `dev` | [`e62aae3b8aef82f762a7ef1a90883bdf1885481f`](https://github.com/cq01/drcom4scut/tree/e62aae3b8aef82f762a7ef1a90883bdf1885481f) |

LuoMuQAQ 的两个 `feature/native-heroui-*` 分支主要为历史 GUI 视觉迭代；master 已包含后续维护。trv3wood 的 `fix-already-login` 分支接受任意初始 EAP Identifier，`windows-service` 与 `dev` 提供服务生命周期和显式退出信号。Accurio 的 `device-ip` 修复已在核心基线中，不能重复退回仅按 MAC 选择地址的旧行为。

## 可复用能力与对应问题

| 能力 / 问题 | 证据 | 本轮处理方向 |
| --- | --- | --- |
| 初次 Identity 的 Identifier 大于 1 时无限 Logoff/Start | [issue #46](https://github.com/SeaLoong/drcom4scut/issues/46)、trv3wood `fix-already-login` | Identifier 按协议视为不透明字节；0～255 均可回答；增加完整认证回归，登录开始只作一次 Logoff 清理。 |
| 长时间没有 UDP 心跳时持续忽略 | [issue #44](https://github.com/SeaLoong/drcom4scut/issues/44)、[PR #47](https://github.com/SeaLoong/drcom4scut/pull/47) | 有限重试、明确失败和重连；恢复等待采用有上限的退避。 |
| 网线拔插、休眠唤醒、DHCP 换地址后不恢复 | [issue #34](https://github.com/SeaLoong/drcom4scut/issues/34)、gchh1 监测器、LuoMuQAQ 稳定性修复 | 设备与实际 IPv4 变化监测、重建会话、取消过期任务，不沿用永久阻塞的线程模型。 |
| 同时连接 Wi-Fi 时校园 DNS/UDP 从错误网卡发出 | gchh1 `src/socket.rs`、README 实测描述 | DNS 和 UDP 绑定选中的有线 IPv4；EAP 报文中的地址覆盖与 UDP 实际源地址分开。 |
| 密码写入 argv、配置和启动日志 | LuoMuQAQ vendor `PATCHES.md`、gchh1 服务配置保护 | GUI 用 Windows 用户级 DPAPI 保存；通过私有标准输入传递给核心，避免复制 fork 的明文环境变量方式。 |
| GUI 关闭而认证子进程仍运行、断开未发送 Logoff | LuoMuQAQ 父进程监督与退出补丁、trv3wood 服务退出信号 | 核心提供有界 Logoff，GUI 对自己启动的进程执行异步退出和兜底清理，不按名称杀死其他进程。 |
| 自诊断、自动启动、服务、日志与状态区分 | gchh1 管理 CLI、LuoMuQAQ GUI | 明确区分进程运行、EAP 成功与完整 UDP 心跳；平台启动入口与安全配置必须按对应平台验证。 |
| EAP-only、日志关闭、DNS 命令行覆盖 | QvPing `src/main.rs` | 保留兼容功能开关；EAP-only 不应谎报 UDP/完整网络认证成功。 |
| OpenWrt 下载产物缺失 | [issue #43](https://github.com/SeaLoong/drcom4scut/issues/43) | 产物按真实 target 构建，提供架构/ABI 说明、服务脚本和校验和，不能把任意 musl 文件称为适配所有路由器。 |
| 旧 Npcap 非分页池增长 | [issue #38](https://github.com/SeaLoong/drcom4scut/issues/38) | 接收端使用 EAPOL 过滤和有限生命周期，提醒更新驱动；本仓库不能承诺修复 Npcap 内核驱动本身。 |

本表记录设计输入，不以其他项目的 README 测试数字、性能百分比或实机认证结论替代本仓库的验证结果。本轮实际通过项和仍需目标设备验证的项目，应以测试命令输出、CI 和发布说明为准。

## 来源与许可证

保留各项目原有版权和许可证。核心及多数 fork 的 `LICENSE` 文件为 LGPL-3.0 文本，历史 `Cargo.toml` 曾声明 GPL-3.0-or-later，二者存在既有不一致；这里记录该事实，不据此擅自重新许可第三方作品。LuoMuQAQ 的 GUI/安装器明确声明 GPL-3.0-or-later，所用 Lucide 图标另为 ISC。移植时优先根据协议和问题重现独立实现，若直接复用代码或资源，应同时保留对应署名与许可证，不因 fork 可公开阅读就假定可无条件复制。
