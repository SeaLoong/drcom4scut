# 相关客户端与协议参考

[返回首页](../README.md)

这是一份**供维护者核查实现依据**的记录，不是安装教程。普通用户无需逐个了解这些项目；需要使用客户端时，请看[电脑使用入口](../README.md#我应该从哪里开始)或[无线网页登录说明](portal.md)。

阅读下表时，EAP/UDP 指有线网卡认证的两个阶段，Portal 指连上 Wi-Fi 后的网页登录；profile 是有线报文的兼容格式。固定提交号用于标明当时查看的源码版本，避免第三方代码后来变化后难以追溯。参考到某个功能，不表示已经完成对应校区的实网验证。

记录日期：2026-10-23（北京时间）。以下固定提交、公开协议行为和可见许可证用于核对兼容性依据。范围限于下述公开检索结果和分支快照，私有、删除及未索引代码不在其中；第三方的自述也不构成本项目的实网验证。有线 EAP/DrCOM、无线 Web Portal 和历史“翼起来”协议分别记录。

## 检索范围

GitHub repository search 使用 `scut drcom`（9 项）、`scutclient in:name`（17 项）、`scut-client in:name`（10 项）、`SCUT OpenWrt`（6 项）、`"SeaLoong/drcom4scut" in:readme`（1 项）、`SCUT network client`（4 项）及 `"华南理工大学" "客户端" in:readme`（152 项，两页全部读取）。结果重叠且包含同名无关项目，不能相加当作客户端数量。另检索 `scut 802.1x`、`"scut" "802"`、`华南理工 校园网`、`scutclient` 和 `"drcom4scut" in:readme`；公开搜索索引可能漏报，直接 fork 列表和引用链接用来补充。

快照中的直接 fork 为核心 11 个、GUI 1 个；对应 API 返回的分支和子 fork 列表见[派生仓库记录](references-forks.md)。下表列出具有实质行为差异的来源：

| 分支来源 | 固定版本 | 行为记录 |
| --- | --- | --- |
| [gchh1/drcom4scut](https://github.com/gchh1/drcom4scut) | `118aea5d` | 有线源地址绑定、网卡/IP 变化检测、诊断和服务管理 |
| [LuoMuQAQ/drcom4scut](https://github.com/LuoMuQAQ/drcom4scut) | `b9845c6e` | Windows GUI、DPAPI、凭据传递、优雅注销、父进程生命周期、托盘/自启 |
| [trv3wood/drcom4scut](https://github.com/trv3wood/drcom4scut) | master `e537b377`；fix-already-login `f20a3027` | 有上限的退避、首次 Identity 标识符不应当作会话状态 |
| [QvPing/drcom4scut](https://github.com/QvPing/drcom4scut) | `2b166e91` | 可关闭 UDP、可禁用日志、DNS CLI |
| [AlexLin625/drcom4scut](https://github.com/AlexLin625/drcom4scut) | `719c6bbb` | DNS 故障切换修复 |
| [gdzhht/drcom4scut](https://github.com/gdzhht/drcom4scut) | `ca7408a0` | DNS 故障切换修复 |

其余 HarryHuangQi、unstartdev、AlexBybye、Accurio、cq01 的默认分支与原核心 HEAD 相同；cq01 的开发分支主要是依赖升级。Accurio GUI fork 与 GUI 基线 `91c61d1f` 相同。相关上游问题包括 #46（首次标识符循环）、#44（心跳）、#43（OpenWrt）、#34（拔线重连）、#38（Npcap 资源）。

## 公开行为与协议差异

这部分回答“为什么实现成这样”。有线与网页自动登录的依据不同，不应将网线认证搬到 Wi-Fi 上使用。无线方案参考的是已有项目公开的网页登录请求，不是本项目新取得的校内抓包或学校官方接口规范。

| 来源 | 观察到的行为 | 兼容性含义与范围 |
| --- | --- | --- |
| [drcom4scut-cpp](https://github.com/HarryHuangQi/drcom4scut-cpp) | 标准 PAE 组播目的地址的 EAP Identity 心跳 | 接受 `01:80:c2:00:00:03` 目的地址，但认证后仍锁定服务端源 MAC |
| 同上 v0.2.3–0.2.4 | 周期 UDP 回包长期缺失时维持健康 EAP；初始建链失败仍严格处理 | 分开认证状态和 UDP 保活状态，不因 UDP 丢包自行注销 EAP |
| 同上 `windows-31` | 260 字节 MiscInfo、网关和双 DNS、16 字节尾部、独立启动心跳 | 显式可选协议配置，保留默认 244 字节 legacy 行为；未知校区不能自动猜 profile |
| 同上地址模型 | 实际源 IPv4、EAP 认证 IPv4、UDP 载荷 IPv4 可以不同 | 绑定真实接口地址；载荷覆盖值不用于给系统配置地址 |
| 同上及 [UDP 61440 选路诊断](https://github.com/BJ1919810/SCUT-DrMain-61440-WiFi-Route-Fix) | Wi-Fi/代理默认路由使 DNS/UDP 走错网卡 | 使用选定有线源地址/接口；诊断网络，不自动禁用 Wi-Fi 或改写系统路由 |
| [scutclient](https://github.com/scutclient/scutclient) | 显式接口、DNS/server/version/hash、上线/下线 hook、logoff、OpenWrt 打包 | 行为独立实现；AGPL 实现代码不直接复制进当前项目 |
| [Vitus213/scutclient-rs](https://github.com/Vitus213/scutclient-rs) | Rust 重写、退避、SIGTERM、procd/UCI、多架构目标 | 参考部署需求；设计文档不当作已通过实机测试的证据 |
| [luci-app-scutclient-plus](https://github.com/AidenLee1994/luci-app-scutclient-plus) | 状态/配置/日志页、服务启停/重连、诊断包、随机或租约主机名 | 路由器部署需权限限制、脱敏诊断、正确区分“进程运行”与“已认证” |
| [SCUTNetLogin](https://github.com/YiZhiQvQ/SCUTNetLogin) | Windows DPAPI、可取消重连、托盘/自启、可禁用 UDP、双协议接入 | GUI 凭据不出现在命令行；无线 Portal 必须有独立实现和验证 |
| [SCUTNetLogin](https://github.com/YiZhiQvQ/SCUTNetLogin)、[luci-app-scut-autologin](https://github.com/Breeze1733/luci-app-scut-autologin) | `/drcom/chkstatus`、动态 AC、ePortal 登录、官方状态确认 | 与原始以太网 EAP 分开；不能以外部连通性探测代替认证成功证据 |
| [CampusNet](https://github.com/CmAsterr/CampusNet) | 多账号、校区配置、暂停/恢复重连，Windows/Android | 未指定开源许可证，仅记录行为，不复制源码或宣传已支持 Android |
| [fsn_server](https://github.com/YSunLIN/fsn_server) | 路由器 Web 状态、账号持久化、自动重连、夜间选项 | 不移植匿名 HTTP 管理、明文凭据或老式自启动方式 |

`windows-31` 的依据为表中固定版本的 drcom4scut-cpp 协议实现及模拟报文对照，没有对应校区实网认证结论。它与 legacy 共用 EAP 基本过程，Identity 扩展均为 `0044610000`；MD5 扩展中的客户端标志为 `0x31`；MiscInfo 长度 260，DNS1/网关/DNS2 分别位于 76/80/84 偏移，OS 区域为零，版本区位于 116，hash 区位于 180，尾部位于 244。校验和覆盖全部 260 字节。MiscResponseInfo 后约 1400ms 发送 40 字节启动心跳（头 `070028000b010f27`），等候类型 0x0b、子类型 6 后才开始周期 Alive。legacy 使用原客户端的 244 字节 MiscInfo，不执行这一步启动心跳确认。两种配置的周期心跳相同；名称与本机运行的操作系统无关。

## 固定版本清单

清单固定到记录日期的提交。源码用于核对公开行为及报文，未执行第三方安装脚本。许可证栏记录可见声明；没有明确授权的实现只作为行为参考，不作为可复制源码。具体文件的版权与许可证仍须单独核对。

| 仓库 | 调研 HEAD | 可见许可证 |
| --- | --- | --- |
| [AidenLee1994/luci-app-scutclient-plus](https://github.com/AidenLee1994/luci-app-scutclient-plus/tree/ead272c8b0a2ed6ddb1da2865de636016010ae62) | `ead272c8b0a2ed6ddb1da2865de636016010ae62` | GPL-3.0 |
| [AidenLee1994/scutclient](https://github.com/AidenLee1994/scutclient/tree/17e25890bf751c3f7a2119e9d69359e1504527d2) | `17e25890bf751c3f7a2119e9d69359e1504527d2` | 未确认独立许可证；不复制实现 |
| [BJ1919810/SCUT-DrMain-61440-WiFi-Route-Fix](https://github.com/BJ1919810/SCUT-DrMain-61440-WiFi-Route-Fix/tree/16587f9d4559c4a64b2ade8c3047ca74ad21fc05) | `16587f9d4559c4a64b2ade8c3047ca74ad21fc05` | README 声称 MIT，未见独立许可证正文 |
| [Breeze1733/luci-app-scut-autologin](https://github.com/Breeze1733/luci-app-scut-autologin/tree/0143bb299dc35642ab54025c55bdbfbc4460a01f) | `0143bb299dc35642ab54025c55bdbfbc4460a01f` | MIT |
| [CmAsterr/CampusNet](https://github.com/CmAsterr/CampusNet/tree/ba634183f91769d92139d39ff8e13e1086ac1c41) | `ba634183f91769d92139d39ff8e13e1086ac1c41` | 未确认独立许可证；不复制实现 |
| [HarryHuangQi/drcom4scut-cpp](https://github.com/HarryHuangQi/drcom4scut-cpp/tree/e5b765d099274883d808984029c00e71868341eb) | `e5b765d099274883d808984029c00e71868341eb` | LGPL-3.0 正文；上游许可证元数据有历史差异 |
| [HyperionHXH/SCUTclient-immortalwrt-mt798x-2512](https://github.com/HyperionHXH/SCUTclient-immortalwrt-mt798x-2512/tree/91d36e5bb1232d376896e38d8e0d2dadb6dd4b98) | `91d36e5bb1232d376896e38d8e0d2dadb6dd4b98` | 未确认独立许可证；不复制实现 |
| [JaxxZu/Scutclient4newif3D2](https://github.com/JaxxZu/Scutclient4newif3D2/tree/4eb9a61de533a63164fdb1733463d386f6069c70) | `4eb9a61de533a63164fdb1733463d386f6069c70` | 未确认独立许可证；不复制实现 |
| [MikeHuang2000/SCUT-Drcom-AutoRestarter-CMD](https://github.com/MikeHuang2000/SCUT-Drcom-AutoRestarter-CMD/tree/78c3d9feedeb57e891991b83e42e861b936e722d) | `78c3d9feedeb57e891991b83e42e861b936e722d` | MIT |
| [Samuka007/scut-drcom-client-rs](https://github.com/Samuka007/scut-drcom-client-rs/tree/84643097396e779c8c85eeca28b47d4ce43f122f) | `84643097396e779c8c85eeca28b47d4ce43f122f` | 未确认独立许可证；不复制实现 |
| [Samuka007/scut_client](https://github.com/Samuka007/scut_client/tree/dee3f030298b6d0120a65569c191190a32a1f5a0) | `dee3f030298b6d0120a65569c191190a32a1f5a0` | 未确认独立许可证；不复制实现 |
| [Samuka007/scutclient_go](https://github.com/Samuka007/scutclient_go/tree/a5b8eb34a9d8d02644d80010d6ccda868b102873) | `a5b8eb34a9d8d02644d80010d6ccda868b102873` | 未确认独立许可证；不复制实现 |
| [Vitus213/scutclient-rs](https://github.com/Vitus213/scutclient-rs/tree/fdbf1dd31e3adc84e950e2a861f80755e41c6574) | `fdbf1dd31e3adc84e950e2a861f80755e41c6574` | 未确认独立许可证；不复制实现 |
| [WanderLandWalker/luci-app-scutwifi](https://github.com/WanderLandWalker/luci-app-scutwifi/tree/3b42a93b97056138a6f03a190e6b4dd09a5fef38) | `3b42a93b97056138a6f03a190e6b4dd09a5fef38` | 未确认独立许可证；不复制实现 |
| [YSunLIN/fsn_server](https://github.com/YSunLIN/fsn_server/tree/50c9b683be9e4402a0a0cdde7257b9df251b5d42) | `50c9b683be9e4402a0a0cdde7257b9df251b5d42` | LGPL-3.0 正文（README 另有商业限制声明） |
| [YiZhiQvQ/SCUTNetLogin](https://github.com/YiZhiQvQ/SCUTNetLogin/tree/65470c3da502527fa5f20673d71639c8bebb9747) | `65470c3da502527fa5f20673d71639c8bebb9747` | MIT |
| [dclsama/openwrt_scut_autologin](https://github.com/dclsama/openwrt_scut_autologin/tree/940daae2257b8c567bb7babf7d12773331e709ca) | `940daae2257b8c567bb7babf7d12773331e709ca` | 未确认独立许可证；不复制实现 |
| [iseekwonderful/DrCOM-Scut](https://github.com/iseekwonderful/DrCOM-Scut/tree/b98c17ffdeb8351a968629a709e5b8a165565b25) | `b98c17ffdeb8351a968629a709e5b8a165565b25` | 未确认独立许可证；不复制实现 |
| [justsong-lab/scutclient](https://github.com/justsong-lab/scutclient/tree/a0256e418a17553fcef4497ef7e26b30ca474f62) | `a0256e418a17553fcef4497ef7e26b30ca474f62` | AGPL-3.0 |
| [libc0607/scutclient-openwrt](https://github.com/libc0607/scutclient-openwrt/tree/e153904b74bdf62f01200d0ee1e8733edf7fdfea) | `e153904b74bdf62f01200d0ee1e8733edf7fdfea` | 未确认独立许可证；不复制实现 |
| [scutclient/luci-app-scutclient](https://github.com/scutclient/luci-app-scutclient/tree/727235341e2cb89150fec7e7b9223ea8fc19058a) | `727235341e2cb89150fec7e7b9223ea8fc19058a` | 未确认独立许可证；不复制实现 |
| [scutclient/pyscutclient_drcom](https://github.com/scutclient/pyscutclient_drcom/tree/8bd75803ee92ead0c6bd4392132e3da094700d69) | `8bd75803ee92ead0c6bd4392132e3da094700d69` | 未确认独立许可证；不复制实现 |
| [scutclient/scutclient](https://github.com/scutclient/scutclient/tree/8c81f5d8968420e9dc13181a5f9295d2de10b14a) | `8c81f5d8968420e9dc13181a5f9295d2de10b14a` | AGPL-3.0 |
| [scutclient/scutrouter](https://github.com/scutclient/scutrouter/tree/034e8a5cde2b2359738f8e8027406d5136a33920) | `034e8a5cde2b2359738f8e8027406d5136a33920` | 未确认独立许可证；不复制实现 |

## 适用范围

无线网页登录的含义是：系统先连接校园 Wi-Fi，程序再尝试代替用户提交兼容页面的账号密码，并检查学校是否确认设备在线。它不会运行页面 JavaScript，也不支持验证码、短信、扫码或统一身份认证页面；遇到不兼容页面，用户仍应使用浏览器。`s.scut.edu.cn` 等默认主机不是所有校区的通用入口。

本项目的门户注销只请求退出当前会话，不承诺清除学校的自动登录或设备绑定。SCUTNetLogin 的部分实现使用 `/mac/unbind`，本项目当前使用 `/eportal/portal/logout` 并检查状态；不能据此声称两者退出行为完全相同。用户操作见[无线指南](portal.md#启动查看状态和退出)。

这里记录的是认证与部署需求。实际校区入口由使用者核对，第三方示例服务器不是通用配置。系统负责无线关联、地址、路由、防火墙和 NAT；Android 与历史“翼起来”客户端也有不同的平台或协议边界。真实账号、私密抓包和运行日志不作为公开测试样本。传输安全、管理页面权限及连接成功判定，应按本项目的[配置](configuration.md)、[门户](portal.md)与[验证文档](development.md)分别核对。
