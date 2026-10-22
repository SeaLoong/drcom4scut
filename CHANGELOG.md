# 更新记录

## 0.4.0

- 稳定版 Rust / Tokio 重构：异步 DNS、UDP、EAP 状态机、有限重试、取消及安全抓包适配。
- 对照公开派生客户端修复初始 EAP 标识符、PAE 组播心跳、重新认证和多网卡出口问题。
- 新增 Windows31 报文 profile、独立源/载荷地址、端口、网关/双 DNS、EAP-only、私有密码文件/管道、诊断、JSON 状态和生命周期 hooks。
- 增加独立无线 DrCOM/ePortal provider，严格限制凭据目的地并确认本机在线。
- 增加 DHCP/接口变化处理、退避、SIGTERM/Logoff 和 Windows SCM 管理。
- 增加 OpenWrt 静态产物、procd/netifd 配置、ABI 检查、跨架构测试及受保护手动发布。
- 补充协议固定报文、异步/端到端/CLI、安全、服务策略、构建打包回归和来源文档。

与 GUI 3.0.0 配合使用。GUI 旧核心明文参数回退已移除；MIPS 等无当前稳定 Rust 标准库分发的架构不包含在预编译支持范围内。
