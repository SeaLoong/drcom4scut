# 无线 ePortal 接入

无线 Web Portal 与有线 802.1X/EAP + UDP DrCOM 是独立接入方式。只有明确选择 `mode: portal` 时才使用本模块；不会根据外网连通性自动切换协议、修改路由或发送账号。

## 信任与凭据边界

配置门户地址前，应在校园网浏览器中核对学校实际使用的域名、入口及证书。默认门户为 `https://s.scut.edu.cn`，API 默认使用同域 HTTPS 802 端口；如果校区使用其他入口，应显式配置，不通过任意第三方网站推断可信登录地址。`api_url` 只能使用与 `base_url` 相同的主机，HTTPS 不允许推断降级至 HTTP。入口 URL 查询只允许公开的网关/终端元数据；包含账号、密码、令牌或其他未知查询参数的登录 URL 会被拒绝，包括百分号编码和大小写变体。请使用裸门户地址或带 `wlanacip` 等设备参数的入口，不要粘贴已填写凭据的请求。API 配置地址不允许查询参数。

密码仍使用核心的私有密码文件或标准输入管道。门户协议本身要求把账号密码放入登录 HTTP GET 查询，不能宣称本地安全传递已经替学校协议提供了端到端加密。HTTPS 在证书验证通过时保护传输；HTTP 801 等部署必须显式设置 `portal.allow_http: true`，这意味着本地网络旁观者可能看到凭据。程序保留 TLS 校验，不记录请求 URL、密码、完整响应及可能回显密码的远端错误文本。

默认构建含 `portal-tls`。较小的 OpenWrt 构建可使用 `--no-default-features --features portal`，此时仅支持明确授权的 HTTP 门户；HTTPS 会明确报错，不会降级。包含 HTTPS 的交叉构建还需要 TLS 后端的目标 C 工具链，不能将 HTTP-only 产物当作 HTTPS 版本。

## 配置字段

```yaml
mode: portal
username: 'student'
password_file: '/etc/drcom4scut/password'
portal:
  base_url: 'https://s.scut.edu.cn'
  api_url: 'https://s.scut.edu.cn:802'
  # ac_ip: '192.0.2.254'  # 自动发现不可用时填写校园入口给出的 AC 地址
  # client_ip: '192.0.2.10'  # 通常从 chkstatus 返回值读取
  allow_http: false
```

`ac_ip`、`client_ip` 和示例 MAC 不是通用校园参数，文中的地址只用于说明。未配置 AC 时，从用户明确指定的入口 URL 的 `wlanacip` 查询参数、同源跳转或简单入口页面赋值中读取。跨源跳转被拒绝；即使登录端点返回跳转，也不会把凭据继续发送至跳转目标。不同校区域名应由用户明确选择。可选的顶层 `mac` 字段会用于在线会话归属确认。顶层 `ip` 选择真实 HTTP 传输源地址；`portal.client_ip` 是门户观察到的认证身份，两者在 NAT 等场景可以不同，程序不会把身份覆盖值当作本机地址配置。默认单次请求超时 5 秒，登录后最多确认 5 次，确认间隔 2 秒。

## 在线判定和生命周期

客户端先请求 `/drcom/chkstatus` 获取本机 IPv4/MAC，再查询 `/eportal/portal/online_list`。只有在线表存在本机 IP，且已知 MAC 时必须存在有效、匹配的会话 MAC，才报告在线；缺失或非法 MAC 不会退回仅按 IP 判定。`result: 1`、空在线表或其他设备的 `is_owner_ip: 1` 都不算本机认证成功。登录返回成功后仍有次数及时间上限地轮询确认，不将“请求被受理”误报为“已放行”。

登录采用 ePortal 的 `login_method=1`、账号原样传递、`wlan_user_mac=000000000000` 及指定 AC 地址。不自动添加运营商后缀；如果学校要求后缀，直接填写完整账号。退出请求同样复查本机在线表。异步请求、轮询和重连可通过关闭信号取消，没有脱离主会话的重试任务。

每个响应最多读取 64 KiB；请求有超时，JSONP 只接受客户端自己的回调名且不执行 JavaScript；兼容 UTF-8 和历史 GB18030/GBK 响应文本。在线确认有上限。错误返回不包含原始 URL 或远端错误回显。

## 验证范围与参考

本模块使用真实 loopback HTTP 模拟服务器和 CLI 子进程覆盖账号参数编码、登录后确认、本机与他机会话区分、同源 AC 发现、恶意跳转拒绝、HTTP opt-in、无 TLS 版本拒绝 HTTPS、异常及超大响应、超时、取消和注销确认。CLI 回归还覆盖配置选择 Portal 的无凭据 `--logoff`、长账号、实际 HTTP 源地址，以及 SIGTERM 在轮询等待或 HTTP 请求挂起期间均完成注销、离线状态和成对上线/下线 hook。云环境没有校园网无线接入，不能把这些检查描述为真实校区认证成功。

行为参考：MIT 项目 [Breeze1733/luci-app-scut-autologin](https://github.com/Breeze1733/luci-app-scut-autologin/tree/0143bb299dc35642ab54025c55bdbfbc4460a01f) 的公开门户调用记录，以及 MIT 项目 [YiZhiQvQ/SCUTNetLogin](https://github.com/YiZhiQvQ/SCUTNetLogin/tree/65470c3da502527fa5f20673d71639c8bebb9747) 的在线会话归属判断。此处使用独立的 Rust 实现和虚构测试地址，没有复制账号、真实认证流量或运行脚本；完整检索范围见 [相关客户端调研](references-clients.md)。
