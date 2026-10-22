# 无线门户登录

适用于学校的 DrCOM/ePortal Web 登录。先通过系统或路由器连接校园无线网络，再让客户端进行门户认证。Portal 与有线 EAP + UDP 是两种接入方式，需显式设置 `mode: portal`；Portal 不需要 Npcap 或原始抓包权限。

## 配置

在校园网络中核对学校实际使用的门户域名与证书，使用裸入口地址或只含公开网关参数的入口链接。不要粘贴包含账号、密码、token 的已填写登录 URL。

```yaml
mode: portal
username: '你的校园网账号'
password_file: password
portal:
  base_url: 'https://s.scut.edu.cn'
  api_url: 'https://s.scut.edu.cn:802'
  allow_http: false
```

这里的域名是默认值，应按实际校区入口核对。密码文件格式与权限见[配置参考](configuration.md#密码与路径)。`api_url` 可省略：HTTPS 入口默认使用同主机 802 端口，HTTP 入口默认使用同主机 801 端口。显式 API 地址仍须与入口使用同一主机，且不带查询参数。

| 字段 | 何时填写 |
| --- | --- |
| `portal.base_url` | 可信门户入口；可带学校提供的 `wlanacip` 等公开网关参数 |
| `portal.api_url` | 学校 API 端口或入口与默认值不同时 |
| `portal.ac_ip` | 入口的同源参数或页面无法提供 AC IPv4 时，填写学校给出的地址 |
| `portal.client_ip` | 门户无法报告客户端 IPv4 时，填写门户识别的终端地址 |
| 顶层 `ip` | 需要固定 HTTP 请求的实际本地 IPv4 时；该地址必须属于本机 |
| 顶层 `mac` | 已知终端 MAC，需要核对在线会话归属时 |

通常不必填写 `ac_ip` 和 `client_ip`。客户端会从可信入口发现 AC，并向门户查询当前终端信息。门户看到的 `client_ip` 与本机传输源 `ip` 在 NAT 等环境中可能不同；配置前应确认二者含义，不要直接套用其他设备的地址。

## 启动、查看状态和退出

```sh
./drcom4scut --config portal.yml --check-config
./drcom4scut --config portal.yml --status-file portal-status.json
```

另一个终端中查看：

```sh
./drcom4scut status --status-file portal-status.json
```

客户端会确认学校在线列表中存在当前设备的 IP；已知 MAC 时，还需匹配该会话的 MAC。登录请求被接受、HTTP 成功或其他设备在线，都不会直接标记本机在线。Portal 状态的 `online: true` 表示门户确认成功，`eap_authenticated` 为 `false`，因为此模式不执行 EAP。

如果在线列表明确显示本机属于另一账号，客户端会提示，既不把它当作所选账号登录成功，也不自动踢掉该账号。换号时先显式执行下方注销命令，再用新的账号运行。学校没有返回账号归属时，在线状态仅确认当前设备的网络会话，不能证明某个特定账号的归属。

按 Ctrl-C 停止；Linux SIGTERM 也会触发注销。需要单独退出现有门户会话时：

```sh
./drcom4scut --config portal.yml --logoff
```

注销不需要读取账号密码，但仍需要正确的门户及终端信息。它会向学校查询当前会话并确认退出，不会启动重新登录。

## 使用 HTTP 门户

部分学校入口使用明文 HTTP。只有确认学校提供该入口时，才把地址改为对应 HTTP URL，并显式设置 `portal.allow_http: true` 或添加 `--allow-insecure-portal`。例如 API 可为学校确认的同主机 `http://...:801`；不要仅因为 HTTPS 失败就猜测或降级。

HTTP 登录会在网络上传输认证所需的账号密码；本地密码文件权限不能加密这段传输。HTTPS 构建保留证书校验，`--require-https-portal` 可覆盖配置中的 HTTP 许可。GNU/Windows 默认包支持 HTTPS；预编译 OpenWrt 静态包只支持显式允许的 HTTP 门户，遇到 HTTPS 会报不支持 TLS。

## 常见问题

| 提示或现象 | 处理方式 |
| --- | --- |
| `HTTP portal requires explicit...` | 先核对学校入口；只有确认使用 HTTP 后才开启许可 |
| `HTTPS portal requires...portal-tls` | 换用包含 HTTPS 的程序；自行构建见[开发文档](development.md#构建特性) |
| `Portal AC address was not discovered` | 核对可信入口里的 `wlanacip`，或填写学校提供的 `portal.ac_ip` |
| `Portal did not report a usable client IPv4` | 核对当前无线连接及门户观察到的地址，必要时填写 `portal.client_ip` |
| `Portal redirect was rejected` | 核对学校实际门户主机，更新显式配置；不要把密码转发给未知跳转目标 |
| `accepted login but did not confirm...` | 检查账号是否需运营商后缀、是否识别了正确终端，以及学校在线列表是否已有本机会话 |

账号按配置原样发送；如果学校要求运营商后缀，应填写完整账号。请求、在线确认和注销均有时间及次数上限。需要报告问题时，只提供已脱敏的错误类别与配置字段名称，不提供登录请求 URL、密码或原始服务器回显。

公开协议参考见[相关客户端记录](references-clients.md)。开发者模拟测试范围见[开发与验证](development.md#测试层次)；实际校区的可用性仍以目标网络验证为准。
