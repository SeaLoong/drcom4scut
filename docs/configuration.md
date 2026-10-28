# 配置参考

[返回首页](../README.md)

本页供命令行用户查找设置项。第一次使用从[Windows](windows.md)、[Mac](macos.md)或[Linux](linux.md)安装指南开始；图形界面用户直接在窗口填写账号和密码即可。

`config.yml` 是一份纯文本设置文件。Mac / Linux 运行 `./drcom4scut init --config config.yml`，Windows PowerShell 运行 `.\drcom4scut.exe init --config config.yml` 可以生成模板；发布包中也有 `config.example.yml`。保留字段名和缩进，在冒号后填写自己的内容。临时在命令行指定的设置优先于文件里的同一项。

## 基础配置

通常只需修改账号、密码文件和连接校园网的网卡名称：

```yaml
mode: eap
username: '你的校园网账号'
password_file: password
interface: eth0
```

`eth0` 是例子，请替换为 `./drcom4scut --list-interfaces` 中实际连接校园网网线的名称。多个网卡时，明确选择可以避免认证到错误网络。

| 想设置什么 | 字段 | 通常怎样填写 |
| --- | --- | --- |
| 有线还是无线网页登录 | `mode` | 网线用默认 `eap`；无线网页登录见[独立指南](portal.md)，使用 `portal` |
| 校园网账号 | `username` | 按学校要求填写完整账号，包括需要的运营商后缀 |
| 密码放在哪里 | `password_file` | 例如 `password`，见下文；使用独立密码文件时让 `password` 留空 |
| 使用哪张有线网卡 | `interface` | 从 `--list-interfaces` 的 `NAME` 一列复制 |
| 是否只完成有线第一阶段 | `no_udp` | 通常保持 `false`，只有确认网络不需要后续认证才设为 `true` |
| 是否只运行一次 | `once` | 默认 `false`；`true` 只测试一次认证，不持续保持连接 |
| 是否记录当前连接结果 | `status_file` | 例如 `status.json`；未填写就不生成状态文件 |
| 是否关闭文件日志 | `no_log` | 默认 `false`；设为 `true` 后不写日志文件 |

有线默认流程先完成身份认证，再与学校服务器建立并保持后续会话。文档和日志中分别称为 EAP、UDP；普通用户不必单独调整它们。`no_udp: true` 适用于只需前一阶段的网络。临时参数 `--with-udp` 可覆盖文件中的这一项。

### 网络地址一般留给程序选择

下面这些字段通常不需要改：

| 字段 | 默认行为或值 | 需要注意什么 |
| --- | --- | --- |
| `ip` | 使用所选网卡已经取得的 IPv4 地址 | 填写本机已取得的地址 |
| `mac` | 使用所选网卡的硬件地址 | 有线时辅助选择网卡；无线网页登录时辅助核对设备 |
| `host` | `s.scut.edu.cn` | 有线后续认证服务器，填写域名或 IPv4，不是网页登录 URL |
| `dns` | 模板中的四个校园 DNS | 用于把服务器域名查成地址；每项可写 `IP` 或 `IP:端口` |
| `hostname` | 当前电脑名称 | 在有线认证时发送给学校的机器名 |

未固定 `ip` 时，程序会在网卡地址变化后重新建立会话。同时填写网卡、硬件地址和 IP 时，使用同一张网卡对应的信息。几张网卡使用相同硬件地址时，单靠 `mac` 选不准，需补充网卡名称或 IP。

网络地址、自动获取地址（DHCP）和路由在操作系统网络设置中配置；客户端使用这些现有地址。

## 密码与路径

推荐把密码单独放在纯文本文件中：只写一行，选择 UTF-8 编码；编辑器若区分“带 BOM”和“无 BOM”，选择“无 BOM”，避免额外添加文件头。结尾有一次换行可以接受。文件名要与 `password_file` 一致，Windows 编辑器若添加了 `.txt`，同步更新配置中的文件名。

Mac / Linux 执行 `chmod 600 password`，让密码仅供自己读写。直接创建普通文件即可；只读的 `0400` 权限也可用。Windows 将文件放在当前用户的私有目录；后台服务和路由器还要满足各自指南中的管理员权限要求。

这里的密码文件是仅供自己访问的纯文本文件。图形界面的“记住密码”则使用系统密码保护，并通过私有输入通道交给核心。

相对路径就是没有写完整目录的文件名，例如 `password`。它从哪里开始找，取决于填写位置：

| 填写位置 | 从哪里开始查找 |
| --- | --- |
| `--config config.yml` | 当前终端所在目录，未指定时默认找 `config.yml` |
| 配置中的 `password_file: password` | `config.yml` 所在目录 |
| 命令行 `--password-file password` | 当前终端所在目录 |
| `status_file` / `--status-file` | 当前终端所在目录 |
| `log.file_directory` | 当前终端所在目录 |

后台部署建议写完整的绝对路径，并先建立可写的状态文件目录。查看状态时须显式指定路径，例如 `./drcom4scut status --status-file status.json`。命令只读取不超过 16 KiB 的普通状态文件，不接受管道或设备文件；通过 `updated_at`（最后更新时间）可以确认状态是否仍在刷新。

<details>
<summary>开发集成或兼容旧配置时的密码来源顺序</summary>

按以下顺序选用：`--password-stdin`、`--password-file PATH`、旧版 `--password` 参数、YAML `password_file`、YAML `password`。前三种命令行密码选项互斥；配置中的 `password` 与 `password_file` 选择一种填写。旧版明文参数只为兼容保留，不推荐日常使用。Windows 后台服务还要求服务专用的受保护密码文件，不接受交互式标准输入。

</details>

## 重连、心跳与日志

“心跳”是客户端定期与学校服务器联系、保持认证有效的请求。一般使用模板默认值即可；只有排障或学校要求不同时再改：

```yaml
time: '07:00'
reconnect: 15
reconnect_max: 300
heartbeat:
  eap_timeout: 60
  udp_timeout: 12
retry:
  count: 2
  interval: 5000
log:
  enable_console: true
  enable_file: true
  file_directory: ./logs
  level: INFO
```

| 设置 | 怎么理解 |
| --- | --- |
| `time` | 学校提示时段限制后，按本机时间在何时再次尝试；格式 `HH:MM` |
| `reconnect` / `reconnect_max` | 重连的起始等待和最大等待，单位秒；连续失败时等待逐渐增加 |
| `heartbeat.eap_timeout` | 有线身份认证心跳等待的基准秒数；最终等待时间还包含重试次数 |
| `heartbeat.udp_timeout` | 有线后续会话保持连接、网页登录检查状态的间隔，单位秒 |
| `retry.count` / `retry.interval` | 重试次数和每次间隔；间隔单位毫秒，`5000` 即 5 秒 |
| `log.enable_console` / `enable_file` | 是否在终端显示、是否写入文件 |
| `log.file_directory` | 日志保存目录 |
| `log.level` | 默认 `INFO` 适合日常使用；需要更多细节时可用 `DEBUG` |

时间值须大于 0，最大重连等待应大于或等于起始等待；重试次数可以为 0。日志等级完整取值为 `OFF`、`ERROR`、`WARN`、`INFO`、`DEBUG`、`TRACE`。`log` 必须是上例这样的字段映射；关闭文件日志将其中的 `enable_file` 改为 `false`，或使用 `--no-log`，不使用 `log: false` 等缩写。

排障时可临时添加 `--debug`，它会显示更详细的日志并打开终端日志输出；配置为 `TRACE` 时保留更详细的级别，显式设置 `OFF` 时日志保持关闭。

默认日志名为 `latest.log`，约 1 MiB 后存成历史文件，最多保留 10 份压缩历史。`./drcom4scut logs --config config.yml` 从普通日志文件末尾最多读取 1 MiB，显示其中最后 200 行，省略被截断的首行；单条尾行超过读取上限时会明确报错，不接受管道或设备文件。`--no-log` 关闭文件日志。少数精简构建没有文件日志，差异见[构建特性](development.md#构建特性)。分享日志前仍需遮住个人信息。

## 更新设置

核心默认在首次完整连接成功 60 秒后检查正式版，以后每 24 小时检查，只提醒新版本。手动检查与安装见[更新程序](update.md)。

```yaml
update:
  enabled: true
  proxy: https://gh-proxy.com/
  interval_hours: 24
```

| 字段 | 作用 |
| --- | --- |
| `update.enabled` | `false` 关闭核心自动检查；手动 `--check-update` 和 `--update` 仍可使用 |
| `update.proxy` | 检查信息、校验清单和程序下载共用的 HTTPS 代理前缀；保留末尾 `/`，不含用户名、密码、查询参数或片段 |
| `update.interval_hours` | 后续检查间隔，单位小时，整数 `1` 到 `8760` |

`--no-update-check` 只关闭本次运行的自动检查；`--update-proxy URL` 临时覆盖代理。图形界面统一管理自己的更新检查，其代理另在 [GUI 更新设置](https://github.com/SeaLoong/drcom4scutGUI/blob/master/docs/update.md#更换更新代理)中配置。

## 有线报文兼容选项

**普通用户保持默认即可，不按操作系统选择。** `profile` 是“程序按哪种格式与学校认证服务器说话”的兼容开关，默认 `legacy`。`windows31` 的名字来自另一种客户端报文格式，各操作系统都使用相同的选择原则。

网络管理员或协议分析确认需要另一种格式时，再切换此项。日常排障优先核对网卡、地址和访问权限。

<details>
<summary>网络维护者需要的字段与报文差异</summary>

| 配置 | 含义 |
| --- | --- |
| `profile: legacy` | 原客户端的 `0x2a` 标志和 244 字节 MiscInfo；别名 `legacy-2a` |
| `profile: windows31` | `0x31` 标志、260 字节 MiscInfo，以及额外 UDP 启动心跳确认；别名 `windows-31` |
| `eap_ip` | EAP 报文中携带的 IPv4，默认使用实际本地地址 |
| `udp_ip` | UDP 报文中携带的 IPv4，默认使用实际本地地址 |
| `local_port` / `server_port` | UDP 本地/服务器端口，默认 `36144` / `61440` |
| `gateway` / `dns2` | 可选的 Windows31 网关/第二 DNS 报文字段 |

`ip` 影响实际发送请求的本地地址；`eap_ip`、`udp_ip` 只改请求里的字段。`windows31` 未指定 `dns2` 时使用 DNS 列表第二项。显式 `data.*` 覆盖值优先于 profile 默认值；通常保留模板空值。详细差异与固定来源见[协议参考](references-clients.md)。

</details>

## 上线与离线命令

这是给有自动化需要的用户准备的功能：连接成功或离线时，额外运行一个自己信任的本地程序。需要时再启用即可。

```yaml
hooks:
  online: []
  offline: []
  timeout: 10
```

`online` 和 `offline` 分别填写“可执行程序及参数”的字符串数组。程序会直接执行，不自动启动 shell、展开通配符或解释命令拼接符。使用绝对路径，可避免后台运行时找错程序。`timeout` 是最长等待秒数。

被调用程序收到 `DRCOM_STATE`、`DRCOM_INTERFACE`、`DRCOM_IP` 三个连接信息变量，账号密码始终留在认证进程内。退出时离线命令最多等待 `min(hooks.timeout, 1)` 秒。命令应可重复运行；即使上线命令中途被取消，客户端仍会尝试执行配对的离线命令，清理可能产生的影响。

## 检查与覆盖

先检查文件填写，再临时覆盖选项：

```sh
./drcom4scut --config config.yml --check-config
./drcom4scut --config config.yml --interface eth0 --no-udp
./drcom4scut --config config.yml --dns 202.38.193.33 --dns 222.201.130.30
```

后两条分别举例临时指定网卡、只运行第一阶段，以及指定备用域名查询服务器；请先确认自己的网络确实需要它们。普通认证配置检查会读取所选密码文件，但不访问网卡或发送认证请求。模板尚未填账号密码时，检查失败是正常的。显式使用 `--logoff` 时不读取或校验无关账号密码，`--check-config --logoff` 只检查注销需要的设置。

其他参数可看 `./drcom4scut --help`。无线网页登录的字段见[无线指南](portal.md#配置)，后台服务的文件要求见 [Windows](windows-service.md) / [OpenWrt](openwrt.md)。

## 检查下载的文件

下载页面会附带 `SHA256SUMS`，其中每行是一份文件名和对应的 SHA-256 校验值。校验用于确认下载完整且与该次发布一致。

在终端中对下载的包计算校验值：

```sh
# Mac
shasum -a 256 '下载的包文件名.tar.gz'

# Linux
sha256sum '下载的包文件名.tar.gz'
```

Windows PowerShell 使用：

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath '下载的包文件名.zip'
```

把引号里的占位文件名换成实际文件名；输出的校验值应与同一条发布记录的 `SHA256SUMS` 中该文件对应的一行完全一致。如果不一致，重新下载并核对发布来源。
