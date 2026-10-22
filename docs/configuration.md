# 配置参考

首次使用可运行 `drcom4scut init --config config.yml` 生成完整模板，发布包也附带 `config.example.yml`。日常使用通常只需填写 `username`、`password_file`，并在多网卡环境设置 `interface`。命令行中的取值参数优先于对应 YAML 字段；下面的文件路径和字段名区分大小写。

## 基础配置

```yaml
mode: eap
username: '你的校园网账号'
password_file: password
interface: eth0
no_udp: false
```

`mode: eap` 使用有线认证；`mode: portal` 使用[无线门户](portal.md)。`no_udp: true` 将有线认证设为仅 EAP；临时添加 `--with-udp` 可覆盖该设置。Portal 模式不使用有线 UDP 心跳参数。

| 字段 | 默认值 | 用途 |
| --- | --- | --- |
| `interface` | 自动选择 | 有线网卡名称，取自 `--list-interfaces` |
| `ip` | 所选网卡的 IPv4 | 固定真实本地 IPv4；须为本机地址 |
| `mac` | 所选网卡的 MAC | 有线网卡选择；Portal 中用于核对在线会话归属 |
| `host` | `s.scut.edu.cn` | UDP 服务器域名或 IPv4，不填写 URL |
| `dns` | 模板中的四个校园 DNS | IPv4 DNS 列表，可写 `IP` 或 `IP:端口` |
| `hostname` | 当前机器名 | 有线认证中发送的主机名 |
| `no_log` | `false` | 关闭文件日志，保留控制台输出设置 |
| `once` | `false` | 测试一次认证流程并退出，不持续保活 |
| `status_file` | 不写文件 | 连接状态 JSON 的路径 |

未固定 `ip` 时，客户端会重新检查网卡地址并在变化后重建会话。指定 `interface` 和 `ip` 时，地址必须已分配给该网卡；指定 `mac` 和 `ip` 时，两项也必须匹配同一网卡。桥接、虚拟网卡等出现重复 MAC 时，仅按 MAC 选择会拒绝歧义，应补充接口名或真实 IPv4。固定地址适用于由用户维护网络配置的场景；修改 `eap_ip`、`udp_ip` 不会替操作系统设置本地地址。

## 密码与路径

推荐使用单独的密码文件，只保存一行不带 BOM 的 UTF-8 密码，可有一个结尾换行。Unix 下必须为普通文件、单链接，且组和其他用户无读写执行权限（通常设为 `0600` 或 `0400`）。Windows 普通运行应使用当前用户私有目录；[Windows 服务](windows-service.md)与 [OpenWrt 服务](openwrt.md)另有严格的所有者和 ACL/权限要求。

密码来源按以下优先级选用：`--password-stdin`、`--password-file PATH`、旧版 `--password` 参数、YAML `password_file`、YAML `password`。前三种命令行密码选项不能同时使用；配置中不要同时填写非空的 `password` 和 `password_file`。旧版明文参数仅用于兼容，日常操作使用文件，GUI 使用私有标准输入管道。

| 路径 | 相对路径的基准 |
| --- | --- |
| `--config` | 当前工作目录，默认 `config.yml` |
| YAML `password_file` | 配置文件所在目录 |
| `--password-file` | 当前工作目录 |
| `status_file` / `--status-file` | 当前工作目录 |
| `log.file_directory` | 当前工作目录 |

后台部署优先使用绝对路径，并确保状态文件的父目录已存在且可写。`status` 子命令需要显式提供 `--status-file`，不会自动读取 YAML 中的该字段。

## 重连、心跳与日志

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

`time` 是收到时段限制后的本地重连时间，格式为 `HH:MM`。`reconnect` 与 `reconnect_max` 是重连退避的起始值和上限，单位为秒，上限须不小于起始值。`heartbeat` 的时间值为秒；`retry.interval` 为毫秒，`retry.count` 为重试次数。时间值需为正数，重试次数可为 0。一般无需调整校园网默认心跳。

日志等级为 `OFF`、`ERROR`、`WARN`、`INFO`、`DEBUG` 或 `TRACE`。默认写入 `latest.log`，约 1 MiB 后滚动，保留最多 10 个压缩历史文件。`logs` 显示当前日志最后 200 行。`--no-log` 关闭文件日志；精简构建只提供控制台日志，构建差异见[开发文档](development.md#构建特性)。

## 有线报文兼容选项

`profile` 默认为 `legacy`，一般保持默认。`windows31` 是另一种服务端报文兼容配置，名称不表示只能在 Windows 使用，也不会根据操作系统自动选择。只有存在明确的校园部署或报文兼容依据时才切换；它不能修复网卡、地址或抓包权限错误。

| 配置 | 含义 |
| --- | --- |
| `profile: legacy` | 原客户端的 `0x2a` 标志和 244 字节 MiscInfo；别名 `legacy-2a` |
| `profile: windows31` | `0x31` 标志、260 字节 MiscInfo，以及额外 UDP 启动心跳确认；别名 `windows-31` |
| `eap_ip` | EAP 报文中携带的 IPv4，默认使用真实本地地址 |
| `udp_ip` | UDP 报文中携带的 IPv4，默认使用真实本地地址 |
| `local_port` / `server_port` | UDP 本地/服务器端口，默认 `36144` / `61440` |
| `gateway` / `dns2` | 可选的 Windows31 网关/第二 DNS 报文字段 |

`ip` 决定真实传输源地址；`eap_ip` / `udp_ip` 只影响报文内容。不要把文档或抓包示例地址直接作为本机网络配置。`windows31` 在未填写 `dns2` 时使用 DNS 列表中的第二项。显式 `data.*` 覆盖值优先于 profile 默认值；这些字段用于已有协议分析结论的部署，普通用户应保留模板中的空值。字段和握手依据见[协议参考记录](references-clients.md)。

## 上线与离线命令

```yaml
hooks:
  online: []
  offline: []
  timeout: 10
```

`online`、`offline` 均为“可执行程序及参数”的字符串数组，空数组表示关闭。程序直接执行数组，不自动启动 shell 或展开通配符。命令收到 `DRCOM_STATE`、`DRCOM_INTERFACE`、`DRCOM_IP` 三个连接信息变量；客户端不向它提供账号密码。`timeout` 的单位为秒。仅配置自己信任的本地程序，并使用绝对路径，避免后台运行时找错命令。

普通上线/下线转换使用 `hooks.timeout`；程序退出时的下线清理最多使用 `min(hooks.timeout, 1)` 秒。命令应快速、可重复执行且不会因重复下线而破坏状态：上线命令中途取消后，客户端仍会尝试执行配对的下线命令，以清理可能已经产生的副作用。

## 检查与覆盖

```sh
./drcom4scut --config config.yml --check-config
./drcom4scut --config config.yml --interface eth0 --no-udp
./drcom4scut --config config.yml --dns 202.38.193.33 --dns 222.201.130.30
```

配置检查会读取当前选中的密码来源，但不会打开网卡或进行认证。模板里尚未填写账号、密码时检查失败属于预期。全部命令参数可通过 `--help` 查看；[Portal 字段](portal.md#配置)和平台服务路径要求见各部署指南。
