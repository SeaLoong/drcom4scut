# Linux 命令行使用

[返回首页](../README.md) · [Linux 图形界面](https://github.com/SeaLoong/drcom4scutGUI/blob/master/docs/linux.md)

本页适合桌面终端和通过 SSH 使用的 Linux 电脑。桌面上喜欢按钮操作时，可选择图形界面；OpenWrt 路由器请使用[路由器安装指南](openwrt.md)。

![Linux 终端实际运行：查看版本、网卡和配置检查](images/linux-cli-check.png)

*Linux 终端中的安装检查过程。下文逐步说明如何操作。*

## 1. 选择程序包

在终端查看处理器类型：

```sh
uname -m
```

从[下载页](https://github.com/SeaLoong/drcom4scut/releases)选择文件名包含 **`desktop`** 的桌面一体包：

| 输出 | 常见设备 | 文件名结尾 |
| --- | --- | --- |
| `x86_64` | Intel / AMD 电脑 | `linux-x64.tar.gz` |
| `aarch64` | ARM64 电脑 | `linux-arm64.tar.gz` |

当前桌面包在 Ubuntu 24.04 上构建和运行检查。选择所需版本，展开 **Assets** 下载压缩包；**Pre-release** 表示预览版。解压到自己的用户目录，例如 `~/应用/drcom4scut`，然后在该目录打开终端。包内 `drcom4scutGUI` 是窗口程序，`drcom4scut` 是下面使用的命令行程序；通过 SSH 连接时直接运行命令行程序即可。

运行下面的命令查看版本：

```sh
chmod +x ./drcom4scut
./drcom4scut --version
```

如果系统提示缺少 `GLIBC_…`，按发行版的升级方式更新到符合运行要求的系统。需要帮助时提供发行版名称、版本和完整错误提示。桌面一体包支持有线认证以及 HTTP / HTTPS 校园网页登录。

## 2. 选择有线网卡，完成一次授权

插好校园网网线，在系统网络设置中确认有线连接已启用并取得地址，再列出网卡：

```sh
./drcom4scut --list-interfaces
```

从 `NAME` 一列找到接学校网线的网卡，例如 `enp3s0`、`enx…` 或 `eth0`。后面的命令用 `enp3s0` 举例，按实际名称替换。

有线认证需要访问网卡上的认证报文。让管理员为核心程序授予这项权限，然后检查：

```sh
sudo setcap cap_net_raw=ep ./drcom4scut
getcap ./drcom4scut
./drcom4scut doctor --interface enp3s0
```

`getcap` 显示 `cap_net_raw=ep`，自检出现 `capture=ok`，就可以继续。Ubuntu / Debian 如果找不到 `setcap`，先安装 `libcap2-bin`：

```sh
sudo apt install libcap2-bin
```

授权后，日常连接使用自己的普通用户。替换核心程序后，重新运行一次 `setcap` 和自检即可。校园网页登录使用普通网络连接，可以直接按[网页认证指南](portal.md)设置。

## 3. 保存账号设置

生成模板：

```sh
./drcom4scut init --config config.yml
```

用文本编辑器打开 `config.yml`，修改以下三项，其他设置先保持默认：

```yaml
username: '你的校园网账号'
password_file: password
interface: enp3s0
```

在同一目录创建名为 `password` 的 UTF-8 纯文本文件，只写一行校园网密码。例如使用 Nano 编辑器：

```sh
nano password
```

填写后按 **Ctrl-O、回车** 保存，再按 **Ctrl-X** 退出；也可以使用自己熟悉的编辑器。让文件仅供自己读写：

```sh
chmod 600 password
```

## 4. 连接与日常使用

检查配置，然后开始连接：

```sh
./drcom4scut --config config.yml --check-config
./drcom4scut --config config.yml --status-file status.json
```

第一条显示 `Configuration is valid.` 后，第二条开始向学校认证。保持终端打开；断线后程序会继续尝试恢复，按 **Ctrl-C** 结束连接。

另开一个终端进入同一目录，查看状态和最近日志：

```sh
./drcom4scut status --status-file status.json
./drcom4scut logs --config config.yml
```

`online: true` 表示认证已完成，`updated_at` 是结果的更新时间。通过 SSH 运行时，可以在自己常用的终端会话管理器中保持程序运行；桌面用户若希望登录系统后自动连接，可使用[图形界面自动启动](https://github.com/SeaLoong/drcom4scutGUI/blob/master/docs/usage.md#自动启动和自动认证)。

运行 `./drcom4scut --check-update` 可查看最新正式版，`./drcom4scut --update` 发现新版后直接安装。重启后使用新版，账号和配置继续保留，见[更新指南](update.md)。

## 常见情况

| 看到什么 | 下一步 |
| --- | --- |
| `Permission denied`，程序不能启动 | 执行 `chmod +x ./drcom4scut`，并把程序放在允许执行文件的目录 |
| 程序可运行，但自检提示权限不足 | 重新运行 `setcap`，用 `getcap` 核对授权；受管理的电脑请管理员协助 |
| `Exec format error` | 按 `uname -m` 的结果选择程序包 |
| 网卡没有可用地址 | 先在系统网络设置中完成以太网地址配置 |
| `Configuration is valid.` 后仍不能联网 | 继续运行连接命令，再按[连接与排障](troubleshooting.md)检查最新认证结果 |

[更多配置](configuration.md) · [校园网页登录](portal.md) · [连接与排障](troubleshooting.md)
