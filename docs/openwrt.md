# OpenWrt 安装与使用

[返回首页](../README.md) · [路由器网页管理](#luci-管理页)

本页适合希望由 **OpenWrt 路由器**持续进行校园网认证的用户。普通电脑用户请使用[图形界面](https://github.com/SeaLoong/drcom4scutGUI)，不需要执行这里的操作。

下载包已包含可运行的认证程序和后台启动脚本，不用在路由器安装 Rust。路由器仍需先接好学校网线，完成自己的网络地址设置。网页管理页（LuCI）是可选的，安装认证程序后再添加即可。

## 选择程序

路由器使用的处理器各不相同，包选错就无法运行。先通过 SSH 登录路由器：在电脑终端执行 `ssh root@路由器地址`，把地址换成实际管理地址；密码为路由器管理密码。在路由器中运行：

```sh
ubus call system board
uname -m
opkg print-architecture
```

这些命令显示设备型号、处理器类型和系统支持的软件包类型。使用 `apk` 管理软件的固件，将最后一条换成 `apk --print-arch`。按输出和设备规格确认后，从[下载页](https://github.com/SeaLoong/drcom4scut/releases)选择以下 `.tar.gz` 包；当前这些包在标有 **Pre-release** 的开发预览中，文件名包含 `0.5.0`。

| 文件名中的这段文字 | 适用设备 |
| --- | --- |
| `x86_64-unknown-linux-musl` | 使用 x86-64 处理器的软路由 |
| `aarch64-unknown-linux-musl` | ARM64 路由器 |
| `armv7-unknown-linux-musleabi` | ARMv7，采用 soft-float 运行约定 |
| `armv5te-unknown-linux-musleabi` | 支持 ARMv5TE 指令的设备 |
| `riscv64gc-unknown-linux-musl` | 支持 GC 扩展的 64 位 RISC-V 设备 |

**没有 MIPS/MIPSEL 预编译包。** 如果自己的设备不在表中，不能靠给另一个包改名来使用。ARMv7 包不能用于 ARMv5，RISC-V 包也要求对应的指令扩展。处理器型号相近仍可能有运行约定（ABI）和最低系统内核差异；不确定时提供上述命令输出和设备型号再确认。技术要求见 [Rust 平台列表](https://doc.rust-lang.org/rustc/platform-support.html)。

## 安装与账号配置

先下载对应包及同一版本的 `SHA256SUMS`。在电脑上计算文件的 SHA-256 并与清单比较，确认下载完整，再使用自己熟悉的文件传输工具上传到路由器并解压。不要下载 `Source code` 代替可执行包。

以下命令均在**路由器的 root SSH 终端**执行。进入解压后的包目录，确认其中能看到 `openwrt` 文件夹，然后安装：

```sh
sh openwrt/install.sh
```

安装器会检查程序能否运行，再把程序放到 `/usr/bin/drcom4scut`，安装后台启动脚本；这时还不会开始认证。原来已有的账号文件和服务设置会保留。

1. 用文本编辑器打开 `/etc/drcom4scut/config.yml`，填写 `username`。首次安装先保留其他校园参数的默认值。
2. 在 `/etc/drcom4scut/password` 中只写一行校园网密码，保存为 UTF-8 纯文本。不要把密码写进命令行或路由器的公开设置。
3. 执行下列命令，确保只有路由器管理员能读取配置和密码：

   ```sh
   chown root:root /etc/drcom4scut /etc/drcom4scut/config.yml /etc/drcom4scut/password
   chmod 700 /etc/drcom4scut
   chmod 600 /etc/drcom4scut/config.yml /etc/drcom4scut/password
   ```

配置和密码应直接保存在 `/etc/drcom4scut/` 中，不要用指向别处的软链接。自定义文件名只用字母、数字、点、下划线或短横线。服务会检查目录为 `0700`、文件为 `0400` 或 `0600`，并由 root 所有；不符合会拒绝启动。`config.yml` 中不要再填写另一个非空的 `password`。

## 网卡与启动

先列出网卡，找出连接学校网线的实际设备：

```sh
/usr/bin/drcom4scut --list-interfaces
```

服务默认使用 OpenWrt 的 `wan` 网络，由系统找到它对应的网卡。这里的 `wan` 是路由器网络设置的名称，不一定等于 `eth0` 这样的设备名。如果默认选择正确，不必改它。

只有确认需要指定某个网卡或 VLAN 时，再修改如下设置。`uci` 是 OpenWrt 保存设置的命令：

```sh
uci set drcom4scut.main.network='wan'
uci set drcom4scut.main.interface='eth0.2'
uci commit drcom4scut
```

把 `eth0.2` 换成实际网卡名；留空 `interface` 则让系统继续选择。这里不会替你创建 VLAN、桥接、路由或自动获取地址的设置。

**有线认证前，所选网卡必须已取得可用 IPv4 地址。** 如果学校要求先以 `0.0.0.0` 认证才能获取地址，当前程序不能独立完成这一启动流程，需要先解决路由器的网络设置。

先检查账号配置，再允许后台运行并启动：

```sh
/usr/bin/drcom4scut --check-config --config /etc/drcom4scut/config.yml --password-file /etc/drcom4scut/password
uci set drcom4scut.main.enabled='1'
uci commit drcom4scut
/etc/init.d/drcom4scut enable
/etc/init.d/drcom4scut start
logread -e drcom4scut
```

第一条只检查填写内容，不会登录。后面依次保存“启用”、设置开机运行、启动认证和查看日志。系统的后台进程管理器（procd）负责保持程序运行，网络管理器（netifd）通知它网络发生了变化。

“程序已运行”还不等于学校已接受认证。查看连接状态，以及重启或停止的方法如下：

| 要做的事 | 在路由器上执行 |
| --- | --- |
| 查看认证状态 | `/usr/bin/drcom4scut status --status-file /var/run/drcom4scut/status.json` |
| 重新认证 | `/etc/init.d/drcom4scut restart` |
| 停止这次运行 | `/etc/init.d/drcom4scut stop` |
| 查看最近事件 | `logread -e drcom4scut` |

状态文件仅供 root 读取。要同时关闭开机启动和自动运行，执行：

```sh
uci set drcom4scut.main.enabled='0'
uci commit drcom4scut
/etc/init.d/drcom4scut stop
/etc/init.d/drcom4scut disable
```

手动运行程序排查问题前，先停止后台服务，避免同一网卡有两个认证客户端。

## LuCI 管理页

LuCI 就是浏览器中打开的 OpenWrt 管理界面。装好本项目的页面后，可以在其中看状态、启动、停止、重新连接和下载诊断信息。

路由器需要已安装 `luci-base`、`rpcd`、`jshn`、`logd`。在同一个解压后的核心包目录运行：

```sh
sh openwrt/install-luci.sh
```

重新登录路由器管理网页，打开 **服务 → SCUT DrCOM**。先勾选启用，点击“保存并应用”，再点击启动。页面不会显示或接收账号密码，仍按上文通过 SSH 在私有文件中填写。

网页本身不受处理器类型限制，但它控制的认证程序必须选对。详细按钮和排障说明见 [LuCI 管理页说明](https://github.com/SeaLoong/drcom4scut/blob/master/packaging/openwrt/luci-app-drcom4scut/README.md)。

## 无线门户、维护与排障

无线网页认证仍然要求路由器先连上学校 Wi-Fi。本项目可尝试自动提交受支持的 DrCOM 网页登录请求，不负责连接无线网络，也不是任意登录网页都适用，当前未在目标校区实网验证。先确认浏览器正常登录方式，再阅读[无线网页登录指南](https://github.com/SeaLoong/drcom4scut/blob/master/docs/portal.md)。

这里的静态包只带 **HTTP 网页认证**，不支持 HTTPS 加密网页登录。如果学校地址以 `https://` 开头，这些包不能用于该网页认证；不要为了让程序运行就把地址改为 HTTP。只有学校确实提供 HTTP 入口时，才按指南明确允许。

替换程序前先停止服务，备份 `/etc/drcom4scut/` 和服务设置，再从新包目录执行安装器。确认账号、程序版本和文件权限后重新启动。默认示例不持续写文件日志，以减少路由器存储写入；日常查看 `logread -e drcom4scut` 即可。

| 遇到的问题 | 下一步 |
| --- | --- |
| 程序无法运行或提示格式错误 | 重新确认处理器、包文件名和最低系统要求 |
| 网卡未准备好 | 检查 `wan` 是否接对学校网线，实际网卡是否已有 IPv4 |
| 启动被拒绝 | 检查 `/etc/drcom4scut/`、配置和密码的所有者、权限及文件名 |
| 程序运行但仍不能联网 | 看认证状态和最近事件，再核对账号、模式及学校网络要求 |

报告问题时提供设备型号、固件版本、程序版本和去掉账号密码后的错误信息。构建产物和自动测试不代表所有路由器型号已实网验证。需要自己编译时，见[开发文档](https://github.com/SeaLoong/drcom4scut/blob/master/docs/development.md#openwrt-交叉构建)。
