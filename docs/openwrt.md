# OpenWrt 安装与使用

OpenWrt 包包含静态认证程序、procd 服务和可选 LuCI 管理页。路由器上不需要安装 Rust；仍需具备匹配的 CPU/ABI、可用的网卡和校园网络连接。

## 选择程序

在路由器上检查设备信息：

```sh
ubus call system board
uname -m
opkg print-architecture
```

使用 apk 的固件可用 `apk --print-arch` 替代最后一项。然后选择对应的静态包：

| 目标文件名中的架构 | CPU/ABI |
| --- | --- |
| `x86_64-unknown-linux-musl` | x86-64 软路由 |
| `aarch64-unknown-linux-musl` | ARM64 |
| `armv7-unknown-linux-musleabi` | ARMv7，soft-float |
| `armv5te-unknown-linux-musleabi` | ARMv5TE；确认 CPU 支持该指令集 |
| `riscv64gc-unknown-linux-musl` | 带 GC 扩展的 64 位 RISC-V |

不同架构不能互换；ARMv7 包不能用于 ARMv5，RV64GC 包不能用于缺少对应扩展的 CPU。还应核对 [Rust 目标平台要求](https://doc.rust-lang.org/rustc/platform-support.html)中的最低内核条件。现有预编译列表不包括 MIPS/MIPSEL，也不代表所有 OpenWrt 型号已完成验证。

## 安装与账号配置

下载对应 `linux-musl` / `linux-musleabi` 的 `.tar.gz`，核对发布校验和，上传并解压。以下操作以 root 通过 SSH 执行，当前目录为解压后的包目录：

```sh
sh openwrt/install.sh
```

安装器先执行程序版本检查，然后安装 `/usr/bin/drcom4scut` 与服务脚本，保留既有账号和 UCI 设置，不立即启动认证。

1. 编辑 `/etc/drcom4scut/config.yml`，填写 `username`。其他校园参数通常保持默认；密码使用下一步的独立文件。
2. 用编辑器在 `/etc/drcom4scut/password` 中写入一行 UTF-8 密码，不放入 UCI、命令行或环境变量。
3. 检查私有目录和文件权限：

   ```sh
   chown root:root /etc/drcom4scut /etc/drcom4scut/config.yml /etc/drcom4scut/password
   chmod 700 /etc/drcom4scut
   chmod 600 /etc/drcom4scut/config.yml /etc/drcom4scut/password
   ```

服务的配置和密码必须是 `/etc/drcom4scut/` 下的直接子文件，文件名只含字母、数字、点、下划线或短横线；不接受软链接、路径穿越或非 root 私有文件。文件权限允许 `0400` 或 `0600`，目录须为 `0700`。YAML 不要再填写另一个非空 `password`。

## 网卡与启动

列出网卡，确认哪一个二层设备连接学校网线：

```sh
/usr/bin/drcom4scut --list-interfaces
```

默认 UCI 使用逻辑网络 `wan`，由 netifd 找到其物理设备。需要固定 VLAN、DSA 或其他接口时，使用实际设备名，例如：

```sh
uci set drcom4scut.main.network='wan'
uci set drcom4scut.main.interface='eth0.2'
uci commit drcom4scut
```

`eth0.2` 只是示例，须换成真实接口；留空 `interface` 则继续由 netifd 选择。`network` 用于解析设备和接收网络变化事件，不会替你创建 VLAN、桥接、DHCP 或路由配置。

**开始有线认证前，所选设备必须已有可用 IPv4。** 若接入要求先用 `0.0.0.0` 完成 EAP、再取得 DHCP 地址，当前程序不能单独完成该启动流程；请先按校园网络要求解决地址配置。

检查配置后启用：

```sh
/usr/bin/drcom4scut --check-config --config /etc/drcom4scut/config.yml --password-file /etc/drcom4scut/password
uci set drcom4scut.main.enabled='1'
uci commit drcom4scut
/etc/init.d/drcom4scut enable
/etc/init.d/drcom4scut start
logread -e drcom4scut
```

procd 管理一个前台客户端；netifd 事件用于重新读取接口状态。程序运行并不等于学校认证成功，连接状态位于 root 私有的 `/var/run/drcom4scut/status.json`：

```sh
/usr/bin/drcom4scut status --status-file /var/run/drcom4scut/status.json
/etc/init.d/drcom4scut restart
/etc/init.d/drcom4scut stop
```

停止自动运行时同时将 UCI `enabled` 设为 `0`、提交，并执行 `/etc/init.d/drcom4scut disable`。请先停止服务，再手动调试同一网卡，避免多个客户端争用认证。

## LuCI 管理页

已安装 `luci-base`、`rpcd`、`jshn`、`logd` 时，可在同一个解压目录执行：

```sh
sh openwrt/install-luci.sh
```

重新登录 LuCI，打开 **服务 → SCUT DrCOM**。先勾选启用并“保存并应用”，再启动或重连。界面提供状态、启停、近期事件、配置路径和诊断 JSON；账号密码仍通过 SSH 在私有文件中维护，不在浏览器填写或返回。

该页面包独立于 CPU，认证程序仍须匹配架构。更多页面说明见 [LuCI 源码 README](https://github.com/SeaLoong/drcom4scut/blob/master/packaging/openwrt/luci-app-drcom4scut/README.md)。浏览器、rpcd/procd 和实际网卡组合应在目标路由器确认可用。

## 无线门户、维护与排障

静态包包含有线认证及 HTTP Portal。使用无线模式时，先由 OpenWrt 连接无线网络，再按[门户指南](https://github.com/SeaLoong/drcom4scut/blob/master/docs/portal.md)配置 `mode: portal` 和学校可信入口。HTTP 须明确许可；这些包不包含 HTTPS 支持，也不会自动降级 HTTPS。

升级前停止服务，备份 `/etc/drcom4scut/` 和 UCI 设置，再从新包目录执行安装器；既有账号文件保留。确认配置、程序版本和权限后手动重启。示例关闭文件日志，减少闪存写入；日常通过 `logread -e drcom4scut` 查看事件，上传问题记录前需脱敏。

设备未就绪时核对 netifd 网络名、实际网卡和 IPv4；启动被拒绝时核对私有目录、文件所有者、权限与路径。自行构建、OpenWrt SDK 打包及测试命令集中在[开发文档](https://github.com/SeaLoong/drcom4scut/blob/master/docs/development.md#openwrt-交叉构建)。
