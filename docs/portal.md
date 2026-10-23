# 校园网页登录

[返回首页](../README.md)

校园无线网通常这样使用：**先在系统里连上 Wi-Fi，再打开学校网页，输入账号密码登录。** 本项目可以替你完成兼容页面的账号密码提交，并定期查看设备是否仍在线。Windows、Mac、Linux 和 OpenWrt 的网页认证使用相同的设置方式。

当前实现面向 **DrCOM/ePortal 账号密码页面**，依据公开客户端记录的页面请求流程编写。自动测试使用模拟服务器，校园实网兼容性仍需要实际使用反馈；验证码、短信、扫码和统一身份登录页面请使用学校网页。

## 第一次使用

1. 在电脑或路由器的网络设置中连接校园 Wi-Fi。
2. 用浏览器打开学校登录页，确认账号密码可以正常登录。
3. 记下填写账号前的登录页地址，用于客户端设置。

网页自动登录使用普通网络连接，无需 Npcap 或有线网卡授权。浏览器手动登录和本项目自动登录都可以按自己的习惯使用。

## 用图形界面连接

打开 [drcom4scutGUI](https://github.com/SeaLoong/drcom4scutGUI#readme)，选择 **“校园网页认证”**，填写校园账号、密码和 **“登录页地址”**，点击 **“连接”**。

“更多网页设置”通常留空。使用学校提供的 HTTPS 地址时，账号密码会通过加密连接发送；学校只提供 HTTP 地址时，可按下文说明启用对应选项。

## 配置

命令行用户先按 [Windows](windows.md)、[Mac](macos.md)或 [Linux](linux.md)指南放好程序，再把下面的内容保存为 `portal.yml`。将 `base_url` 替换为自己核对过的学校登录页地址：

```yaml
mode: portal
username: '你的校园网账号'
password_file: password
portal:
  base_url: '在这里填写实际的学校登录页地址'
  allow_http: false
```

在同目录创建只含一行密码的 `password` 文件。Mac / Linux 执行 `chmod 600 password`，完整步骤见[密码与路径](configuration.md#密码与路径)。

登录入口以浏览器实际页面或学校说明为准。模板中的 `s.scut.edu.cn` 是默认主机名，各校区当前入口可能不同。保存登录页的公开地址即可；含密码或个人会话信息的请求链接应留在本机。

### 高级字段什么时候需要填？

通常程序会自动补齐以下信息。学校管理员提供了具体值，或已从学校页面确认时，可手动填写：

| 字段 | 用途 |
| --- | --- |
| `portal.base_url` | 学校网页登录入口，可保留学校提供的公开接入点参数 |
| `portal.api_url` | 页面背后提交认证请求的地址；默认在同一主机尝试 HTTPS 802 或 HTTP 801 端口 |
| `portal.ac_ip` | 学校接入设备的地址；程序未能自动发现时填写 |
| `portal.client_ip` | 学校登录系统看到的本设备地址；学校未自动报告时填写 |
| 顶层 `ip` | 电脑实际已取得的本地地址；多网卡时可固定从此地址发出请求 |
| 顶层 `mac` | 本设备网卡的硬件地址，用于进一步核对在线设备 |

入口与认证接口使用同一主机，凭据只交给已配置的学校地址。学校更换入口时，核实后更新配置即可。经过路由器转发时，学校看到的设备地址可能与电脑本地地址不同。

## 启动、查看状态和退出

在程序目录中检查设置，然后开始连接。Mac / Linux：

```sh
./drcom4scut --config portal.yml --check-config
./drcom4scut --config portal.yml --status-file portal-status.json
```

Windows PowerShell：

```powershell
.\drcom4scut.exe --config portal.yml --check-config
.\drcom4scut.exe --config portal.yml --status-file portal-status.json
```

在另一个终端查看连接结果（Windows 将开头换为 `.\drcom4scut.exe`）：

```sh
./drcom4scut status --status-file portal-status.json
```

学校确认当前设备在线后，状态变为 `online`。此模式通过网页认证，状态中的有线字段 `eap_authenticated` 为 `false` 属于正常情况。

如果学校提示该设备已由另一账号登录，先在学校页面退出原账号，再用目标账号连接。学校只报告在线状态而没有报告账号时，客户端会按可取得的设备状态显示结果。

按 **Ctrl-C** 停止时，程序会请求退出当前会话。也可单独执行：

```sh
./drcom4scut --config portal.yml --logoff
```

Windows PowerShell 使用 `.\drcom4scut.exe --config portal.yml --logoff`。这条命令根据登录入口和设备信息完成注销。学校网页中的“自动登录”“记住我”或设备绑定由学校管理；希望保持离线时，可同时在学校页面关闭相关设置。

## 使用 HTTP 门户

优先使用学校提供的 **HTTPS** 地址。学校只提供 `http://` 入口时，在确认地址后将 `portal.allow_http` 设为 `true`；图形界面中勾选 **“登录页使用 HTTP（明文传输）”**。HTTP 会以明文传输账号密码，这个选择由你明确启用，客户端保持所选协议。

Windows、macOS 和 Linux 桌面一体包支持 HTTPS 并检查网站证书。OpenWrt 路由器包提供 HTTP 网页登录；需要 HTTPS 的路由器用户可按[开发说明](development.md#构建特性)构建带 `portal-tls` 的版本。

## 在 OpenWrt 后台使用

先完成 [OpenWrt 安装](openwrt.md)，在路由器网络设置中加入校园 Wi-Fi。把本页的网页登录设置写入 `/etc/drcom4scut/config.yml`，密码保存在 `/etc/drcom4scut/password`；学校入口为 HTTP 时，设置 `portal.allow_http: true`。

服务跟随校园无线所对应的 OpenWrt 网络运行。例如该网络在“网络 → 接口”中叫 `wwan`，在路由器执行：

```sh
uci set drcom4scut.main.network='wwan'
uci set drcom4scut.main.interface=''
uci commit drcom4scut
/etc/init.d/drcom4scut restart
```

把 `wwan` 换成实际网络名称。连接状态和日志的查看方法与 [OpenWrt 日常管理](openwrt.md#网卡与启动)相同。

## 常见问题

| 提示或情况 | 下一步 |
| --- | --- |
| 连接 Wi-Fi 后没有登录页 | 在浏览器打开学校公布的入口，检查无线网络设置 |
| 页面要求验证码、短信或扫码 | 使用学校网页登录 |
| `HTTP portal requires explicit...` | 当前地址为 HTTP；确认学校入口后启用 HTTP 选项 |
| `HTTPS portal requires...portal-tls` | 换用支持 HTTPS 的桌面包，或构建带 `portal-tls` 的程序 |
| `Portal AC address was not discovered` | 核对登录入口；有学校提供的接入设备地址时填入 `portal.ac_ip` |
| `Portal did not report a usable client IPv4` | 核对无线连接；已确认学校看到的设备地址时填入 `portal.client_ip` |
| `Portal redirect was rejected` | 学校页面跳到了另一个主机，确认新的入口后更新设置 |
| `accepted login but did not confirm...` | 用浏览器确认账号可用，再核对完整账号、设备地址和页面兼容性 |
| 停止后又自动上线 | 到学校网页检查自动登录与设备绑定设置 |

账号按填写内容提交，需要运营商后缀时一并填写。反馈可提供客户端版本、网页登录方式和遮住个人信息后的错误提示。

## 自动登录方案从哪里来？

实现参考 [SCUTNetLogin 的无线认证代码](https://github.com/YiZhiQvQ/SCUTNetLogin/blob/65470c3da502527fa5f20673d71639c8bebb9747/src/wifi/webauth_process.cpp)与 [OpenWrt 自动登录脚本](https://github.com/Breeze1733/luci-app-scut-autologin/blob/0143bb299dc35642ab54025c55bdbfbc4460a01f/root/usr/lib/scut-autologin/login.sh)公开记录的网页登录请求：**查设备状态 → 提交账号密码 → 确认在线 → 请求注销**。

本项目独立实现这些网络请求，Wi-Fi 连接仍由操作系统完成。来源快照见[相关客户端记录](references-clients.md)，自动测试覆盖范围见[开发与验证](development.md#测试层次)。
