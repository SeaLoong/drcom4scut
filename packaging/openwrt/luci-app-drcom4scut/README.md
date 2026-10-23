# SCUT DrCOM 的 LuCI 管理页

LuCI 是 OpenWrt 在浏览器中提供的路由器管理界面。本页面让你在 **服务 → SCUT DrCOM** 中查看校园网认证状态、启动、停止、重新连接，并下载用于排查问题的诊断文件。

第一次安装，请先完成[路由器安装和账号配置](https://github.com/SeaLoong/drcom4scut/blob/master/docs/openwrt.md)，再添加网页。下载包根目录的 `OPENWRT.md` 也提供离线安装说明。网页配合认证核心使用，账号由管理员通过 SSH 保存在私有文件中。

## 安装

确认路由器已装有管理网页所需的 `luci-base`、`rpcd`、`jshn`、`logd`。通过 SSH 登录路由器，在解压后的、与处理器匹配的 OpenWrt 发布包目录执行：

```sh
sh openwrt/install-luci.sh
```

安装脚本会放好页面和菜单，并重新加载相关网页服务。完成后重新登录路由器管理网页，打开 **服务 → SCUT DrCOM**。

如果你在制作自己的 OpenWrt 固件，编译方法见[开发文档](https://github.com/SeaLoong/drcom4scut/blob/master/docs/development.md#luci-页面包)。页面包标记为 `Architecture: all`，意思是网页文件不挑处理器；认证核心仍必须选对架构。

## 使用

1. 在 **Logical network（网络名称）** 中选择校园网对应的网络，有线通常为 `wan`，配置文件和密码文件路径保持安装器提供的默认值。
2. 勾选 **Enable service（启用服务）**，点击 **Save & Apply（保存并应用）**。
3. 点击 **Start（启动）**，查看 **Connection status（连接状态）** 和 **Updated（更新时间）**。显示 **Online** 表示认证在线。

| 页面上的文字 | 用来做什么 |
| --- | --- |
| `Start` | 开始连接 |
| `Stop` | 结束本次连接 |
| `Reconnect` | 重新开始认证 |
| `Export redacted diagnostics` | 下载已筛选的状态和事件，供反馈问题使用 |
| `Logical network` | 连接学校网络的 OpenWrt 接口名称，通常是 `wan` |
| `Physical Ethernet device` | 需要手动指定网卡时填写，通常留空让系统选择 |
| `Private configuration path` | 账号配置文件，默认 `/etc/drcom4scut/config.yml` |
| `Private password file path` | 密码文件，默认 `/etc/drcom4scut/password` |

保存并启用后，启动和重连按钮即可使用；停止按钮随时可结束已有进程。后台会检查账号文件与访问权限，并在需要调整时给出提示。

**Service process: Running** 表示程序正在工作，**Connection status: Online** 表示学校认证已完成。看状态时结合 **Updated** 的更新时间即可。

## 访问与诊断

使用你平时的路由器管理账号登录，沿用原有 HTTPS 加密访问设置。页面提供本服务的状态查看和连接管理。

账号与密码文件须直接位于仅管理员可访问的目录中，具体见[账号文件要求](https://github.com/SeaLoong/drcom4scut/blob/master/docs/openwrt.md#安装与账号配置)。密码保留在服务专用的私有文件中。

遇到问题时先核对账号文件、网卡名称和是否已取得 IP 地址，再看 **Recent log events（近期事件）**。诊断文件提供筛选后的状态与事件，适合排查问题。分享前核对内容即可；完整日志由管理员通过 SSH 查看。

开发者需要了解接口和权限时，可阅读[测试说明](https://github.com/SeaLoong/drcom4scut/blob/master/docs/development.md#测试层次)、[LuCI JavaScript API](https://openwrt.github.io/luci/jsapi/) 和 [rpcd 插件接口](https://openwrt.org/docs/techref/rpcd)。

本页面遵循 [LGPL-3.0-or-later](LICENSE)。
