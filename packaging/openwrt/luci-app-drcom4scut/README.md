# SCUT DrCOM 的 LuCI 管理页

在 OpenWrt 的 **服务 → SCUT DrCOM** 中查看认证状态、启停和重新连接，设置专用服务的网络/配置路径，并下载脱敏诊断 JSON。近期事件显示分类和等级，完整本地日志由管理员通过 SSH 查看。

该页面不提供账号或密码输入框，也不读取密码文件。账号和密码仍由 root 在私有配置中维护。先完成[核心安装和账号配置](https://github.com/SeaLoong/drcom4scut/blob/master/docs/openwrt.md)，再安装页面；发布包根目录的 `OPENWRT.md` 也提供离线安装说明。

## 安装

路由器需已有 `luci-base`、`rpcd`、`jshn`、`logd`。在解压后的、架构匹配的核心发布包目录执行：

```sh
sh openwrt/install-luci.sh
```

脚本安装页面、菜单和专用 RPC，重启 rpcd 并重新加载可用的 uhttpd。重新登录 LuCI 后打开管理页。

也可使用对应 OpenWrt SDK 构建页面包；命令及验证集中在[开发文档](https://github.com/SeaLoong/drcom4scut/blob/master/docs/development.md#luci-页面包)。页面包为 `Architecture: all`，不包含认证程序；核心仍必须匹配 CPU/ABI。

## 使用

1. 核对逻辑网络、可选物理网卡，以及 `/etc/drcom4scut/` 下的配置和密码文件路径。
2. 勾选启用，点击“保存并应用”。
3. 点击启动或重新连接；页面显示当前阶段与更新时间。需要结束已有进程时使用停止。

尚未启用、或修改尚未保存应用时，启动与重连按钮不可用；停止仍可用于已有进程。路径及文件权限仍会在后端启动时检查，不能仅靠浏览器中的字段值判断可运行。

## 访问与诊断

使用现有 LuCI 登录和 HTTPS 设置。页面的 RPC 权限仅用于此服务、专用 UCI 设置和固定操作，不授予通用文件读取或任意命令执行。配置与密码须是 root 私有目录中的直接文件，详见[路径要求](https://github.com/SeaLoong/drcom4scut/blob/master/docs/openwrt.md#安装与账号配置)。

诊断下载不包含账号密码、原始服务端回显或完整日志文本。分享前仍应检查内容；真实浏览器、rpcd/procd、网卡和校园网组合需在目标设备验证。开发测试和权限检查见[测试说明](https://github.com/SeaLoong/drcom4scut/blob/master/docs/development.md#测试层次)。

本页面使用 [LuCI JavaScript API](https://openwrt.github.io/luci/jsapi/) 和 [rpcd 插件接口](https://openwrt.org/docs/techref/rpcd)，遵循 [LGPL-3.0-or-later](LICENSE)。
