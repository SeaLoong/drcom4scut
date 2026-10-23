# SCUT DrCOM 的 LuCI 管理页

LuCI 是 OpenWrt 在浏览器中提供的路由器管理界面。本页面让你在 **服务 → SCUT DrCOM** 中查看校园网认证状态、启动、停止、重新连接，并下载用于排查问题的诊断文件。

第一次安装，请先完成[路由器安装和账号配置](https://github.com/SeaLoong/drcom4scut/blob/master/docs/openwrt.md)，再添加网页。下载包根目录的 `OPENWRT.md` 也提供离线安装说明。网页不包含认证程序，也没有账号密码输入框；账号仍由管理员通过 SSH 在私有文件中填写。

## 安装

确认路由器已装有管理网页所需的 `luci-base`、`rpcd`、`jshn`、`logd`。通过 SSH 登录路由器，在解压后的、与处理器匹配的核心发布包目录执行：

```sh
sh openwrt/install-luci.sh
```

安装脚本会放好页面和菜单，并重新加载相关网页服务。完成后重新登录路由器管理网页，打开 **服务 → SCUT DrCOM**。

如果你在制作自己的 OpenWrt 固件，编译方法见[开发文档](https://github.com/SeaLoong/drcom4scut/blob/master/docs/development.md#luci-页面包)。页面包标记为 `Architecture: all`，意思是网页文件不挑处理器；认证核心仍必须选对架构。

## 使用

1. 确认网络名称（通常为 `wan`）和配置文件、密码文件路径。只有需要固定网卡时才填写物理网卡名称。
2. 勾选“启用”，点击“保存并应用”。修改设置后也需要先保存。
3. 点击“启动”，观察页面上的认证阶段和更新时间。要重新尝试认证，点击“重新连接”；要断开本次认证，点击“停止”。

尚未启用或设置尚未保存时，启动和重连按钮不能使用；停止按钮仍可结束已有进程。后台会检查文件是否存在及权限是否正确，网页中填了路径并不表示配置已经可用。

“进程运行”只表示客户端正在工作，仍可能在等待网卡或重试账号认证。判断是否认证成功，要看连接状态和最新更新时间；不要只凭进程存在判断已经联网。

## 访问与诊断

使用你平时的路由器管理账号登录，沿用原有 HTTPS 加密访问设置。页面只能管理本服务，不能用来浏览任意文件或执行任意命令。

账号与密码文件须直接位于仅管理员可访问的目录中，具体见[账号文件要求](https://github.com/SeaLoong/drcom4scut/blob/master/docs/openwrt.md#安装与账号配置)。本页面不读取或显示密码。

遇到问题时先核对账号文件、网卡名称和是否已取得 IP 地址，再看“近期事件”。下载的诊断文件是便于排查的结构化文本，不包含账号密码、服务器原始回复或完整日志。分享前仍应自己检查一遍；完整本地日志由管理员通过 SSH 查看。

自动测试不代替你这台路由器、浏览器和校园网的实际验证。开发者需要了解接口和权限时，可阅读[测试说明](https://github.com/SeaLoong/drcom4scut/blob/master/docs/development.md#测试层次)、[LuCI JavaScript API](https://openwrt.github.io/luci/jsapi/) 和 [rpcd 插件接口](https://openwrt.org/docs/techref/rpcd)。

本页面遵循 [LGPL-3.0-or-later](LICENSE)。
