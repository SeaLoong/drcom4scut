# 更新程序

[返回首页](../README.md) · [下载与首次安装](download.md)

已安装的程序可以直接检查和更新到**最新正式版**，保留账号、密码和配置。程序内的更新检查不选择标为 Pre-release 的预览版；检查信息、校验清单和下载文件默认都通过 `https://gh-proxy.com/` 获取。

## 使用图形界面

窗口下方的“检查更新”更新图形界面，“检查核心更新”更新负责联网的核心。两个部分分别检查、分别确认，点击新版本提示也可以开始更新。

更新核心会短暂断开，完成后恢复本次连接；更新图形界面会注销连接并重启窗口，未记住的密码需要重新输入。完整操作和截图见[图形界面更新指南](https://github.com/SeaLoong/drcom4scutGUI/blob/master/docs/update.md)。

## 在终端检查和更新核心

进入程序所在文件夹。Windows PowerShell 运行：

```powershell
.\drcom4scut.exe --check-update
.\drcom4scut.exe --update
```

Mac / Linux 终端运行：

```sh
./drcom4scut --check-update
./drcom4scut --update
```

第一条只检查版本；第二条发现新版后直接下载、校验并替换核心，无需再次确认。两条命令都不进行校园认证，也不需要输入校园账号密码。使用其他配置文件时，可以加上 `--config 路径`。

| 显示的文字 | 接下来怎么做 |
| --- | --- |
| `is up to date` | 已是最新版本，可以继续使用 |
| `New drcom4scut version … is available` | 有新版本，运行 `--update` 安装 |
| `Installed drcom4scut … Restart drcom4scut to use it.` | 新文件已安装，重新启动核心后使用新版 |

更新只替换当前核心程序，账号、密码文件和 `config.yml` 继续保留。已在运行的连接仍使用旧进程；按 **Ctrl-C** 结束后，再按原命令启动。Windows 后台服务和 OpenWrt 后台服务应先停止，更新后再启动，见[Windows 服务](windows-service.md)或[OpenWrt](openwrt.md)。

安装目录需要可写。Linux 核心已有有线网卡权限时，更新会保留这些权限；终端提示无法保留时，以管理员身份重新运行更新。

## 连接后的自动提醒

每次打开核心，首次完整连接成功后等待 60 秒检查一次，以后默认每 24 小时检查。断线重连不会重新计时；到检查时间仍离线时，等恢复在线再检查。仅身份认证模式在该模式连接完成后开始计时，普通有线模式则等待后续会话也连接完成。

自动检查只在发现新版时提示运行 `--update`，不会安装。没有新版或检查暂时失败时保持安静。由图形界面启动的核心交给窗口统一检查。

需要暂停本次运行的自动提醒，在原连接命令后加 `--no-update-check`。长期关闭或修改检查间隔见[更新设置](configuration.md#更新设置)；手动检查和更新仍可使用。

## 更新网络与代理

默认代理无需设置。需要使用自己信任的 HTTPS 代理时，可在本次命令中指定：

```sh
./drcom4scut --check-update --update-proxy https://gh-proxy.com/
./drcom4scut --update --update-proxy https://gh-proxy.com/
```

Windows 将开头的 `./drcom4scut` 换成 `.\drcom4scut.exe`。长期设置使用 `config.yml` 中的 `update.proxy`，命令行参数优先。代理填写以 `/` 结尾的 HTTPS 前缀，不含用户名、密码、查询参数或 `#` 片段。

检查失败时先确认已能联网，再手动重试。下载或校验未通过时，按终端提示处理后重新运行更新；也可以从[下载页](download.md)取得完整桌面包。
