# 命令行快速开始

[返回首页](../README.md) · [下载程序](download.md)

命令行就是在终端中输入命令来运行程序，适合喜欢终端操作或需要后台运行的用户。日常在电脑上点按钮连接，也可以直接使用[图形界面](https://github.com/SeaLoong/drcom4scutGUI)。

## 第一次使用，按你的系统开始

桌面一体包里已经有命令行程序，解压后即可按下面的系统指南选择网卡、填写账号并连接。图形界面与命令行共用同一份下载：

| 系统 | 从这里开始 | 首次有线连接需要准备 |
| --- | --- | --- |
| Windows | [Windows 命令行](windows.md) | 安装 Npcap，然后在 PowerShell 中操作 |
| macOS | [Mac 使用指南](macos.md) | 给当前用户授予有线网卡访问权限 |
| Linux | [Linux 命令行](linux.md) | 给核心程序授予网卡访问权限 |
| OpenWrt | [路由器安装](openwrt.md) | 选择匹配路由器的程序，并配置后台服务 |

校园 Wi-Fi 使用[网页登录指南](portal.md)：先连接无线网络，确认学校登录页可用，再设置自动提交账号密码。

## 准备好后，文件夹里有什么？

完整解压桌面一体包，保留其中的文件。命令行主要使用以下三项，后两项在首次设置时创建：

| 文件 | 用来做什么 |
| --- | --- |
| `drcom4scut`，Windows 为 `drcom4scut.exe` | 负责校园网连接的程序 |
| `config.yml` | 账号、使用哪张网卡，以及其他设置 |
| `password` 或 `password.txt` | 只包含一行校园网密码，文件名与设置中的 `password_file` 一致 |

用 `init` 命令生成 `config.yml`，在模板中修改账号、密码文件名和网卡名称即可。完整填写过程见上面的系统指南，其余设置先保留默认。

![Linux 终端中的版本、网卡与配置检查](images/linux-cli-check.png)

*命令行检查示例，截图来自 Linux 终端实际运行。*

## 每次连接

先进入放有上述文件的文件夹。Windows PowerShell：

```powershell
.\drcom4scut.exe --config config.yml --check-config
.\drcom4scut.exe --config config.yml --status-file status.json
```

Mac / Linux 终端：

```sh
./drcom4scut --config config.yml --check-config
./drcom4scut --config config.yml --status-file status.json
```

第一条检查填写内容，显示 `Configuration is valid.` 后运行第二条，开始向学校认证。以后没有改过配置时，直接运行第二条即可。

程序在运行期间保持连接，网络中断后继续尝试恢复。保留这个终端窗口，结束时按 **Ctrl-C**。

## 看连接结果

运行连接的终端会显示进度。也可以另开一个终端，进入同一文件夹查看状态。

Windows PowerShell：

```powershell
.\drcom4scut.exe status --status-file status.json
.\drcom4scut.exe logs --config config.yml
```

Mac / Linux：

```sh
./drcom4scut status --status-file status.json
./drcom4scut logs --config config.yml
```

第一条显示连接结果：`online` 为 `true` 表示校园网认证已完成，`updated_at` 是这份结果的更新时间。第二条显示最近的运行日志，适合找出连接失败的提示。

## 接下来

- [更新程序](update.md)：检查正式版并更新核心，账号和配置继续保留。
- [连接与排障](troubleshooting.md)：按屏幕提示处理网卡、权限、账号和掉线问题。
- [Windows 后台服务](windows-service.md)：需要开机后、登录系统前就联网时使用。
- [配置参考](configuration.md)：修改日志、重连等待等选项。
- [校园网页登录](portal.md)：让程序代为提交受支持的学校登录页。
