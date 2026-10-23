# 命令行快速开始

[返回首页](../README.md)

下面用终端完成一次有线连接。喜欢窗口操作的电脑用户，可以从[图形界面](https://github.com/SeaLoong/drcom4scutGUI#readme)开始。

先按[下载指南](download.md)解压核心程序，并接好校园网网线。以下命令在解压目录运行；Windows PowerShell 将 `./drcom4scut` 换成 `.\drcom4scut.exe`。

## 1. 选择网卡

在系统的网络设置中确认以太网已经连接并取得 IP 地址，然后列出网卡：

```sh
./drcom4scut --list-interfaces
```

复制连接校园网的网卡在 `NAME` 一列中的名称。下面用 `eth0` 举例，Mac 可能是 `en0`、`en5`，请换成自己的名称。

## 2. 保存账号设置

生成设置文件：

```sh
./drcom4scut init --config config.yml
```

用文本编辑器打开 `config.yml`，修改这三项，其余设置保持默认：

```yaml
username: '你的校园网账号'
password_file: password
interface: eth0
```

在同一目录创建名为 `password` 的纯文本文件，只写一行校园网密码，保存为 **UTF-8（无 BOM）**。Windows 若将它保存为 `password.txt`，同时把配置中的文件名改为 `password.txt` 即可。

Mac / Linux 执行下面的命令，把密码文件设为仅自己可读写：

```sh
chmod 600 password
```

密码留在这个私有文件中，终端命令只填写文件名。更多设置见[密码与路径](configuration.md#密码与路径)。

## 3. 检查并连接

```sh
./drcom4scut --config config.yml --check-config
./drcom4scut doctor --interface eth0
./drcom4scut --config config.yml --status-file status.json
```

前两条分别检查账号设置和网卡环境；最后一条开始认证。首次有线认证需要网卡访问权限：Windows 安装 [Npcap](https://npcap.com/#download)，Mac 按[网卡授权步骤](macos.md#有线抓包权限)操作，Linux 按[首次运行说明](https://github.com/SeaLoong/drcom4scutGUI/blob/master/docs/usage.md#linux)完成授权后重新自检。

认证期间保持终端打开。默认设置会完成通常所需的完整有线流程，`profile` 保持默认即可。

## 日常使用

再次连接时，运行最后一条命令即可。程序会保持连接，并在网线恢复、地址变化或认证中断后尝试重新连接。

另开一个终端查看连接结果：

```sh
./drcom4scut status --status-file status.json
```

`online` 表示当前校园网认证已完成；同时核对 `updated_at` 的更新时间，了解状态是否仍在刷新。查看最近日志：

```sh
./drcom4scut logs --config config.yml
```

结束时，在运行认证的终端按 **Ctrl-C**，程序会尝试退出本次会话。每张网卡使用一个认证客户端即可。

[连接与排障](troubleshooting.md) · [无线网页登录](portal.md) · [配置参考](configuration.md) · [Windows 后台服务](windows-service.md)
