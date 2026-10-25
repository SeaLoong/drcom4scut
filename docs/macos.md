# Mac 命令行使用

[返回首页](../README.md) · [Mac 图形界面安装](https://github.com/SeaLoong/drcom4scutGUI/blob/master/docs/macos.md)

本页带你在 Mac 的“终端”中连接校园网。喜欢窗口和按钮时，直接按图形界面指南安装；有线连接需要的网卡授权方法两种用法通用。

## 下载与首次运行

在 **苹果菜单 → 关于本机** 查看芯片，从[下载页](https://github.com/SeaLoong/drcom4scut/releases/latest)选择文件名包含 **`desktop`** 的桌面一体包：

| “关于本机”显示 | 桌面一体包的文件名结尾 |
| --- | --- |
| 芯片 Apple M 系列 | `osx-arm64.tar.gz` |
| 处理器 Intel | `osx-x64.tar.gz` |

展开所选版本的 **Assets** 下载程序压缩包，**Pre-release** 表示预览版。在访达中双击压缩包解压，包内已放好 `drcom4scutGUI.app` 和 `drcom4scut`。双击 `.app` 可以使用窗口，下面介绍同包中的命令行程序。

打开“终端”，输入 `cd `（末尾有一个空格），把刚解压的文件夹拖进终端，再按回车。随后查看程序版本：

```sh
./drcom4scut --version
```

当前程序没有 Apple Developer ID 签名和公证，首次运行时 macOS 可能显示来源提示。确认下载来自本项目发布页后，到 **系统设置 → 隐私与安全性**，按提示允许打开这份程序，再运行版本命令。操作位置见 [Apple 的说明](https://support.apple.com/guide/mac-help/open-a-mac-app-from-an-unknown-developer-mh40616/mac)。发布页的 `SHA256SUMS` 可用来[核对下载完整性](configuration.md#检查下载的文件)。

看到版本号后继续下一步。使用图形界面的 Mac 需要 macOS 15 或更新且受支持的系统。一体包中 `.app` 和命令行程序已放在一起，移动时保持整个文件夹完整；窗口使用方法见[图形界面指南](https://github.com/SeaLoong/drcom4scutGUI/blob/master/docs/macos.md)。

## 有线抓包权限

插好校园网网线或 USB / 雷雳网卡，在 **系统设置 → 网络** 确认以太网已连接并取得地址。在刚才的终端列出网卡：

```sh
./drcom4scut --list-interfaces
```

找到接学校网线的网卡在 `NAME` 一列中的名称，例如 `en5`。用实际名称检查网卡：

```sh
./drcom4scut doctor --interface en5
```

显示 `capture=ok` 即可继续。若提示没有访问权限，给当前用户授予有线认证需要的权限。Mac 把这项网络报文访问能力称为 **BPF**，它由系统提供。

在**你自己的终端**里执行：

```sh
sudo chown "$(id -un)" /dev/bpf[0-9]*
sudo chmod u+rw /dev/bpf[0-9]*
```

`sudo` 要求输入的是 **Mac 管理员密码**。输入时终端不显示字符，输完按回车即可。这两条命令让当前用户访问已有的 BPF 设备；重启或出现新设备后，可按自检提示再次授权。日常连接以自己的普通用户运行。

长期使用可由管理员采用 Wireshark 的 [ChmodBPF 权限方案](https://github.com/wireshark/wireshark/tree/master/packaging/macosx/ChmodBPF)。学校或单位统一管理的 Mac 沿用管理员设置。

授权完成后，再运行一次上述 `doctor` 命令，确认 `capture=ok`。校园网页登录使用普通网络连接，可直接按[网页登录指南](portal.md)操作。

## 配置与认证

在程序所在目录生成设置文件，并用“文本编辑”打开：

```sh
./drcom4scut init --config config.yml
open -e config.yml
```

修改模板中的以下三项，其余设置先保持默认。`en5` 换成刚才查到的实际网卡名称：

```yaml
username: '你的校园网账号'
password_file: password
interface: en5
```

保存配置，再创建只供自己读写的密码文件并打开：

```sh
touch password
chmod 600 password
open -e password
```

在文件中只填写一行校园网密码。使用“文本编辑”时，选择 **格式 → 制作纯文本**，保存为 UTF-8 纯文本；如果已经是纯文本，格式菜单会显示“制作富文本”，保持当前格式即可。实际文件名应与 `password_file` 一致，如果编辑器保存成 `password.txt`，在配置中同步填写 `password.txt`。

保存后回到终端，确认密码文件仅自己可读写，再检查设置并开始连接（文件名以实际保存结果为准）：

```sh
chmod 600 password
./drcom4scut --config config.yml --check-config
./drcom4scut --config config.yml --status-file status.json
```

第一条显示 `Configuration is valid.` 后运行第二条，开始向学校认证。保留这个终端窗口，程序会持续保持连接并在中断后尝试恢复。

## 日常使用

以后进入程序目录，直接运行连接命令即可。另开一个终端进入同一目录，可以查看状态和最近日志：

```sh
./drcom4scut status --status-file status.json
./drcom4scut logs --config config.yml
```

`online` 为 `true` 表示校园网认证已完成，`updated_at` 是结果的更新时间。结束时回到运行认证的终端，按 **Ctrl-C**。合盖或拔掉网卡后，等系统恢复网络，再观察最新连接结果。

运行 `./drcom4scut --check-update` 可查看最新正式版，`./drcom4scut --update` 发现新版后直接安装。重启后使用新版，账号和配置继续保留，见[更新指南](update.md)。

## 无线与 GUI

校园 Wi-Fi 先在 macOS 的 Wi-Fi 菜单中连接，再打开学校登录页。本项目可代为提交受支持的 DrCOM/ePortal 账号密码页面，步骤见[校园网页登录](portal.md)。

使用图形界面时，在窗口填写账号和密码即可；自动启动、多账号和菜单栏操作见 [GUI 日常使用](https://github.com/SeaLoong/drcom4scutGUI/blob/master/docs/usage.md)。

## 常见情况

| 看到什么 | 下一步 |
| --- | --- |
| 系统阻止打开核心 | 到“隐私与安全性”按提示允许本次下载的程序，再查看版本 |
| 程序提示处理器类型不符 | 按“关于本机”重新选择 Apple 芯片或 Intel 版本 |
| 重启后有线自检提示权限 | 按[网卡授权步骤](#有线抓包权限)完成授权后再自检 |
| 密码文件找不到 | 核对文件名是否带 `.txt`，以及它是否与配置文件放在一起 |
| 自检通过但连接失败 | 查看最近日志，按[连接与排障](troubleshooting.md)核对账号和网络 |
