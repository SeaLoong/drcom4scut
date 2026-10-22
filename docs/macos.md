# macOS 使用指南

[返回首页](../README.md)

## 下载与首次运行

在[发行页面](https://github.com/SeaLoong/drcom4scut/releases)选择与电脑处理器对应的包：

| 电脑 | 核心包 |
| --- | --- |
| Intel Mac | `x86_64-apple-darwin.tar.gz` |
| Apple Silicon Mac | `aarch64-apple-darwin.tar.gz` |

两个包分别包含原生程序；Apple Silicon 用户选择 `aarch64` 包即可原生运行，无需 Rosetta。核心包与 GUI 包单独下载；GUI 的系统版本要求见[图形界面说明](https://github.com/SeaLoong/drcom4scutGUI#安装)，不能用核心的系统兼容范围推断 GUI 可用范围。

下载后用 `shasum -a 256 文件名` 计算归档摘要，与同一 Release 的 `SHA256SUMS` 中对应文件那一行比较，再解压。终端进入解压后的目录，运行：

```sh
./drcom4scut --version
./drcom4scut --list-interfaces
```

当前发行没有 Apple Developer ID 签名和公证。首次运行被系统拦截时，核对来源与摘要，再按 Apple 的[打开未知开发者应用说明](https://support.apple.com/guide/mac-help/open-a-mac-app-from-an-unknown-developer-mh40616/mac)，在“系统设置 → 隐私与安全性”中允许这份程序。不要关闭整个系统的 Gatekeeper。

## 有线抓包权限

macOS 有线认证使用系统自带的 BPF 设备，不安装 Npcap。USB/雷雳以太网适配器必须已被系统识别，且已有可用 IPv4。先找出实际接口名，再检查，例如：

```sh
./drcom4scut doctor --interface en5
```

`en5` 只是示例，应替换为 `--list-interfaces` 显示的校园网以太网接口。`capture=unavailable` 且提示权限不足时，需要管理员向实际使用者授予 `/dev/bpf*` 的读写权限；这包含抓包和发送原始帧的能力。

持续使用时，可由管理员采用 Wireshark 官方 [ChmodBPF](https://github.com/wireshark/wireshark/tree/master/packaging/macosx/ChmodBPF) 等受管理方案，仅将需要抓包的账号加入受限组。已有 Wireshark 或组织设备管理策略时，沿用管理员的配置。

在没有现成抓包权限管理的个人机器上，管理员也可临时将现有 BPF 设备授权给当前登录用户。在该用户的终端中执行：

```sh
sudo chown "$(id -un)" /dev/bpf[0-9]*
sudo chmod u+rw /dev/bpf[0-9]*
```

此方式不安装后台服务；重启以及新 BPF 设备出现后，可能需要重新授权。不要套用到已有组或组织策略管理的机器，也不要将设备改为所有用户可写。授权后，回到普通用户身份重新运行 `doctor`。GUI 始终使用普通用户启动，不要用 `sudo` 启动整个图形界面。

## 配置与认证

```sh
./drcom4scut init --config config.yml
```

在生成的文件中填写账号、密码文件和实际接口名：

```yaml
username: '你的校园网账号'
password_file: password
interface: en5
```

用编辑器创建 `password`，仅写一行不带 BOM 的 UTF-8 密码，然后限制文件权限并启动：

```sh
chmod 600 password
./drcom4scut --config config.yml --check-config
./drcom4scut --config config.yml --status-file status.json
```

密码文件权限与 BPF 设备权限分别检查。校园网 DHCP、地址及路由由系统负责；客户端不会替网络接口分配地址。默认有线认证完成 EAP 后建立 UDP 会话并持续心跳，无需按 macOS 选择另一个 `profile`。

按 Ctrl-C 停止并尝试注销。合盖、休眠、拔出网卡可能使会话失效；恢复后观察状态和重连日志，不要把睡眠前的状态文件当作当前网络状态。

## 无线与 GUI

无线 [Portal 模式](portal.md)不访问 BPF，也不需要管理员抓包权限。先通过系统连接校园无线网络，再配置明确可信的门户地址。

使用 [drcom4scutGUI](https://github.com/SeaLoong/drcom4scutGUI) 时，选择与本机 CPU 对应的 GUI 包，将本核心程序 `drcom4scut` 放在 `drcom4scutGUI.app` **同级目录**，不修改 `.app` 内部文件。GUI 3.1.0 需要核心 0.5.0 或更新版本，详细安装和密码保存方法见 [GUI 文档](https://github.com/SeaLoong/drcom4scutGUI#readme)。

遇到问题时先检查实际接口、IPv4、BPF 权限和核心版本，再分享脱敏诊断。原生 CI、回环测试和进程测试不代替校园交换机、实际网卡及长期在线验证。
