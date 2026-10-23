# macOS 使用指南

[返回首页](../README.md) · [图形界面安装](https://github.com/SeaLoong/drcom4scutGUI#安装)

普通桌面使用推荐图形界面：安装后选择网卡、填写账号密码，点击“连接”即可。本页说明 Mac 上的下载选择、首次打开和有线认证所需权限；想在终端运行的用户，再继续阅读“配置与认证”。

## 下载与首次运行

先点击屏幕左上角 **苹果菜单 → 关于本机**。显示“芯片 Apple M…”的是 Apple Silicon；显示“处理器 Intel…”的是 Intel Mac。按下表下载与处理器匹配的原生版本。

| 你的 Mac | 核心包文件名的结尾 | GUI 包文件名的结尾 |
| --- | --- | --- |
| Intel | `x86_64-apple-darwin.tar.gz` | `osx-x64.tar.gz` |
| Apple Silicon（M 系列） | `aarch64-apple-darwin.tar.gz` | `osx-arm64.tar.gz` |

核心是负责认证的程序，GUI 是提供按钮和窗口的程序，两者需要分别下载。前往[核心下载页](https://github.com/SeaLoong/drcom4scut/releases)和 [GUI 下载页](https://github.com/SeaLoong/drcom4scutGUI/releases)，展开所选版本的 **Assets** 查看文件。当前 Mac 包在标有 **Pre-release** 的开发预览中；核心文件名包含 `0.5.1`，GUI 文件名包含 `3.1.1`。选择程序压缩包；`Source code` 供开发者使用。

GUI 适用于 **macOS 15 或更新的受支持版本**；终端核心使用独立的系统要求。

解压后，把核心 `drcom4scut` 放在 `drcom4scutGUI.app` **旁边**，保留 `.app` 的完整结构，让两者位于同一文件夹，随后打开 `.app`；以后移动安装位置时也一起移动。GUI 的具体操作见[使用说明](https://github.com/SeaLoong/drcom4scutGUI/blob/master/docs/usage.md)。

发布页同时提供 `SHA256SUMS`，它是用于检查下载是否完整的文件指纹清单。在终端运行 `shasum -a 256 下载的文件名`，比较输出的长字符串与清单中相同文件名的一行；不一致时重新下载。

当前程序没有 Apple Developer ID 签名和公证，首次打开可能被系统阻止。核对下载来源和上述文件指纹后，按 Apple 的[单个应用放行说明](https://support.apple.com/guide/mac-help/open-a-mac-app-from-an-unknown-developer-mh40616/mac)，到 **系统设置 → 隐私与安全性** 允许这份程序。系统的其他安全检查保持开启。核心程序也可能需要单独允许打开。

## 有线抓包权限

有线认证需要直接读写网卡上的认证报文，这项能力通常叫“抓包”。Mac 通过系统自带的 **BPF 设备**提供这项权限，使用系统自带功能即可。无线网页登录直接使用普通网络连接。

先插好校园网网线或 USB/雷雳网卡，确认 macOS“系统设置 → 网络”已识别该网卡并取得 IP 地址。在 GUI 中点击“环境自检”查看结果；终端用户可在解压后的核心目录运行：

```sh
./drcom4scut --list-interfaces
./drcom4scut doctor --interface en5
```

第一条列出网卡，第二条检查指定网卡。`en5` 只是示例，要换成第一条中连接校园网的实际名称。若显示 `capture=unavailable` 并提示权限不足，说明当前用户还不能读写 BPF 设备，需要管理员授权。

长期使用可由管理员采用 Wireshark 官方 [ChmodBPF](https://github.com/wireshark/wireshark/tree/master/packaging/macosx/ChmodBPF) 方案，将需要认证的用户加入受限组。学校或单位已统一管理设备时，沿用管理员的设置。

没有现成权限管理方案的个人 Mac，也可以临时授权。在**实际使用者自己的终端**中执行下列命令；`sudo` 会要求输入 Mac 管理员密码，不是校园网密码：

```sh
sudo chown "$(id -un)" /dev/bpf[0-9]*
sudo chmod u+rw /dev/bpf[0-9]*
```

这两条只授权当前已有的 BPF 设备，重启或出现新设备后可能需要重新执行。已有管理策略的设备沿用管理员设置。完成后重新自检，并**以普通用户打开 GUI**。

## 配置与认证

本节用于终端操作；使用 GUI 时在窗口填写账号密码即可，不必创建这里的配置文件。

1. 在解压后的核心目录创建配置：

   ```sh
   ./drcom4scut init --config config.yml
   ```

2. 用文本编辑器打开 `config.yml`，填写账号、密码文件名和网卡名。其他项目先保持默认：

   ```yaml
   username: '你的校园网账号'
   password_file: password
   interface: en5
   ```

3. 在同一目录创建名为 `password` 的纯文本文件，只写一行校园网密码。保存为 UTF-8 纯文本；若编辑器区分“带 BOM”和“无 BOM”，选择“无 BOM”，避免额外文件头。如果使用“文本编辑”，先选择 **格式 → 制作纯文本**，保存为无扩展名的纯文本文件。
4. 限制密码文件仅自己可读写，检查配置，然后开始认证：

   ```sh
   chmod 600 password
   ./drcom4scut --config config.yml --check-config
   ./drcom4scut --config config.yml --status-file status.json
   ```

`--check-config` 只检查填写内容，不会登录学校。最后一条才开始认证，并在运行期间维持连接；按 **Ctrl-C** 停止并尝试注销。默认有线流程已包含完整认证步骤，Mac 也保持默认 `profile` 即可。

密码文件权限与上一节的 BPF 权限是两件事：前者保护密码，后者允许有线认证读写网卡。IP 地址由 macOS 的网络设置取得，客户端使用该现有地址。

## 无线与 GUI

先在系统设置里连接校园 Wi-Fi，再通过学校网页登录。本项目可自动提交兼容的 DrCOM/ePortal 页面的账号密码，适用范围和步骤见[校园网页登录](portal.md)。这项功能使用普通网络连接，无需 BPF 授权。

GUI 3.1.1 需要核心 0.5.0 或更新版本。密码保存、窗口和托盘操作见 [GUI 使用说明](https://github.com/SeaLoong/drcom4scutGUI/blob/master/docs/usage.md)。

遇到问题按这个顺序检查：程序能否打开 → 网卡是否已连接并取得地址 → 有线权限是否通过自检 → 账号和模式是否正确。合盖、休眠或拔掉网卡后，观察恢复后的新状态；以最新的状态更新时间为准。报告问题时附程序版本和去掉账号、密码后的错误信息即可。
