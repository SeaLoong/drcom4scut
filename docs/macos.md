# macOS 使用指南

[返回首页](../README.md) · [图形界面安装](https://github.com/SeaLoong/drcom4scutGUI#安装)

普通桌面使用推荐图形界面：安装后选择网卡、填写账号密码，点击“认证”即可。本页说明 Mac 上的下载选择、首次打开和有线认证所需权限；想在终端运行的用户，再继续阅读“配置与认证”。

## 下载与首次运行

先点击屏幕左上角 **苹果菜单 → 关于本机**。显示“芯片 Apple M…”的是 Apple Silicon；显示“处理器 Intel…”的是 Intel Mac。按下表下载，不需要安装 Rosetta 来运行另一种架构的包。

| 你的 Mac | 核心包文件名的结尾 | GUI 包文件名的结尾 |
| --- | --- | --- |
| Intel | `x86_64-apple-darwin.tar.gz` | `osx-x64.tar.gz` |
| Apple Silicon（M 系列） | `aarch64-apple-darwin.tar.gz` | `osx-arm64.tar.gz` |

核心是负责认证的程序，GUI 是提供按钮和窗口的程序，两者需要分别下载。前往[核心下载页](https://github.com/SeaLoong/drcom4scut/releases)和 [GUI 下载页](https://github.com/SeaLoong/drcom4scutGUI/releases)，展开所选版本的 **Assets** 查看文件。当前 Mac 包在标有 **Pre-release** 的开发预览中；核心文件名包含 `0.5.0`，GUI 文件名包含 `3.1.0`。不要下载 `Source code`，那是开发者使用的源码。

GUI 需要 **macOS 15 或更新的受支持版本**。终端核心的系统要求与 GUI 不同，不能因为核心能启动，就认为 GUI 也能运行。

解压后，把核心 `drcom4scut` 放在 `drcom4scutGUI.app` **旁边**，不要放进 `.app` 内部。保留两者在同一文件夹中，随后打开 `.app`；以后移动安装位置时也一起移动。GUI 的具体操作见[使用说明](https://github.com/SeaLoong/drcom4scutGUI/blob/master/docs/usage.md)。

发布页同时提供 `SHA256SUMS`，它是用于检查下载是否完整的文件指纹清单。在终端运行 `shasum -a 256 下载的文件名`，比较输出的长字符串与清单中相同文件名的一行；不一致时重新下载。

当前程序没有 Apple Developer ID 签名和公证，首次打开可能被系统阻止。核对下载来源和上述文件指纹后，按 Apple 的[单个应用放行说明](https://support.apple.com/guide/mac-help/open-a-mac-app-from-an-unknown-developer-mh40616/mac)，到 **系统设置 → 隐私与安全性** 允许这份程序。无需关闭整个系统的安全检查。核心程序也可能需要单独允许打开。

## 有线抓包权限

有线认证需要直接读写网卡上的认证报文，这项能力通常叫“抓包”。Mac 通过系统自带的 **BPF 设备**提供这项权限，无需安装 Windows 使用的 Npcap 驱动。**无线网页登录不需要这一步。**

先插好校园网网线或 USB/雷雳网卡，确认 macOS“系统设置 → 网络”已识别该网卡并取得 IP 地址。在 GUI 中点击“环境自检”查看结果；终端用户可在解压后的核心目录运行：

```sh
./drcom4scut --list-interfaces
./drcom4scut doctor --interface en5
```

第一条列出网卡，第二条检查指定网卡。`en5` 只是示例，要换成第一条中连接校园网的实际名称。若显示 `capture=unavailable` 并提示权限不足，说明当前用户还不能读写 BPF 设备，需要管理员授权。

长期使用可请管理员采用 Wireshark 官方 [ChmodBPF](https://github.com/wireshark/wireshark/tree/master/packaging/macosx/ChmodBPF) 方案，将需要认证的用户加入受限组。学校或单位已统一管理设备时，沿用管理员的设置。

没有现成权限管理方案的个人 Mac，也可以临时授权。在**实际使用者自己的终端**中执行下列命令；`sudo` 会要求输入 Mac 管理员密码，不是校园网密码：

```sh
sudo chown "$(id -un)" /dev/bpf[0-9]*
sudo chmod u+rw /dev/bpf[0-9]*
```

这两条只授权当前已有的 BPF 设备，重启或出现新设备后可能需要重新执行。已有组权限或组织管理策略时不要套用；也不要把设备设置成所有用户可写。完成后重新自检，**以普通用户打开 GUI，不要用 `sudo` 启动 GUI**。

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

3. 在同一目录创建名为 `password` 的纯文本文件，只写一行校园网密码。保存为 UTF-8 纯文本；若编辑器区分“带 BOM”和“无 BOM”，选择“无 BOM”，避免额外文件头。如果使用“文本编辑”，先选择 **格式 → 制作纯文本**，不要存成富文本或带 `.rtf` 的文件。
4. 限制密码文件仅自己可读写，检查配置，然后开始认证：

   ```sh
   chmod 600 password
   ./drcom4scut --config config.yml --check-config
   ./drcom4scut --config config.yml --status-file status.json
   ```

`--check-config` 只检查填写内容，不会登录学校。最后一条才开始认证，并在运行期间维持连接；按 **Ctrl-C** 停止并尝试注销。默认有线流程包含两阶段认证，一般保持默认，不需要因为使用 Mac 而更改 `profile`。

密码文件权限与上一节的 BPF 权限是两件事：前者保护密码，后者允许有线认证读写网卡。IP 地址仍由 macOS 的网络设置取得，客户端不会替网卡分配地址。

## 无线与 GUI

无线网络通常是在连上校园 Wi-Fi 后，打开学校网页输入账号密码登录。浏览器手动登录不需要安装本项目。

本项目的[无线网页登录功能](portal.md)尝试代替填写受支持的 DrCOM 登录页；它不会替你搜索或连接 Wi-Fi，也不能登录任意网站。目前没有在目标校区真实无线网络上验证，建议先确认浏览器能正常登录，再按该指南判断是否适用。它不使用 BPF，也不需要有线抓包权限。

GUI 3.1.0 需要核心 0.5.0 或更新版本。密码保存、窗口和托盘操作见 [GUI 使用说明](https://github.com/SeaLoong/drcom4scutGUI/blob/master/docs/usage.md)。

遇到问题按这个顺序检查：程序能否打开 → 网卡是否已连接并取得地址 → 有线权限是否通过自检 → 账号和模式是否正确。合盖、休眠或拔掉网卡后，观察恢复后的新状态；不要把睡眠前留下的状态文件当作当前连接。报告问题时附程序版本和去掉账号、密码后的错误信息即可。
