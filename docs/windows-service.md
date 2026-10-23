# Windows 后台服务部署

[返回首页](../README.md) · [普通桌面用户使用图形界面](https://github.com/SeaLoong/drcom4scutGUI)

如果只想登录电脑后自动联网，使用 GUI 的“登录系统时启动”和“打开 GUI 后自动认证”即可。**本页面向管理员**，适合需要在任何人登录 Windows 之前就开始认证的电脑。

后台服务由 Windows 管理，不需要一直开着认证窗口。它使用固定名称 `drcom4scut`，以 Windows 自带的高权限系统账号（LocalSystem）运行，因此程序和密码文件都必须保护好，不能放在其他普通用户能随意替换的目录。

先在终端中确认账号配置能正常认证，再安装服务。有线认证需要安装 [Npcap](https://npcap.com/#download)，它让程序能读写有线认证所需的网卡报文。无线网页登录不需要该驱动，但系统仍须先连上对应 Wi-Fi；兼容范围见[无线指南](portal.md)。不要同时用 GUI 和服务在同一网卡认证。

## 准备配置

从[下载页](https://github.com/SeaLoong/drcom4scut/releases)选择适合本机处理器的 Windows 核心包。在只有当前用户可访问的目录中准备 `config.yml` 和单独的 `password` 文件，例如：

```yaml
username: '你的校园网账号'
password_file: password
interface: '填入 --list-interfaces 显示的实际名称'
```

密码文件只写一行校园网密码，保存为 UTF-8 纯文本；编辑器若区分“带 BOM”和“无 BOM”，选择“无 BOM”，避免额外文件头。使用网页登录时改用[对应配置](portal.md)。GUI 保存的密码受原 Windows 用户保护（DPAPI），服务使用的是另一个系统账号，不能直接拿 GUI 的加密内容当作密码文件。

Windows 的文件访问规则称为 ACL，决定谁能读取和修改文件。服务会检查程序、配置、密码以及上级文件夹的所有者和访问规则：普通用户不能替换服务程序，也不能读取服务密码。网络共享路径和会跳转到其他位置的文件或文件夹（重解析点）也不会接受。

安装服务的命令只登记路径，不会帮你复制文件或修改权限。下一节提供完整准备步骤，不要通过给“所有人”访问权限来绕过检查。

## 创建受保护目录

在开始菜单找到 **Windows PowerShell**，右键选择“以管理员身份运行”。以下脚本适用于 Windows PowerShell 5.1：先进入刚准备好的文件夹，其中应包含已核对下载指纹（SHA-256）的 `drcom4scut.exe`，以及自己的 `config.yml` 和 `password`。

脚本会创建 `%ProgramData%\drcom4scut`，只允许管理员和系统账号访问，并把这三个文件复制进去。它不会显示密码内容。为避免覆盖已有安装，目标目录已存在时会停止；已有安装请按后面的维护步骤操作。完整保留权限设置，不要只挑复制文件的几行执行。

```powershell
$ErrorActionPreference = 'Stop'
$source = (Get-Location).Path
$root = Join-Path $env:ProgramData 'drcom4scut'
if (Test-Path -LiteralPath $root) { throw '目录已存在，请按维护步骤处理' }

$admin = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetOwner($admin)
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in @($admin, $system)) {
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
}
$directory = [IO.DirectoryInfo]::new($root)
$directory.Create($acl)
if (([int]$directory.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw '拒绝重解析点'
}
if ((Get-Acl -LiteralPath $root).GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $admin.Value) {
    throw '目录所有者不符'
}
foreach ($name in @('drcom4scut.exe', 'config.yml', 'password')) {
    $bytes = [IO.File]::ReadAllBytes((Join-Path $source $name))
    $target = Join-Path $root $name
    $stream = [IO.File]::Open($target, 'CreateNew', 'Write', 'None')
    try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
    $fileAcl = [Security.AccessControl.FileSecurity]::new()
    $fileAcl.SetOwner($admin)
    $fileAcl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($admin, $system)) {
        $fileAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'Allow'))
    }
    Set-Acl -LiteralPath $target -AclObject $fileAcl
    [Array]::Clear($bytes, 0, $bytes.Length)
}
```

完成后，服务使用受保护目录里的密码文件。原文件、备份和编辑器留下的临时副本也可能包含密码，应同样妥善保存。若配置改为引用另一个密码文件，该文件及其上级文件夹也必须满足相同要求；只保护 `config.yml` 还不够。

## 安装与日常管理

仍在管理员 PowerShell 中，先检查配置，再安装、启动并查看服务：

```powershell
$core = Join-Path $env:ProgramData 'drcom4scut\drcom4scut.exe'
$config = Join-Path $env:ProgramData 'drcom4scut\config.yml'
& $core --check-config --config $config
& $core --service-install --config $config
& $core --service-start
& $core --service-status
```

第一条只检查文件内容；`--service-install` 登记后台服务，`--service-start` 才开始运行，最后一条查看运行情况。已有同名服务不会被覆盖。服务运行时没有窗口供你输入密码，必须从配置中的 `password_file` 读取；不要把密码放在启动参数里。

`--service-status` 中的 `Running` 表示程序正在运行，`StartPending` 表示正在启动，`Stopped` 表示已停止。**Running 不代表学校认证成功**，还需要查看配置目录中的连接状态：

```powershell
$status = Join-Path $env:ProgramData 'drcom4scut\status.json'
& $core status --status-file $status
```

连接状态保存在同目录的 `status.json`，日志在 `logs` 文件夹中，不会写进 Windows 的 System32。认证失败时客户端会按配置重试；服务本身意外退出时，Windows 约 30 秒后重新启动它。正常停止会先尝试向学校注销，再退出。

## 修改、升级与卸载

修改账号、配置或替换程序前，先停止服务并确认显示 `Stopped`，再由管理员备份和更新文件。保持原目录与文件的所有者和访问规则；更新后重新检查配置，再启动：

```powershell
& $core --service-stop
& $core --service-status
& $core --service-start
```

需要卸载时，先停止并确认 Stopped，再执行：

```powershell
& $core --service-uninstall
```

卸载只取消 Windows 中的服务登记，不会删除程序、配置、密码和日志。确认不再需要后，再由管理员处理这些文件。

| 现象 | 下一步 |
| --- | --- |
| 安装或启动被拒绝 | 看错误指出的路径，检查文件及上级目录是否仍由管理员和系统账号保护 |
| 服务在运行，但认证失败 | 查看 `status.json` 和 `logs`，确认账号、网卡名称、地址和认证模式 |
| 有线自检提示无法抓包 | 检查 Npcap 是否安装，以及实际网卡是否已取得 IPv4 地址 |

分享日志前移除账号、密码和私人网络信息。自动测试和服务状态不能代替这台电脑在校园网中的实际联网检查。
