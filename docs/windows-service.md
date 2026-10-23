# Windows 后台服务部署

[返回首页](../README.md) · [Windows 命令行入门](windows.md) · [图形界面安装](https://github.com/SeaLoong/drcom4scutGUI/blob/master/docs/windows.md)

如果只想登录电脑后自动联网，使用 GUI 的“登录系统时启动”和“打开后自动连接”即可。**本页面向管理员**，适合需要在任何人登录 Windows 之前就开始认证的电脑。

后台服务由 Windows 管理，在后台持续运行。它使用固定名称 `drcom4scut`，以 Windows 自带的高权限系统账号（LocalSystem）运行，程序和密码集中保存在仅管理员与系统账号可修改的目录中。下文脚本会完成这些目录设置。

先按 [Windows 命令行指南](windows.md)完成一次连接，再安装服务。有线认证需要安装 [Npcap](https://npcap.com/#download)，它让程序能读写有线认证所需的网卡报文。无线网页登录不需要该驱动，但系统仍须先连上对应 Wi-Fi；兼容范围见[无线指南](portal.md)。同一网卡选择 GUI 或服务中的一种方式运行。

## 准备配置

从[下载页](https://github.com/SeaLoong/drcom4scut/releases)选择适合本机处理器的 Windows 桌面一体包，解压后使用其中的 `drcom4scut.exe`。在只有当前用户可访问的目录中准备 `config.yml` 和单独的 `password` 文件，例如：

```yaml
username: '你的校园网账号'
password_file: password
interface: '填入 --list-interfaces 显示的实际名称'
```

密码文件只写一行校园网密码，保存为 UTF-8 纯文本；编辑器若区分“带 BOM”和“无 BOM”，选择“无 BOM”，避免额外文件头。使用网页登录时改用[对应配置](portal.md)。GUI 保存的密码受原 Windows 用户保护（DPAPI），服务使用的是另一个系统账号，因此请为服务单独准备密码文件。

Windows 的文件访问规则称为 ACL，决定谁能读取和修改文件。服务会检查程序、配置、密码以及上级文件夹的所有者和访问规则：程序与密码保存在管理员保护的本地普通目录中，只有管理员与系统账号能修改。

先按下一节准备文件与访问权限，再运行安装命令登记服务路径。

## 创建受保护目录

在开始菜单找到 **Windows PowerShell**，右键选择“以管理员身份运行”。以下脚本适用于 Windows PowerShell 5.1：先进入刚准备好的文件夹，其中应包含已核对下载指纹（SHA-256）的 `drcom4scut.exe`，以及自己的 `config.yml` 和 `password`。

脚本会创建 `%ProgramData%\drcom4scut`，只允许管理员和系统账号访问，并把这三个文件复制进去。请完整执行脚本以保留这些权限设置。已有安装按后面的维护步骤操作，首次安装脚本会在目标目录已存在时提示。

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

完成后，服务使用受保护目录里的密码文件。原文件和备份同样存放在私有目录中；若自定义密码文件位置，对该文件及其上级目录使用相同的管理员访问设置。

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

第一条只检查文件内容；`--service-install` 登记后台服务，`--service-start` 才开始运行，最后一条查看运行情况。已有同名服务不会被覆盖。服务从配置中的 `password_file` 读取密码，适合无人值守运行。

`--service-status` 中的 `Running` 表示程序正在运行，`StartPending` 表示正在启动，`Stopped` 表示已停止。学校认证结果请查看配置目录中的连接状态：

```powershell
$status = Join-Path $env:ProgramData 'drcom4scut\status.json'
& $core status --status-file $status
```

连接状态保存在同目录的 `status.json`，日志在 `logs` 文件夹中，所有运行文件集中保存在受保护的安装目录。认证失败时客户端会按配置重试；服务本身意外退出时，Windows 约 30 秒后重新启动它。正常停止会先尝试向学校注销，再退出。

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

卸载后，程序、配置、密码和日志保留在原目录，可由管理员按需归档或删除。

| 现象 | 下一步 |
| --- | --- |
| 安装或启动被拒绝 | 看错误指出的路径，检查文件及上级目录是否仍由管理员和系统账号保护 |
| 服务在运行，但认证失败 | 查看 `status.json` 和 `logs`，确认账号、网卡名称、地址和认证模式 |
| 有线自检提示无法抓包 | 检查 Npcap 是否安装，以及实际网卡是否已取得 IPv4 地址 |

分享日志前移除账号、密码和私人网络信息。
