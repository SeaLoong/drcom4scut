# Windows 后台服务部署

后台服务适合在用户未登录、未打开 GUI 时持续认证。普通桌面使用可选择 [Windows GUI](https://github.com/SeaLoong/drcom4scutGUI)；只有需要系统级自动运行时才部署服务。

服务使用固定名称 `drcom4scut`，以 LocalSystem 身份自动启动。有线模式需要 Npcap；Portal 模式不需要抓包驱动，但系统须已连接对应网络。先在控制台确认自己的配置可以认证，再进行后台部署。不要同时运行 GUI 认证和服务。

## 准备配置

使用默认发布版核心，在私有位置准备 `config.yml` 和单独的 `password` 文件，例如：

```yaml
username: '你的校园网账号'
password_file: password
interface: '填入 --list-interfaces 显示的实际名称'
```

密码文件仅含一行不带 BOM 的 UTF-8 密码。Portal 模式改用[对应配置](portal.md)。GUI 的 DPAPI 密文只供原 Windows 用户解密，不可直接当作 LocalSystem 服务的密码文件。

程序、配置、密码及其父目录均需具备受保护的所有者与 ACL。服务安装会拒绝网络路径、重解析点、普通用户可替换的程序/配置以及普通用户可读取的密码。安装命令不会自动复制文件或替你修正权限。

## 创建受保护目录

以下示例在**管理员 Windows PowerShell 5.1** 中执行。当前目录应包含核对过 SHA-256 的 `drcom4scut.exe`，以及自己的 `config.yml`、`password`。示例仅创建全新目录，已有安装按下文维护；不会输出文件内容。

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

密码保留在受保护的部署目录中；来源文件、备份和编辑器临时文件也应妥善保护。若配置引用其他密码文件，它及全部父目录同样必须通过检查；仅保护 YAML 不够。

## 安装与日常管理

继续在管理员 PowerShell 中运行：

```powershell
$core = Join-Path $env:ProgramData 'drcom4scut\drcom4scut.exe'
$config = Join-Path $env:ProgramData 'drcom4scut\config.yml'
& $core --check-config --config $config
& $core --service-install --config $config
& $core --service-start
& $core --service-status
```

安装只登记受保护程序和配置的路径，不立即认证，也不覆盖已有同名服务。服务不接受交互式密码输入或明文密码参数；使用 YAML 中的 `password_file`，并优先采用相对于配置目录或绝对的私有路径。

`--service-status` 显示 Running、StartPending 或 Stopped 等进程状态。查看认证是否在线，应读取配置目录下的 `status.json`；服务日志位于同目录的 `logs`，不使用 System32 作为日志目录：

```powershell
$status = Join-Path $env:ProgramData 'drcom4scut\status.json'
& $core status --status-file $status
```

服务级故障由 Windows 在约 30 秒后重启，普通认证重试由客户端处理。停止时会尝试有时间上限的注销和清理。

## 修改、升级与卸载

修改配置或替换程序前先停止服务，等待状态为 Stopped；保留受保护目录及文件的所有者和 ACL，备份后再由管理员更新。重新检查配置与认证状态后启动。

```powershell
& $core --service-stop
& $core --service-status
& $core --service-start
```

需要卸载时，先停止并确认 Stopped，再执行：

```powershell
& $core --service-uninstall
```

卸载只移除服务登记，程序、配置、状态和日志仍保留。启动被拒绝时，检查实际选中的配置/密码文件及祖先目录权限、驱动和网卡 IPv4；不要通过放宽密码访问权限绕过检查。普通 Running 状态、CI 或模拟认证不能替代目标 Windows 机器的实际联网确认。
