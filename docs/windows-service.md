# Windows 后台服务

`drcom4scut` 可作为 Windows Service Control Manager（SCM）管理的独立服务运行；不需要用户登录，也不需要 GUI 一直打开。它与控制台共用同一套 Tokio 认证、心跳、设备恢复和有界退出逻辑。此模式仅适用于 Windows，要求默认 `log4rs` 特性和可用的 Npcap 驱动。

服务以 **LocalSystem** 身份运行，安装和管理需要管理员权限。这是可选的系统级部署；普通 GUI 的用户级 DPAPI 密码不应复制给 LocalSystem，也不能假定另一个 Windows 账户可以解密它。服务使用专用 YAML 配置，密码文件必须只允许管理员和 SYSTEM 读取。

## 准备受保护的程序和配置

先用控制台完成实机认证，再部署服务。服务安装命令不复制程序、不改写文件 ACL、不覆盖已有服务，也不立即启动认证。安装前会检查程序、配置和父路径：拒绝网络路径、重解析点、可被普通用户替换的文件，以及可被普通用户读取的密码文件。

在管理员 **Windows PowerShell 5.1** 中可用以下方式准备一个全新的目录。先将 `$exeSource`、`$configSource` 设置为已经核对 SHA-256 的本版本程序和自己的配置；命令不会输出配置内容。若目标目录已经存在，应先停止服务、备份自己的数据，再人工决定升级步骤，不要盲目删除或覆盖。

```powershell
$ErrorActionPreference = 'Stop'
$exeSource = (Resolve-Path '.\drcom4scut.exe').Path
$configSource = (Resolve-Path '.\config.yml').Path
$root = Join-Path $env:ProgramData 'drcom4scut'
if (Test-Path -LiteralPath $root) { throw '目标目录已存在，请先备份并处理已有安装' }

$admin = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$directoryAcl = [Security.AccessControl.DirectorySecurity]::new()
$directoryAcl.SetOwner($admin)
$directoryAcl.SetAccessRuleProtection($true, $false)
foreach ($sid in @($admin, $system)) {
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $directoryAcl.AddAccessRule($rule)
}
$directory = [IO.DirectoryInfo]::new($root)
$directory.Create($directoryAcl)
if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw '拒绝重解析点' }
if ((Get-Acl -LiteralPath $root).GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $admin.Value) {
    throw '目录所有者不符'
}

# 写入内容，而不是复制来源文件的 DACL；新文件继承受保护目录的 ACL。
# CreateNew 保留既有文件，避免意外覆盖。
foreach ($pair in @(@($exeSource, 'drcom4scut.exe'), @($configSource, 'config.yml'))) {
    $bytes = [IO.File]::ReadAllBytes($pair[0])
    $target = Join-Path $root $pair[1]
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

配置本身应是完整且已验证的 YAML。`--check-config` 可以检查格式和字段，但不代表学校已接受认证。准备目录中的旧明文来源文件、备份及日志也应自行妥善保护。

配置可用 `password_file: private/password.key` 引用单独的密码文件；相对路径以 YAML 所在目录为基准。该文件同样必须由 Administrators、SYSTEM 或受信任系统安装服务拥有，禁止普通用户读取或写入，且全部父目录必须通过相同的所有者、DACL 和重解析点检查。安装和每次服务启动都会检查实际选中的密码文件，**受保护的 YAML 不能替代外部密码文件的权限保护**。`password` 与 `password_file` 不能同时配置，密码文件只应包含一行 UTF-8 密码。

SCM 注册只保存配置路径，不保存密码值。若管理员手动配置服务命令行中的 `--password-file` 覆盖，它也会按实际来源重新检查权限；CLI 相对文件路径沿用当前工作目录语义，因此在服务中应使用绝对路径。服务明确拒绝 `--password-stdin` 和明文 `--password`，不能等待交互式终端或把密码暴露在服务命令行。推荐将密码文件放在上述受保护部署目录中，并在 YAML 内引用，而非修改 SCM 命令行。

## 安装、启停和查询

继续在管理员 PowerShell 中运行受保护目录内的程序：

```powershell
$core = Join-Path $env:ProgramData 'drcom4scut\drcom4scut.exe'
$config = Join-Path $env:ProgramData 'drcom4scut\config.yml'
& $core --check-config --config $config
& $core --service-install --config $config
& $core --service-start
& $core --service-status
```

安装使用固定服务名 `drcom4scut`，启动类型为自动启动。程序和配置路径按独立参数传给 SCM；账号、密码不会出现在服务命令行中。已有同名服务会报错，不会被替换。服务失败时由 SCM 在 30 秒后重启；协议级恢复仍由客户端负责，不需要不断重启 GUI。

`--service-status` 返回的是 SCM 的 Running、StartPending 或 Stopped 等状态。**Running 仅表示监督进程已运行，不能证明 EAP、UDP 或互联网连通。** 认证结果应查看配置目录中的 `status.json`；服务日志固定放在该目录的 `logs`，避免 Windows 默认工作目录 System32 中产生文件。日志保留默认滚动策略，账号密码不会作为启动诊断输出。

```powershell
& $core --service-stop
& $core --service-status  # 等待 Stopped 后再卸载
& $core --service-uninstall
```

停止会通知异步客户端退出，尽力发送有时间上限的 EAPOL-Logoff。卸载只删除服务注册，保留程序、配置、状态和日志，方便管理员备份或排查。修改服务配置后先停止服务，完成修改，再重新启动；不要同时运行 GUI 认证和后台服务。

## 验证边界

可移植测试检查固定启动参数、路径与平台分支；Windows 交叉编译检查用于发现 SCM API 类型错误。Windows CI 还运行 `powershell -NoProfile -NonInteractive -File scripts/test-service-acl.ps1`，用原生安全描述符检查 null DACL、所有者、普通/通用权限位、外部密码文件对 Everyone 可读/写的拒绝行为，并用实际 FileInfo/DirectoryInfo 验证祖先遍历；这组策略测试不需要管理员、SCM 或 Npcap。真正的 SCM 安装、权限检查、开机未登录认证、Npcap、睡眠唤醒和断线恢复，仍须在 Windows 目标机器实测；Linux 或 CI 的模拟认证结果不能代替这些验证。
