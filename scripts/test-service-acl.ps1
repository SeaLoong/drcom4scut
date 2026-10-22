# Native Windows PowerShell regression tests. No SCM, Npcap, elevation or mutation
# of system ACLs: raw descriptors are synthetic; directory traversal is real.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'audit-service-acl.ps1') -FunctionsOnly
$script:Assertions = 0
function Expect-Rejection([scriptblock] $Action, [string] $Name, [string] $Reason) {
    $rejected = $false
    try { & $Action } catch {
        if ($_.Exception.Message -notlike "*$Reason*") { throw "Unexpected failure for ${Name}: $($_.Exception.Message)" }
        $rejected = $true
    }
    if (!$rejected) { throw "Expected rejection: $Name" }
    $script:Assertions++
}
function Descriptor([string] $Sddl) {
    return [Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
}
$write = [int64](2 + 4 + 16 + 64 + 256 + 65536 + 262144 + 524288 + 0x10000000 + 0x40000000)
$readWrite = $write -bor [int64]1 -bor [int64]2147483648
$safe = Descriptor 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'
Assert-ServiceSecurityDescriptor $safe $readWrite
$script:Assertions++
$nullDacl = Descriptor 'O:BAG:BAD:NO_ACCESS_CONTROL'
if ($null -ne $nullDacl.DiscretionaryAcl) { throw 'Invalid null-DACL fixture' }
Expect-Rejection { Assert-ServiceSecurityDescriptor $nullDacl $readWrite } 'null DACL' 'Null DACL'
$untrustedOwner = Descriptor 'O:S-1-5-21-1-2-3-1000G:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'
if ($untrustedOwner.Owner.Value -ne 'S-1-5-21-1-2-3-1000') { throw 'Invalid owner fixture' }
Expect-Rejection { Assert-ServiceSecurityDescriptor $untrustedOwner $write } 'untrusted owner with otherwise safe rules' 'Untrusted service path owner'
$emptyDacl = Descriptor 'O:BAG:BAD:'
if ($null -eq $emptyDacl.DiscretionaryAcl -or $emptyDacl.DiscretionaryAcl.Count -ne 0) { throw 'Invalid empty-DACL fixture' }
Assert-ServiceSecurityDescriptor $emptyDacl $readWrite # empty DACL denies all
$script:Assertions++
foreach ($rights in @('FR', 'GR', 'FA', 'GA', 'FW', 'GW')) {
    $descriptor = Descriptor "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;$rights;;;WD)"
    Expect-Rejection { Assert-ServiceSecurityDescriptor $descriptor $readWrite } "untrusted $rights on config" 'Untrusted service path access rule'
}
$readableBinary = Descriptor 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)'
Assert-ServiceSecurityDescriptor $readableBinary $write
$script:Assertions++
$denyAndAllow = Descriptor 'O:BAG:BAD:P(D;;FR;;;WD)(A;;FR;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)'
Expect-Rejection { Assert-ServiceSecurityDescriptor $denyAndAllow $readWrite } 'deny does not relax an unsafe allow' 'Untrusted service path access rule'

# Use native FileInfo/DirectoryInfo ancestors but mocked security descriptors.
# This catches accidental reliance on PSIsContainer after the initial Get-Item.
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('drcom4scut-service-acl-' + [Guid]::NewGuid().ToString('N'))
$leaf = Join-Path $temporary 'parent\private\config.yml'
$null = New-Item -ItemType Directory -Path (Split-Path $leaf) -Force
[IO.File]::WriteAllText($leaf, 'synthetic test data')
$script:Visited = [Collections.Generic.List[string]]::new()
$script:UnsafeAncestor = $null
$script:PublicPasswordFile = $null
$script:WritablePasswordFile = $null
function Get-Acl {
    param([string] $LiteralPath)
    $script:Visited.Add($LiteralPath)
    $sddl = if ($LiteralPath -eq $script:UnsafeAncestor) {
        'O:S-1-5-21-1-2-3-1000G:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'
    } elseif ($LiteralPath -eq $script:PublicPasswordFile) {
        'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;WD)'
    } elseif ($LiteralPath -eq $script:WritablePasswordFile) {
        'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FW;;;WD)'
    } else { 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)' }
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetSecurityDescriptorSddlForm($sddl)
    return $acl
}
try {
    Assert-ServicePath $leaf $true
    $expected = 0
    $item = [IO.FileInfo]::new($leaf)
    while ($null -ne $item) {
        $expected++
        $item = if ($item -is [IO.DirectoryInfo]) { $item.Parent } else { $item.Directory }
    }
    if ($script:Visited.Count -ne $expected) { throw 'ACL walk did not reach the drive root' }
    $script:Assertions++
    $script:UnsafeAncestor = [IO.DirectoryInfo]::new((Split-Path $leaf)).Parent.FullName
    Expect-Rejection { Assert-ServicePath $leaf $true } 'untrusted owner above immediate parent' 'Untrusted service path owner'
    $script:UnsafeAncestor = $null

    # A protected main config is insufficient when it delegates its password to
    # another file. Exercise the production entry point with each unsafe source.
    $publicDirectory = Join-Path $temporary 'public'
    $null = New-Item -ItemType Directory -Path $publicDirectory -Force
    $script:PublicPasswordFile = Join-Path $publicDirectory 'readable.key'
    $script:WritablePasswordFile = Join-Path $publicDirectory 'writable.key'
    [IO.File]::WriteAllText($script:PublicPasswordFile, 'synthetic test data')
    [IO.File]::WriteAllText($script:WritablePasswordFile, 'synthetic test data')
    $env:DRCOM_SERVICE_EXE_PATH = $leaf
    $env:DRCOM_SERVICE_CONFIG_PATH = $leaf
    foreach ($credentialFile in @($script:PublicPasswordFile, $script:WritablePasswordFile)) {
        $env:DRCOM_SERVICE_PASSWORD_PATH = $credentialFile
        Expect-Rejection { . (Join-Path $PSScriptRoot 'audit-service-acl.ps1') } 'untrusted external password source' 'Untrusted service path access rule'
    }
} finally {
    Remove-Item -LiteralPath $temporary -Recurse -Force
}
Write-Output "$script:Assertions Windows service ACL policy checks passed"
