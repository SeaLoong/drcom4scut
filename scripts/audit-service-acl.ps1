param([switch] $FunctionsOnly)

$ErrorActionPreference = 'Stop'
$script:ServiceTrustedSids = @(
    'S-1-5-18',       # LocalSystem
    'S-1-5-32-544',   # Builtin Administrators
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' # TrustedInstaller
)

function Assert-ServiceSecurityDescriptor {
    param(
        [Security.AccessControl.RawSecurityDescriptor] $Descriptor,
        [int64] $ForbiddenRights
    )
    # An owner can rewrite a DACL through implicit WRITE_DAC, independently of
    # current allow rules. Missing owners and null DACLs are never safe defaults.
    if ($null -eq $Descriptor.Owner -or $script:ServiceTrustedSids -notcontains $Descriptor.Owner.Value) {
        throw 'Untrusted service path owner'
    }
    if (($Descriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) -eq 0 -or
        $null -eq $Descriptor.DiscretionaryAcl) { throw 'Null DACL or absent DACL grants unrestricted access' }
    foreach ($ace in $Descriptor.DiscretionaryAcl) {
        if (($ace.AceFlags -band [Security.AccessControl.AceFlags]::InheritOnly) -ne 0) { continue }
        # Evaluate raw ACEs so native GENERIC_* masks and callback ACEs cannot be
        # silently omitted by FileSystemSecurity.GetAccessRules conversion.
        if ($ace -isnot [Security.AccessControl.QualifiedAce]) { throw 'Unsupported DACL entry' }
        if ($ace.AceQualifier -eq [Security.AccessControl.AceQualifier]::AccessDenied) { continue }
        if ($ace.AceQualifier -ne [Security.AccessControl.AceQualifier]::AccessAllowed) {
            throw 'Unsupported DACL qualifier'
        }
        if ($script:ServiceTrustedSids -notcontains $ace.SecurityIdentifier.Value -and
            (([int64]$ace.AccessMask -band $ForbiddenRights) -ne 0)) {
            throw 'Untrusted service path access rule'
        }
    }
}

function Assert-ServicePath {
    param([string] $Path, [bool] $Secret)
    # Concrete write/delete/change-owner rights plus GENERIC_ALL/GENERIC_WRITE.
    $write = [int64](2 + 4 + 16 + 64 + 256 + 65536 + 262144 + 524288 + 0x10000000 + 0x40000000)
    # An ancestor need not be private, but cannot be replaced or have its DACL
    # rewritten. Creating unrelated siblings does not replace a protected child.
    $replace = [int64](64 + 65536 + 262144 + 524288 + 0x10000000)
    $item = Get-Item -LiteralPath $Path -Force
    $depth = 0
    while ($null -ne $item) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse point in service path' }
        $acl = Get-Acl -LiteralPath $item.FullName
        $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(), 0)
        $mask = if ($depth -le 1) { $write } else { $replace }
        # READ_DATA and GENERIC_READ both expose a plaintext service password.
        if ($depth -eq 0 -and $Secret) { $mask = $mask -bor [int64]1 -bor [int64]2147483648 }
        Assert-ServiceSecurityDescriptor $descriptor $mask
        # DirectoryInfo returned by .Parent/.Directory has no provider-added
        # PSIsContainer note property; use the filesystem attribute at every depth.
        $item = if (($item.Attributes -band [IO.FileAttributes]::Directory) -ne 0) { $item.Parent } else { $item.Directory }
        $depth++
    }
}

if (!$FunctionsOnly) {
    Assert-ServicePath $env:DRCOM_SERVICE_EXE_PATH $false
    Assert-ServicePath $env:DRCOM_SERVICE_CONFIG_PATH $true
    if (![string]::IsNullOrEmpty($env:DRCOM_SERVICE_PASSWORD_PATH)) {
        Assert-ServicePath $env:DRCOM_SERVICE_PASSWORD_PATH $true
    }
}
