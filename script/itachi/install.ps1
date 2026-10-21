#Requires -RunAsAdministrator
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
function Test-Package([string]$Directory) {
    $Required=@('easytier-core.exe','easytier-cli.exe','install.ps1','uninstall.ps1','rollback.ps1','installer-common.ps1','LICENSE','README.txt','wintun.dll','DRIVER-PROVENANCE.json','WINTUN-LICENSE.txt')
    foreach ($Name in @('SHA256SUMS','MANIFEST.json')+$Required) { $I=Get-Item -LiteralPath (Join-Path $Directory $Name) -Force; if ($I.PSIsContainer -or (($I.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'Unsafe package member' } }
    $M=Get-Content -LiteralPath (Join-Path $Directory 'MANIFEST.json') -Raw | ConvertFrom-Json
    $Declared=@($M.files.PSObject.Properties)
    if ($Declared.Count -ne $Required.Count) { throw 'Incomplete manifest' }
    $Sums=@{}
    foreach ($Line in Get-Content -LiteralPath (Join-Path $Directory 'SHA256SUMS')) {
        if ($Line -cnotmatch '^([0-9a-f]{64})  ([A-Za-z0-9_.-]+)$') { throw 'Invalid SHA256SUMS' }
        $Hash=$Matches[1];$Name=$Matches[2]
        if ($Sums.ContainsKey($Name) -or ($Name -cne 'MANIFEST.json' -and $Required -cnotcontains $Name)) { throw 'Unknown/duplicate checksum member' }
        $Sums[$Name]=$Hash
        if ((Get-FileHash -LiteralPath (Join-Path $Directory $Name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Hash) { throw "Package checksum failure: $Name" }
    }
    if ($Sums.Count -ne ($Required.Count+1) -or -not $Sums.ContainsKey('MANIFEST.json')) { throw 'Incomplete checksums' }
    foreach ($P in $Declared) {
        if ($Required -cnotcontains $P.Name -or $P.Value.sha256 -cne $Sums[$P.Name] -or $P.Value.bytes -ne (Get-Item -LiteralPath (Join-Path $Directory $P.Name)).Length) { throw 'Manifest/checksum/size disagreement' }
    }
    $script:PackageFiles=@('SHA256SUMS','MANIFEST.json')+$Required
}
Test-Package $PSScriptRoot
$Stage=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) ('EasyTierItachi-stage-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Stage -ErrorAction Stop | Out-Null
try {
    # Program Files is protected against unprivileged replacement. Set a fresh exact DACL before copying.
    $Dacl=New-Object Security.AccessControl.DirectorySecurity
    $Dacl.SetAccessRuleProtection($true,$false)
    $Dacl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    foreach ($Sid in @('S-1-5-18','S-1-5-32-544')) { $Dacl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($Sid)),[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))) }
    Set-Acl -LiteralPath $Stage -AclObject $Dacl
    foreach ($Name in $PackageFiles) { Copy-Item -LiteralPath (Join-Path $PSScriptRoot $Name) -Destination (Join-Path $Stage $Name) }
    Test-Package $Stage
    . (Join-Path $Stage 'installer-common.ps1')
    Invoke-ItachiOperation 'install'
} finally {
    # Only fixed package members inside our fresh private stage; never recursive deletion.
    foreach ($Name in $PackageFiles) { $P=Join-Path $Stage $Name; if (Test-Path -LiteralPath $P) { Remove-Item -LiteralPath $P -Force } }
    Remove-Item -LiteralPath $Stage
}
