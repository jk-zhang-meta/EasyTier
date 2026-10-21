# Only dot-sourced from a complete hash-verified private staging copy.
$ErrorActionPreference = 'Stop'
$Origin = 'https://www.itachi.fans'
$Root = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'EasyTierItachi'
$State = Join-Path $Root 'state'
$ServiceName = 'EasyTierItachi'
$RecordPath = Join-Path $Root 'install-record.json'
$DefinitionPath = Join-Path $Root 'service-definition.txt'
$AllowedSids = @('S-1-5-18','S-1-5-32-544')
function Assert-NoReparse([string]$Path) {
    $Current = [IO.Path]::GetFullPath($Path)
    while ($Current) {
        if (Test-Path -LiteralPath $Current) { if (((Get-Item -LiteralPath $Current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Reparse path refused: $Current" } }
        $Parent = Split-Path -Parent $Current
        if ($Parent -eq $Current) { break }; $Current = $Parent
    }
}
function Set-PrivateAcl([string]$Path) {
    $Item = Get-Item -LiteralPath $Path -Force
    if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse point refused' }
    if ($Item.PSIsContainer) { $Acl = New-Object Security.AccessControl.DirectorySecurity; $Inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit' }
    else { $Acl = New-Object Security.AccessControl.FileSecurity; $Inheritance = [Security.AccessControl.InheritanceFlags]::None }
    $Acl.SetAccessRuleProtection($true,$false)
    $Acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    foreach ($Sid in $AllowedSids) { $Rule = New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($Sid)),[Security.AccessControl.FileSystemRights]::FullControl,$Inheritance,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow); $Acl.AddAccessRule($Rule) }
    Set-Acl -LiteralPath $Path -AclObject $Acl
}
function Assert-PrivateTree([string]$Path) {
    Assert-NoReparse $Path
    $Queue = New-Object 'Collections.Generic.Queue[string]'; $Queue.Enqueue($Path); $Count = 0
    while ($Queue.Count -gt 0) {
        $P = $Queue.Dequeue(); $Count++; if ($Count -gt 512) { throw 'Private tree inspection cap exceeded' }
        $I = Get-Item -LiteralPath $P -Force
        if (($I.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse point in private installation' }
        $Acl = Get-Acl -LiteralPath $P
        if ($AllowedSids -notcontains $Acl.GetOwner([Security.Principal.SecurityIdentifier]).Value) { throw "Unexpected private path owner: $P" }
        if ($P -eq $Path -and -not $Acl.AreAccessRulesProtected) { throw 'Private root inherits foreign access' }
        $Rules = @($Acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
        if ($Rules.Count -ne 2) { throw "Unexpected private access entries: $P" }
        foreach ($Rule in $Rules) { if ($AllowedSids -notcontains $Rule.IdentityReference.Value -or $Rule.AccessControlType -ne 'Allow' -or $Rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl) { throw "Unsafe private access: $P" } }
        if ($I.PSIsContainer) { foreach ($Child in Get-ChildItem -LiteralPath $P -Force) { $Queue.Enqueue($Child.FullName) } }
    }
}
function Write-InstallRecord([string]$Status) {
    $Record = [ordered]@{format=1;platform='windows';core_sha256=$Digest;package_sha256=$PackageDigest;service_sha256=$DefinitionDigest;origin=$Origin;baseline='absent';status=$Status}
    $Tmp = Join-Path $Root ('.record-' + [guid]::NewGuid().ToString('N'))
    [IO.File]::WriteAllText($Tmp,($Record | ConvertTo-Json),[Text.UTF8Encoding]::new($false)); Set-PrivateAcl $Tmp
    if (Test-Path -LiteralPath $RecordPath) { [IO.File]::Replace($Tmp,$RecordPath,$null) } else { [IO.File]::Move($Tmp,$RecordPath) }
}
function Get-OwnedCommand([string]$Hash) {
    if ($Hash -cnotmatch '^[0-9a-f]{64}$') { throw 'Invalid owned version hash' }
    $Version = Join-Path $Root ('versions\' + $Hash)
    return '"' + $Version + '\easytier-core.exe" --daemon --managed-origin "' + $Origin + '" --managed-state "' + $State + '" --rpc-portal 127.0.0.1:57212'
}
function Assert-LiveService {
    $Service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    if (-not $Service -or $Service.PathName -cne (Get-OwnedCommand $Digest) -or $Service.StartName -ne 'LocalSystem') { throw 'Live service identity changed; refusing to touch it' }
    if ((Get-FileHash -LiteralPath $DefinitionPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $DefinitionDigest -or [IO.File]::ReadAllText($DefinitionPath) -cne $Service.PathName) { throw 'Protected service definition receipt mismatch' }
    return $Service
}
function Read-OwnedRecord {
    Assert-PrivateTree $Root
    if (-not (Test-Path -LiteralPath $RecordPath -PathType Leaf)) { throw 'No protected installation record' }
    $R = Get-Content -LiteralPath $RecordPath -Raw | ConvertFrom-Json
    if ($R.format -ne 1 -or $R.platform -ne 'windows' -or $R.origin -cne $Origin -or $R.baseline -ne 'absent' -or $R.status -notin @('installed','absent','staged')) { throw 'Unsupported ownership record' }
    foreach ($Hash in @($R.core_sha256,$R.package_sha256,$R.service_sha256)) { if ($Hash -cnotmatch '^[0-9a-f]{64}$') { throw 'Invalid receipt hash' } }
    $script:Digest=$R.core_sha256; $script:PackageDigest=$R.package_sha256; $script:DefinitionDigest=$R.service_sha256
    $script:Version=Join-Path $Root ('versions\' + $Digest)
    if ($R.status -eq 'staged' -and -not (Test-Path -LiteralPath $Version)) { return $R }
    if ((Get-FileHash -LiteralPath "$Version\easytier-core.exe").Hash.ToLowerInvariant() -cne $Digest -or (Get-FileHash -LiteralPath "$Version\MANIFEST.json").Hash.ToLowerInvariant() -cne $PackageDigest) { throw 'Installed package mismatch' }
    Test-Package $Version
    if ($R.status -ne 'staged' -and ((Get-FileHash -LiteralPath $DefinitionPath).Hash.ToLowerInvariant() -cne $DefinitionDigest -or [IO.File]::ReadAllText($DefinitionPath) -cne (Get-OwnedCommand $Digest))) { throw 'Invalid protected command' }
    return $R
}
function Remove-OwnedService {
    $null=Assert-LiveService
    $S=Get-Service -Name $ServiceName
    if ($S.Status -ne 'Stopped') { Stop-Service -Name $ServiceName }
    $null=Assert-LiveService
    & sc.exe delete $ServiceName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Owned service deletion failed' }
    Write-InstallRecord 'absent'
}
function Invoke-ItachiOperation([string]$Operation) {
    $Mutex = New-Object Threading.Mutex($false,'Global\EasyTierItachiInstallerV1'); $Locked=$false; $CreatedService=$false
    try {
        try { $Locked=$Mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $Locked=$true }
        if (-not $Locked) { throw 'Another installer operation is in progress' }
        Assert-NoReparse $Root; Assert-NoReparse $State
        if ($Operation -eq 'install') {
            $IncomingDigest=(Get-FileHash -LiteralPath "$Stage\easytier-core.exe").Hash.ToLowerInvariant()
            $IncomingPackage=(Get-FileHash -LiteralPath "$Stage\MANIFEST.json").Hash.ToLowerInvariant()
            if (Test-Path -LiteralPath $Root) {
                $R=Read-OwnedRecord
                if ($IncomingDigest -cne $Digest -or $IncomingPackage -cne $PackageDigest) { throw 'Only fresh installation / exact same-package reinstall supported; upgrades need a reviewed migration' }
                if ($R.status -eq 'installed') { $null=Assert-LiveService; if ((Get-Service $ServiceName).Status -ne 'Running') { throw 'Owned service is not running; left unchanged' }; Write-Output 'Exact owned package already installed; no changes'; return }
            } else {
                if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) { throw 'Existing unowned service' }
                New-Item -ItemType Directory -Path $Root -ErrorAction Stop | Out-Null; Set-PrivateAcl $Root
                $script:Digest=$IncomingDigest; $script:PackageDigest=$IncomingPackage
                $script:Version=Join-Path $Root ('versions\' + $Digest)
                $script:DefinitionDigest='0'*64
                # Persist ownership/absent baseline before any child creation.
                Write-InstallRecord 'staged'
            }
            foreach ($Directory in @("$Root\versions",$State)) { if (-not (Test-Path -LiteralPath $Directory)) { New-Item -ItemType Directory -Path $Directory -ErrorAction Stop | Out-Null; Set-PrivateAcl $Directory } }
            if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) { throw 'Expected absent baseline, but a service exists' }
            if (-not (Test-Path -LiteralPath $Version)) {
                $VersionStage=Join-Path "$Root\versions" ('.stage-' + [guid]::NewGuid().ToString('N'))
                New-Item -ItemType Directory -Path $VersionStage | Out-Null; Set-PrivateAcl $VersionStage
                foreach ($Name in $PackageFiles) { Copy-Item -LiteralPath (Join-Path $Stage $Name) -Destination (Join-Path $VersionStage $Name); Set-PrivateAcl (Join-Path $VersionStage $Name) }
                Test-Package $VersionStage; [IO.Directory]::Move($VersionStage,$Version)
            }
            # Initialize/print public identity before the service can hold identity.lock.
            & "$Version\easytier-core.exe" --managed-state $State --managed-status
            if ($LASTEXITCODE -ne 0) { throw 'Could not initialize public device identity' }
            Assert-PrivateTree $Root
            $Command=Get-OwnedCommand $Digest
            [IO.File]::WriteAllText($DefinitionPath,$Command,[Text.UTF8Encoding]::new($false)); Set-PrivateAcl $DefinitionPath
            $script:DefinitionDigest=(Get-FileHash -LiteralPath $DefinitionPath).Hash.ToLowerInvariant()
            New-Service -Name $ServiceName -DisplayName 'EasyTier Itachi managed network' -BinaryPathName $Command -StartupType Automatic | Out-Null
            $CreatedService=$true; Write-InstallRecord 'installed'; $null=Assert-LiveService
            & sc.exe failure $ServiceName 'reset=' '86400' 'actions=' 'restart/5000/restart/15000' | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Could not configure owned service recovery' }
            Start-Service -Name $ServiceName
            (Get-Service $ServiceName).WaitForStatus('Running',[TimeSpan]::FromSeconds(20))
            Assert-PrivateTree $Root
            $CreatedService=$false
            Write-Output 'Installed background/startup service, pending approval at https://www.itachi.fans.'
            Write-Output "Rollback/uninstall: run $Version\rollback.ps1 elevated. Baseline is no service; identity retained."
        } else {
            $R=Read-OwnedRecord
            if ($R.status -in @('absent','staged')) { if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) { throw 'Unexpected live service; left untouched' }; Write-Output 'Original absent-service baseline already restored'; return }
            Remove-OwnedService
            Write-Output 'Restored original baseline: no EasyTier Itachi service. Identity and verified package retained.'
        }
    } catch {
        $Original=$_
        if ($CreatedService) { try { Remove-OwnedService } catch { Write-Warning 'Could not verify/remove owned service; left it untouched for operator recovery' } }
        throw $Original
    } finally { if ($Locked) { $Mutex.ReleaseMutex() }; $Mutex.Dispose() }
}
