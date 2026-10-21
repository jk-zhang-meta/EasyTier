# Native deterministic enumeration/rename regression. No service or production paths.
param(
    [Parameter(Mandatory=$true)][string]$CommonPath,
    [ValidateSet('BaselineFailure','CandidatePass')][string]$Expectation='CandidatePass'
)
$ErrorActionPreference='Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Native Windows required' }
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Elevated token required for exact private ACL fixture' }
. $CommonPath
$Scratch=Join-Path ([IO.Path]::GetTempPath()) ('itachi-private-tree-race-'+[guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $Scratch) { throw 'Fresh scratch conflict' }
$null=New-Item -ItemType Directory -Path $Scratch;Set-PrivateAcl $Scratch
$Checks=0;$Results=@();$RaceFrom=$null;$RaceTo=$null;$RacePoint='item';$RaceAction=$null;$RaceFired=0
# Test-only command adapters: execute a real rename/delete immediately before
# invoking the real native cmdlet. No production test hook or parameter exists.
function Get-Item {
    [CmdletBinding()]param([string]$LiteralPath,[switch]$Force)
    if ($script:RacePoint -eq 'item' -and $script:RaceFired -eq 0 -and $LiteralPath -eq $script:RaceFrom) {
        $script:RaceFired=1;& $script:RaceAction
    }
    Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath -Force:$Force -ErrorAction Stop
}
function Get-Acl {
    [CmdletBinding()]param([string]$LiteralPath)
    if ($script:RacePoint -eq 'acl' -and $script:RaceFired -eq 0 -and $LiteralPath -eq $script:RaceFrom) {
        $script:RaceFired=1;& $script:RaceAction
    }
    Microsoft.PowerShell.Security\Get-Acl -LiteralPath $LiteralPath -ErrorAction Stop
}
function Check([bool]$OK,[string]$Label) { if (-not $OK) { throw "Fixture assertion failed: $Label" };$script:Checks++ }
function New-Fixture([string]$Name,[string]$Leaf='authority.11111111-2222-4333-8444-555555555555.tmp',[bool]$OutsideState=$false) {
    $script:RaceFrom=$null;$script:RacePoint='disabled'
    $script:Root=Join-Path $Scratch $Name;$script:State=Join-Path $Root 'state'
    $null=New-Item -ItemType Directory -Path $Root;Set-PrivateAcl $Root
    $null=New-Item -ItemType Directory -Path $State;Set-PrivateAcl $State
    $Parent=$State
    if ($OutsideState) { $Parent=Join-Path $Root 'other';$null=New-Item -ItemType Directory -Path $Parent;Set-PrivateAcl $Parent }
    $NewFile=Join-Path $Parent $Leaf
    [IO.File]::WriteAllText($NewFile,'fixture');Set-PrivateAcl $NewFile
    $script:RaceFrom=$NewFile
    $script:RaceTo=Join-Path $Parent 'authority.json'
    $script:RacePoint='item';$script:RaceFired=0
    $script:RaceAction={ [IO.File]::Move($script:RaceFrom,$script:RaceTo) }
}
function Run-Check([string]$Name,[bool]$ShouldPass,[bool]$MustFire=$true) {
    $ErrorText=$null
    try { Assert-PrivateTree $Root } catch { $ErrorText=$_.Exception.ToString() }
    Check (($null -eq $ErrorText) -eq $ShouldPass) $Name
    if ($MustFire) { Check ($RaceFired -eq 1) ($Name+': actual after-enumeration boundary fired') }
    $script:Results+=@{test=$Name;passed=$true;accepted=$ShouldPass;actual_rename_hook_fired=($RaceFired -eq 1);failure=$ErrorText}
}
try {
    New-Fixture 'native-item-rename'
    Run-Check 'actual Get-Item enumerate then native rename' ($Expectation -eq 'CandidatePass')
    if ($Expectation -eq 'CandidatePass') {
        New-Fixture 'native-acl-rename';$RacePoint='acl'
        Run-Check 'actual Get-Acl entry exists then native rename' $true
        foreach ($Base in @('identity','public-identity','watermark','status','directory')) {
            New-Fixture ('native-'+$Base) ($Base+'.11111111-2222-4333-8444-555555555555.tmp')
            $RaceTo=Join-Path $State ($Base+'.json')
            Run-Check ('exact native basename '+$Base) $true
        }
        New-Fixture 'stable-missing' 'authority.json';$RaceTo=Join-Path $State 'moved.bin'
        Run-Check 'vanished stable name must fail' $false
        New-Fixture 'unknown-basename' 'unknown.11111111-2222-4333-8444-555555555555.tmp'
        Run-Check 'unknown basename must fail' $false
        New-Fixture 'non-v4-uuid' 'authority.11111111-2222-3333-8444-555555555555.tmp'
        Run-Check 'non-v4 temporary must fail' $false
        New-Fixture 'outside-state' 'authority.11111111-2222-4333-8444-555555555555.tmp' $true
        Run-Check 'same native name outside exact State must fail' $false
        New-Fixture 'access-denied';$RaceAction={ throw [UnauthorizedAccessException]::new('injected access denied; no disappearance') }
        Run-Check 'access denied must fail' $false
        New-Fixture 'missing-without-stable';$RaceAction={ [IO.File]::Delete($script:RaceFrom) }
        Run-Check 'vanished temp without protected stable JSON must fail' $false
        New-Fixture 'unsafe-parent-after-enumeration'
        $RaceAction={
            [IO.File]::Move($script:RaceFrom,$script:RaceTo)
            $A=Microsoft.PowerShell.Security\Get-Acl -LiteralPath $script:State
            $A.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-1-0')),'Read','ContainerInherit,ObjectInherit','None','Allow')))
            Set-Acl -LiteralPath $script:State -AclObject $A
        }
        Run-Check 'parent ACL changed at boundary must fail' $false
        Set-PrivateAcl $State
        New-Fixture 'vanished-native-looking-directory'
        $Original=$RaceFrom;$RaceFrom=$null
        Remove-Item -LiteralPath $Original -Force
        $null=New-Item -ItemType Directory -Path $Original;Set-PrivateAcl $Original
        $RaceFrom=$Original;$RaceAction={ [IO.Directory]::Move($script:RaceFrom,$script:RaceTo) }
        Run-Check 'vanished native-looking directory must fail' $false
        New-Fixture 'unsafe-owner';$Original=$RaceFrom;$RaceFrom=$null
        $A=Microsoft.PowerShell.Security\Get-Acl -LiteralPath $Original
        $A.SetOwner([Security.Principal.WindowsIdentity]::GetCurrent().User)
        Set-Acl -LiteralPath $Original -AclObject $A
        Run-Check 'present wrong-owner temp must fail' $false $false
        Set-PrivateAcl $Original
        New-Fixture 'unsafe-present-temp';$RaceFrom=$null
        $F=Join-Path $State 'authority.11111111-2222-4333-8444-555555555555.tmp'
        $A=Microsoft.PowerShell.Security\Get-Acl -LiteralPath $F
        $A.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-1-0')),'Read','Allow')))
        Set-Acl -LiteralPath $F -AclObject $A
        Run-Check 'present unsafe native-looking temp must fail' $false $false
        Set-PrivateAcl $F
        New-Fixture 'present-reparse-temp';$Original=$RaceFrom;$RaceFrom=$null
        Remove-Item -LiteralPath $Original -Force
        $Target=Join-Path $Root 'safe-target';[IO.File]::WriteAllText($Target,'preserve');Set-PrivateAcl $Target
        $null=New-Item -ItemType SymbolicLink -Path $Original -Target $Target
        Run-Check 'present native-looking reparse temp must fail' $false $false
        Remove-Item -LiteralPath $Original -Force
        Check ([IO.File]::ReadAllText($Target) -eq 'preserve') 'reparse target unchanged'
    }
    $Out=[ordered]@{expectation=$Expectation;status='PASS';checks=$Checks;results=$Results;ps_version=$PSVersionTable.PSVersion.ToString();service_actions=0;scratch_cleanup='pending'}
} finally {
    $RaceFrom=$null;$RaceAction=$null
    # Every fixture is new and task-owned; restore strict ACLs before bounded cleanup.
    foreach ($Dir in Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $Scratch -Directory) {
        foreach ($P in Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $Dir.FullName -Recurse -Force) {
            if (($P.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Unexpected fixture reparse retained for inspection' }
        }
        Assert-PrivateTree $Dir.FullName
        Remove-Item -LiteralPath $Dir.FullName -Recurse -Force
    }
    Remove-Item -LiteralPath $Scratch -Force
}
$Out.scratch_cleanup='removed_exact_owned_fixture_tree'
$Out | ConvertTo-Json -Depth 8
