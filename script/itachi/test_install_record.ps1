# Native Windows, no Pester/dependencies/service actions. Tests private TEMP files only.
param(
    [Parameter(Mandatory=$true)][string]$CommonPath,
    [ValidateSet('BaselineFailure','CandidatePass')][string]$Expectation='CandidatePass'
)
$ErrorActionPreference='Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Native Windows required' }
$Principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Elevated token required for exact BA+SY ACL test' }
# Dot sourcing declares installer helpers but never invokes its service transaction.
. $CommonPath
$Root=Join-Path ([IO.Path]::GetTempPath()) ('itachi-install-record-test-'+[guid]::NewGuid().ToString('N'))
$RecordPath=Join-Path $Root 'install-record.json'
$Digest='1'*64; $PackageDigest='2'*64; $DefinitionDigest='3'*64
$Checks=0; $SharingHandle=$null; $BaselineError=$null; $BaselineException=$null; $FailureError=$null
function Check([bool]$Condition,[string]$Label) { if (-not $Condition) { throw "Regression assertion failed: $Label" }; $script:Checks++ }
if (Test-Path -LiteralPath $Root) { throw 'Fresh scratch unexpectedly exists' }
New-Item -ItemType Directory -Path $Root | Out-Null
try {
    Set-PrivateAcl $Root
    Assert-PrivateTree $Root
    Add-Type -TypeDefinition 'public static class ItachiNullStringProbe { public static bool IsNull(string value) { return value == null; } }'
    Check (-not [ItachiNullStringProbe]::IsNull($null)) 'PowerShell dollar-null is converted to empty string for string parameter'
    Check ([ItachiNullStringProbe]::IsNull([System.Management.Automation.Language.NullString]::Value)) 'Native NullString sentinel is a real CLR null'
    Write-InstallRecord 'staged'
    $OriginalBytes=[IO.File]::ReadAllBytes($RecordPath)
    $OriginalHash=(Get-FileHash -LiteralPath $RecordPath).Hash
    Check ((Get-Content -LiteralPath $RecordPath -Raw | ConvertFrom-Json).status -eq 'staged') 'first creation is parseable staged receipt'
    Assert-PrivateTree $Root
    try { Write-InstallRecord 'installed' } catch { $BaselineError=$_.Exception.ToString(); $BaselineException=$_.Exception.GetBaseException() }
    if ($Expectation -eq 'BaselineFailure') {
        Check ($null -ne $BaselineError) 'original null backup parameter reproduces failure'
        Check ($BaselineException -is [ArgumentException]) 'failure is the backup-path argument conversion'
        Check ((Get-FileHash -LiteralPath $RecordPath).Hash -eq $OriginalHash) 'failed replacement preserves old receipt bytes'
        Assert-PrivateTree $Root
    } else {
        Check ($null -eq $BaselineError) 'replacement succeeds with CLR null backup'
        $R=Get-Content -LiteralPath $RecordPath -Raw | ConvertFrom-Json
        Check ($R.status -eq 'installed' -and $R.baseline -eq 'absent' -and $R.core_sha256 -eq $Digest) 'replacement is complete owned installed receipt'
        Assert-PrivateTree $Root
        Check (@(Get-ChildItem -LiteralPath $Root -Filter '.record-*' -Force).Count -eq 0) 'successful replace consumes temporary file without backup'
        $BeforeBlocked=(Get-FileHash -LiteralPath $RecordPath).Hash
        # No FILE_SHARE_DELETE: real native replacement must fail, never unlink first.
        $SharingHandle=[IO.File]::Open($RecordPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try { Write-InstallRecord 'absent' } catch { $FailureError=$_.Exception.ToString() }
        $SharingHandle.Dispose();$SharingHandle=$null
        Check ($null -ne $FailureError) 'native sharing violation is propagated'
        Check ((Get-FileHash -LiteralPath $RecordPath).Hash -eq $BeforeBlocked) 'blocked replacement preserves complete old receipt'
        Assert-PrivateTree $Root
        # Only remove task-created private temp after the intentional failed write.
        foreach ($F in Get-ChildItem -LiteralPath $Root -Filter '.record-*' -Force) {
            Check ($F.Name -match '^\.record-[0-9a-f]{32}$' -and -not $F.PSIsContainer) 'failed-write temp belongs to this test'
            Remove-Item -LiteralPath $F.FullName -Force
        }
        Write-InstallRecord 'absent'
        Check ((Get-Content -LiteralPath $RecordPath -Raw | ConvertFrom-Json).status -eq 'absent') 'subsequent owned rollback receipt replacement succeeds'
        Assert-PrivateTree $Root
        $Checks++ # exact protected BA+SY DACL/owner checks ran after every state.
    }
    $Result=[ordered]@{expectation=$Expectation;checks=$Checks;status='PASS';ps_version=$PSVersionTable.PSVersion.ToString();framework=[Runtime.InteropServices.RuntimeInformation]::FrameworkDescription;baseline_error=$BaselineError;sharing_failure_observed=($null -ne $FailureError);service_actions=0;scratch_cleanup='pending'}
} finally {
    if ($SharingHandle) { $SharingHandle.Dispose() }
    # Fresh GUID root, exact private tree; refuse cleanup if any unknown entry appeared.
    Assert-PrivateTree $Root
    foreach ($F in Get-ChildItem -LiteralPath $Root -Force) {
        if ($F.PSIsContainer -or ($F.Name -ne 'install-record.json' -and $F.Name -notmatch '^\.record-[0-9a-f]{32}$')) { throw 'Unknown test scratch entry; preserved' }
        Remove-Item -LiteralPath $F.FullName -Force
    }
    Remove-Item -LiteralPath $Root -Force
}
$Result.scratch_cleanup='removed_exact_owned_files_and_empty_directory'
$Result | ConvertTo-Json -Depth 5
# Keep the existing Windows CI entrypoint covering the live-state rename race.
if ($Expectation -eq 'CandidatePass') {
    & (Join-Path $PSScriptRoot 'test_private_tree_race.ps1') -CommonPath $CommonPath -Expectation CandidatePass
}
