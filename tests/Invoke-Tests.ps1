<#
.SYNOPSIS
Runs the Pester 3.4.0 unit tests and labels the engine (docs/PLAN.md section 11).

.DESCRIPTION
Imports exactly Pester 3.4.0, runs tests\*.Tests.ps1 (or -Path), excludes the tag
'Integration' by default, prints the engine label and exits with the number of failed tests.

The label is "PS 2.0" only on a real PS 2.0 engine (PSVersion major 2 and CLR major 2).
On Windows 11 24H2+ "powershell.exe -Version 2" silently runs 5.1; that run is labelled
"PS 5.1... (not PS 2.0)".

Written in PS 2.0 syntax so it also runs on a PS 2.0 test host.

.PARAMETER Path
Test files or folders. Default: the tests folder.

.PARAMETER Tag
Only run Describe blocks with these tags (Invoke-Pester -Tag).

.PARAMETER ExcludeTag
Skip Describe blocks with these tags. Default: Integration.

.EXAMPLE
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests\Invoke-Tests.ps1 -Path tests\Principals.Tests.ps1
#>
param(
    [string[]]$Path,
    [string[]]$Tag,
    [string[]]$ExcludeTag = @('Integration')
)

$testsDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Path) { $Path = @($testsDir) }

# --- engine label (PLAN section 11) -----------------------------------------------
$psVersion = $PSVersionTable.PSVersion
$clrMajor = 0
$clrText = 'unknown'
if ($PSVersionTable.CLRVersion) {
    $clrMajor = $PSVersionTable.CLRVersion.Major
    $clrText = $PSVersionTable.CLRVersion.ToString()
}
if (($psVersion.Major -eq 2) -and ($clrMajor -eq 2)) {
    $engineLabel = 'PS 2.0'
} else {
    $engineLabel = 'PS {0} (not PS 2.0)' -f $psVersion.ToString()
}
Write-Host ('Engine: {0}  [PSVersion {1}, CLR {2}, {3}-bit]' -f $engineLabel, $psVersion.ToString(), $clrText, ([IntPtr]::Size * 8))

# --- Pester 3.4.0 -----------------------------------------------------------------
$requiredPester = New-Object System.Version('3.4.0')
try {
    Get-Module -Name Pester | Remove-Module -Force
    if ($psVersion.Major -ge 3) {
        Import-Module Pester -RequiredVersion 3.4.0 -ErrorAction Stop # lint-ignore: Ps2-Parameter
    } else {
        # PS 2.0 has no -RequiredVersion: pick the 3.4.0 module by path.
        $pesterModule = Get-Module -ListAvailable -Name Pester |
            Where-Object { $_.Version -eq $requiredPester } | Select-Object -First 1
        if (-not $pesterModule) { throw 'Pester 3.4.0 is not installed.' }
        Import-Module $pesterModule.Path -ErrorAction Stop
    }
} catch {
    Write-Host ('Cannot load Pester 3.4.0: {0}' -f $_.Exception.Message) -ForegroundColor Red
    exit 1
}

# --- run ----------------------------------------------------------------------------
$pesterArgs = @{ Script = $Path; PassThru = $true }
if ($Tag) { $pesterArgs['Tag'] = $Tag }
if ($ExcludeTag) { $pesterArgs['ExcludeTag'] = $ExcludeTag }

$result = Invoke-Pester @pesterArgs

Write-Host ''
Write-Host ('Engine: {0}  Passed: {1}  Failed: {2}  Skipped: {3}  Pending: {4}' -f $engineLabel,
    $result.PassedCount, $result.FailedCount, $result.SkippedCount, $result.PendingCount)
exit $result.FailedCount
