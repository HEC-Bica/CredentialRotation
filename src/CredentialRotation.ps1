#Requires -Version 2.0
<#
.SYNOPSIS
    Credential Rotation tool - M1: read-only audit (docs/PLAN.md).

.DESCRIPTION
    Discovers the local accounts, groups, rights, dependents, auto-logon, write filter and SQL Server state,
    compares them with the configuration and reports what -Apply would change. M1 changes nothing.
    Start it through Start-CredentialRotation.cmd ("Run as administrator").

.PARAMETER Apply
    Not available in this version (M1 is audit only).

.PARAMETER Only
    Slot names to audit, e.g. BiCAAdmin, AutoLogon. Check-mode accounts are only audited without -Only.

.PARAMETER ConfigPath
    The .psd1 configuration. Default: CredentialRotation.psd1 next to this script, or ..\config\ when unbundled.

.PARAMETER LogPath
    Root folder for logs. Default: %ProgramData%\CredentialRotation.
#>
[CmdletBinding()]
param(
    [switch]$Apply,
    [string[]]$Only,
    [string]$ConfigPath,
    [string]$LogPath
)

$ErrorActionPreference = 'Stop'
$script:CrToolVersion = '0.1.0'
$script:CrScriptPath = $MyInvocation.MyCommand.Path
$script:CrScriptDir = Split-Path -Parent $script:CrScriptPath

# <CR-LIB-IMPORT>
foreach ($crLib in @('Compat', 'Log', 'Config', 'Native', 'Accounts', 'Groups', 'Rights', 'Principals',
                     'Services', 'Tasks', 'ComPlus', 'IisReport', 'Sql', 'AutoLogon', 'Preflight', 'Plan')) {
    . (Join-Path $script:CrScriptDir ('lib\' + $crLib + '.ps1'))
}
# </CR-LIB-IMPORT>

# With powershell.exe -File, "-Only A,B" arrives as the single string "A,B".
if ($Only) {
    $Only = @(foreach ($o in $Only) { foreach ($p in ([string]$o -split ',')) { if ($p.Trim()) { $p.Trim() } } })
}

$script:CrExitCodes = @{ Ok = 0; FollowUp = 4; Partial = 1; PreflightFailed = 2; Aborted = 3; Drift = 10 }

function Get-CrFileSha256 {
    param([string]$Path)
    $sha = New-Object System.Security.Cryptography.SHA256CryptoServiceProvider
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $bytes = $sha.ComputeHash($stream)
    } finally {
        $stream.Close()
        $sha.Clear()
    }
    return ([System.BitConverter]::ToString($bytes) -replace '-', '').ToLowerInvariant()
}

function Show-CrFileHashes {
    param([string[]]$Paths)
    Write-Host 'SHA-256 of the tool files (compare with the published release hashes):'
    foreach ($p in $Paths) {
        if (-not $p -or -not (Test-Path -LiteralPath $p)) { continue }
        $h = Get-CrFileSha256 -Path $p
        Write-Host ('  {0}  {1}' -f $h, (Split-Path -Leaf $p))
        Write-CrLog ('SHA-256 {0} {1}' -f $h, $p)
    }
}

function Resolve-CrDefaultConfigPath {
    $local = Join-Path $script:CrScriptDir 'CredentialRotation.psd1'
    if (Test-Path -LiteralPath $local) { return $local }
    return (Join-Path (Split-Path -Parent $script:CrScriptDir) 'config\CredentialRotation.psd1')
}

# Runs one discovery section; a failure is recorded and the run continues.
function Invoke-CrDiscoverySection {
    param($State, [string]$Name, [scriptblock]$Body)
    Write-Host ('Discovering {0} ...' -f $Name)
    try {
        $State[$Name] = & $Body
    } catch {
        $State[$Name] = @{ Error = $_.Exception.Message }
        [void]$State['Errors'].Add(@{ Section = $Name; Message = $_.Exception.Message })
        Write-CrLog ('Discovery of {0} failed: {1}' -f $Name, $_.Exception.Message) 'Warning'
    }
}

function Invoke-CrAudit {
    Write-Host ('Credential Rotation {0} - audit (read-only)' -f $script:CrToolVersion)

    # Runtime requirements (PLAN 3)
    $principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host 'Run this tool elevated ("Run as administrator").'
        $script:CrResult = $script:CrExitCodes['PreflightFailed']; return
    }
    if ([string]$ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
        Write-Host ('PowerShell runs in {0} mode; FullLanguage is required.' -f $ExecutionContext.SessionState.LanguageMode)
        $script:CrResult = $script:CrExitCodes['PreflightFailed']; return
    }
    if ($Apply) {
        Write-Host '-Apply is not available in this version (M1 is audit only). Nothing was changed.'
        $script:CrResult = $script:CrExitCodes['PreflightFailed']; return
    }

    $mutex = New-Object System.Threading.Mutex($false, 'Global\CredentialRotation')
    $owned = $false
    try {
        try { $owned = $mutex.WaitOne(0) } catch { if ($_.Exception.InnerException -is [System.Threading.AbandonedMutexException]) { $owned = $true } else { throw } }
        if (-not $owned) {
            Write-Host 'Another instance of the tool is running.'
            $script:CrResult = $script:CrExitCodes['PreflightFailed']; return
        }

        $runId = (Get-Date).ToString('yyyyMMdd-HHmmss')
        $log = Initialize-CrLog -Root $LogPath -RunId $runId
        Write-Host ('Log: {0}' -f $log['File'])
        if ($log['Corrected']) { Write-Host 'Warning: the log folder had unsafe permissions; they were corrected and an existing journal is ignored.' }

        if (-not $ConfigPath) { $ConfigPath = Resolve-CrDefaultConfigPath }
        Add-Type -AssemblyName System.Core
        $launcher = Join-Path $script:CrScriptDir 'Start-CredentialRotation.cmd'
        Show-CrFileHashes -Paths @($script:CrScriptPath, $launcher, $ConfigPath)

        $config = Import-CrConfig -Path $ConfigPath
        $configErrors = @(Test-CrConfig -Config $config)
        if ($configErrors.Count -gt 0) {
            Write-Host 'The configuration is invalid:'
            foreach ($e in $configErrors) { Write-Host ('  - ' + $e); Write-CrLog ('Config error: ' + $e) 'Error' }
            $script:CrResult = $script:CrExitCodes['PreflightFailed']; return
        }

        Initialize-CrNative
        if (-not (Test-CrNativeReady)) { Write-CrLog ('Native helpers unavailable: ' + $script:CrNativeError) 'Error' }

        $state = @{ Errors = New-Object System.Collections.ArrayList }
        Invoke-CrDiscoverySection $state 'Computer'    { Get-CrComputerInfo -Config $config }
        Invoke-CrDiscoverySection $state 'Policy'      { Get-CrPasswordPolicy }
        Invoke-CrDiscoverySection $state 'WriteFilter' { Get-CrWriteFilterState }
        Invoke-CrDiscoverySection $state 'Users'       { Get-CrLocalUsers }
        Invoke-CrDiscoverySection $state 'Groups'      { Get-CrLocalGroups }
        Invoke-CrDiscoverySection $state 'Rights'      { Get-CrLsaRightsMap }
        Invoke-CrDiscoverySection $state 'Services'    { Get-CrServices }
        Invoke-CrDiscoverySection $state 'Tasks'       { Get-CrScheduledTasks }
        Invoke-CrDiscoverySection $state 'ComPlus'     { Get-CrComPlusApplications }
        Invoke-CrDiscoverySection $state 'Dcom'        { Get-CrDcomRunAs }
        Invoke-CrDiscoverySection $state 'Iis'         { Get-CrIisIdentities }
        Invoke-CrDiscoverySection $state 'Sql'         { Get-CrSqlState }
        Invoke-CrDiscoverySection $state 'AutoLogon'   { Get-CrAutoLogonState }

        # Without users, groups and rights no account can be judged.
        foreach ($critical in @('Users', 'Groups', 'Rights', 'Computer')) {
            if ($state[$critical] -is [hashtable] -and $state[$critical]['Error']) {
                Write-Host ('Discovery of {0} failed: {1}' -f $critical, $state[$critical]['Error'])
                $script:CrResult = $script:CrExitCodes['PreflightFailed']; return
            }
        }

        $preflight = Invoke-CrPreflight -State $state -Config $config
        $resolved = Resolve-CrAccounts -Config $config -State $state
        $plan = New-CrPlan -State $state -Config $config -Resolved $resolved -Preflight $preflight -Only $Only

        Write-CrFindingsReport -Findings $plan['Findings']
        $csv = Join-Path $log['Directory'] ('CredentialRotation_{0}_{1}.csv' -f $env:COMPUTERNAME, $runId)
        Export-CrFindingsCsv -Findings $plan['Findings'] -Path $csv
        foreach ($f in (ConvertTo-CrArray $plan['Findings'])) {
            Write-CrLog ('{0} | {1} | {2} | {3} | {4}' -f $f['Severity'], $f['Area'], $f['Slot'], $f['Account'], $f['Message'])
        }

        Write-Host ''
        $exit = $script:CrExitCodes['Ok']
        if ($preflight['MachineBlocked']) {
            Write-Host 'Result: preflight failed; -Apply would be blocked on this machine.'
            $exit = $script:CrExitCodes['PreflightFailed']
        } elseif ($plan['Drift']) {
            Write-Host 'Result: drift found; -Apply would change the items listed under "Drift".'
            $exit = $script:CrExitCodes['Drift']
        } else {
            Write-Host 'Result: no drift.'
        }
        Write-Host ('Report: {0}' -f $csv)
        Write-CrLog ('Audit finished with exit code {0}' -f $exit)
        $script:CrResult = $exit
    } finally {
        if ($owned) { $mutex.ReleaseMutex() }
        $mutex.Close()
    }
}

$script:CrResult = $script:CrExitCodes['Aborted']
try {
    [void](Invoke-CrAudit)
} catch {
    Write-Host ('Aborted: {0}' -f $_.Exception.Message)
    try { Write-CrLog ('Aborted: ' + $_.Exception.Message + ' at ' + $_.InvocationInfo.PositionMessage) 'Error' } catch { }
    $script:CrResult = $script:CrExitCodes['Aborted']
}
exit $script:CrResult
