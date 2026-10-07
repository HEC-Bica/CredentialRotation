#Requires -Version 2.0
<#
.SYNOPSIS
    Credential Rotation tool - audit (default) and -Apply (docs/PLAN.md).

.DESCRIPTION
    Discovers the local accounts, groups, rights, dependents, auto-logon, write filter and SQL Server state,
    compares them with the configuration and reports what -Apply would change (audit, changes nothing).
    With -Apply (account model v10, PLAN D21-D25) it lists the enabled local accounts and what happens to each,
    asks about the other enabled accounts, prompts for the passwords per credential slot, probes ApplicationUser's old
    password, shows the plan and, after YES, creates the missing managed accounts (SOP-Admin, ApplicationUser,
    PUB-User), sets their passwords (ApplicationUser: changed), enforces groups and flags, updates and moves the
    dependents, runs the auto-logon step, disables the replaced and chosen accounts, runs the check-mode fixes and
    disables the running account last (PLAN sections 6 and 8). SQL rotation is not part of this version.
    Start it through Start-CredentialRotation.cmd ("Run as administrator").

.PARAMETER Apply
    Apply the changes after the audit; asks for the passwords and a final YES. Secrets are only ever typed at
    the prompts, never on the command line (D4).

.PARAMETER Only
    Slot names to audit or apply, e.g. SOPAdmin, AppUser, PubUser. Check-mode accounts, retired accounts and other
    enabled accounts are only processed without -Only.

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
    [string]$LogPath,
    # Collects stray words (e.g. "echo %ERRORLEVEL%" typed on the same line). Because this is the only
    # parameter with a Position, the others can only be given by name.
    [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
    [string[]]$UnexpectedArguments
)

if ($UnexpectedArguments) {
    Write-Host ('Unexpected arguments: {0}' -f ($UnexpectedArguments -join ' '))
    Write-Host 'Parameters must be named, e.g. -Only SOPAdmin. Run "echo %ERRORLEVEL%" as a separate command.'
    exit 2
}

$ErrorActionPreference = 'Stop'
$script:CrToolVersion = '0.3.0'
$script:CrScriptPath = $MyInvocation.MyCommand.Path
$script:CrScriptDir = Split-Path -Parent $script:CrScriptPath

# <CR-LIB-IMPORT>
foreach ($crLib in @('Compat', 'Log', 'Config', 'Native', 'Adapters', 'Journal', 'Secrets', 'Accounts', 'Groups',
                     'Rights', 'Principals', 'Services', 'Tasks', 'ComPlus', 'IisReport', 'Sql', 'AutoLogon',
                     'Preflight', 'Plan', 'Apply')) {
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

# Discovery of the machine state (CONTRACTS "The machine state"); also used for the re-audit after -Apply.
function Get-CrMachineState {
    param($Config)
    $state = @{ Errors = New-Object System.Collections.ArrayList }
    Invoke-CrDiscoverySection $state 'Computer'    { Get-CrComputerInfo -Config $Config }
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
    return $state
}

# Message for the first critical discovery section that failed, or $null.
# Without users, groups and rights no account can be judged.
function Get-CrCriticalDiscoveryError {
    param($State)
    foreach ($critical in @('Users', 'Groups', 'Rights', 'Computer')) {
        if ($State[$critical] -is [hashtable] -and $State[$critical]['Error']) {
            return ('Discovery of {0} failed: {1}' -f $critical, $State[$critical]['Error'])
        }
    }
    return $null
}

function Invoke-CrMain {
    $mode = 'audit (read-only)'
    if ($Apply) { $mode = 'apply' }
    Write-Host ('Credential Rotation {0} - {1}' -f $script:CrToolVersion, $mode)

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

        $state = Get-CrMachineState -Config $config
        $criticalError = Get-CrCriticalDiscoveryError -State $state
        if ($criticalError) {
            Write-Host $criticalError
            $script:CrResult = $script:CrExitCodes['PreflightFailed']; return
        }

        $runningSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $preflight = Invoke-CrPreflight -State $state -Config $config
        $resolved = Resolve-CrAccounts -Config $config -State $state
        $plan = New-CrPlan -State $state -Config $config -Resolved $resolved -Preflight $preflight -Only $Only -RunningSid $runningSid

        Write-CrFindingsReport -Findings $plan['Findings']
        $csv = Join-Path $log['Directory'] ('CredentialRotation_{0}_{1}.csv' -f $env:COMPUTERNAME, $runId)
        Export-CrFindingsCsv -Findings $plan['Findings'] -Path $csv
        foreach ($f in (ConvertTo-CrArray $plan['Findings'])) {
            Write-CrLog ('{0} | {1} | {2} | {3} | {4}' -f $f['Severity'], $f['Area'], $f['Slot'], $f['Account'], $f['Message'])
        }

        Write-Host ''
        if ($Apply) {
            Invoke-CrApplyFlow -State $state -Config $config -Resolved $resolved -Preflight $preflight -Plan $plan -Log $log -RunId $runId -RunningSid $runningSid
            return
        }

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

# -Apply (CONTRACTS "v10: account model", "Apply.ps1 / entry point"; PLAN 6 steps 6-11). Sets $script:CrResult.
# Order: accounts overview -> other accounts (D23) -> passwords -> probe (Change accounts) -> summary -> decisions ->
# YES -> Invoke-CrApply -> report -> journal completion -> re-audit -> exit code. Nothing changes before YES.
function Invoke-CrApplyFlow {
    param($State, $Config, $Resolved, $Preflight, $Plan, $Log, [string]$RunId, [string]$RunningSid)
    if ($Preflight['MachineBlocked']) {
        Write-Host 'Result: preflight failed; -Apply is blocked on this machine. Nothing was changed.'
        Write-CrLog 'Apply refused: preflight failed' 'Warning'
        $script:CrResult = $script:CrExitCodes['PreflightFailed']; return
    }
    if (-not (Test-CrNativeReady)) {
        Write-Host ('Result: the native helpers are not available ({0}). Nothing was changed.' -f $script:CrNativeError)
        $script:CrResult = $script:CrExitCodes['PreflightFailed']; return
    }

    $blockedSlots = @{}
    if ($Preflight['BlockedSlots'] -is [hashtable]) { $blockedSlots = $Preflight['BlockedSlots'] }
    $onlyGiven = [bool]($Only -and @($Only).Count -gt 0)
    $journal = Open-CrJournal -Root $Log['Root'] -Trusted ([bool]$Log['JournalTrusted'])
    $slotSecrets = $null
    $runStarted = $false
    $applyStarted = $false
    try {
        # D21: the enabled local accounts and what happens to each; D23: the operator decides on the others
        # (only without -Only: under -Only other accounts are not processed).
        $others = @()
        if (-not $onlyGiven) { $others = Get-CrOtherEnabledAccounts -State $State -Resolved $Resolved }
        $fates = Get-CrApplyAccountFates -State $State -Resolved $Resolved -RunningSid $RunningSid -Only $Only -Others $others
        Write-CrApplyAccountOverview -Fates $fates
        $otherDecisions = @{}
        if ((ConvertTo-CrArray $others).Count -gt 0) { $otherDecisions = Read-CrOtherAccountDecisions -Accounts $others }

        # 6 prompt (Ctrl+C here or later aborts; nothing is changed before YES)
        $slotSecrets = Read-CrSlotSecrets -Config $Config -Resolved $Resolved -State $State -Only $Only -BlockedSlots $blockedSlots
        Start-CrJournalRun -Journal $journal -RunId $RunId
        $runStarted = $true

        # 7 probe: only the accounts whose password is changed with the old one (ApplicationUser, D9)
        $probes = Invoke-CrSlotProbes -State $State -Config $Config -Resolved $Resolved -Preflight $Preflight -SlotSecrets $slotSecrets -Journal $journal -RunId $RunId -Only $Only

        # 8 summary: creations, sets/changes, disables with replacements, dependent moves, auto-logon, running account
        $promptFindings = New-Object System.Collections.ArrayList
        foreach ($k in @($slotSecrets.Keys)) {
            $entry = $slotSecrets[$k]
            if (-not ($entry -is [hashtable])) { continue }
            foreach ($f in (ConvertTo-CrArray $entry['Findings'])) { if ($f -is [hashtable]) { [void]$promptFindings.Add($f) } }
        }
        if ($promptFindings.Count -gt 0) { Write-CrFindingsReport -Findings $promptFindings }
        $preview = Get-CrApplyPreview -Config $Config -Resolved $Resolved -Preflight $Preflight -SlotSecrets $slotSecrets -Probes $probes -Only $Only
        $disablePlan = Get-CrApplyDisablePlan -State $State -Resolved $Resolved -Preview $preview -RunningSid $RunningSid -Only $Only -OtherDecisions $otherDecisions -DependentDecisions @{}
        $alDecision = Get-CrApplyAutoLogonPreview -State $State -Config $Config -Resolved $Resolved -Preview $preview -RunningSid $RunningSid -Only $Only
        Write-CrApplySummary -Preview $preview -DisablePlan $disablePlan -Plan $Plan -AutoLogonDecision $alDecision -Only $Only

        # Operator decisions (D13): ApplicationUser's old password not usable (set with DPAPI loss / skip),
        # dependents of accounts without replacement (move to ApplicationUser / keep enabled), ambiguous auto-logon.
        Resolve-CrProbeDecisions -State $State -Config $Config -Resolved $Resolved -Preflight $Preflight -SlotSecrets $slotSecrets -Probes $probes -Journal $journal -RunId $RunId -Only $Only
        $preview = Get-CrApplyPreview -Config $Config -Resolved $Resolved -Preflight $Preflight -SlotSecrets $slotSecrets -Probes $probes -Only $Only
        $disablePlan = Get-CrApplyDisablePlan -State $State -Resolved $Resolved -Preview $preview -RunningSid $RunningSid -Only $Only -OtherDecisions $otherDecisions -DependentDecisions @{}
        $dependentDecisions = Read-CrDependentDecisions -DisablePlan $disablePlan -Resolved $Resolved
        $disablePlan = Get-CrApplyDisablePlan -State $State -Resolved $Resolved -Preview $preview -RunningSid $RunningSid -Only $Only -OtherDecisions $otherDecisions -DependentDecisions $dependentDecisions
        $alDecision = Get-CrApplyAutoLogonPreview -State $State -Config $Config -Resolved $Resolved -Preview $preview -RunningSid $RunningSid -Only $Only
        $alChoice = $null
        if ($alDecision -is [hashtable] -and $alDecision['Action'] -eq 'Ambiguous') {
            $alChoice = Read-CrAutoLogonChoice -Decision $alDecision
            Write-Host ('Auto-logon decision: {0}' -f $alChoice)
            Write-CrLog ('Auto-logon operator decision before YES: {0}' -f $alChoice)
        }
        Write-Host ''
        Write-Host 'Final plan after your decisions:'
        foreach ($p in (ConvertTo-CrArray $preview)) {
            foreach ($a in (ConvertTo-CrArray $p['Accounts'])) { Write-Host ('  {0,-22} {1}' -f $a['Name'], (Get-CrApplyPathText $a)) }
        }
        foreach ($i in (ConvertTo-CrArray $disablePlan)) { Write-Host ('  {0,-22} {1}' -f $i['Name'], (Get-CrApplyDisableText $i)) }
        Write-Host ''
        if (-not (Confirm-CrYes -Prompt 'Type YES (upper case) to apply; anything else aborts')) {
            Write-Host 'Not confirmed. Nothing was changed.'
            Write-CrLog 'Apply not confirmed; nothing was changed'
            $script:CrResult = $script:CrExitCodes['Aborted']; return
        }

        # 9-10 slots and enforcement phase
        $applyStarted = $true
        Write-CrLog 'Apply confirmed with YES'
        $promptForAutoLogon = { param($Decision) Read-CrAutoLogonChoice -Decision $Decision }
        $result = Invoke-CrApply -State $State -Config $Config -Resolved $Resolved -Preflight $Preflight -Plan $Plan `
            -SlotSecrets $slotSecrets -Probes $probes -Journal $journal -RunId $RunId -Only $Only -RunningSid $RunningSid `
            -OtherDecisions $otherDecisions -DependentDecisions $dependentDecisions -AutoLogonChoice $alChoice -AutoLogonPrompt $promptForAutoLogon

        # 11 report
        Write-CrFindingsReport -Findings $result['Findings']
        Write-CrApplyResult -Result $result
        $csv = Join-Path $Log['Directory'] ('CredentialRotation_{0}_{1}_apply.csv' -f $env:COMPUTERNAME, $RunId)
        Export-CrFindingsCsv -Findings $result['Findings'] -Path $csv
        foreach ($s in (ConvertTo-CrArray $result['Slots'])) {
            Write-CrLog ('Slot {0}: {1}; errors: {2}; pending: {3}' -f $s['Slot'], $s['Status'], ((ConvertTo-CrArray $s['Errors']) -join ' | '), ((ConvertTo-CrArray $s['Pending']) -join ' | '))
        }
        foreach ($d in (ConvertTo-CrArray $result['Disables'])) {
            Write-CrLog ('Disable {0} ({1}): {2}; {3}' -f $d['Name'], $d['Kind'], $d['Status'], $d['Reason'])
        }
        Complete-CrJournalRun -Journal $journal -RunId $RunId
        if ($result['RunningAccount'] -is [hashtable] -and $result['RunningAccount']['Disabled']) {
            Write-Host ''
            Write-Host 'Your own account is disabled now. This RDP session continues; log on as SOP-Admin next time and update saved RDP credentials.'
        }

        # Re-audit: how much drift is left
        Write-Host ''
        Write-Host 'Re-audit after the apply ...'
        try {
            $after = Get-CrMachineState -Config $Config
            $afterError = Get-CrCriticalDiscoveryError -State $after
            if ($afterError) { throw $afterError }
            $afterPreflight = Invoke-CrPreflight -State $after -Config $Config
            $afterResolved = Resolve-CrAccounts -Config $Config -State $after
            $afterPlan = New-CrPlan -State $after -Config $Config -Resolved $afterResolved -Preflight $afterPreflight -Only $Only -RunningSid $RunningSid
            $afterFindings = ConvertTo-CrArray $afterPlan['Findings']
            $drift = @($afterFindings | Where-Object { $_['Severity'] -eq 'Drift' })
            Write-Host ('Drift left after the apply: {0} item(s).' -f $drift.Count)
            foreach ($f in $drift) { Write-Host ('  - [{0} / {1}] {2}: {3}' -f $f['Slot'], $f['Account'], $f['Area'], $f['Message']) }
            Write-CrLog ('Re-audit: {0} drift item(s) left' -f $drift.Count)
        } catch {
            Write-Host ('The re-audit failed: {0}' -f $_.Exception.Message)
            Write-CrLog ('Re-audit failed: ' + $_.Exception.Message) 'Warning'
        }

        Write-Host ''
        $exit = [int]$result['ExitCode']
        if ($exit -eq 0) {
            Write-Host 'Result: applied, nothing outstanding.'
        } elseif ($exit -eq 4) {
            Write-Host 'Result: applied; FOLLOW-UP REQUIRED (see above).'
        } elseif ($exit -eq 1) {
            Write-Host 'Result: partial failure; re-run with the same passwords to complete the pending steps.'
        } else {
            Write-Host ('Result: exit code {0}.' -f $exit)
        }
        Write-Host ('Report: {0}' -f $csv)
        Write-CrLog ('Apply finished with exit code {0}' -f $exit)
        $script:CrResult = $exit
    } finally {
        # A run that changed nothing is closed; an interrupted apply stays unfinished, so the next probe tests
        # the new password first (PLAN 6 step 7, 7.10).
        if ($runStarted -and -not $applyStarted) {
            try { Complete-CrJournalRun -Journal $journal -RunId $RunId } catch { }
        }
        Clear-CrSlotSecrets -SlotSecrets $slotSecrets
        $slotSecrets = $null
    }
}

$script:CrResult = $script:CrExitCodes['Aborted']
try {
    [void](Invoke-CrMain)
} catch {
    Write-Host ('Aborted: {0}' -f $_.Exception.Message)
    try { Write-CrLog ('Aborted: ' + $_.Exception.Message + ' at ' + $_.InvocationInfo.PositionMessage) 'Error' } catch { }
    $script:CrResult = $script:CrExitCodes['Aborted']
}
exit $script:CrResult
