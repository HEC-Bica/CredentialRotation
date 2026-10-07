# Journal.ps1 - run journal (docs/PLAN.md section 7.10, docs/dev/CONTRACTS.md "Journal.ps1").
# Records per run and per account SID the steps completed and whether the run finished. Holds no secrets.
# Stored as <log root>\journal.clixml and rewritten after every change.

$script:CrJournalFileName = 'journal.clixml'
$script:CrJournalSteps = @('PreSteps', 'CcpCleared', 'CcpRestored', 'Unlocked', 'Secret', 'Dependents', 'Grants', 'Verified', 'AutoLogon',
                           'Created', 'Enabled', 'Disabled', 'DependentsMoved')   # v10 account model (D21-D25)

function New-CrJournalObject {
    param([string]$Path)
    return @{ Runs = (New-Object System.Collections.ArrayList); Path = $Path; LastSaveError = $null }
}

# Rebuilds one deserialized run with known types; $null for anything malformed.
function ConvertTo-CrJournalRun {
    param($Run)
    if (-not ($Run -is [hashtable])) { return $null }
    if (-not $Run['RunId']) { return $null }
    $accounts = @{}
    $rawAccounts = $Run['Accounts']
    if ($rawAccounts -is [hashtable]) {
        foreach ($key in @($rawAccounts.Keys)) {
            $steps = New-Object System.Collections.ArrayList
            if ($null -ne $rawAccounts[$key]) {
                foreach ($step in @($rawAccounts[$key])) {
                    if (($script:CrJournalSteps -contains [string]$step) -and ($steps -notcontains [string]$step)) { [void]$steps.Add([string]$step) }
                }
            }
            $accounts[[string]$key] = $steps
        }
    }
    return @{
        RunId    = [string]$Run['RunId']
        Started  = $Run['Started']
        Finished = ($Run['Finished'] -eq $true)
        Accounts = $accounts
    }
}

# Import-Clixml/Export-Clixml have no -LiteralPath in PS 2.0; the journal path contains no wildcard characters.
function Read-CrJournalFile {
    param([string]$Path)
    return Import-Clixml -Path $Path -ErrorAction Stop
}

function Write-CrJournalFile {
    param([string]$Path, $Data)
    $tmp = $Path + '.tmp'
    # Depth: root > Runs > run > Accounts > steps; the default depth of 2 would flatten Accounts to a string.
    Export-Clixml -Path $tmp -InputObject $Data -Depth 8 -Force -ErrorAction Stop
    if ([System.IO.File]::Exists($Path)) {
        # Replace keeps the previous version as .bak (a $null backup name may arrive as '' from PowerShell).
        [System.IO.File]::Replace($tmp, $Path, ($Path + '.bak'))
    } else {
        [System.IO.File]::Move($tmp, $Path)
    }
}

# Empty journal when the file is missing, unreadable or the log folder was not trusted (Log.ps1 JournalTrusted).
# The returned journal always carries its path, so a new run overwrites an ignored file.
function Open-CrJournal {
    param([string]$Root, [bool]$Trusted)
    $fullRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Root)
    $path = Join-Path $fullRoot $script:CrJournalFileName
    $journal = New-CrJournalObject -Path $path
    if (-not $Trusted) {
        Write-CrLog 'Run journal ignored: the log folder was not trusted.' 'Warning'
        return $journal
    }
    if (-not [System.IO.File]::Exists($path)) { return $journal }
    try {
        $data = Read-CrJournalFile -Path $path
    } catch {
        Write-CrLog ('Run journal could not be read and is ignored: {0}' -f (Get-CrInnermostMessage $_)) 'Warning'
        return $journal
    }
    if (-not ($data -is [hashtable]) -or ($null -eq $data['Runs'])) {
        Write-CrLog 'Run journal has an unexpected format and is ignored.' 'Warning'
        return $journal
    }
    $skipped = 0
    foreach ($run in @($data['Runs'])) {
        $clean = ConvertTo-CrJournalRun $run
        if ($clean) { [void]$journal.Runs.Add($clean) } else { $skipped++ }
    }
    if ($skipped -gt 0) { Write-CrLog ('Run journal: {0} malformed run(s) ignored.' -f $skipped) 'Warning' }
    return $journal
}

# Writes the journal; on failure logs a warning and keeps the error in LastSaveError (never throws).
function Save-CrJournal {
    param($Journal)
    if (-not $Journal['Path']) { return }
    try {
        Write-CrJournalFile -Path $Journal['Path'] -Data @{ Runs = $Journal['Runs'] }
        $Journal['LastSaveError'] = $null
    } catch {
        $Journal['LastSaveError'] = Get-CrInnermostMessage $_
        Write-CrLog ('Run journal could not be saved: {0}' -f $Journal['LastSaveError']) 'Warning'
    }
}

function Find-CrJournalRun {
    param($Journal, [string]$RunId)
    if ($null -eq $Journal['Runs']) { throw 'Journal has no Runs list; use Open-CrJournal' }
    foreach ($run in $Journal['Runs']) {
        if ([string]$run['RunId'] -eq $RunId) { return $run }
    }
    return $null
}

function Start-CrJournalRun {
    param($Journal, [string]$RunId)
    if (-not $RunId) { throw 'Start-CrJournalRun: RunId is required' }
    $run = Find-CrJournalRun -Journal $Journal -RunId $RunId
    if (-not $run) {
        $run = @{ RunId = $RunId; Started = (Get-Date); Finished = $false; Accounts = @{} }
        [void]$Journal['Runs'].Add($run)
    }
    Save-CrJournal -Journal $Journal
}

function Add-CrJournalStep {
    param($Journal, [string]$RunId, [string]$Sid, [string]$Step)
    if ($script:CrJournalSteps -notcontains $Step) { throw ('Add-CrJournalStep: unknown step {0}' -f $Step) }
    if (-not $Sid) { throw 'Add-CrJournalStep: Sid is required' }
    $run = Find-CrJournalRun -Journal $Journal -RunId $RunId
    if (-not $run) {
        $run = @{ RunId = $RunId; Started = (Get-Date); Finished = $false; Accounts = @{} }
        [void]$Journal['Runs'].Add($run)
    }
    $key = $null
    foreach ($k in @($run['Accounts'].Keys)) { if ([string]$k -ieq $Sid) { $key = $k; break } }
    if ($null -eq $key) {
        $key = $Sid
        $run['Accounts'][$key] = New-Object System.Collections.ArrayList
    }
    $steps = $run['Accounts'][$key]
    if (-not ($steps -is [System.Collections.ArrayList])) {
        $list = New-Object System.Collections.ArrayList
        if ($null -ne $steps) { foreach ($s in @($steps)) { [void]$list.Add([string]$s) } }
        $steps = $list
        $run['Accounts'][$key] = $steps
    }
    if ($steps -notcontains $Step) { [void]$steps.Add($Step) }
    Save-CrJournal -Journal $Journal
}

function Complete-CrJournalRun {
    param($Journal, [string]$RunId)
    $run = Find-CrJournalRun -Journal $Journal -RunId $RunId
    if ($run) { $run['Finished'] = $true }
    Save-CrJournal -Journal $Journal
}

# $true if any unfinished run other than -ExceptRunId recorded the step for the SID.
function Test-CrJournalStepInUnfinishedRun {
    param($Journal, [string]$Sid, [string]$Step, [string]$ExceptRunId)
    if (-not ($Journal -is [hashtable]) -or ($null -eq $Journal['Runs'])) { return $false }
    foreach ($run in $Journal['Runs']) {
        if ($run['Finished'] -eq $true) { continue }
        if ($ExceptRunId -and ([string]$run['RunId'] -eq $ExceptRunId)) { continue }
        if (-not ($run['Accounts'] -is [hashtable])) { continue }
        foreach ($k in @($run['Accounts'].Keys)) {
            if ([string]$k -ine $Sid) { continue }
            $steps = $run['Accounts'][$k]
            if (($null -ne $steps) -and (@($steps) -contains $Step)) { return $true }
        }
    }
    return $false
}
