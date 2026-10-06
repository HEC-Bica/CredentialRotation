$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$lib = Join-Path $here '..\src\lib'
foreach ($m in @('Compat', 'Config', 'Rights', 'Principals', 'AutoLogon', 'Plan')) { . (Join-Path $lib ($m + '.ps1')) }
. (Join-Path $here 'Fixtures.ps1')

function New-CrTestPlan {
    param($State, [string[]]$Only, $Preflight)
    $config = New-CrTestConfig
    if (-not $Preflight) { $Preflight = @{ MachineBlocked = $false; BlockedSlots = @{}; Findings = @() } }
    $resolved = Resolve-CrAccounts -Config $config -State $State
    return New-CrPlan -State $State -Config $config -Resolved $resolved -Preflight $Preflight -Only $Only -RunningSid 'S-1-5-21-9-9-9-9999'
}

function Get-CrTestFindings {
    param($Plan, [string]$Severity, [string]$Area, [string]$Account, [string]$Like)
    return @($Plan['Findings'] | Where-Object {
        (-not $Severity -or $_['Severity'] -eq $Severity) -and (-not $Area -or $_['Area'] -eq $Area) -and
        (-not $Account -or $_['Account'] -eq $Account) -and (-not $Like -or $_['Message'] -like $Like)
    })
}

Describe 'New-CrPlan on an SM-like machine' {
    Mock Get-CrPathAllowSids { return , @('S-1-5-32-545', 'S-1-5-18', 'S-1-5-32-544') }
    $state = New-CrTestState -Profile SM
    $plan = New-CrTestPlan -State $state

    It 'reports drift' {
        $plan['Drift'] | Should Be $true
    }
    It 'removes BiCA Admin from Offer Remote Assistance Helpers' {
        @(Get-CrTestFindings $plan 'Drift' 'Groups' 'BiCA Admin' 'Remove from Offer Remote Assistance Helpers*').Count | Should Be 1
    }
    It 'keeps BiCA Remote in Remote Desktop Users (allowed extra group)' {
        @(Get-CrTestFindings $plan 'Drift' 'Groups' 'BiCA Remote' '*Remote Desktop Users*').Count | Should Be 0
    }
    It 'removes FTP users from Users and flags folder access granted only through Users' {
        @(Get-CrTestFindings $plan 'Drift' 'Groups' $null 'Remove from Users*').Count | Should BeGreaterThan 0
        @(Get-CrTestFindings $plan 'HighImpact' 'Groups' $null 'FTP folder access is granted only through Users*').Count | Should BeGreaterThan 0
    }
    It 'flags SQL Server running as the application user' {
        @(Get-CrTestFindings $plan 'HighImpact' 'Services' $null 'SQL Server runs as this account*').Count | Should Be 1
    }
    It 'turns off the admin auto-logon on an SM machine' {
        @(Get-CrTestFindings $plan 'Drift' 'AutoLogon' $null 'Turn auto-logon off*').Count | Should Be 1
    }
    It 'lists a LOGINS follow-up for rotated accounts with a LOGINS entry' {
        @(Get-CrTestFindings $plan 'FollowUp' 'LOGINS' 'BiCA Admin').Count | Should Be 1
        @(Get-CrTestFindings $plan 'FollowUp' 'LOGINS' 'WinUser1').Count | Should Be 0
    }
    It 'never creates findings with an unknown severity' {
        $bad = @($plan['Findings'] | Where-Object { @('Drift', 'HighImpact', 'Blocked', 'Ambiguous', 'FollowUp', 'Info') -notcontains $_['Severity'] })
        $bad.Count | Should Be 0
    }
}

Describe 'New-CrPlan flags' {
    It 'clears "password not required" on a rotated account' {
        $state = New-CrTestState -Profile SM
        (Get-CrTestUser $state 'BiCA Admin')['PasswordNotRequired'] = $true
        $plan = New-CrTestPlan -State $state
        @(Get-CrTestFindings $plan 'Drift' 'Flags' 'BiCA Admin' '*UF_PASSWD_NOTREQD*').Count | Should Be 1
    }
}

Describe 'New-CrPlan with -Only' {
    Mock Get-CrPathAllowSids { return , @() }
    $state = New-CrTestState -Profile SM
    $plan = New-CrTestPlan -State $state -Only @('BiCAAdmin')

    It 'skips other slots and check-mode accounts' {
        @(Get-CrTestFindings $plan $null 'SQL').Count | Should Be 0
        @(Get-CrTestFindings $plan $null $null 'WinUser1').Count | Should Be 0
    }
    It 'still runs the auto-logon step because BiCA Admin is the current auto-logon account' {
        @(Get-CrTestFindings $plan $null 'AutoLogon').Count | Should BeGreaterThan 0
    }
}

Describe 'New-CrPlan with a blocked machine' {
    It 'adds one machine-wide Blocked finding and keeps the preflight findings' {
        $state = New-CrTestState -Profile IPT01
        $slotFinding = New-CrFinding -Severity Blocked -Area Preflight -Message 'SQL not reachable' -Slot SQLApplication
        $pf = @{ MachineBlocked = $true; BlockedSlots = @{ SQLApplication = 'SQL not reachable' }; Findings = @($slotFinding) }
        $plan = New-CrTestPlan -State $state -Preflight $pf
        @(Get-CrTestFindings $plan 'Blocked' 'Preflight').Count | Should Be 2
        @(Get-CrTestFindings $plan 'Blocked' 'Preflight' $null '-Apply is blocked*').Count | Should Be 1
    }
}
