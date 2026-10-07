$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$lib = Join-Path $here '..\src\lib'
foreach ($m in @('Compat', 'Config', 'Rights', 'Principals', 'AutoLogon', 'Plan')) { . (Join-Path $lib ($m + '.ps1')) }
. (Join-Path $here 'Fixtures.ps1')

# Pester 3.4 keeps a Mock for the whole Describe/Context it is defined in: every Mock lives in its own Context.

function New-CrTestPlan {
    param($State, [string[]]$Only, $Preflight, [string]$RunningSid = 'S-1-5-21-9-9-9-9999')
    $config = New-CrTestConfig
    if (-not $Preflight) { $Preflight = @{ MachineBlocked = $false; BlockedSlots = @{}; Findings = @() } }
    $resolved = Resolve-CrAccounts -Config $config -State $State
    return New-CrPlan -State $State -Config $config -Resolved $resolved -Preflight $Preflight -Only $Only -RunningSid $RunningSid
}

function Get-CrTestFindings {
    param($Plan, [string]$Severity, [string]$Area, [string]$Account, [string]$Like)
    return @($Plan['Findings'] | Where-Object {
        (-not $Severity -or $_['Severity'] -eq $Severity) -and (-not $Area -or $_['Area'] -eq $Area) -and
        (-not $Account -or $_['Account'] -eq $Account) -and (-not $Like -or $_['Message'] -like $Like)
    })
}

Describe 'New-CrPlan on an SM-like machine (v10 account model)' {
    Context 'audit run as BiCA Remote' {
        Mock Get-CrPathAllowSids { return , @('S-1-5-32-545', 'S-1-5-18', 'S-1-5-32-544') }
        $state = New-CrTestState -Profile SM
        $plan = New-CrTestPlan -State $state -RunningSid (Get-CrTestUserSid $state 'BiCA Remote')

        It 'reports drift' {
            $plan['Drift'] | Should Be $true
        }
        It 'creates SOP-Admin and PUB-User (D21)' {
            $sop = Get-CrTestFindings $plan 'Drift' 'Accounts' 'SOP-Admin' 'Create SOP-Admin'
            $sop.Count | Should Be 1
            $sop[0]['Slot'] | Should Be 'SOPAdmin'
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'PUB-User' 'Create PUB-User').Count | Should Be 1
        }
        It 'adds the created SOP-Admin to its role groups' {
            @(Get-CrTestFindings $plan 'Drift' 'Groups' 'SOP-Admin' 'Add to Administrators').Count | Should Be 1
            @(Get-CrTestFindings $plan 'Drift' 'Groups' 'SOP-Admin' 'Add to Remote Desktop Users').Count | Should Be 1
            @(Get-CrTestFindings $plan 'Drift' 'Groups' 'SOP-Admin' 'Add to Offer Remote Assistance Helpers').Count | Should Be 1
            @(Get-CrTestFindings $plan 'Drift' 'Groups' 'PUB-User' 'Add to Users').Count | Should Be 1
        }
        It 'disables the replaced accounts (D22)' {
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'BiCA Admin' 'Disable BiCA Admin (replaced by SOP-Admin)').Count | Should Be 1
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'BiCA Remote' 'Disable BiCA Remote (replaced by SOP-Admin)').Count | Should Be 1
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'WinAutoUser' 'Disable WinAutoUser (replaced by PUB-User)').Count | Should Be 1
        }
        It 'leaves the already disabled built-in Administrator alone' {
            @(Get-CrTestFindings $plan 'Drift' $null 'LocalAdm').Count | Should Be 0
            @(Get-CrTestFindings $plan 'Info' 'Accounts' 'LocalAdm' 'Already disabled (replaced by ApplicationUser)').Count | Should Be 1
        }
        It 'does not enforce groups or flags on replaced accounts' {
            @(Get-CrTestFindings $plan $null 'Groups' 'BiCA Admin').Count | Should Be 0
            @(Get-CrTestFindings $plan $null 'Flags' 'BiCA Admin').Count | Should Be 0
        }
        It 'disables the running account last and says so (D25)' {
            $f = Get-CrTestFindings $plan 'HighImpact' 'Accounts' 'BiCA Remote' 'The running account BiCA Remote is disabled at the end; log on as SOP-Admin next time*'
            $f.Count | Should Be 1
            (Get-CrTestFindings $plan 'Drift' 'Accounts' 'BiCA Remote' 'Disable*')[0]['Detail'] | Should Match 'last step \(D25\)'
        }
        It 'moves the password-stored task of WinAutoUser to PUB-User (D24)' {
            $f = Get-CrTestFindings $plan 'HighImpact' 'Tasks' 'WinAutoUser' 'Move scheduled task \KioskTask from WinAutoUser to PUB-User (D24)'
            $f.Count | Should Be 1
            $f[0]['Slot'] | Should Be 'PubUser'
        }
        It 'disables SP Admin (no replacement) and reports the missing SYS Admin' {
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'SP Admin' 'Disable SP Admin (no replacement)').Count | Should Be 1
            @(Get-CrTestFindings $plan 'Info' 'Accounts' 'SYS Admin' 'Account not found (nothing to disable)*').Count | Should Be 1
        }
        It 'puts the dependents of SP Admin to the operator (D24, O5)' {
            $f = Get-CrTestFindings $plan 'Ambiguous' 'Tasks' 'SP Admin' 'Operator decides: move scheduled task \SpMaintenance from SP Admin to ApplicationUser or keep SP Admin enabled*'
            $f.Count | Should Be 1
            @(Get-CrTestFindings $plan 'HighImpact' $null 'SP Admin' 'Move*').Count | Should Be 0
        }
        It 'puts every other enabled account to the operator (D23)' {
            $all = Get-CrTestFindings $plan 'Ambiguous' 'Accounts' $null 'Operator decides: disable or keep*'
            $all.Count | Should Be 2
            $admin = Get-CrTestFindings $plan 'Ambiguous' 'Accounts' 'OtherAdmin' 'Operator decides: disable or keep OtherAdmin (D23)'
            $admin.Count | Should Be 1
            $admin[0]['Detail'] | Should Match 'Administrators'
            @(Get-CrTestFindings $plan 'Ambiguous' 'Accounts' 'myftpuser').Count | Should Be 1
        }
        It 'changes ApplicationUser with its old password and probes only that account' {
            @(Get-CrTestFindings $plan 'Info' 'Password' 'ApplicationUser' 'Password change with the old password*').Count | Should Be 1
            $probes = Get-CrTestFindings $plan 'Info' 'Probe'
            $probes.Count | Should Be 1
            $probes[0]['Account'] | Should Be 'ApplicationUser'
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
        It 'lists LOGINS follow-ups for SOP-Admin, ApplicationUser and the SQL logins' {
            $sop = Get-CrTestFindings $plan 'FollowUp' 'LOGINS' 'SOP-Admin'
            $sop.Count | Should Be 1
            $sop[0]['Detail'] | Should Match 'BiCA Admin, BiCA Remote'
            @(Get-CrTestFindings $plan 'FollowUp' 'LOGINS' 'ApplicationUser').Count | Should Be 1
            @(Get-CrTestFindings $plan 'FollowUp' 'LOGINS' 'SQLApplication').Count | Should Be 1
            @(Get-CrTestFindings $plan 'FollowUp' 'LOGINS' 'BiCA Admin').Count | Should Be 0
            @(Get-CrTestFindings $plan 'FollowUp' 'LOGINS' 'BiCA Remote').Count | Should Be 0
            @(Get-CrTestFindings $plan 'FollowUp' 'LOGINS' 'PUB-User').Count | Should Be 0
            @(Get-CrTestFindings $plan 'FollowUp' 'LOGINS' 'WinUser1').Count | Should Be 0
        }
        It 'puts the findings into HighImpact and FollowUps' {
            @($plan['HighImpact']).Count | Should BeGreaterThan 0
            @($plan['FollowUps']).Count | Should Be 5
        }
        It 'never creates findings with an unknown severity' {
            $bad = @($plan['Findings'] | Where-Object { @('Drift', 'HighImpact', 'Blocked', 'Ambiguous', 'FollowUp', 'Info') -notcontains $_['Severity'] })
            $bad.Count | Should Be 0
        }
    }
}

Describe 'New-CrPlan on an IPT01-like machine (v10 account model)' {
    $state = New-CrTestState -Profile IPT01
    $plan = New-CrTestPlan -State $state

    It 'creates nothing: all managed accounts exist' {
        @(Get-CrTestFindings $plan 'Drift' 'Accounts' $null 'Create*').Count | Should Be 0
    }
    It 'sets the password of an existing set account without a probe' {
        @(Get-CrTestFindings $plan 'Info' 'Password' 'SOP-Admin' 'Password set (D9: no old password)').Count | Should Be 1
        @(Get-CrTestFindings $plan $null 'Probe' 'SOP-Admin').Count | Should Be 0
        @(Get-CrTestFindings $plan $null 'Probe' 'PUB-User').Count | Should Be 0
    }
    It 'adds the existing SOP-Admin to Remote Desktop Users' {
        @(Get-CrTestFindings $plan 'Drift' 'Groups' 'SOP-Admin' 'Add to Remote Desktop Users').Count | Should Be 1
        @(Get-CrTestFindings $plan 'Drift' 'Groups' 'SOP-Admin' 'Add to Administrators').Count | Should Be 0
    }
    It 'disables the enabled built-in Administrator (replaced by ApplicationUser)' {
        $f = Get-CrTestFindings $plan 'Drift' 'Accounts' 'Administrator' 'Disable Administrator (replaced by ApplicationUser)'
        $f.Count | Should Be 1
        $f[0]['Slot'] | Should Be 'AppUser'
    }
    It 'moves the service of BiCA Admin to SOP-Admin (D24)' {
        @(Get-CrTestFindings $plan 'HighImpact' 'Services' 'BiCA Admin' 'Move service AppHelper from BiCA Admin to SOP-Admin (D24)').Count | Should Be 1
    }
    It 'puts the service of SYS Admin to the operator (D24, O5)' {
        @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'SYS Admin' 'Disable SYS Admin (no replacement)').Count | Should Be 1
        @(Get-CrTestFindings $plan 'Ambiguous' 'Services' 'SYS Admin' 'Operator decides: move service LegacySync from SYS Admin to ApplicationUser or keep SYS Admin enabled (D24, O5)').Count | Should Be 1
    }
    It 'has no other enabled accounts' {
        @(Get-CrTestFindings $plan 'Ambiguous' 'Accounts' $null 'Operator decides: disable or keep*').Count | Should Be 0
    }
    It 'has no D25 item when the running account is not replaced' {
        @(Get-CrTestFindings $plan 'HighImpact' 'Accounts' $null 'The running account*').Count | Should Be 0
    }
    It 'switches the admin auto-logon to PUB-User on a non-SM machine' {
        @(Get-CrTestFindings $plan 'Drift' 'AutoLogon' $null 'Switch auto-logon from * to PUB-User*').Count | Should Be 1
    }
    It 'finds no SID overlap' {
        @(Get-CrTestFindings $plan 'Ambiguous' 'Principals').Count | Should Be 0
    }
}

Describe 'New-CrPlan: accounts created in this run and the auto-logon step' {
    Context 'PUB-User is created' {
        Mock Get-CrAutoLogonDecision { return @{ Action = 'NoChange'; CurrentSid = $null; CurrentName = 'BiCA Admin'; TargetSid = $null; TargetName = $null; Reasons = @(); OperatorOptions = @(); HighImpact = @() } }
        $state = New-CrTestState -Profile IPT01 -OmitUsers 'PUB-User'
        $plan = New-CrTestPlan -State $state

        It 'passes PUB-User in CreatedTargetNames' {
            Assert-MockCalled Get-CrAutoLogonDecision -Times 1 -Exactly -ParameterFilter { @($CreatedTargetNames) -contains 'PUB-User' }
        }
        It 'creates PUB-User and disables WinAutoUser' {
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'PUB-User' 'Create PUB-User').Count | Should Be 1
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'WinAutoUser' 'Disable WinAutoUser (replaced by PUB-User)').Count | Should Be 1
        }
    }

    Context 'the PUB-User slot is blocked' {
        Mock Get-CrAutoLogonDecision { return @{ Action = 'NoChange'; CurrentSid = $null; CurrentName = 'BiCA Admin'; TargetSid = $null; TargetName = $null; Reasons = @(); OperatorOptions = @(); HighImpact = @() } }
        $state = New-CrTestState -Profile IPT01 -OmitUsers 'PUB-User'
        $pf = @{ MachineBlocked = $false; BlockedSlots = @{ PubUser = 'test' }; Findings = @() }
        $plan = New-CrTestPlan -State $state -Preflight $pf

        It 'does not count the account as created and verified' {
            Assert-MockCalled Get-CrAutoLogonDecision -Times 1 -Exactly -ParameterFilter { @($CreatedTargetNames) -notcontains 'PUB-User' }
        }
    }
}

Describe 'New-CrPlan account state findings' {
    It 'clears "password not required" on a managed account' {
        $state = New-CrTestState -Profile IPT01
        (Get-CrTestUser $state 'SOP-Admin')['PasswordNotRequired'] = $true
        $plan = New-CrTestPlan -State $state
        @(Get-CrTestFindings $plan 'Drift' 'Flags' 'SOP-Admin' '*UF_PASSWD_NOTREQD*').Count | Should Be 1
    }
    It 'enables a disabled managed account' {
        $state = New-CrTestState -Profile IPT01
        (Get-CrTestUser $state 'PUB-User')['Disabled'] = $true
        $plan = New-CrTestPlan -State $state
        @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'PUB-User' 'Enable the account (D21)').Count | Should Be 1
    }
    It 'says the old password cannot be test-logged-on when ForceGuest leaves no logon type (D16)' {
        $state = New-CrTestState -Profile IPT01
        $state.Policy.ForceGuest = $true
        $sid = Get-CrTestUserSid $state 'ApplicationUser'
        Set-CrTestRight -State $state -Right 'SeDenyInteractiveLogonRight' -Sids @($sid)
        Set-CrTestRight -State $state -Right 'SeDenyBatchLogonRight' -Sids @($sid)
        Set-CrTestRight -State $state -Right 'SeDenyServiceLogonRight' -Sids @($sid)
        $plan = New-CrTestPlan -State $state
        $f = Get-CrTestFindings $plan 'Info' 'Probe' 'ApplicationUser'
        $f.Count | Should Be 1
        $f[0]['Message'] | Should Match 'cannot be verified by a test logon'
        $f[0]['Detail'] | Should Not Match 'Network is used'
    }
    It 'reports a running account in a Disable entry (D25)' {
        $state = New-CrTestState -Profile IPT01
        $plan = New-CrTestPlan -State $state -RunningSid (Get-CrTestUserSid $state 'SYS Admin')
        @(Get-CrTestFindings $plan 'HighImpact' 'Accounts' 'SYS Admin' 'The running account SYS Admin is disabled at the end; log on as SOP-Admin next time*').Count | Should Be 1
    }
    It 'reports an already disabled retired account as Info only' {
        $state = New-CrTestState -Profile IPT01
        (Get-CrTestUser $state 'SYS Admin')['Disabled'] = $true
        $plan = New-CrTestPlan -State $state
        @(Get-CrTestFindings $plan 'Drift' $null 'SYS Admin').Count | Should Be 0
        @(Get-CrTestFindings $plan 'Info' 'Accounts' 'SYS Admin' 'Already disabled*').Count | Should Be 1
        @(Get-CrTestFindings $plan 'Ambiguous' $null 'SYS Admin').Count | Should Be 0
    }
    It 'blocks every Windows entry and asks nothing when the Users part failed' {
        $state = New-CrTestState -Profile IPT01 -Parts @{ Users = @{ Error = 'access denied' } }
        $plan = New-CrTestPlan -State $state
        @(Get-CrTestFindings $plan 'Blocked' 'Accounts').Count | Should Be 6
        @(Get-CrTestFindings $plan $null 'Accounts' $null 'Create*').Count | Should Be 0
        @(Get-CrTestFindings $plan 'Ambiguous' 'Accounts' $null 'Operator decides*').Count | Should Be 0
    }
}

Describe 'New-CrPlan with -Only' {
    Context 'only the SOP-Admin slot' {
        Mock Get-CrPathAllowSids { return , @() }
        $state = New-CrTestState -Profile SM
        $plan = New-CrTestPlan -State $state -Only @('SOPAdmin')

        It 'skips other slots, check-mode accounts, retired and other accounts' {
            @(Get-CrTestFindings $plan $null 'SQL').Count | Should Be 0
            @(Get-CrTestFindings $plan $null $null 'WinUser1').Count | Should Be 0
            @(Get-CrTestFindings $plan $null $null 'SP Admin').Count | Should Be 0
            @(Get-CrTestFindings $plan $null $null 'PUB-User').Count | Should Be 0
            @(Get-CrTestFindings $plan 'Ambiguous' 'Accounts' $null 'Operator decides: disable or keep*').Count | Should Be 0
        }
        It 'keeps the creation and the replaced accounts of the selected slot' {
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'SOP-Admin' 'Create SOP-Admin').Count | Should Be 1
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'BiCA Admin' 'Disable BiCA Admin*').Count | Should Be 1
        }
        It 'still runs the auto-logon step because BiCA Admin (replaced by this slot) is the current auto-logon account' {
            @(Get-CrTestFindings $plan $null 'AutoLogon').Count | Should BeGreaterThan 0
        }
    }

    Context 'only a SQL slot' {
        Mock Get-CrPathAllowSids { return , @() }
        $state = New-CrTestState -Profile SM
        $plan = New-CrTestPlan -State $state -Only @('SQLApplication')

        It 'does not run the auto-logon step' {
            @(Get-CrTestFindings $plan $null 'AutoLogon').Count | Should Be 0
        }
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
