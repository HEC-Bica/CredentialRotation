$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$lib = Join-Path $here '..\src\lib'
foreach ($m in @('Compat', 'Config', 'Rights', 'Principals', 'AutoLogon', 'Plan')) { . (Join-Path $lib ($m + '.ps1')) }
. (Join-Path $here 'Fixtures.ps1')

# Pester 3.4 keeps a Mock for the whole Describe/Context it is defined in: every Mock lives in its own Context.
# Account model PLAN v10.3 (D18, D21-D25): BiCA Admin, BiCA Remote (the operator's account), ApplicationUser (replaces
# RID-500) and the auto-logon accounts PUB-User / WinAutoUser are managed; SP Admin, SYS Admin and SOP-Admin are retired.

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

Describe 'New-CrPlan on an SM-like machine (account model v10.3)' {
    Context 'audit run as BiCA Remote' {
        Mock Get-CrPathAllowSids { return , @('S-1-5-32-545', 'S-1-5-18', 'S-1-5-32-544') }
        $state = New-CrTestState -Profile SM
        $plan = New-CrTestPlan -State $state -RunningSid (Get-CrTestUserSid $state 'BiCA Remote')

        It 'reports drift' {
            $plan['Drift'] | Should Be $true
        }
        It 'creates nothing: BiCA Admin and BiCA Remote exist, PUB-User is never created (D21)' {
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' $null 'Create*').Count | Should Be 0
            @(Get-CrTestFindings $plan $null $null 'PUB-User' 'Create PUB-User').Count | Should Be 0
            @(Get-CrTestFindings $plan 'Info' 'Accounts' 'PUB-User' 'Account not found (never created): PUB-User').Count | Should Be 1
        }
        It 'sets the passwords of BiCA Admin, BiCA Remote and WinAutoUser without a probe (D9)' {
            @(Get-CrTestFindings $plan 'Info' 'Password' 'BiCA Admin' 'Password set (D9: no old password)').Count | Should Be 1
            @(Get-CrTestFindings $plan 'Info' 'Password' 'BiCA Remote' 'Password set (D9: no old password)').Count | Should Be 1
            @(Get-CrTestFindings $plan 'Info' 'Password' 'WinAutoUser' 'Password set (D9: no old password)').Count | Should Be 1
        }
        It 'keeps the managed accounts enabled: BiCA Admin, BiCA Remote and WinAutoUser are not replaced' {
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' $null 'Disable BiCA Admin*').Count | Should Be 0
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' $null 'Disable BiCA Remote*').Count | Should Be 0
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' $null 'Disable WinAutoUser*').Count | Should Be 0
        }
        It 'enforces the role groups: BiCA Admin leaves the helpers group, BiCA Remote keeps Remote Desktop Users' {
            @(Get-CrTestFindings $plan 'Drift' 'Groups' 'BiCA Admin' 'Remove from Offer Remote Assistance Helpers*').Count | Should Be 1
            @(Get-CrTestFindings $plan $null 'Groups' 'BiCA Remote').Count | Should Be 0
        }
        It 'enforces the role flags of the managed accounts' {
            @(Get-CrTestFindings $plan 'Drift' 'Flags' 'BiCA Admin' '*UF_PASSWD_NOTREQD*').Count | Should Be 1
            @(Get-CrTestFindings $plan 'Drift' 'Flags' 'BiCA Remote' 'Set "user cannot change password"').Count | Should Be 1
        }
        It 'leaves the already disabled built-in Administrator alone' {
            @(Get-CrTestFindings $plan 'Drift' $null 'LocalAdm').Count | Should Be 0
            @(Get-CrTestFindings $plan 'Info' 'Accounts' 'LocalAdm' 'Already disabled (replaced by ApplicationUser)').Count | Should Be 1
        }
        It 'does not enforce groups or flags on retired or replaced accounts' {
            foreach ($n in @('SP Admin', 'LocalAdm')) {
                @(Get-CrTestFindings $plan $null 'Groups' $n).Count | Should Be 0
                @(Get-CrTestFindings $plan $null 'Flags' $n).Count | Should Be 0
            }
        }
        It 'updates the password-stored task of WinAutoUser in place (no move) and grants the batch right' {
            $f = @(Get-CrTestFindings $plan 'Info' 'Tasks' 'WinAutoUser' 'Scheduled task re-registered with the new password: \KioskTask*')
            $f.Count | Should Be 1
            $f[0]['Slot'] | Should Be 'AutoLogon'
            @(Get-CrTestFindings $plan $null $null $null 'Move scheduled task \KioskTask*').Count | Should Be 0
            @(Get-CrTestFindings $plan 'Drift' 'Rights' 'WinAutoUser' 'Grant SeBatchLogonRight*').Count | Should Be 1
        }
        It 'has no D25 item: the running account BiCA Remote is managed, not disabled' {
            @(Get-CrTestFindings $plan 'HighImpact' 'Accounts' $null 'The running account*').Count | Should Be 0
        }
        It 'disables SP Admin (no replacement) and reports the missing SYS Admin and SOP-Admin' {
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'SP Admin' 'Disable SP Admin (no replacement)').Count | Should Be 1
            @(Get-CrTestFindings $plan 'Info' 'Accounts' 'SYS Admin' 'Account not found (nothing to disable)*').Count | Should Be 1
            @(Get-CrTestFindings $plan 'Info' 'Accounts' 'SOP-Admin' 'Account not found (nothing to disable)*').Count | Should Be 1
        }
        It 'puts the dependents of SP Admin to the operator (D24, O5)' {
            $f = @(Get-CrTestFindings $plan 'Ambiguous' 'Tasks' 'SP Admin' 'Operator decides: move scheduled task \SpMaintenance from SP Admin to ApplicationUser or keep SP Admin enabled*')
            $f.Count | Should Be 1
            @(Get-CrTestFindings $plan 'HighImpact' $null 'SP Admin' 'Move*').Count | Should Be 0
        }
        It 'puts every other enabled account to the operator (D23)' {
            $all = @(Get-CrTestFindings $plan 'Ambiguous' 'Accounts' $null 'Operator decides: disable or keep*')
            $all.Count | Should Be 2
            $admin = @(Get-CrTestFindings $plan 'Ambiguous' 'Accounts' 'OtherAdmin' 'Operator decides: disable or keep OtherAdmin (D23)')
            $admin.Count | Should Be 1
            $admin[0]['Detail'] | Should Match 'Administrators'
            @(Get-CrTestFindings $plan 'Ambiguous' 'Accounts' 'myftpuser').Count | Should Be 1
        }
        It 'changes ApplicationUser with its old password and probes only that account' {
            @(Get-CrTestFindings $plan 'Info' 'Password' 'ApplicationUser' 'Password change with the old password*').Count | Should Be 1
            $probes = @(Get-CrTestFindings $plan 'Info' 'Probe')
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
        It 'lists LOGINS follow-ups for BiCA Admin, BiCA Remote, ApplicationUser and the SQL logins' {
            @(Get-CrTestFindings $plan 'FollowUp' 'LOGINS' 'BiCA Admin').Count | Should Be 1
            @(Get-CrTestFindings $plan 'FollowUp' 'LOGINS' 'BiCA Remote').Count | Should Be 1
            @(Get-CrTestFindings $plan 'FollowUp' 'LOGINS' 'ApplicationUser').Count | Should Be 1
            @(Get-CrTestFindings $plan 'FollowUp' 'LOGINS' 'SQLApplication').Count | Should Be 1
            @(Get-CrTestFindings $plan 'FollowUp' 'LOGINS' 'PUB-User').Count | Should Be 0
            @(Get-CrTestFindings $plan 'FollowUp' 'LOGINS' 'WinAutoUser').Count | Should Be 0
            @(Get-CrTestFindings $plan 'FollowUp' 'LOGINS' 'WinUser1').Count | Should Be 0
        }
        It 'puts the findings into HighImpact and FollowUps' {
            @($plan['HighImpact']).Count | Should BeGreaterThan 0
            @($plan['FollowUps']).Count | Should Be 6
        }
        It 'never creates findings with an unknown severity' {
            $bad = @($plan['Findings'] | Where-Object { @('Drift', 'HighImpact', 'Blocked', 'Ambiguous', 'FollowUp', 'Info') -notcontains $_['Severity'] })
            $bad.Count | Should Be 0
        }
    }
}

Describe 'New-CrPlan on an IPT01-like machine (account model v10.3)' {
    $state = New-CrTestState -Profile IPT01
    $plan = New-CrTestPlan -State $state

    It 'creates nothing: all managed accounts exist' {
        @(Get-CrTestFindings $plan 'Drift' 'Accounts' $null 'Create*').Count | Should Be 0
    }
    It 'sets the passwords of the set accounts without a probe (D9)' {
        foreach ($n in @('BiCA Admin', 'BiCA Remote', 'PUB-User', 'WinAutoUser')) {
            @(Get-CrTestFindings $plan 'Info' 'Password' $n 'Password set (D9: no old password)').Count | Should Be 1
            @(Get-CrTestFindings $plan $null 'Probe' $n).Count | Should Be 0
        }
    }
    It 'leaves the groups of BiCA Remote alone (Remote Desktop Users allowed, the optional helpers group missing)' {
        @(Get-CrTestFindings $plan $null 'Groups' 'BiCA Remote').Count | Should Be 0
    }
    It 'disables the enabled built-in Administrator (replaced by ApplicationUser)' {
        $f = @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'Administrator' 'Disable Administrator (replaced by ApplicationUser)')
        $f.Count | Should Be 1
        $f[0]['Slot'] | Should Be 'AppUser'
    }
    It 'updates the service of BiCA Admin in place (no move) and grants the service right' {
        @(Get-CrTestFindings $plan 'Info' 'Services' 'BiCA Admin' 'SCM credential update, restart pending (D17): AppHelper').Count | Should Be 1
        @(Get-CrTestFindings $plan 'Drift' 'Rights' 'BiCA Admin' 'Grant SeServiceLogonRight*').Count | Should Be 1
        @(Get-CrTestFindings $plan $null $null $null 'Move service AppHelper*').Count | Should Be 0
    }
    It 'disables none of the managed accounts and creates no PUB-User' {
        foreach ($n in @('BiCA Admin', 'BiCA Remote', 'PUB-User', 'WinAutoUser')) {
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' $n ('Disable ' + $n + '*')).Count | Should Be 0
        }
        @(Get-CrTestFindings $plan $null $null 'PUB-User' 'Create PUB-User').Count | Should Be 0
    }
    It 'disables the retired SOP-Admin (no replacement, D22) without asking' {
        @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'SOP-Admin' 'Disable SOP-Admin (no replacement)').Count | Should Be 1
        @(Get-CrTestFindings $plan 'Ambiguous' $null 'SOP-Admin').Count | Should Be 0
    }
    It 'puts the service of SYS Admin to the operator (D24, O5)' {
        @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'SYS Admin' 'Disable SYS Admin (no replacement)').Count | Should Be 1
        @(Get-CrTestFindings $plan 'Ambiguous' 'Services' 'SYS Admin' 'Operator decides: move service LegacySync from SYS Admin to ApplicationUser or keep SYS Admin enabled (D24, O5)').Count | Should Be 1
    }
    It 'has no other enabled accounts' {
        @(Get-CrTestFindings $plan 'Ambiguous' 'Accounts' $null 'Operator decides: disable or keep*').Count | Should Be 0
    }
    It 'has no D25 item when the running account is not disabled' {
        @(Get-CrTestFindings $plan 'HighImpact' 'Accounts' $null 'The running account*').Count | Should Be 0
    }
    It 'switches the admin auto-logon to PUB-User on a non-SM machine' {
        @(Get-CrTestFindings $plan 'Drift' 'AutoLogon' $null 'Switch auto-logon from * to PUB-User*').Count | Should Be 1
    }
    It 'finds no SID overlap' {
        @(Get-CrTestFindings $plan 'Ambiguous' 'Principals').Count | Should Be 0
    }
}

Describe 'New-CrPlan: created and disabled accounts and the auto-logon step' {
    Context 'BiCA Admin is missing: it is created (D21)' {
        Mock Get-CrAutoLogonDecision { return @{ Action = 'NoChange'; CurrentSid = $null; CurrentName = 'Bica Admin'; TargetSid = $null; TargetName = $null; Reasons = @(); OperatorOptions = @(); HighImpact = @() } }
        $state = New-CrTestState -Profile IPT01 -OmitUsers 'BiCA Admin'
        $plan = New-CrTestPlan -State $state

        It 'creates BiCA Admin in its slot and adds it to its role group' {
            $f = @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'BiCA Admin' 'Create BiCA Admin')
            $f.Count | Should Be 1
            $f[0]['Slot'] | Should Be 'BiCAAdmin'
            $f[0]['Detail'] | Should Match 'D21'
            @(Get-CrTestFindings $plan 'Drift' 'Groups' 'BiCA Admin' 'Add to Administrators').Count | Should Be 1
        }
        It 'reports that the created account has no Windows login in SQL Server' {
            @(Get-CrTestFindings $plan 'Info' 'SQL' 'BiCA Admin' '*no Windows login in SQL Server*').Count | Should Be 1
        }
        It 'has no password, probe or flag findings for the account to create, but a LOGINS follow-up' {
            @(Get-CrTestFindings $plan $null 'Password' 'BiCA Admin').Count | Should Be 0
            @(Get-CrTestFindings $plan $null 'Probe' 'BiCA Admin').Count | Should Be 0
            @(Get-CrTestFindings $plan $null 'Flags' 'BiCA Admin').Count | Should Be 0
            @(Get-CrTestFindings $plan 'FollowUp' 'LOGINS' 'BiCA Admin').Count | Should Be 1
        }
        It 'passes only existing accounts as verified to the auto-logon decision' {
            Assert-MockCalled Get-CrAutoLogonDecision -Times 1 -Exactly -Scope Context -ParameterFilter { @($VerifiedSids).Count -eq 4 -and @($VerifiedSids) -notcontains '' }
        }
    }

    Context 'WinAutoUser is disabled: it stays disabled and is not counted as verified (D21)' {
        Mock Get-CrAutoLogonDecision { return @{ Action = 'NoChange'; CurrentSid = $null; CurrentName = 'Bica Admin'; TargetSid = $null; TargetName = $null; Reasons = @(); OperatorOptions = @(); HighImpact = @() } }
        $state = New-CrTestState -Profile IPT01
        (Get-CrTestUser $state 'WinAutoUser')['Disabled'] = $true
        $pubSid = Get-CrTestUserSid $state 'PUB-User'
        $winAutoSid = Get-CrTestUserSid $state 'WinAutoUser'
        $plan = New-CrTestPlan -State $state

        It 'passes PUB-User but not the disabled WinAutoUser as verified' {
            Assert-MockCalled Get-CrAutoLogonDecision -Times 1 -Exactly -Scope Context -ParameterFilter { @($VerifiedSids) -contains $pubSid -and @($VerifiedSids) -notcontains $winAutoSid }
        }
        It 'never disables WinAutoUser' {
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'WinAutoUser' 'Disable*').Count | Should Be 0
        }
    }

    Context 'the AutoLogon slot is blocked' {
        Mock Get-CrAutoLogonDecision { return @{ Action = 'NoChange'; CurrentSid = $null; CurrentName = 'Bica Admin'; TargetSid = $null; TargetName = $null; Reasons = @(); OperatorOptions = @(); HighImpact = @() } }
        $state = New-CrTestState -Profile IPT01
        $pubSid = Get-CrTestUserSid $state 'PUB-User'
        $winAutoSid = Get-CrTestUserSid $state 'WinAutoUser'
        $bicaSid = Get-CrTestUserSid $state 'BiCA Admin'
        $pf = @{ MachineBlocked = $false; BlockedSlots = @{ AutoLogon = 'test' }; Findings = @() }
        $null = New-CrTestPlan -State $state -Preflight $pf

        It 'does not count its accounts as verified' {
            Assert-MockCalled Get-CrAutoLogonDecision -Times 1 -Exactly -Scope Context -ParameterFilter {
                @($VerifiedSids) -notcontains $pubSid -and @($VerifiedSids) -notcontains $winAutoSid -and @($VerifiedSids) -contains $bicaSid
            }
        }
    }
}

Describe 'Get-CrAutoLogonSlot' {
    It 'returns the slot of the entry with the AutoLogon block' {
        $state = New-CrTestState -Profile IPT01
        $resolved = Resolve-CrAccounts -Config (New-CrTestConfig) -State $state
        Get-CrAutoLogonSlot -Resolved $resolved | Should Be 'AutoLogon'
    }
    It 'returns $null without such an entry' {
        $null -eq (Get-CrAutoLogonSlot -Resolved @(@{ Id = 'X'; Kind = 'Windows'; Slot = 'X'; AutoLogon = $null })) | Should Be $true
    }
}

Describe 'New-CrPlan account state findings' {
    It 'clears "password not required" on a managed account' {
        $state = New-CrTestState -Profile IPT01
        (Get-CrTestUser $state 'PUB-User')['PasswordNotRequired'] = $true
        $plan = New-CrTestPlan -State $state
        @(Get-CrTestFindings $plan 'Drift' 'Flags' 'PUB-User' '*UF_PASSWD_NOTREQD*').Count | Should Be 1
    }
    It 'enables a disabled ApplicationUser (EnableIfDisabled, D21)' {
        $state = New-CrTestState -Profile IPT01
        (Get-CrTestUser $state 'ApplicationUser')['Disabled'] = $true
        $plan = New-CrTestPlan -State $state
        @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'ApplicationUser' 'Enable the account (D21)').Count | Should Be 1
        @(Get-CrTestFindings $plan 'Info' 'Accounts' 'ApplicationUser' '*stays disabled*').Count | Should Be 0
    }
    It 'sets the password of a disabled WinAutoUser but does not enable it (D21)' {
        $state = New-CrTestState -Profile IPT01
        (Get-CrTestUser $state 'WinAutoUser')['Disabled'] = $true
        $plan = New-CrTestPlan -State $state
        @(Get-CrTestFindings $plan 'Info' 'Accounts' 'WinAutoUser' 'Account is disabled: it gets the new password but stays disabled*').Count | Should Be 1
        @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'WinAutoUser' 'Enable*').Count | Should Be 0
        @(Get-CrTestFindings $plan 'Info' 'Password' 'WinAutoUser' 'Password set (D9: no old password)').Count | Should Be 1
    }
    It 'says the old password cannot be test-logged-on when ForceGuest leaves no logon type (D16)' {
        $state = New-CrTestState -Profile IPT01
        $state.Policy.ForceGuest = $true
        $sid = Get-CrTestUserSid $state 'ApplicationUser'
        Set-CrTestRight -State $state -Right 'SeDenyInteractiveLogonRight' -Sids @($sid)
        Set-CrTestRight -State $state -Right 'SeDenyBatchLogonRight' -Sids @($sid)
        Set-CrTestRight -State $state -Right 'SeDenyServiceLogonRight' -Sids @($sid)
        $plan = New-CrTestPlan -State $state
        $f = @(Get-CrTestFindings $plan 'Info' 'Probe' 'ApplicationUser')
        $f.Count | Should Be 1
        $f[0]['Message'] | Should Match 'cannot be verified by a test logon'
        $f[0]['Detail'] | Should Not Match 'Network is used'
    }
    It 'reports a retired running account (D25): log on as BiCA Remote next time' {
        $state = New-CrTestState -Profile IPT01
        $plan = New-CrTestPlan -State $state -RunningSid (Get-CrTestUserSid $state 'SOP-Admin')
        @(Get-CrTestFindings $plan 'HighImpact' 'Accounts' 'SOP-Admin' 'The running account SOP-Admin is disabled at the end; log on as BiCA Remote next time (D25)').Count | Should Be 1
        @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'SOP-Admin' 'Disable SOP-Admin (no replacement)')[0]['Detail'] | Should Match 'last step \(D25\)'
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
        # BiCAAdmin, BiCARemote, AppUser, AutoLogon, Retired, WinUsers, FtpUsers
        @(Get-CrTestFindings $plan 'Blocked' 'Accounts').Count | Should Be 7
        @(Get-CrTestFindings $plan $null 'Accounts' $null 'Create*').Count | Should Be 0
        @(Get-CrTestFindings $plan 'Ambiguous' 'Accounts' $null 'Operator decides*').Count | Should Be 0
    }
}

Describe 'New-CrPlan with -Only' {
    Context 'only the BiCAAdmin slot' {
        Mock Get-CrPathAllowSids { return , @() }
        $state = New-CrTestState -Profile SM
        $plan = New-CrTestPlan -State $state -Only @('BiCAAdmin')

        It 'skips other slots, check-mode accounts, retired and other accounts' {
            @(Get-CrTestFindings $plan $null 'SQL').Count | Should Be 0
            foreach ($n in @('BiCA Remote', 'ApplicationUser', 'WinAutoUser', 'WinUser1', 'SP Admin')) {
                @(Get-CrTestFindings $plan $null $null $n).Count | Should Be 0
            }
            @(Get-CrTestFindings $plan 'Ambiguous' 'Accounts' $null 'Operator decides: disable or keep*').Count | Should Be 0
        }
        It 'keeps the findings of the selected slot' {
            @(Get-CrTestFindings $plan 'Info' 'Password' 'BiCA Admin' 'Password set (D9: no old password)').Count | Should Be 1
            @(Get-CrTestFindings $plan 'FollowUp' 'LOGINS' 'BiCA Admin').Count | Should Be 1
        }
        It 'still runs the auto-logon step because BiCA Admin (managed by this slot) is the current auto-logon account' {
            @(Get-CrTestFindings $plan 'Drift' 'AutoLogon' $null 'Turn auto-logon off*').Count | Should Be 1
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
