$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$lib = Join-Path $here '..\src\lib'
foreach ($m in @('Compat', 'Config', 'Rights', 'Principals', 'Sql', 'AutoLogon', 'Plan')) { . (Join-Path $lib ($m + '.ps1')) }
. (Join-Path $here 'Fixtures.ps1')

# Pester 3.4 keeps a Mock for the whole Describe/Context it is defined in: every Mock lives in its own Context.
# Account model PLAN v10.6 (D18, D21-D29): SOP-Admin (the operator's account; replaces BiCA Admin and BiCA Remote and gets
# their SQL Server access), ApplicationUser (replaces RID-500) and the auto-logon accounts PUB-User / WinAutoUser are
# managed; SP Admin is managed too (v10.7, D30: created if missing, Administrators only, nothing else); SYS Admin (also
# spelled SYS-Admin) is retired; no account is kept untouched (Mode Keep); the default config has no SQL login slots (D27).
# The fixtures have neither SOP-Admin nor SP Admin, so they are created unless a test adds them.
# v10.4 (D24): the dependents of retired and operator-disabled accounts always move to ApplicationUser; nothing moves to
# an account created in this run (the account with dependents stays enabled).

function New-CrTestPlan {
    param($State, [string[]]$Only, $Preflight, [string]$RunningSid = 'S-1-5-21-9-9-9-9999', $Config)
    if (-not $Config) { $Config = New-CrTestConfig }
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

Describe 'New-CrPlan on an SM-like machine (account model v10.6)' {
    Context 'audit run as BiCA Remote' {
        Mock Get-CrPathAllowSids { return , @('S-1-5-32-545', 'S-1-5-18', 'S-1-5-32-544') }
        $state = New-CrTestState -Profile SM
        $plan = New-CrTestPlan -State $state -RunningSid (Get-CrTestUserSid $state 'BiCA Remote')

        It 'reports drift' {
            $plan['Drift'] | Should Be $true
        }
        It 'creates SOP-Admin (D28) and SP Admin (D30); PUB-User is never created (D21)' {
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' $null 'Create*').Count | Should Be 2
            $f = @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'SOP-Admin' 'Create SOP-Admin')
            $f.Count | Should Be 1
            $f[0]['Slot'] | Should Be 'SOPAdmin'
            $f = @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'SP Admin' 'Create SP Admin')
            $f.Count | Should Be 1
            $f[0]['Slot'] | Should Be 'SPAdmin'
            @(Get-CrTestFindings $plan $null $null 'PUB-User' 'Create PUB-User').Count | Should Be 0
            @(Get-CrTestFindings $plan 'Info' 'Accounts' 'PUB-User' 'Account not found (never created): PUB-User').Count | Should Be 1
        }
        It 'adds SOP-Admin to Administrators, Remote Desktop Users and Offer Remote Assistance Helpers' {
            foreach ($g in @('Administrators', 'Remote Desktop Users', 'Offer Remote Assistance Helpers')) {
                @(Get-CrTestFindings $plan 'Drift' 'Groups' 'SOP-Admin' ('Add to ' + $g)).Count | Should Be 1
            }
            @(Get-CrTestFindings $plan $null 'Password' 'SOP-Admin').Count | Should Be 0
        }
        It 'grants SOP-Admin the SQL Server access of BiCA Admin and BiCA Remote (D29)' {
            $f = @(Get-CrTestFindings $plan 'Drift' 'SQL' 'SOP-Admin' 'SQL Server: create the Windows login SM-TEST01\SOP-Admin, add it to the server role sysadmin')
            $f.Count | Should Be 1
            $f[0]['Slot'] | Should Be 'SOPAdmin'
            $f[0]['Detail'] | Should Be 'The same access as BiCA Admin (OLD-NAME01\BiCA Admin), BiCA Remote (OLD-NAME01\BiCA Remote) (D29); written after its logon test, as the running account'
            @(Get-CrTestFindings $plan $null 'SQL' 'SOP-Admin' '*no Windows login in SQL Server*').Count | Should Be 0
            @(Get-CrTestFindings $plan 'HighImpact' 'SQL').Count | Should Be 0
        }
        It 'sets the password of WinAutoUser without a probe (D9); the BiCA accounts get none' {
            @(Get-CrTestFindings $plan 'Info' 'Password' 'WinAutoUser' 'Password set (D9: no old password)').Count | Should Be 1
            foreach ($n in @('BiCA Admin', 'BiCA Remote')) {
                @(Get-CrTestFindings $plan $null 'Password' $n).Count | Should Be 0
                @(Get-CrTestFindings $plan $null 'Groups' $n).Count | Should Be 0
                @(Get-CrTestFindings $plan $null 'Flags' $n).Count | Should Be 0
            }
        }
        It 'disables BiCA Admin, replaced by SOP-Admin once it is verified and has their SQL Server access (D22, D28, D29)' {
            $f = @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'BiCA Admin' 'Disable BiCA Admin (replaced by SOP-Admin)')
            $f.Count | Should Be 1
            $f[0]['Slot'] | Should Be 'SOPAdmin'
            $f[0]['Detail'] | Should Be 'D22: disabled only after SOP-Admin is verified in this run and has their SQL Server access (D29); groups and password stay unchanged'
            @(Get-CrTestFindings $plan $null $null 'BiCA Admin' 'Not disabled*').Count | Should Be 0
        }
        It 'disables the running account BiCA Remote last (D25): log on as SOP-Admin next time' {
            $f = @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'BiCA Remote' 'Disable BiCA Remote (replaced by SOP-Admin)')
            $f.Count | Should Be 1
            $f[0]['Detail'] | Should Match 'last step \(D25\)'
            @(Get-CrTestFindings $plan 'HighImpact' 'Accounts' 'BiCA Remote' 'The running account BiCA Remote is disabled at the end; log on as SOP-Admin next time (D25)').Count | Should Be 1
            @(Get-CrTestFindings $plan 'HighImpact' 'Accounts' $null 'The running account*').Count | Should Be 1
        }
        It 'leaves the already disabled built-in Administrator alone' {
            @(Get-CrTestFindings $plan 'Drift' $null 'LocalAdm').Count | Should Be 0
            @(Get-CrTestFindings $plan 'Info' 'Accounts' 'LocalAdm' 'Already disabled (replaced by ApplicationUser)').Count | Should Be 1
        }
        It 'does not enforce groups or flags on retired or replaced accounts' {
            foreach ($n in @('SYS Admin', 'LocalAdm', 'BiCA Admin', 'BiCA Remote')) {
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
        It 'disables SYS Admin (no replacement) and reports the missing SYS-Admin' {
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'SYS Admin' 'Disable SYS Admin (no replacement)').Count | Should Be 1
            @(Get-CrTestFindings $plan 'Info' 'Accounts' 'SYS Admin' 'Account not found*').Count | Should Be 0
            @(Get-CrTestFindings $plan 'Info' 'Accounts' 'SYS-Admin' 'Account not found (nothing to disable)*').Count | Should Be 1
        }
        It 'creates SP Admin in Administrators only and gives it nothing else: no SQL login, no LOGINS follow-up (D30, v10.7)' {
            @(Get-CrTestFindings $plan 'Drift' 'Groups' 'SP Admin' 'Add to Administrators').Count | Should Be 1
            @(Get-CrTestFindings $plan 'Drift' 'Groups' 'SP Admin').Count | Should Be 1
            @(Get-CrTestFindings $plan 'Drift' 'SQL' 'SP Admin').Count | Should Be 0
            @(Get-CrTestFindings $plan 'Info' 'SQL' 'SP Admin' '*no Windows login in SQL Server*').Count | Should Be 1
            @(Get-CrTestFindings $plan 'FollowUp' $null 'SP Admin').Count | Should Be 0
            @(Get-CrTestFindings $plan $null $null 'SP Admin' 'Kept untouched*').Count | Should Be 0
        }
        It 'moves the dependents of SYS Admin to ApplicationUser (D24, v10.4)' {
            $f = @(Get-CrTestFindings $plan 'HighImpact' 'Tasks' 'SYS Admin' 'Move scheduled task \SpMaintenance from SYS Admin to ApplicationUser (D24)')
            $f.Count | Should Be 1
            $f[0]['Detail'] | Should Be 'Only to a verified ApplicationUser with its new password from this run; otherwise SYS Admin stays enabled'
            $f[0]['Slot'] | Should BeNullOrEmpty
            @(Get-CrTestFindings $plan 'Ambiguous' $null 'SYS Admin').Count | Should Be 0
            @(Get-CrTestFindings $plan 'HighImpact' 'Accounts' 'SYS Admin' 'Not disabled*').Count | Should Be 0
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
        It 'lists LOGINS follow-ups for SOP-Admin (in place of the BiCA entries) and ApplicationUser, none for the SQL logins (D27)' {
            $f = @(Get-CrTestFindings $plan 'FollowUp' 'LOGINS' 'SOP-Admin')
            $f.Count | Should Be 1
            $f[0]['Detail'] | Should Be 'Replaces the LOGINS entries of: BiCA Admin, BiCA Remote'
            @(Get-CrTestFindings $plan 'FollowUp' 'LOGINS' 'BiCA Admin').Count | Should Be 0
            @(Get-CrTestFindings $plan 'FollowUp' 'LOGINS' 'BiCA Remote').Count | Should Be 0
            @(Get-CrTestFindings $plan 'FollowUp' 'LOGINS' 'ApplicationUser').Count | Should Be 1
            @(Get-CrTestFindings $plan 'FollowUp' 'LOGINS' 'SQLApplication').Count | Should Be 0
            @(Get-CrTestFindings $plan 'FollowUp' 'LOGINS' 'PUB-User').Count | Should Be 0
            @(Get-CrTestFindings $plan 'FollowUp' 'LOGINS' 'WinAutoUser').Count | Should Be 0
            @(Get-CrTestFindings $plan 'FollowUp' 'LOGINS' 'WinUser1').Count | Should Be 0
        }
        It 'puts the findings into HighImpact and FollowUps' {
            @($plan['HighImpact']).Count | Should BeGreaterThan 0
            @($plan['FollowUps']).Count | Should Be 2
        }
        It 'never creates findings with an unknown severity' {
            $bad = @($plan['Findings'] | Where-Object { @('Drift', 'HighImpact', 'Blocked', 'Ambiguous', 'FollowUp', 'Info') -notcontains $_['Severity'] })
            $bad.Count | Should Be 0
        }
    }
}

Describe 'New-CrPlan on an IPT01-like machine (account model v10.6)' {
    $state = New-CrTestState -Profile IPT01
    $plan = New-CrTestPlan -State $state

    It 'creates SOP-Admin and SP Admin; SOP-Admin goes to Administrators and Remote Desktop Users (the optional helpers group is missing)' {
        $f = @(Get-CrTestFindings $plan 'Drift' 'Accounts' $null 'Create*')
        $f.Count | Should Be 2
        $f[0]['Message'] | Should Be 'Create SOP-Admin'
        $f[1]['Message'] | Should Be 'Create SP Admin'
        @(Get-CrTestFindings $plan 'Drift' 'Groups' 'SOP-Admin' 'Add to Administrators').Count | Should Be 1
        @(Get-CrTestFindings $plan 'Drift' 'Groups' 'SOP-Admin' 'Add to Remote Desktop Users').Count | Should Be 1
        @(Get-CrTestFindings $plan 'Drift' 'Groups' 'SOP-Admin').Count | Should Be 2
    }
    It 'sets the passwords of the auto-logon accounts without a probe (D9)' {
        foreach ($n in @('PUB-User', 'WinAutoUser')) {
            @(Get-CrTestFindings $plan 'Info' 'Password' $n 'Password set (D9: no old password)').Count | Should Be 1
            @(Get-CrTestFindings $plan $null 'Probe' $n).Count | Should Be 0
        }
    }
    It 'disables the enabled built-in Administrator (replaced by ApplicationUser)' {
        $f = @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'Administrator' 'Disable Administrator (replaced by ApplicationUser)')
        $f.Count | Should Be 1
        $f[0]['Slot'] | Should Be 'AppUser'
    }
    It 'keeps BiCA Admin and its service AppHelper: SOP-Admin is created in this run (D24)' {
        $f = @(Get-CrTestFindings $plan 'HighImpact' 'Accounts' 'BiCA Admin' 'Not disabled: SOP-Admin is created in this run, so the services, scheduled tasks and COM+ applications of BiCA Admin are not moved to it; migrate them manually (D24)')
        $f.Count | Should Be 1
        $f[0]['Slot'] | Should Be 'SOPAdmin'
        @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'BiCA Admin' 'Disable*').Count | Should Be 0
        @(Get-CrTestFindings $plan $null $null $null 'Move service AppHelper*').Count | Should Be 0
        @(Get-CrTestFindings $plan $null 'Services' 'BiCA Admin').Count | Should Be 0
    }
    It 'disables BiCA Remote (no dependents), replaced by SOP-Admin (D28)' {
        @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'BiCA Remote' 'Disable BiCA Remote (replaced by SOP-Admin)').Count | Should Be 1
    }
    It 'disables none of the managed accounts and creates no PUB-User' {
        foreach ($n in @('PUB-User', 'WinAutoUser', 'ApplicationUser')) {
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' $n ('Disable ' + $n + '*')).Count | Should Be 0
        }
        @(Get-CrTestFindings $plan $null $null 'PUB-User' 'Create PUB-User').Count | Should Be 0
    }
    It 'grants SOP-Admin the SQL Server login on the Express instance (D29)' {
        @(Get-CrTestFindings $plan 'Drift' 'SQL' 'SOP-Admin' 'SQL Server: create the Windows login IPT01-TEST01\SOP-Admin, add it to the server role sysadmin').Count | Should Be 1
    }
    It 'disables the retired SYS-Admin (no replacement, D22) without asking' {
        @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'SYS-Admin' 'Disable SYS-Admin (no replacement)').Count | Should Be 1
        @(Get-CrTestFindings $plan 'Ambiguous' $null 'SYS-Admin').Count | Should Be 0
    }
    It 'moves the service of SYS Admin to ApplicationUser (D24, v10.4)' {
        @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'SYS Admin' 'Disable SYS Admin (no replacement)').Count | Should Be 1
        @(Get-CrTestFindings $plan 'HighImpact' 'Services' 'SYS Admin' 'Move service LegacySync from SYS Admin to ApplicationUser (D24)').Count | Should Be 1
        @(Get-CrTestFindings $plan 'Ambiguous' $null 'SYS Admin').Count | Should Be 0
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
    Context 'SOP-Admin is missing: it is created (D21, D28)' {
        Mock Get-CrAutoLogonDecision { return @{ Action = 'NoChange'; CurrentSid = $null; CurrentName = 'Bica Admin'; TargetSid = $null; TargetName = $null; Reasons = @(); OperatorOptions = @(); HighImpact = @() } }
        $state = New-CrTestState -Profile IPT01
        $plan = New-CrTestPlan -State $state

        It 'creates SOP-Admin in its slot' {
            $f = @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'SOP-Admin' 'Create SOP-Admin')
            $f.Count | Should Be 1
            $f[0]['Slot'] | Should Be 'SOPAdmin'
            $f[0]['Detail'] | Should Match 'D21'
        }
        It 'grants its SQL Server login instead of reporting that it has none (D29)' {
            @(Get-CrTestFindings $plan 'Info' 'SQL' 'SOP-Admin' '*no Windows login in SQL Server*').Count | Should Be 0
            @(Get-CrTestFindings $plan 'Drift' 'SQL' 'SOP-Admin').Count | Should Be 1
        }
        It 'has no password, probe or flag findings for the account to create, but a LOGINS follow-up' {
            @(Get-CrTestFindings $plan $null 'Password' 'SOP-Admin').Count | Should Be 0
            @(Get-CrTestFindings $plan $null 'Probe' 'SOP-Admin').Count | Should Be 0
            @(Get-CrTestFindings $plan $null 'Flags' 'SOP-Admin').Count | Should Be 0
            @(Get-CrTestFindings $plan 'FollowUp' 'LOGINS' 'SOP-Admin').Count | Should Be 1
        }
        It 'passes only existing accounts as verified to the auto-logon decision' {
            Assert-MockCalled Get-CrAutoLogonDecision -Times 1 -Exactly -Scope Context -ParameterFilter { @($VerifiedSids).Count -eq 3 -and @($VerifiedSids) -notcontains '' }
        }
    }

    Context 'ApplicationUser is missing: the created account still reports that it has no SQL Server login' {
        Mock Get-CrAutoLogonDecision { return @{ Action = 'NoChange'; CurrentSid = $null; CurrentName = 'Bica Admin'; TargetSid = $null; TargetName = $null; Reasons = @(); OperatorOptions = @(); HighImpact = @() } }
        $state = New-CrTestState -Profile IPT01 -OmitUsers 'ApplicationUser'
        $plan = New-CrTestPlan -State $state

        It 'reports that the created ApplicationUser has no Windows login in SQL Server (PLAN 1.1)' {
            @(Get-CrTestFindings $plan 'Info' 'SQL' 'ApplicationUser' '*no Windows login in SQL Server*').Count | Should Be 1
        }
    }

    Context 'an existing SOP-Admin is taken over; BiCA Remote is already disabled (QS-K1 state, D28)' {
        Mock Get-CrAutoLogonDecision { return @{ Action = 'NoChange'; CurrentSid = $null; CurrentName = 'Bica Admin'; TargetSid = $null; TargetName = $null; Reasons = @(); OperatorOptions = @(); HighImpact = @() } }
        $state = New-CrTestState -Profile IPT01
        $sop = Add-CrTestUser -State $state -Name 'SOP-Admin' -Groups @('Administrators') -PasswordNeverExpires
        $remote = Get-CrTestUser $state 'BiCA Remote'
        $remote.Disabled = $true
        $remote.Flags = $remote.Flags -bor 0x2
        $plan = New-CrTestPlan -State $state

        It 'sets the password of SOP-Admin and enforces its role (no Keep entry any more)' {
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'SOP-Admin' 'Create*').Count | Should Be 0
            @(Get-CrTestFindings $plan 'Info' 'Password' 'SOP-Admin' 'Password set (D9: no old password)').Count | Should Be 1
            @(Get-CrTestFindings $plan 'Drift' 'Groups' 'SOP-Admin' 'Add to Remote Desktop Users').Count | Should Be 1
            @(Get-CrTestFindings $plan 'Drift' 'Flags' 'SOP-Admin' 'Set "user cannot change password"').Count | Should Be 1
            @(Get-CrTestFindings $plan $null $null 'SOP-Admin' 'Kept untouched*').Count | Should Be 0
        }
        It 'counts SOP-Admin as verified for the auto-logon decision' {
            Assert-MockCalled Get-CrAutoLogonDecision -Times 1 -Exactly -Scope Context -ParameterFilter { @($VerifiedSids) -contains $sop.Sid }
        }
        It 'reports the disabled BiCA Remote as Info only' {
            @(Get-CrTestFindings $plan 'Info' 'Accounts' 'BiCA Remote' 'Already disabled (replaced by SOP-Admin)').Count | Should Be 1
            @(Get-CrTestFindings $plan 'Drift' $null 'BiCA Remote').Count | Should Be 0
        }
        It 'disables BiCA Admin and moves its service AppHelper to SOP-Admin (D24)' {
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'BiCA Admin' 'Disable BiCA Admin (replaced by SOP-Admin)').Count | Should Be 1
            $f = @(Get-CrTestFindings $plan 'HighImpact' 'Services' 'BiCA Admin' 'Move service AppHelper from BiCA Admin to SOP-Admin (D24)')
            $f.Count | Should Be 1
            $f[0]['Slot'] | Should Be 'SOPAdmin'
        }
        It 'still copies the SQL access of the disabled BiCA Remote (its login is sysadmin)' {
            $f = @(Get-CrTestFindings $plan 'Drift' 'SQL' 'SOP-Admin')
            $f.Count | Should Be 1
            $f[0]['Detail'] | Should Match 'BiCA Remote \(OLD-NAME01\\BiCA Remote\)'
        }
    }

    Context 'a disabled SOP-Admin is enabled (EnableIfDisabled)' {
        Mock Get-CrAutoLogonDecision { return @{ Action = 'NoChange'; CurrentSid = $null; CurrentName = 'Bica Admin'; TargetSid = $null; TargetName = $null; Reasons = @(); OperatorOptions = @(); HighImpact = @() } }
        $state = New-CrTestState -Profile IPT01
        [void](Add-CrTestUser -State $state -Name 'SOP-Admin' -Groups @('Administrators') -PasswordNeverExpires -Disabled)
        $plan = New-CrTestPlan -State $state

        It 'enables it and sets its password' {
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'SOP-Admin' 'Enable the account (D21)').Count | Should Be 1
            @(Get-CrTestFindings $plan 'Info' 'Password' 'SOP-Admin' 'Password set (D9: no old password)').Count | Should Be 1
            @(Get-CrTestFindings $plan 'Info' 'Accounts' 'SOP-Admin' '*stays disabled*').Count | Should Be 0
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
        $appSid = Get-CrTestUserSid $state 'ApplicationUser'
        $pf = @{ MachineBlocked = $false; BlockedSlots = @{ AutoLogon = 'test' }; Findings = @() }
        $null = New-CrTestPlan -State $state -Preflight $pf

        It 'does not count its accounts as verified' {
            Assert-MockCalled Get-CrAutoLogonDecision -Times 1 -Exactly -Scope Context -ParameterFilter {
                @($VerifiedSids) -notcontains $pubSid -and @($VerifiedSids) -notcontains $winAutoSid -and @($VerifiedSids) -contains $appSid
            }
        }
    }
}

Describe 'New-CrPlan: SQL Server access and logon rights of SOP-Admin (D28, D29)' {
    Context 'SQL Server is installed but stopped' {
        Mock Get-CrPathAllowSids { return , @() }
        $state = New-CrTestState -Profile SM
        $state.Sql.ServiceState = 'Stopped'
        $state.Sql.Connected = $false
        $state.Sql.Logins = @()
        $plan = New-CrTestPlan -State $state

        It 'says that the access cannot be checked' {
            $f = @(Get-CrTestFindings $plan 'HighImpact' 'SQL' 'SOP-Admin' 'The SQL Server access of SOP-Admin cannot be checked: the default SQL Server instance is not running (state Stopped)*')
            $f.Count | Should Be 1
            @(Get-CrTestFindings $plan 'Drift' 'SQL').Count | Should Be 0
        }
        It 'keeps both BiCA accounts enabled' {
            foreach ($n in @('BiCA Admin', 'BiCA Remote')) {
                $f = @(Get-CrTestFindings $plan 'HighImpact' 'Accounts' $n 'Not disabled: the SQL Server access of SOP-Admin cannot be checked*')
                $f.Count | Should Be 1
                $f[0]['Detail'] | Should Match 'keeps its current password'
                @(Get-CrTestFindings $plan 'Drift' 'Accounts' $n 'Disable*').Count | Should Be 0
            }
        }
    }

    Context 'the running account is not sysadmin (preflight SqlWriteBlocked)' {
        Mock Get-CrPathAllowSids { return , @() }
        $state = New-CrTestState -Profile SM
        $pf = @{ MachineBlocked = $false; BlockedSlots = @{}; Findings = @(); SqlWriteBlocked = 'the running account (SM-TEST01\Someone) is not sysadmin' }
        $plan = New-CrTestPlan -State $state -Preflight $pf

        It 'reports the grant as drift that cannot be applied now' {
            @(Get-CrTestFindings $plan 'Drift' 'SQL' 'SOP-Admin').Count | Should Be 1
            @(Get-CrTestFindings $plan 'HighImpact' 'SQL' 'SOP-Admin' 'The SQL Server access of SOP-Admin cannot be granted now: the running account (SM-TEST01\Someone) is not sysadmin (D29)').Count | Should Be 1
        }
        It 'keeps both BiCA accounts enabled' {
            foreach ($n in @('BiCA Admin', 'BiCA Remote')) {
                @(Get-CrTestFindings $plan 'HighImpact' 'Accounts' $n 'Not disabled: SOP-Admin cannot get the SQL Server access of the accounts it replaces: the running account*').Count | Should Be 1
                @(Get-CrTestFindings $plan 'Drift' 'Accounts' $n 'Disable*').Count | Should Be 0
            }
        }
    }

    Context 'SOP-Admin exists and its login is sysadmin already' {
        Mock Get-CrPathAllowSids { return , @() }
        $state = New-CrTestState -Profile SM
        $sop = Add-CrTestUser -State $state -Name 'SOP-Admin' -Groups @('Administrators', 'Remote Desktop Users', 'Offer Remote Assistance Helpers') -PasswordNeverExpires -CannotChangePassword
        $state.Sql.Logins = @($state.Sql.Logins) + @(New-CrTestSqlLogin -Name 'SM-TEST01\SOP-Admin' -Type 'WINDOWS_LOGIN' -Sid $sop.Sid -Sysadmin)
        $plan = New-CrTestPlan -State $state

        It 'reports the access as in place and disables both BiCA accounts' {
            @(Get-CrTestFindings $plan 'Drift' 'SQL').Count | Should Be 0
            @(Get-CrTestFindings $plan 'Info' 'SQL' 'SOP-Admin' 'SQL Server: SOP-Admin has the access of BiCA Admin (OLD-NAME01\BiCA Admin), BiCA Remote (OLD-NAME01\BiCA Remote) (D29)').Count | Should Be 1
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'BiCA Admin' 'Disable BiCA Admin (replaced by SOP-Admin)').Count | Should Be 1
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'BiCA Remote' 'Disable BiCA Remote (replaced by SOP-Admin)').Count | Should Be 1
            @(Get-CrTestFindings $plan 'Drift' $null 'SOP-Admin').Count | Should Be 0
        }
    }

    Context 'no SQL Server on the machine' {
        Mock Get-CrPathAllowSids { return , @() }
        $state = New-CrTestState -Profile SM
        $state.Sql = @{ DefaultInstancePresent = $false; OtherInstances = @(); Connected = $false; Error = $null; Logins = @(); MasterFiles = @(); AgentJobs = @() }
        $plan = New-CrTestPlan -State $state

        It 'has no SQL finding and disables both BiCA accounts' {
            @(Get-CrTestFindings $plan $null 'SQL').Count | Should Be 0
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'BiCA Admin' 'Disable BiCA Admin (replaced by SOP-Admin)').Count | Should Be 1
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'BiCA Remote' 'Disable BiCA Remote (replaced by SOP-Admin)').Count | Should Be 1
        }
    }

    Context 'a named instance next to the default instance' {
        Mock Get-CrPathAllowSids { return , @() }
        $state = New-CrTestState -Profile SM
        $state.Sql.OtherInstances = @('SQLEXPRESS')
        $plan = New-CrTestPlan -State $state

        It 'reports it as not covered' {
            @(Get-CrTestFindings $plan 'HighImpact' 'SQL' 'SOP-Admin' 'SQL Server instance SQLEXPRESS is not covered*').Count | Should Be 1
        }
    }

    Context 'SOP-Admin is denied RDP logon (IPT01)' {
        Mock Get-CrAutoLogonDecision { return @{ Action = 'NoChange'; CurrentSid = $null; CurrentName = 'Bica Admin'; TargetSid = $null; TargetName = $null; Reasons = @(); OperatorOptions = @(); HighImpact = @() } }
        $state = New-CrTestState -Profile IPT01
        $sop = Add-CrTestUser -State $state -Name 'SOP-Admin' -Groups @('Administrators', 'Remote Desktop Users') -PasswordNeverExpires -CannotChangePassword
        Add-CrTestRight -State $state -Right 'SeDenyRemoteInteractiveLogonRight' -Sids @($sop.Sid)
        $plan = New-CrTestPlan -State $state

        It 'keeps BiCA Remote enabled: it can log on over RDP, SOP-Admin cannot' {
            $f = @(Get-CrTestFindings $plan 'HighImpact' 'Accounts' 'BiCA Remote' 'Not disabled: SOP-Admin would not be allowed to log on over RDP as BiCA Remote can (logon right not granted, or denied; D28)')
            $f.Count | Should Be 1
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'BiCA Remote' 'Disable*').Count | Should Be 0
        }
        It 'still disables BiCA Admin, which is denied RDP itself and may log on locally like SOP-Admin' {
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'BiCA Admin' 'Disable BiCA Admin (replaced by SOP-Admin)').Count | Should Be 1
        }
    }

    Context 'a created SOP-Admin would be denied local logon through a group (SM)' {
        Mock Get-CrPathAllowSids { return , @() }
        $state = New-CrTestState -Profile SM
        Add-CrTestRight -State $state -Right 'SeDenyInteractiveLogonRight' -Sids @('S-1-5-32-555')
        $plan = New-CrTestPlan -State $state

        It 'keeps BiCA Admin, which may log on locally, enabled' {
            @(Get-CrTestFindings $plan 'HighImpact' 'Accounts' 'BiCA Admin' 'Not disabled: SOP-Admin would not be allowed to log on locally as BiCA Admin can*').Count | Should Be 1
        }
        It 'disables BiCA Remote, which is denied local logon itself' {
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'BiCA Remote' 'Disable BiCA Remote (replaced by SOP-Admin)').Count | Should Be 1
        }
    }
}

Describe 'New-CrPlan: ApplicationUser is created in this run (D24, v10.4)' {
    # A created account has a new SID: nothing is moved to it, so an account with movable dependents stays enabled.
    function Add-CrTestService {
        param($State, [string]$Name, [string]$Sid)
        $svc = @{ Name = $Name; DisplayName = $Name; StartName = '.\synthetic'; StartNameSid = $Sid; StartMode = 'Auto'; State = 'Running'
                  PathExecutable = 'C:\App\Synthetic.exe'; DependentServices = @(); DependsOn = @() }
        $State.Services = @($State.Services) + @($svc)
    }

    Context 'the built-in Administrator runs a service, SYS Admin runs LegacySync, SYS-Admin runs nothing' {
        Mock Get-CrAutoLogonDecision { return @{ Action = 'NoChange'; CurrentSid = $null; CurrentName = 'Bica Admin'; TargetSid = $null; TargetName = $null; Reasons = @(); OperatorOptions = @(); HighImpact = @() } }
        $state = New-CrTestState -Profile IPT01 -OmitUsers 'ApplicationUser'
        Add-CrTestService -State $state -Name 'AdminJob' -Sid (Get-CrTestUserSid $state 'Administrator')
        $plan = New-CrTestPlan -State $state
        $sysAdminSid = Get-CrTestUserSid $state 'SYS Admin'

        It 'creates ApplicationUser (D21)' {
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'ApplicationUser' 'Create ApplicationUser').Count | Should Be 1
        }
        It 'keeps the replaced Administrator enabled with one HighImpact item and no move' {
            $f = @(Get-CrTestFindings $plan 'HighImpact' 'Accounts' 'Administrator' 'Not disabled: ApplicationUser is created in this run, so the services, scheduled tasks and COM+ applications of Administrator are not moved to it; migrate them manually (D24)')
            $f.Count | Should Be 1
            $f[0]['Slot'] | Should Be 'AppUser'
            $f[0]['Detail'] | Should Be 'A created account has a new SID: no SQL login, ACLs or profile of Administrator'
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'Administrator' 'Disable*').Count | Should Be 0
            @(Get-CrTestFindings $plan $null $null 'Administrator' 'Move*').Count | Should Be 0
            @(Get-CrTestFindings $plan $null $null 'Administrator').Count | Should Be 1
        }
        It 'keeps the retired SYS Admin enabled with one HighImpact item and no move' {
            $f = @(Get-CrTestFindings $plan 'HighImpact' 'Accounts' 'SYS Admin' 'Not disabled: ApplicationUser is created in this run, so the services, scheduled tasks and COM+ applications of SYS Admin are not moved to it; migrate them manually (D24)')
            $f.Count | Should Be 1
            $f[0]['Slot'] | Should BeNullOrEmpty
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'SYS Admin' 'Disable*').Count | Should Be 0
            @(Get-CrTestFindings $plan $null $null 'SYS Admin' 'Move*').Count | Should Be 0
            @(Get-CrTestFindings $plan 'Ambiguous' $null 'SYS Admin').Count | Should Be 0
        }
        It 'disables the retired SYS-Admin without dependents as usual' {
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'SYS-Admin' 'Disable SYS-Admin (no replacement)').Count | Should Be 1
            @(Get-CrTestFindings $plan $null $null 'SYS-Admin' 'Not disabled*').Count | Should Be 0
        }
        It 'has no D25 item when the running retired account stays enabled' {
            $running = New-CrTestPlan -State $state -RunningSid $sysAdminSid
            @(Get-CrTestFindings $running 'HighImpact' 'Accounts' 'SYS Admin' 'The running account*').Count | Should Be 0
            @(Get-CrTestFindings $running 'HighImpact' 'Accounts' 'SYS Admin' 'Not disabled*').Count | Should Be 1
        }
    }

    Context 'the built-in Administrator has no dependents' {
        Mock Get-CrAutoLogonDecision { return @{ Action = 'NoChange'; CurrentSid = $null; CurrentName = 'Bica Admin'; TargetSid = $null; TargetName = $null; Reasons = @(); OperatorOptions = @(); HighImpact = @() } }
        $state = New-CrTestState -Profile IPT01 -OmitUsers 'ApplicationUser'
        $plan = New-CrTestPlan -State $state

        It 'disables it as usual (replaced by ApplicationUser)' {
            $f = @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'Administrator' 'Disable Administrator (replaced by ApplicationUser)')
            $f.Count | Should Be 1
            $f[0]['Slot'] | Should Be 'AppUser'
            @(Get-CrTestFindings $plan $null $null 'Administrator' 'Not disabled*').Count | Should Be 0
        }
        It 'still keeps SYS Admin (service LegacySync) enabled' {
            @(Get-CrTestFindings $plan 'HighImpact' 'Accounts' 'SYS Admin' 'Not disabled: ApplicationUser is created in this run*').Count | Should Be 1
        }
    }

    Context 'ApplicationUser exists' {
        Mock Get-CrAutoLogonDecision { return @{ Action = 'NoChange'; CurrentSid = $null; CurrentName = 'Bica Admin'; TargetSid = $null; TargetName = $null; Reasons = @(); OperatorOptions = @(); HighImpact = @() } }
        $state = New-CrTestState -Profile IPT01
        Add-CrTestService -State $state -Name 'AdminJob' -Sid (Get-CrTestUserSid $state 'Administrator')
        $plan = New-CrTestPlan -State $state

        It 'disables the Administrator and moves its service to ApplicationUser (D24)' {
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'Administrator' 'Disable Administrator (replaced by ApplicationUser)').Count | Should Be 1
            $f = @(Get-CrTestFindings $plan 'HighImpact' 'Services' 'Administrator' 'Move service AdminJob from Administrator to ApplicationUser (D24)')
            $f.Count | Should Be 1
            $f[0]['Slot'] | Should Be 'AppUser'
            @(Get-CrTestFindings $plan $null $null 'Administrator' 'Not disabled*').Count | Should Be 0
        }
    }
}

Describe 'Get-CrMovableDependentCount (D24)' {
    $sid = 'S-1-5-21-1000-2000-3000-1050'
    $state = @{
        Services = @(@{ Name = 'S1'; StartNameSid = $sid }, @{ Name = 'S2'; StartNameSid = 'S-1-5-18' })
        Tasks    = @(@{ Path = '\T1'; UserSid = $sid; LogonType = 1 }, @{ Path = '\T6'; UserSid = $sid; LogonType = 6 }, @{ Path = '\T3'; UserSid = $sid; LogonType = 3 })
        ComPlus  = @(@{ Name = 'C1'; IdentitySid = $sid; Activation = 'Server' }, @{ Name = 'C2'; IdentitySid = $sid; Activation = 'Library' })
        Dcom     = @(@{ AppId = '{00000000-0000-0000-0000-000000000009}'; Name = 'D1'; RunAsSid = $sid })
        Iis      = @{ Installed = $true; AppPools = @(@{ Name = 'P1'; UserSid = $sid }); VirtualDirectories = @() }
    }

    It 'counts services, password-stored tasks and COM+ server identities only' {
        Get-CrMovableDependentCount -State $state -Sid $sid | Should Be 4
    }
    It 'is 0 for an account without dependents and for no SID' {
        Get-CrMovableDependentCount -State $state -Sid 'S-1-5-21-1000-2000-3000-1099' | Should Be 0
        Get-CrMovableDependentCount -State $state -Sid '' | Should Be 0
    }
    It 'counts the dependents of ApplicationUser on the SM fixture' {
        $sm = New-CrTestState -Profile SM
        # 4 services, 3 password-stored tasks, 1 COM+ application
        Get-CrMovableDependentCount -State $sm -Sid (Get-CrTestUserSid $sm 'ApplicationUser') | Should Be 8
    }
}

Describe 'Test-CrEntryCreated' {
    It 'is true for an entry with a ToCreate placeholder' {
        Test-CrEntryCreated @{ Accounts = @(@{ Name = 'ApplicationUser'; Sid = $null; User = $null; ToCreate = $true }) } | Should Be $true
    }
    It 'is false for an entry with existing accounts only' {
        Test-CrEntryCreated @{ Accounts = @(@{ Name = 'ApplicationUser'; Sid = 'S-1-5-21-1000-2000-3000-1003'; User = @{} }) } | Should Be $false
    }
    It 'is false without accounts or without an entry' {
        Test-CrEntryCreated @{ Accounts = @() } | Should Be $false
        Test-CrEntryCreated $null | Should Be $false
        Test-CrEntryCreated 'AppUser' | Should Be $false
    }
}

Describe 'Add-CrDisableDependentFindings -TargetName (D24)' {
    $sid = 'S-1-5-21-1000-2000-3000-1050'
    $state = @{
        Services = @(@{ Name = 'S1'; StartNameSid = $sid })
        Tasks    = @(@{ Path = '\T1'; UserSid = $sid; LogonType = 1 }, @{ Path = '\T3'; UserSid = $sid; LogonType = 3 })
        ComPlus  = @(@{ Name = 'C1'; IdentitySid = $sid; Activation = 'Server' })
        Dcom     = @()
        Iis      = @{ Installed = $false }
    }
    $plan = @{ Findings = New-Object System.Collections.ArrayList; Drift = $false }
    Add-CrDisableDependentFindings -Plan $plan -State $state -Sid $sid -Name 'Old Account' -Slot 'X' -TargetName 'New Account'

    It 'gives one HighImpact move per movable item, to the target' {
        @(Get-CrTestFindings $plan 'HighImpact' 'Services' 'Old Account' 'Move service S1 from Old Account to New Account (D24)').Count | Should Be 1
        @(Get-CrTestFindings $plan 'HighImpact' 'Tasks' 'Old Account' 'Move scheduled task \T1 from Old Account to New Account (D24)').Count | Should Be 1
        @(Get-CrTestFindings $plan 'HighImpact' 'ComPlus' 'Old Account' 'Move COM+ application C1 from Old Account to New Account (D24)').Count | Should Be 1
        @(Get-CrTestFindings $plan $null $null $null 'Move*').Count | Should Be 3
    }
    It 'reports a task without a stored password as not moved' {
        @(Get-CrTestFindings $plan 'HighImpact' 'Tasks' 'Old Account' 'Scheduled task runs as Old Account without a stored password (LogonType 3)*\T3').Count | Should Be 1
    }
    It 'asks the operator nothing' {
        @(Get-CrTestFindings $plan 'Ambiguous').Count | Should Be 0
    }
}

Describe 'Test-CrAppUserEntry / Test-CrOperatorEntry / Test-CrSqlAccessEntry (v10.6)' {
    $resolved = Resolve-CrAccounts -Config (New-CrTestConfig) -State (New-CrTestState -Profile IPT01)
    $sop = $null; $app = $null
    foreach ($e in $resolved) { if ($e['Id'] -eq 'SOPAdmin') { $sop = $e }; if ($e['Id'] -eq 'AppUser') { $app = $e } }

    It 'finds the application account by Application, not by Replaces (SOP-Admin replaces accounts too)' {
        Test-CrAppUserEntry $app | Should Be $true
        Test-CrAppUserEntry $sop | Should Be $false
        Test-CrAppUserEntry @{ Config = @{ Application = $true } } | Should Be $true
        Test-CrAppUserEntry @{ Config = @{ Replaces = @('RID-500') } } | Should Be $false
        Test-CrAppUserEntry $null | Should Be $false
    }
    It 'finds the operator account SOP-Admin' {
        Test-CrOperatorEntry $sop | Should Be $true
        Test-CrOperatorEntry $app | Should Be $false
        Test-CrOperatorEntry @{ Config = @{ Operator = $true } } | Should Be $true
        Get-CrOperatorAccountName -Resolved $resolved -Fallback 'x' | Should Be 'SOP-Admin'
    }
    It 'finds the entry that gets the SQL Server access of the accounts it replaces' {
        Test-CrSqlAccessEntry $sop | Should Be $true
        Test-CrSqlAccessEntry $app | Should Be $false
        Test-CrSqlAccessEntry @{ Config = @{ SqlAccess = 'FromReplaced' } } | Should Be $true
        Test-CrSqlAccessEntry 'SOPAdmin' | Should Be $false
    }
}

Describe 'Get-CrLogonGaps / Copy-CrStateWithMember (D28)' {
    $state = New-CrTestState -Profile IPT01
    $bicaAdmin = Get-CrTestUserSid $state 'BiCA Admin'
    $bicaRemote = Get-CrTestUserSid $state 'BiCA Remote'
    $newSid = 'S-1-5-21-1000-2000-4000-1200'

    It 'adds a member to the given groups in a copy only' {
        $copy = Copy-CrStateWithMember -State $state -MemberSid $newSid -GroupSids @('S-1-5-32-544', 'S-1-5-32-555')
        (@((Get-CrTestGroup $copy 'S-1-5-32-544').MemberSids) -contains $newSid) | Should Be $true
        (@((Get-CrTestGroup $copy 'S-1-5-32-555').MemberSids) -contains $newSid) | Should Be $true
        (@((Get-CrTestGroup $copy 'S-1-5-32-545').MemberSids) -contains $newSid) | Should Be $false
        (@((Get-CrTestGroup $state 'S-1-5-32-544').MemberSids) -contains $newSid) | Should Be $false
    }
    It 'finds no gap for an account in Administrators and Remote Desktop Users' {
        $copy = Copy-CrStateWithMember -State $state -MemberSid $newSid -GroupSids @('S-1-5-32-544', 'S-1-5-32-555')
        (Get-CrLogonGaps -State $copy -ReplacementSid $newSid -ReplacedSid $bicaAdmin).Count | Should Be 0
        (Get-CrLogonGaps -State $copy -ReplacementSid $newSid -ReplacedSid $bicaRemote).Count | Should Be 0
    }
    It 'finds the RDP gap of a replacement that is denied RDP' {
        $copy = Copy-CrStateWithMember -State $state -MemberSid $newSid -GroupSids @('S-1-5-32-544')
        $copy['Rights'] = @{}
        foreach ($k in $state['Rights'].Keys) { $copy['Rights'][$k] = $state['Rights'][$k] }
        $copy['Rights']['SeDenyRemoteInteractiveLogonRight'] = @($state['Rights']['SeDenyRemoteInteractiveLogonRight']) + @($newSid)
        $gaps = Get-CrLogonGaps -State $copy -ReplacementSid $newSid -ReplacedSid $bicaRemote
        ($gaps -join ',') | Should Be 'RemoteInteractive'
        Get-CrLogonGapText $gaps | Should Be 'over RDP'
        # BiCA Admin is denied RDP itself: no gap
        (Get-CrLogonGaps -State $copy -ReplacementSid $newSid -ReplacedSid $bicaAdmin).Count | Should Be 0
    }
    It 'finds the RDP gap of a replacement without groups (local logon comes through Users), and none without SIDs' {
        $gaps = Get-CrLogonGaps -State $state -ReplacementSid $newSid -ReplacedSid (Get-CrTestUserSid $state 'Administrator')
        ($gaps -join ',') | Should Be 'RemoteInteractive'
        Get-CrLogonGapText @('Interactive', 'RemoteInteractive') | Should Be 'locally and over RDP'
        (Get-CrLogonGaps -State $state -ReplacementSid '' -ReplacedSid $bicaAdmin).Count | Should Be 0
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
    It 'reports a retired running account (D25): log on as SOP-Admin next time' {
        $state = New-CrTestState -Profile IPT01
        $plan = New-CrTestPlan -State $state -RunningSid (Get-CrTestUserSid $state 'SYS-Admin')
        @(Get-CrTestFindings $plan 'HighImpact' 'Accounts' 'SYS-Admin' 'The running account SYS-Admin is disabled at the end; log on as SOP-Admin next time (D25)').Count | Should Be 1
        @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'SYS-Admin' 'Disable SYS-Admin (no replacement)')[0]['Detail'] | Should Match 'last step \(D25\)'
    }
    It 'sets the password of an existing SP Admin and keeps it in Administrators only; not disabled, not asked about (D30, v10.7)' {
        $state = New-CrTestState -Profile IPT01
        [void](Add-CrTestUser -State $state -Name 'SP Admin' -Groups @('Administrators', 'Remote Desktop Users') -PasswordNeverExpires)
        $plan = New-CrTestPlan -State $state
        $f = @(Get-CrTestFindings $plan 'Info' 'Password' 'SP Admin' 'Password set (D9: no old password)')
        $f.Count | Should Be 1
        $f[0]['Slot'] | Should Be 'SPAdmin'
        @(Get-CrTestFindings $plan 'Drift' 'Groups' 'SP Admin' 'Remove from Remote Desktop Users (enforcement phase)').Count | Should Be 1
        @(Get-CrTestFindings $plan 'Drift' 'Flags' 'SP Admin' 'Set "user cannot change password"').Count | Should Be 1
        @(Get-CrTestFindings $plan $null $null 'SP Admin' 'Kept untouched*').Count | Should Be 0
        @(Get-CrTestFindings $plan $null 'Accounts' 'SP Admin' 'Disable*').Count | Should Be 0
        @(Get-CrTestFindings $plan 'Ambiguous' $null 'SP Admin').Count | Should Be 0
        @(Get-CrTestFindings $plan $null 'SQL' 'SP Admin').Count | Should Be 0
    }
    It 'still keeps an account of a Mode Keep entry untouched (D26; the default config has none since v10.7)' {
        $state = New-CrTestState -Profile IPT01
        [void](Add-CrTestUser -State $state -Name 'Kept Admin' -Groups @('Administrators') -PasswordNeverExpires)
        $config = New-CrTestConfig
        $config.Accounts = @($config.Accounts) + @(@{ Id = 'Untouched'; Kind = 'Windows'; Names = @('Kept Admin'); Mode = 'Keep' })
        $plan = New-CrTestPlan -State $state -Config $config
        $f = @(Get-CrTestFindings $plan $null $null 'Kept Admin')
        $f.Count | Should Be 1
        $f[0]['Severity'] | Should Be 'Info'
        $f[0]['Message'] | Should Be 'Kept untouched (config: Mode Keep)'
        $f[0]['Slot'] | Should BeNullOrEmpty
    }
    It 'manages an existing SOP-Admin (v10.6): no Keep finding; as the running account it is never disabled' {
        $state = New-CrTestState -Profile IPT01
        $sop = Add-CrTestUser -State $state -Name 'SOP-Admin' -Groups @('Administrators') -PasswordNeverExpires
        $plan = New-CrTestPlan -State $state -RunningSid $sop.Sid
        @(Get-CrTestFindings $plan $null $null 'SOP-Admin' 'Kept untouched*').Count | Should Be 0
        @(Get-CrTestFindings $plan 'Info' 'Password' 'SOP-Admin' 'Password set (D9: no old password)').Count | Should Be 1
        @(Get-CrTestFindings $plan $null 'Accounts' 'SOP-Admin' 'Disable*').Count | Should Be 0
        @(Get-CrTestFindings $plan 'HighImpact' 'Accounts' $null 'The running account*').Count | Should Be 0
    }
    It 'reports an already disabled retired account as Info only' {
        $state = New-CrTestState -Profile IPT01
        (Get-CrTestUser $state 'SYS Admin')['Disabled'] = $true
        $plan = New-CrTestPlan -State $state
        @(Get-CrTestFindings $plan 'Drift' $null 'SYS Admin').Count | Should Be 0
        @(Get-CrTestFindings $plan 'Info' 'Accounts' 'SYS Admin' 'Already disabled*').Count | Should Be 1
        @(Get-CrTestFindings $plan 'Ambiguous' $null 'SYS Admin').Count | Should Be 0
    }
    It 'tells the operator that the dependents of an other account move to ApplicationUser if it is disabled (D23, D24)' {
        $state = New-CrTestState -Profile IPT01
        $extra = Add-CrTestUser -State $state -Name 'ExtraUser' -Groups @('S-1-5-32-545')
        $svc = @{ Name = 'ExtraSvc'; DisplayName = 'Extra Service'; StartName = '.\ExtraUser'; StartNameSid = $extra.Sid; StartMode = 'Auto'; State = 'Running'
                  PathExecutable = 'C:\App\Extra.exe'; DependentServices = @(); DependsOn = @() }
        $state.Services = @($state.Services) + @($svc)
        $plan = New-CrTestPlan -State $state
        $f = @(Get-CrTestFindings $plan 'Ambiguous' 'Accounts' 'ExtraUser' 'Operator decides: disable or keep ExtraUser (D23)')
        $f.Count | Should Be 1
        $f[0]['Detail'] | Should Be 'member of: Users; dependents (moved to ApplicationUser if it is disabled, D24): service ExtraSvc'
        @(Get-CrTestFindings $plan $null $null 'ExtraUser' 'Move*').Count | Should Be 0
    }
    It 'blocks every Windows entry and asks nothing when the Users part failed' {
        $state = New-CrTestState -Profile IPT01 -Parts @{ Users = @{ Error = 'access denied' } }
        $plan = New-CrTestPlan -State $state
        # SOPAdmin, AppUser, SPAdmin, AutoLogon, Retired, WinUsers, FtpUsers
        @(Get-CrTestFindings $plan 'Blocked' 'Accounts').Count | Should Be 7
        @(Get-CrTestFindings $plan $null 'Accounts' $null 'Create*').Count | Should Be 0
        @(Get-CrTestFindings $plan 'Ambiguous' 'Accounts' $null 'Operator decides*').Count | Should Be 0
    }
}

Describe 'New-CrPlan with -Only' {
    Context 'only the SOPAdmin slot' {
        Mock Get-CrPathAllowSids { return , @() }
        $state = New-CrTestState -Profile SM
        $plan = New-CrTestPlan -State $state -Only @('SOPAdmin')

        It 'skips other slots, check-mode accounts, retired and other accounts' {
            foreach ($n in @('ApplicationUser', 'WinAutoUser', 'WinUser1', 'SYS Admin', 'LocalAdm', 'SP Admin')) {
                @(Get-CrTestFindings $plan $null $null $n).Count | Should Be 0
            }
            @(Get-CrTestFindings $plan 'Ambiguous' 'Accounts' $null 'Operator decides: disable or keep*').Count | Should Be 0
        }
        It 'keeps the findings of the selected slot: SOP-Admin with its SQL access, the BiCA accounts it replaces' {
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'SOP-Admin' 'Create SOP-Admin').Count | Should Be 1
            @(Get-CrTestFindings $plan 'Drift' 'SQL' 'SOP-Admin').Count | Should Be 1
            @(Get-CrTestFindings $plan 'FollowUp' 'LOGINS' 'SOP-Admin').Count | Should Be 1
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'BiCA Admin' 'Disable BiCA Admin (replaced by SOP-Admin)').Count | Should Be 1
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'BiCA Remote' 'Disable BiCA Remote (replaced by SOP-Admin)').Count | Should Be 1
        }
        It 'still runs the auto-logon step because BiCA Admin (replaced by this slot) is the current auto-logon account' {
            @(Get-CrTestFindings $plan 'Drift' 'AutoLogon' $null 'Turn auto-logon off*').Count | Should Be 1
        }
    }

    Context 'only the AppUser slot' {
        Mock Get-CrPathAllowSids { return , @() }
        $state = New-CrTestState -Profile SM
        $plan = New-CrTestPlan -State $state -Only @('AppUser')

        It 'neither creates SOP-Admin or SP Admin nor touches the BiCA accounts nor grants SQL access' {
            foreach ($n in @('SOP-Admin', 'SP Admin', 'BiCA Admin', 'BiCA Remote')) {
                @(Get-CrTestFindings $plan $null $null $n).Count | Should Be 0
            }
            @(Get-CrTestFindings $plan $null 'SQL').Count | Should Be 0
        }
        It 'does not run the auto-logon step (its current account BiCA Admin belongs to the SOPAdmin slot)' {
            @(Get-CrTestFindings $plan $null 'AutoLogon').Count | Should Be 0
        }
    }

    Context 'only a SQL slot (config with SQL entries, D27)' {
        Mock Get-CrPathAllowSids { return , @() }
        $state = New-CrTestState -Profile SM
        $plan = New-CrTestPlan -State $state -Only @('SQLApplication') -Config (New-CrTestSqlConfig)

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
