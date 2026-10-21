$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$lib = Join-Path $here '..\src\lib'
foreach ($m in @('Compat', 'Config', 'Rights', 'Principals', 'Sql', 'AutoLogon', 'Plan')) { . (Join-Path $lib ($m + '.ps1')) }
. (Join-Path $here 'Fixtures.ps1')

# Pester 3.4 keeps a Mock for the whole Describe/Context it is defined in: every Mock lives in its own Context.
# Account model PLAN v10.8 (D18, D21-D31): SOP-Admin (the operator's account; replaces BiCA Admin and BiCA Remote and gets
# their SQL Server access), ApplicationUser (replaces RID-500; never created since v10.8), SP Admin (v10.7, D30: created
# if missing, Administrators only, nothing else) and the auto-logon account PUB-User (v10.8: created if missing, replaces
# WinAutoUser) are managed and enabled if disabled; SYS Admin (also spelled SYS-Admin) is retired; no account is kept
# untouched (Mode Keep); the default config has no SQL login slots (D27).
# The fixtures have neither SOP-Admin nor SP Admin, and SM has no PUB-User, so they are created unless a test adds them.
# Every active auto-logon is switched to PUB-User, on SM machines too (no RestrictedComputerPattern since v10.8).
# v10.4 (D24): the dependents of retired and operator-disabled accounts move to ApplicationUser, or to SOP-Admin without
# it (v10.8); nothing moves to an account created in this run (the account with dependents stays enabled). Without
# ApplicationUser the built-in Administrator is disabled like a retired account (v10.8).

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

Describe 'New-CrPlan on an SM-like machine (account model v10.8)' {
    Context 'audit run as BiCA Remote' {
        Mock Get-CrPathAllowSids { return , @('S-1-5-32-545', 'S-1-5-18', 'S-1-5-32-544') }
        $state = New-CrTestState -Profile SM
        $plan = New-CrTestPlan -State $state -RunningSid (Get-CrTestUserSid $state 'BiCA Remote')

        It 'reports drift' {
            $plan['Drift'] | Should Be $true
        }
        It 'creates SOP-Admin (D28), SP Admin (D30) and PUB-User (v10.8), each in its slot' {
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' $null 'Create*').Count | Should Be 3
            $f = @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'SOP-Admin' 'Create SOP-Admin')
            $f.Count | Should Be 1
            $f[0]['Slot'] | Should Be 'SOPAdmin'
            $f = @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'SP Admin' 'Create SP Admin')
            $f.Count | Should Be 1
            $f[0]['Slot'] | Should Be 'SPAdmin'
            $f = @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'PUB-User' 'Create PUB-User')
            $f.Count | Should Be 1
            $f[0]['Slot'] | Should Be 'AutoLogon'
            @(Get-CrTestFindings $plan 'Info' 'Accounts' $null 'Account not found (never created)*').Count | Should Be 0
        }
        It 'creates PUB-User in Users only, without a password finding; it has no Windows login in SQL Server (PLAN 1.1)' {
            @(Get-CrTestFindings $plan 'Drift' 'Groups' 'PUB-User' 'Add to Users').Count | Should Be 1
            @(Get-CrTestFindings $plan 'Drift' 'Groups' 'PUB-User').Count | Should Be 1
            @(Get-CrTestFindings $plan $null 'Password' 'PUB-User').Count | Should Be 0
            @(Get-CrTestFindings $plan 'Info' 'SQL' 'PUB-User' '*no Windows login in SQL Server*').Count | Should Be 1
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
        It 'gives the replaced accounts BiCA Admin, BiCA Remote and WinAutoUser no new password, groups or flags (D22)' {
            foreach ($n in @('BiCA Admin', 'BiCA Remote', 'WinAutoUser')) {
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
            foreach ($n in @('SYS Admin', 'LocalAdm', 'BiCA Admin', 'BiCA Remote', 'WinAutoUser')) {
                @(Get-CrTestFindings $plan $null 'Groups' $n).Count | Should Be 0
                @(Get-CrTestFindings $plan $null 'Flags' $n).Count | Should Be 0
            }
        }
        It 'keeps WinAutoUser and its password-stored task \KioskTask: PUB-User is created in this run (D24, v10.8)' {
            $f = @(Get-CrTestFindings $plan 'HighImpact' 'Accounts' 'WinAutoUser' 'Not disabled: PUB-User is created in this run, so the services, scheduled tasks and COM+ applications of WinAutoUser are not moved to it; migrate them manually (D24)')
            $f.Count | Should Be 1
            $f[0]['Slot'] | Should Be 'AutoLogon'
            $f[0]['Detail'] | Should Be 'A created account has a new SID: no SQL login, ACLs or profile of WinAutoUser'
            @(Get-CrTestFindings $plan $null $null 'WinAutoUser').Count | Should Be 1
            @(Get-CrTestFindings $plan $null $null $null '*\KioskTask*').Count | Should Be 0
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
        It 'switches the admin auto-logon to the PUB-User it creates, on an SM machine too (D18, v10.8)' {
            $f = @(Get-CrTestFindings $plan 'Drift' 'AutoLogon' 'BiCA Admin' 'Switch auto-logon from BiCA Admin to PUB-User (D18)')
            $f.Count | Should Be 1
            $f[0]['Slot'] | Should Be 'AutoLogon'
            @(Get-CrTestFindings $plan $null 'AutoLogon' $null 'Turn auto-logon off*').Count | Should Be 0
            @(Get-CrTestFindings $plan 'Ambiguous' 'AutoLogon').Count | Should Be 0
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

Describe 'New-CrPlan on an IPT01-like machine (account model v10.8)' {
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
    It 'sets the password of PUB-User without a probe (D9); the replaced WinAutoUser gets none' {
        @(Get-CrTestFindings $plan 'Info' 'Password' 'PUB-User' 'Password set (D9: no old password)').Count | Should Be 1
        @(Get-CrTestFindings $plan $null 'Probe' 'PUB-User').Count | Should Be 0
        @(Get-CrTestFindings $plan $null 'Password' 'WinAutoUser').Count | Should Be 0
        @(Get-CrTestFindings $plan $null 'Probe' 'WinAutoUser').Count | Should Be 0
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
    It 'disables none of the managed accounts and creates no PUB-User (it exists)' {
        foreach ($n in @('PUB-User', 'ApplicationUser')) {
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' $n ('Disable ' + $n + '*')).Count | Should Be 0
        }
        @(Get-CrTestFindings $plan $null $null 'PUB-User' 'Create PUB-User').Count | Should Be 0
    }
    It 'disables WinAutoUser (no dependents), replaced by PUB-User once it is verified (D22, v10.8)' {
        $f = @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'WinAutoUser' 'Disable WinAutoUser (replaced by PUB-User)')
        $f.Count | Should Be 1
        $f[0]['Slot'] | Should Be 'AutoLogon'
        $f[0]['Detail'] | Should Be 'D22: disabled only after PUB-User is verified in this run; groups and password stay unchanged'
        @(Get-CrTestFindings $plan $null $null 'WinAutoUser').Count | Should Be 1
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
    It 'switches the admin auto-logon to the existing PUB-User (D18)' {
        @(Get-CrTestFindings $plan 'Drift' 'AutoLogon' 'BiCA Admin' 'Switch auto-logon from BiCA Admin to PUB-User (D18)').Count | Should Be 1
    }
    It 'finds no SID overlap' {
        @(Get-CrTestFindings $plan 'Ambiguous' 'Principals').Count | Should Be 0
    }
}

Describe 'New-CrPlan: created and disabled accounts and the auto-logon step' {
    Context 'SOP-Admin is missing: it is created (D21, D28)' {
        Mock Get-CrAutoLogonDecision { return @{ Action = 'NoChange'; CurrentSid = $null; CurrentName = 'Bica Admin'; TargetSid = $null; TargetName = $null; Reasons = @(); OperatorOptions = @(); HighImpact = @() } }
        $state = New-CrTestState -Profile IPT01
        $appSid = Get-CrTestUserSid $state 'ApplicationUser'
        $pubSid = Get-CrTestUserSid $state 'PUB-User'
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
        It 'passes only existing accounts as verified to the auto-logon decision (ApplicationUser, PUB-User; not the created SOP-Admin and SP Admin)' {
            Assert-MockCalled Get-CrAutoLogonDecision -Times 1 -Exactly -Scope Context -ParameterFilter {
                @($VerifiedSids).Count -eq 2 -and @($VerifiedSids) -contains $appSid -and @($VerifiedSids) -contains $pubSid
            }
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
            # In Administrators: Windows refuses CCP (1322), so it is reported, not drift.
            @(Get-CrTestFindings $plan 'Drift' 'Flags' 'SOP-Admin' 'Set "user cannot change password"').Count | Should Be 0
            @(Get-CrTestFindings $plan 'Info' 'Flags' 'SOP-Admin' (Get-CrCcpNotSetText)).Count | Should Be 1
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

    Context 'WinAutoUser is disabled already: replaced by PUB-User, it gets nothing (D22, v10.8)' {
        Mock Get-CrAutoLogonDecision { return @{ Action = 'NoChange'; CurrentSid = $null; CurrentName = 'Bica Admin'; TargetSid = $null; TargetName = $null; Reasons = @(); OperatorOptions = @(); HighImpact = @() } }
        $state = New-CrTestState -Profile IPT01
        (Get-CrTestUser $state 'WinAutoUser')['Disabled'] = $true
        $pubSid = Get-CrTestUserSid $state 'PUB-User'
        $winAutoSid = Get-CrTestUserSid $state 'WinAutoUser'
        $plan = New-CrTestPlan -State $state

        It 'passes PUB-User but not WinAutoUser as verified' {
            Assert-MockCalled Get-CrAutoLogonDecision -Times 1 -Exactly -Scope Context -ParameterFilter { @($VerifiedSids) -contains $pubSid -and @($VerifiedSids) -notcontains $winAutoSid }
        }
        It 'reports it as Info only: no password, no enable, no disable' {
            @(Get-CrTestFindings $plan 'Info' 'Accounts' 'WinAutoUser' 'Already disabled (replaced by PUB-User)').Count | Should Be 1
            @(Get-CrTestFindings $plan $null $null 'WinAutoUser').Count | Should Be 1
        }
    }

    Context 'PUB-User is disabled: its slot enables it, so the auto-logon decision sees it enabled (D21, v10.8)' {
        Mock Get-CrAutoLogonDecision { return @{ Action = 'NoChange'; CurrentSid = $null; CurrentName = 'Bica Admin'; TargetSid = $null; TargetName = $null; Reasons = @(); OperatorOptions = @(); HighImpact = @() } }
        $state = New-CrTestState -Profile IPT01
        $pub = Get-CrTestUser $state 'PUB-User'
        $pub['Disabled'] = $true
        $pub['Flags'] = $pub['Flags'] -bor 0x2
        $pubSid = $pub['Sid']
        $plan = New-CrTestPlan -State $state

        It 'enables it and sets its password' {
            $f = @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'PUB-User' 'Enable the account (D21)')
            $f.Count | Should Be 1
            $f[0]['Slot'] | Should Be 'AutoLogon'
            @(Get-CrTestFindings $plan 'Info' 'Password' 'PUB-User' 'Password set (D9: no old password)').Count | Should Be 1
            @(Get-CrTestFindings $plan 'Info' 'Accounts' 'PUB-User' '*stays disabled*').Count | Should Be 0
        }
        It 'passes it enabled and verified to the auto-logon decision' {
            Assert-MockCalled Get-CrAutoLogonDecision -Times 1 -Exactly -Scope Context -ParameterFilter {
                @($VerifiedSids) -contains $pubSid -and
                @($State['Users'] | Where-Object { $_['Sid'] -eq $pubSid -and -not $_['Disabled'] }).Count -eq 1
            }
        }
        It 'leaves the discovered account disabled' {
            $pub['Disabled'] | Should Be $true
            ($pub['Flags'] -band 0x2) | Should Be 2
        }
    }

    Context 'PUB-User is missing (SM): the PUB-User its slot creates counts for the auto-logon decision (v10.8)' {
        Mock Get-CrPathAllowSids { return , @() }
        Mock Get-CrAutoLogonDecision { return @{ Action = 'NoChange'; CurrentSid = $null; CurrentName = 'BiCA Admin'; TargetSid = $null; TargetName = $null; Reasons = @(); OperatorOptions = @(); HighImpact = @() } }
        $state = New-CrTestState -Profile SM
        $usersBefore = @($state.Users).Count
        $null = New-CrTestPlan -State $state

        It 'passes it under the null SID S-1-0-0, enabled, in Users and verified' {
            Assert-MockCalled Get-CrAutoLogonDecision -Times 1 -Exactly -Scope Context -ParameterFilter {
                @($VerifiedSids) -contains 'S-1-0-0' -and
                @($State['Users'] | Where-Object { $_['Name'] -eq 'PUB-User' -and $_['Sid'] -eq 'S-1-0-0' -and -not $_['Disabled'] }).Count -eq 1 -and
                @(@($State['Groups'] | Where-Object { $_['Sid'] -eq 'S-1-5-32-545' })[0]['MemberSids']) -contains 'S-1-0-0'
            }
        }
        It 'leaves the discovered state unchanged' {
            @($state.Users).Count | Should Be $usersBefore
            $null -eq (Get-CrTestUser $state 'PUB-User') | Should Be $true
            (@((Get-CrTestGroup $state 'Users').MemberSids) -contains 'S-1-0-0') | Should Be $false
        }
    }

    Context 'PUB-User is missing (SM) and the AutoLogon slot is blocked' {
        Mock Get-CrPathAllowSids { return , @() }
        Mock Get-CrAutoLogonDecision { return @{ Action = 'NoChange'; CurrentSid = $null; CurrentName = 'BiCA Admin'; TargetSid = $null; TargetName = $null; Reasons = @(); OperatorOptions = @(); HighImpact = @() } }
        $state = New-CrTestState -Profile SM
        $pf = @{ MachineBlocked = $false; BlockedSlots = @{ AutoLogon = 'test' }; Findings = @() }
        $null = New-CrTestPlan -State $state -Preflight $pf

        It 'neither adds nor verifies the PUB-User to create' {
            Assert-MockCalled Get-CrAutoLogonDecision -Times 1 -Exactly -Scope Context -ParameterFilter {
                @($VerifiedSids) -notcontains 'S-1-0-0' -and @($State['Users'] | Where-Object { $_['Name'] -eq 'PUB-User' }).Count -eq 0
            }
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

    Context 'SOP-Admin is the running account and has no SQL Server login; BiCA Remote is disabled (QS-K1)' {
        Mock Get-CrPathAllowSids { return , @() }
        $state = New-CrTestState -Profile SM
        $sop = Add-CrTestUser -State $state -Name 'SOP-Admin' -Groups @('Administrators', 'Remote Desktop Users', 'Offer Remote Assistance Helpers') -PasswordNeverExpires -CannotChangePassword
        (Get-CrTestUser $state 'BiCA Remote')['Disabled'] = $true
        $state.Sql.Connected = $false
        $state.Sql.ConnectErrorNumber = 18456
        $state.Sql.Error = 'Connect: Login failed for user'
        $state.Sql.Logins = @()
        $plan = New-CrTestPlan -State $state -RunningSid $sop.Sid

        It 'says that SOP-Admin cannot give itself access and names BiCA Admin to run as' {
            $f = @(Get-CrTestFindings $plan 'HighImpact' 'SQL' 'SOP-Admin' 'The SQL Server access of SOP-Admin cannot be checked: SOP-Admin is the running account and cannot log on to SQL Server*')
            $f.Count | Should Be 1
            $f[0]['Message'] | Should Match 'cannot give itself the access of BiCA Admin, BiCA Remote; run the tool as an account that is sysadmin through its own Windows login, e\.g\. BiCA Admin \(D29\)$'
        }
        It 'keeps BiCA Admin enabled' {
            @(Get-CrTestFindings $plan 'HighImpact' 'Accounts' 'BiCA Admin' 'Not disabled: the SQL Server access of SOP-Admin cannot be checked: SOP-Admin is the running account*').Count | Should Be 1
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'BiCA Admin' 'Disable*').Count | Should Be 0
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

Describe 'New-CrPlan: ApplicationUser is missing: never created, the built-in Administrator is retired (D22, D24, v10.8)' {
    # Without ApplicationUser the dependents of disabled accounts move to SOP-Admin. A created SOP-Admin has a new SID:
    # nothing is moved to it, so an account with movable dependents stays enabled.
    function Add-CrTestService {
        param($State, [string]$Name, [string]$Sid)
        $svc = @{ Name = $Name; DisplayName = $Name; StartName = '.\synthetic'; StartNameSid = $Sid; StartMode = 'Auto'; State = 'Running'
                  PathExecutable = 'C:\App\Synthetic.exe'; DependentServices = @(); DependsOn = @() }
        $State.Services = @($State.Services) + @($svc)
    }

    Context 'the built-in Administrator runs a service, SYS Admin runs LegacySync, SYS-Admin runs nothing; SOP-Admin is created' {
        Mock Get-CrAutoLogonDecision { return @{ Action = 'NoChange'; CurrentSid = $null; CurrentName = 'Bica Admin'; TargetSid = $null; TargetName = $null; Reasons = @(); OperatorOptions = @(); HighImpact = @() } }
        $state = New-CrTestState -Profile IPT01 -OmitUsers 'ApplicationUser'
        Add-CrTestService -State $state -Name 'AdminJob' -Sid (Get-CrTestUserSid $state 'Administrator')
        $plan = New-CrTestPlan -State $state
        $sysAdminSid = Get-CrTestUserSid $state 'SYS Admin'

        It 'does not create ApplicationUser: it is not found and its entry is not applicable (v10.8)' {
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'ApplicationUser' 'Create*').Count | Should Be 0
            $f = @(Get-CrTestFindings $plan 'Info' 'Accounts' 'ApplicationUser' 'Account not found (never created): ApplicationUser')
            $f.Count | Should Be 1
            $f[0]['Slot'] | Should Be 'AppUser'
            $f = @(Get-CrTestFindings $plan 'Info' 'Accounts' $null 'Not applicable on this machine: AppUser')
            $f.Count | Should Be 1
            $f[0]['Slot'] | Should Be 'AppUser'
            @(Get-CrTestFindings $plan $null $null 'ApplicationUser').Count | Should Be 1
        }
        It 'keeps the Administrator enabled with one HighImpact item and no move: SOP-Admin is created in this run (D24)' {
            $f = @(Get-CrTestFindings $plan 'HighImpact' 'Accounts' 'Administrator' 'Not disabled: SOP-Admin is created in this run, so the services, scheduled tasks and COM+ applications of Administrator are not moved to it; migrate them manually (D24)')
            $f.Count | Should Be 1
            $f[0]['Slot'] | Should BeNullOrEmpty
            $f[0]['Detail'] | Should Be 'A created account has a new SID: no ACLs or profile of Administrator; its SQL Server login is created in this run (D29). A later run moves them'
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'Administrator' 'Disable*').Count | Should Be 0
            @(Get-CrTestFindings $plan $null $null 'Administrator' 'Move*').Count | Should Be 0
            @(Get-CrTestFindings $plan $null $null 'Administrator').Count | Should Be 1
        }
        It 'keeps the retired SYS Admin enabled with one HighImpact item and no move' {
            $f = @(Get-CrTestFindings $plan 'HighImpact' 'Accounts' 'SYS Admin' 'Not disabled: SOP-Admin is created in this run, so the services, scheduled tasks and COM+ applications of SYS Admin are not moved to it; migrate them manually (D24)')
            $f.Count | Should Be 1
            $f[0]['Slot'] | Should BeNullOrEmpty
            $f[0]['Detail'] | Should Be 'A created account has a new SID: no ACLs or profile of SYS Admin; its SQL Server login is created in this run (D29). A later run moves them'
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

        It 'disables it like a retired account: its replacement ApplicationUser does not exist (D22, v10.8)' {
            $f = @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'Administrator' 'Disable Administrator (its replacement ApplicationUser does not exist)')
            $f.Count | Should Be 1
            $f[0]['Slot'] | Should BeNullOrEmpty
            $f[0]['Detail'] | Should Be 'D22: groups and password stay unchanged'
            @(Get-CrTestFindings $plan $null $null 'Administrator' 'Not disabled*').Count | Should Be 0
            @(Get-CrTestFindings $plan $null $null 'Administrator').Count | Should Be 1
        }
        It 'disables the running Administrator last (D25): log on as SOP-Admin next time' {
            $running = New-CrTestPlan -State $state -RunningSid (Get-CrTestUserSid $state 'Administrator')
            $f = @(Get-CrTestFindings $running 'Drift' 'Accounts' 'Administrator' 'Disable Administrator (its replacement ApplicationUser does not exist)')
            $f.Count | Should Be 1
            $f[0]['Detail'] | Should Match 'last step \(D25\)'
            @(Get-CrTestFindings $running 'HighImpact' 'Accounts' 'Administrator' 'The running account Administrator is disabled at the end; log on as SOP-Admin next time (D25)').Count | Should Be 1
        }
        It 'still keeps SYS Admin (service LegacySync) enabled' {
            @(Get-CrTestFindings $plan 'HighImpact' 'Accounts' 'SYS Admin' 'Not disabled: SOP-Admin is created in this run*').Count | Should Be 1
        }
    }

    Context 'SOP-Admin exists: the dependents of the Administrator and of SYS Admin move to SOP-Admin (D24, v10.8)' {
        Mock Get-CrAutoLogonDecision { return @{ Action = 'NoChange'; CurrentSid = $null; CurrentName = 'Bica Admin'; TargetSid = $null; TargetName = $null; Reasons = @(); OperatorOptions = @(); HighImpact = @() } }
        $state = New-CrTestState -Profile IPT01 -OmitUsers 'ApplicationUser'
        [void](Add-CrTestUser -State $state -Name 'SOP-Admin' -Groups @('Administrators', 'Remote Desktop Users') -PasswordNeverExpires -CannotChangePassword)
        Add-CrTestService -State $state -Name 'AdminJob' -Sid (Get-CrTestUserSid $state 'Administrator')
        $plan = New-CrTestPlan -State $state

        It 'disables the Administrator and moves its service AdminJob to SOP-Admin' {
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'Administrator' 'Disable Administrator (its replacement ApplicationUser does not exist)').Count | Should Be 1
            $f = @(Get-CrTestFindings $plan 'HighImpact' 'Services' 'Administrator' 'Move service AdminJob from Administrator to SOP-Admin (D24)')
            $f.Count | Should Be 1
            $f[0]['Slot'] | Should BeNullOrEmpty
            $f[0]['Detail'] | Should Be 'Only to a verified SOP-Admin with its new password from this run; otherwise Administrator stays enabled'
            @(Get-CrTestFindings $plan $null $null 'Administrator' 'Not disabled*').Count | Should Be 0
        }
        It 'disables SYS Admin and moves its service LegacySync to SOP-Admin' {
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'SYS Admin' 'Disable SYS Admin (no replacement)').Count | Should Be 1
            @(Get-CrTestFindings $plan 'HighImpact' 'Services' 'SYS Admin' 'Move service LegacySync from SYS Admin to SOP-Admin (D24)').Count | Should Be 1
        }
    }

    Context 'the renamed built-in Administrator LocalAdm is disabled already (SM)' {
        Mock Get-CrPathAllowSids { return , @() }
        $state = New-CrTestState -Profile SM -OmitUsers 'ApplicationUser'
        $plan = New-CrTestPlan -State $state

        It 'reports it as Info only (D22)' {
            @(Get-CrTestFindings $plan 'Info' 'Accounts' 'LocalAdm' 'Already disabled (its replacement ApplicationUser does not exist, D22)').Count | Should Be 1
            @(Get-CrTestFindings $plan $null $null 'LocalAdm').Count | Should Be 1
        }
        It 'keeps SYS Admin and its task \SpMaintenance: SOP-Admin is created in this run (D24)' {
            @(Get-CrTestFindings $plan 'HighImpact' 'Accounts' 'SYS Admin' 'Not disabled: SOP-Admin is created in this run, so the services, scheduled tasks and COM+ applications of SYS Admin are not moved to it; migrate them manually (D24)').Count | Should Be 1
            @(Get-CrTestFindings $plan $null $null $null 'Move scheduled task \SpMaintenance*').Count | Should Be 0
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

Describe 'Get-CrDependentTargetEntry / Get-CrEntryDisplayName (D24, v10.8)' {
    $withApp = Resolve-CrAccounts -Config (New-CrTestConfig) -State (New-CrTestState -Profile IPT01)
    $withoutApp = Resolve-CrAccounts -Config (New-CrTestConfig) -State (New-CrTestState -Profile IPT01 -OmitUsers 'ApplicationUser')

    It 'is the ApplicationUser entry when the account exists' {
        $e = Get-CrDependentTargetEntry -Resolved $withApp
        $e['Id'] | Should Be 'AppUser'
        Get-CrEntryDisplayName $e | Should Be 'ApplicationUser'
    }
    It 'is the operator entry SOP-Admin when ApplicationUser does not exist, also while SOP-Admin is still to be created' {
        $e = Get-CrDependentTargetEntry -Resolved $withoutApp
        $e['Id'] | Should Be 'SOPAdmin'
        Get-CrEntryDisplayName $e | Should Be 'SOP-Admin'
        Test-CrEntryCreated $e | Should Be $true
    }
    It 'takes an application entry whose account is created, even after the operator entry' {
        $resolved = @(
            @{ Id = 'Op'; Kind = 'Windows'; Mode = 'Rotate'; Slot = 'S1'; Operator = $true; NotApplicable = $false; Accounts = @() },
            @{ Id = 'App'; Kind = 'Windows'; Mode = 'Rotate'; Slot = 'S2'; Application = $true; NotApplicable = $false
               Accounts = @(@{ Name = 'New App'; Sid = $null; User = $null; ToCreate = $true }) }
        )
        (Get-CrDependentTargetEntry -Resolved $resolved)['Id'] | Should Be 'App'
    }
    It 'ignores application entries that are not managed, have no slot or no account, and is $null without an operator entry' {
        $resolved = @(
            @{ Id = 'AppCheck'; Kind = 'Windows'; Mode = 'Check'; Slot = 'S1'; Application = $true; NotApplicable = $false },
            @{ Id = 'AppNoSlot'; Kind = 'Windows'; Mode = 'Rotate'; Slot = $null; Application = $true; NotApplicable = $false },
            @{ Id = 'AppMissing'; Kind = 'Windows'; Mode = 'Rotate'; Slot = 'S2'; Application = $true; NotApplicable = $true }
        )
        $null -eq (Get-CrDependentTargetEntry -Resolved $resolved) | Should Be $true
        $null -eq (Get-CrDependentTargetEntry -Resolved @()) | Should Be $true
    }
    It 'names an entry by its first account, else by its configured Name, else by its Id' {
        Get-CrEntryDisplayName @{ Id = 'X'; Accounts = @(@{ Name = 'First' }, @{ Name = 'Second' }); Config = @{ Name = 'Configured' } } | Should Be 'First'
        Get-CrEntryDisplayName @{ Id = 'X'; Accounts = @(); Config = @{ Name = 'Configured' } } | Should Be 'Configured'
        Get-CrEntryDisplayName @{ Id = 'X'; Accounts = @(); Config = @{ Names = @('A', 'B') } } | Should Be 'X'
        $null -eq (Get-CrEntryDisplayName $null) | Should Be $true
    }
    It 'names the not applicable ApplicationUser entry by its configured Name' {
        $app = $null
        foreach ($e in $withoutApp) { if ($e['Id'] -eq 'AppUser') { $app = $e } }
        $app['NotApplicable'] | Should Be $true
        Get-CrEntryDisplayName $app | Should Be 'ApplicationUser'
    }
}

Describe 'Test-CrReplacedRetired (v10.8)' {
    $resolved = Resolve-CrAccounts -Config (New-CrTestConfig) -State (New-CrTestState -Profile IPT01 -OmitUsers 'ApplicationUser')
    $full = Resolve-CrAccounts -Config (New-CrTestConfig) -State (New-CrTestState -Profile IPT01)
    $byId = @{}
    foreach ($e in $resolved) { $byId[$e['Id']] = $e }
    $fullApp = $null
    foreach ($e in $full) { if ($e['Id'] -eq 'AppUser') { $fullApp = $e } }

    It 'is true for the ApplicationUser entry without its account while the built-in Administrator exists' {
        Test-CrReplacedRetired $byId['AppUser'] | Should Be $true
    }
    It 'is false for an entry whose account exists or is created, and for the retired entry' {
        @($fullApp['Replaced']).Count | Should Be 1
        Test-CrReplacedRetired $fullApp | Should Be $false
        @($byId['SOPAdmin']['Replaced']).Count | Should Be 2
        Test-CrReplacedRetired $byId['SOPAdmin'] | Should Be $false
        Test-CrReplacedRetired $byId['Retired'] | Should Be $false
    }
    It 'is false without replaced accounts, with unreadable account data, or without an entry' {
        Test-CrReplacedRetired @{ Kind = 'Windows'; Mode = 'Rotate'; NotApplicable = $true; Replaced = @() } | Should Be $false
        Test-CrReplacedRetired @{ Kind = 'Windows'; Mode = 'Rotate'; NotApplicable = $true; Error = 'access denied'
                                  Replaced = @(@{ Name = 'Administrator'; Sid = 'S-1-5-21-1000-2000-4000-500' }) } | Should Be $false
        Test-CrReplacedRetired $null | Should Be $false
    }
}

Describe 'Get-CrPlannedAutoLogonState (v10.8)' {
    Context 'PUB-User is created (SM)' {
        $state = New-CrTestState -Profile SM
        $entry = Find-CrAutoLogonEntry -Resolved (Resolve-CrAccounts -Config (New-CrTestConfig) -State $state)
        $usersBefore = @($state.Users).Count
        $r = Get-CrPlannedAutoLogonState -State $state -Entry $entry -Create $true -EnableSids @() -RunningSid 'S-1-5-21-9-9-9-9999'

        It 'adds it under the null SID S-1-0-0, enabled, and returns that SID' {
            $r['CreatedSid'] | Should Be 'S-1-0-0'
            $u = Get-CrTestUser $r['State'] 'PUB-User'
            $u['Sid'] | Should Be 'S-1-0-0'
            $u['Disabled'] | Should Be $false
            $u['Planned'] | Should Be $true
            @($r['State'].Users).Count | Should Be ($usersBefore + 1)
        }
        It 'puts it into the groups of its role (Users)' {
            (@((Get-CrTestGroup $r['State'] 'Users').MemberSids) -contains 'S-1-0-0') | Should Be $true
            (@((Get-CrTestGroup $r['State'] 'Administrators').MemberSids) -contains 'S-1-0-0') | Should Be $false
        }
        It 'makes it a usable auto-logon target' {
            (Test-CrAutoLogonUsable -State $r['State'] -User (Get-CrTestUser $r['State'] 'PUB-User') -RemovedAdminSids @())['Usable'] | Should Be $true
        }
        It 'leaves the discovered state unchanged' {
            @($state.Users).Count | Should Be $usersBefore
            $null -eq (Get-CrTestUser $state 'PUB-User') | Should Be $true
            (@((Get-CrTestGroup $state 'Users').MemberSids) -contains 'S-1-0-0') | Should Be $false
        }
    }

    Context 'a disabled PUB-User is enabled (IPT01)' {
        $state = New-CrTestState -Profile IPT01
        $pub = Get-CrTestUser $state 'PUB-User'
        $pub['Disabled'] = $true
        $pub['Flags'] = $pub['Flags'] -bor 0x2
        $entry = Find-CrAutoLogonEntry -Resolved (Resolve-CrAccounts -Config (New-CrTestConfig) -State $state)
        $r = Get-CrPlannedAutoLogonState -State $state -Entry $entry -Create $false -EnableSids @($pub['Sid']) -RunningSid 'S-1-5-21-9-9-9-9999'

        It 'shows it enabled in a copy and creates nothing' {
            $u = Get-CrTestUser $r['State'] 'PUB-User'
            $u['Sid'] | Should Be $pub['Sid']
            $u['Disabled'] | Should Be $false
            ($u['Flags'] -band 0x2) | Should Be 0
            $null -eq $r['CreatedSid'] | Should Be $true
            @($r['State'].Users).Count | Should Be @($state.Users).Count
        }
        It 'leaves the discovered account disabled' {
            $pub['Disabled'] | Should Be $true
            ($pub['Flags'] -band 0x2) | Should Be 2
        }
    }

    Context 'nothing to create or enable' {
        It 'returns the discovered state itself and no SID' {
            $state = New-CrTestState -Profile IPT01
            $r = Get-CrPlannedAutoLogonState -State $state -Entry @{ Id = 'AutoLogon'; Accounts = @() } -Create $false -EnableSids @() -RunningSid ''
            [object]::ReferenceEquals($r['State'], $state) | Should Be $true
            $null -eq $r['CreatedSid'] | Should Be $true
        }
        It 'adds no account when the entry has none to create' {
            $state = New-CrTestState -Profile IPT01
            $entry = @{ Id = 'AutoLogon'; Accounts = @(@{ Name = 'PUB-User'; Sid = (Get-CrTestUserSid $state 'PUB-User'); User = (Get-CrTestUser $state 'PUB-User') }) }
            $r = Get-CrPlannedAutoLogonState -State $state -Entry $entry -Create $true -EnableSids @() -RunningSid ''
            $null -eq $r['CreatedSid'] | Should Be $true
            @($r['State'].Users).Count | Should Be @($state.Users).Count
        }
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
    It 'enables a disabled PUB-User, which the auto-logon step then switches to (EnableIfDisabled, D18, D21, v10.8)' {
        $state = New-CrTestState -Profile IPT01
        $pub = Get-CrTestUser $state 'PUB-User'
        $pub['Disabled'] = $true
        $pub['Flags'] = $pub['Flags'] -bor 0x2
        $plan = New-CrTestPlan -State $state
        @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'PUB-User' 'Enable the account (D21)').Count | Should Be 1
        @(Get-CrTestFindings $plan 'Info' 'Accounts' 'PUB-User' '*stays disabled*').Count | Should Be 0
        @(Get-CrTestFindings $plan 'Drift' 'AutoLogon' 'BiCA Admin' 'Switch auto-logon from BiCA Admin to PUB-User (D18)').Count | Should Be 1
        @(Get-CrTestFindings $plan 'Ambiguous' 'AutoLogon').Count | Should Be 0
    }
    It 'enables a disabled SP Admin (EnableIfDisabled, D21, v10.8)' {
        $state = New-CrTestState -Profile IPT01
        [void](Add-CrTestUser -State $state -Name 'SP Admin' -Groups @('Administrators') -PasswordNeverExpires -CannotChangePassword -Disabled)
        $plan = New-CrTestPlan -State $state
        $f = @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'SP Admin' 'Enable the account (D21)')
        $f.Count | Should Be 1
        $f[0]['Slot'] | Should Be 'SPAdmin'
        @(Get-CrTestFindings $plan 'Info' 'Accounts' 'SP Admin' '*stays disabled*').Count | Should Be 0
        @(Get-CrTestFindings $plan 'Info' 'Password' 'SP Admin' 'Password set (D9: no old password)').Count | Should Be 1
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
        @(Get-CrTestFindings $plan 'Drift' 'Flags' 'SP Admin' 'Set "user cannot change password"').Count | Should Be 0
        @(Get-CrTestFindings $plan 'Info' 'Flags' 'SP Admin' (Get-CrCcpNotSetText)).Count | Should Be 1
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
        @(Get-CrTestFindings $plan 'Info' 'Accounts' 'SYS Admin' 'Already disabled (no replacement, D22)').Count | Should Be 1
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
    It 'names SOP-Admin as the target of those dependents when ApplicationUser does not exist (D23, D24, v10.8)' {
        $state = New-CrTestState -Profile IPT01 -OmitUsers 'ApplicationUser'
        [void](Add-CrTestUser -State $state -Name 'SOP-Admin' -Groups @('Administrators', 'Remote Desktop Users') -PasswordNeverExpires -CannotChangePassword)
        $extra = Add-CrTestUser -State $state -Name 'ExtraUser' -Groups @('S-1-5-32-545')
        $svc = @{ Name = 'ExtraSvc'; DisplayName = 'Extra Service'; StartName = '.\ExtraUser'; StartNameSid = $extra.Sid; StartMode = 'Auto'; State = 'Running'
                  PathExecutable = 'C:\App\Extra.exe'; DependentServices = @(); DependsOn = @() }
        $state.Services = @($state.Services) + @($svc)
        $plan = New-CrTestPlan -State $state
        $f = @(Get-CrTestFindings $plan 'Ambiguous' 'Accounts' 'ExtraUser' 'Operator decides: disable or keep ExtraUser (D23)')
        $f.Count | Should Be 1
        $f[0]['Detail'] | Should Be 'member of: Users; dependents (moved to SOP-Admin if it is disabled, D24): service ExtraSvc'
    }
    It 'says that those dependents stay when SOP-Admin is created in this run and ApplicationUser does not exist (D24, v10.8)' {
        $state = New-CrTestState -Profile IPT01 -OmitUsers 'ApplicationUser'
        $extra = Add-CrTestUser -State $state -Name 'ExtraUser' -Groups @('S-1-5-32-545')
        $svc = @{ Name = 'ExtraSvc'; DisplayName = 'Extra Service'; StartName = '.\ExtraUser'; StartNameSid = $extra.Sid; StartMode = 'Auto'; State = 'Running'
                  PathExecutable = 'C:\App\Extra.exe'; DependentServices = @(); DependsOn = @() }
        $state.Services = @($state.Services) + @($svc)
        $plan = New-CrTestPlan -State $state
        $f = @(Get-CrTestFindings $plan 'Ambiguous' 'Accounts' 'ExtraUser' 'Operator decides: disable or keep ExtraUser (D23)')
        $f.Count | Should Be 1
        $f[0]['Detail'] | Should Be 'member of: Users; dependents (SOP-Admin is created in this run, so they are not moved and the account stays enabled even if you choose disable, D24): service ExtraSvc'
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
            foreach ($n in @('ApplicationUser', 'PUB-User', 'WinAutoUser', 'WinUser1', 'SYS Admin', 'LocalAdm', 'SP Admin')) {
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
            # The AutoLogon slot is not selected, so PUB-User is not created and there is nothing to switch to (D13).
            $f = @(Get-CrTestFindings $plan 'Ambiguous' 'AutoLogon' 'BiCA Admin' 'Operator decision needed: TurnOff / LeaveUnchanged')
            $f.Count | Should Be 1
            $f[0]['Detail'] | Should Match 'No usable auto-logon target \(PUB-User\) exists for a switch'
            @(Get-CrTestFindings $plan 'Drift' 'AutoLogon').Count | Should Be 0
        }
    }

    Context 'only the AutoLogon slot (SM)' {
        Mock Get-CrPathAllowSids { return , @() }
        $state = New-CrTestState -Profile SM
        $plan = New-CrTestPlan -State $state -Only @('AutoLogon')

        It 'creates PUB-User and keeps WinAutoUser with its task (D24); nothing of other slots, retired or other accounts' {
            @(Get-CrTestFindings $plan 'Drift' 'Accounts' 'PUB-User' 'Create PUB-User').Count | Should Be 1
            @(Get-CrTestFindings $plan 'HighImpact' 'Accounts' 'WinAutoUser' 'Not disabled: PUB-User is created in this run*').Count | Should Be 1
            foreach ($n in @('SOP-Admin', 'SP Admin', 'ApplicationUser', 'LocalAdm', 'BiCA Remote', 'SYS Admin', 'OtherAdmin', 'WinUser1')) {
                @(Get-CrTestFindings $plan $null $null $n).Count | Should Be 0
            }
        }
        It 'switches the auto-logon to the PUB-User it creates (D18, v10.8)' {
            @(Get-CrTestFindings $plan 'Drift' 'AutoLogon' 'BiCA Admin' 'Switch auto-logon from BiCA Admin to PUB-User (D18)').Count | Should Be 1
            @(Get-CrTestFindings $plan 'Ambiguous' 'AutoLogon').Count | Should Be 0
        }
    }

    Context 'only the AppUser slot' {
        Mock Get-CrPathAllowSids { return , @() }
        $state = New-CrTestState -Profile SM
        $plan = New-CrTestPlan -State $state -Only @('AppUser')

        It 'neither creates SOP-Admin, SP Admin or PUB-User nor touches the BiCA accounts or WinAutoUser nor grants SQL access' {
            foreach ($n in @('SOP-Admin', 'SP Admin', 'PUB-User', 'BiCA Admin', 'BiCA Remote', 'WinAutoUser')) {
                @(Get-CrTestFindings $plan $null $null $n).Count | Should Be 0
            }
            @(Get-CrTestFindings $plan $null 'SQL').Count | Should Be 0
        }
        It 'does not run the auto-logon step (its current account BiCA Admin belongs to the SOPAdmin slot)' {
            @(Get-CrTestFindings $plan $null 'AutoLogon').Count | Should Be 0
        }
    }

    Context 'only the AppUser slot while ApplicationUser is missing (IPT01)' {
        $state = New-CrTestState -Profile IPT01 -OmitUsers 'ApplicationUser'
        $plan = New-CrTestPlan -State $state -Only @('AppUser')

        It 'reports the missing ApplicationUser but does not retire the built-in Administrator (only without -Only, v10.8)' {
            @(Get-CrTestFindings $plan 'Info' 'Accounts' 'ApplicationUser' 'Account not found (never created): ApplicationUser').Count | Should Be 1
            @(Get-CrTestFindings $plan 'Info' 'Accounts' $null 'Not applicable on this machine: AppUser').Count | Should Be 1
            @(Get-CrTestFindings $plan $null 'Accounts').Count | Should Be 2
            @(Get-CrTestFindings $plan $null $null 'Administrator').Count | Should Be 0
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
