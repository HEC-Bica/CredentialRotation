# Pester 3.4 tests for src\lib\Apply.ps1 (PLAN sections 6 steps 7-11, 7.5, 8; D11, D13, D20).
# Synthetic machine state from Fixtures.ps1; every building block of other modules is stubbed and mocked.
# Pester 3.4 leaks a Mock defined inside an It into later Its: mocks are only defined at Describe/Context level,
# each scenario runs once in its Context body and the Its assert with -Scope Context.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$lib = Join-Path $here '..\src\lib'
foreach ($m in @('Compat', 'Log', 'Config', 'Rights', 'Principals', 'AutoLogon', 'Plan', 'Apply')) { . (Join-Path $lib ($m + '.ps1')) }
. (Join-Path $here 'Fixtures.ps1')

# Stubs of the building blocks (CONTRACTS "M2/M3"), defined after the libs so the parameters match the contract.
function Get-CrUserInfo { param([string]$UserName) }
function Invoke-CrLogonTest { param([string]$UserName, $Secret, [string]$LogonType) }
function Unlock-CrAccount { param([string]$UserName) }
function Invoke-CrPasswordRotation { param($User, $OldSecret, $NewSecret, [string]$Path, $Journal, [string]$RunId) }
function Set-CrAccountFlags { param($User, $Role) }
function Invoke-CrGroupMembershipChange { param($State, [string]$MemberSid, [string[]]$AddGroupSids, [string[]]$RemoveGroupSids) }
function Grant-CrDependentRights { param([string]$Sid, [string[]]$Rights) }
function Update-CrServiceCredentials { param($State, [string]$Sid, $Secret) }
function Update-CrTaskCredentials { param($State, [string]$Sid, $Secret) }
function Update-CrComPlusCredentials { param($State, [string]$Sid, $Secret) }
function Invoke-CrAutoLogonAction { param($Decision, $State, $Secret) }
function Add-CrJournalStep { param($Journal, [string]$RunId, [string]$Sid, [string]$Step) }
function Read-CrHostLine { param([string]$Prompt) }
function Read-CrSecureHost { param([string]$Prompt) }
function Test-CrSecretEqual { param($A, $B) }
function Invoke-CrCredentialProbe { param($State, $Account, $OldSecret, $NewSecret, $Journal, [string]$RunId) }

$TestRunningSid = 'S-1-5-21-9-9-9-9999'

# Slot secrets as Read-CrSlotSecrets returns them; the SecureStrings are empty (only identity matters here).
function New-TestSlotSecrets {
    param($Resolved, [string[]]$Slots, [string[]]$ReapplySids = @())
    $result = @{}
    foreach ($slot in $Slots) {
        $accounts = New-Object System.Collections.ArrayList
        foreach ($e in $Resolved) {
            if ($e['Slot'] -ne $slot -or $e['Mode'] -ne 'Rotate') { continue }
            foreach ($a in $e['Accounts']) {
                [void]$accounts.Add(@{ Sid = $a['Sid']; Name = $a['Name']; OldSecret = (New-Object System.Security.SecureString); Reapply = ($ReapplySids -contains $a['Sid']) })
            }
        }
        $result[$slot] = @{ Slot = $slot; Label = $slot; Skipped = $false; Reason = $null; NewSecret = (New-Object System.Security.SecureString); Accounts = $accounts.ToArray(); Findings = @() }
    }
    return $result
}

function New-TestProbes {
    param($SlotSecrets, [hashtable]$Outcomes = @{}, [hashtable]$Paths = @{})
    $probes = @{}
    foreach ($k in @($SlotSecrets.Keys)) {
        foreach ($a in $SlotSecrets[$k]['Accounts']) {
            $o = 'Old'
            if ($a['Reapply']) { $o = 'Reapply' }
            if ($Outcomes.ContainsKey($a['Sid'])) { $o = $Outcomes[$a['Sid']] }
            $probes[$a['Sid']] = @{ Sid = $a['Sid']; Name = $a['Name']; Outcome = $o; LogonType = 'Network'; Fallback = $false; Win32Error = 0; Attempts = 1; Message = $null }
            if ($Paths.ContainsKey($a['Sid'])) { $probes[$a['Sid']]['Path'] = $Paths[$a['Sid']] }
        }
    }
    return $probes
}

# Runs Invoke-CrApply on a fixture state; the slot secrets are kept in $global:CrTestSlotSecrets for the filters.
function Invoke-TestApply {
    param(
        $State, [string[]]$Slots, [hashtable]$Outcomes = @{}, [hashtable]$Paths = @{}, [string[]]$ReapplySids = @(),
        [string[]]$Only, [string]$RunningSid = $TestRunningSid, $Preflight, [string]$AutoLogonChoice
    )
    $config = New-CrTestConfig
    $resolved = Resolve-CrAccounts -Config $config -State $State
    if (-not $Preflight) { $Preflight = @{ MachineBlocked = $false; BlockedSlots = @{}; Findings = @() } }
    $plan = New-CrPlan -State $State -Config $config -Resolved $resolved -Preflight $Preflight -Only $Only -RunningSid $RunningSid
    $ss = New-TestSlotSecrets -Resolved $resolved -Slots $Slots -ReapplySids $ReapplySids
    $probes = New-TestProbes -SlotSecrets $ss -Outcomes $Outcomes -Paths $Paths
    $global:CrTestSlotSecrets = $ss
    return Invoke-CrApply -State $State -Config $config -Resolved $resolved -Preflight $Preflight -Plan $plan -SlotSecrets $ss `
        -Probes $probes -Journal @{ Runs = @() } -RunId 'test-run' -Only $Only -RunningSid $RunningSid -AutoLogonChoice $AutoLogonChoice
}

function Get-TestSlot {
    param($Result, [string]$Slot)
    foreach ($s in $Result['Slots']) { if ($s['Slot'] -eq $Slot) { return $s } }
    return $null
}

function Get-TestFindings {
    param($Result, [string]$Severity, [string]$Area, [string]$Account, [string]$Like)
    return @($Result['Findings'] | Where-Object {
        (-not $Severity -or $_['Severity'] -eq $Severity) -and (-not $Area -or $_['Area'] -eq $Area) -and
        (-not $Account -or $_['Account'] -eq $Account) -and (-not $Like -or $_['Message'] -like $Like)
    })
}

Describe 'Get-CrApplyAccountPath' {
    $sa = @{ Sid = 'S-1-5-21-1000-2000-3000-1001'; Name = 'A'; Reapply = $false }
    $saReapply = @{ Sid = 'S-1-5-21-1000-2000-3000-1001'; Name = 'A'; Reapply = $true }
    It 'Old -> Change' { (Get-CrApplyAccountPath -Probe @{ Outcome = 'Old' } -SecretAccount $sa)['Path'] | Should Be 'Change' }
    It 'New -> New (secret step skipped)' { (Get-CrApplyAccountPath -Probe @{ Outcome = 'New' } -SecretAccount $sa)['Path'] | Should Be 'New' }
    It 'Reapply -> Reapply' { (Get-CrApplyAccountPath -Probe @{ Outcome = 'Reapply' } -SecretAccount $saReapply)['Path'] | Should Be 'Reapply' }
    It 'Unverifiable -> Change' { (Get-CrApplyAccountPath -Probe @{ Outcome = 'Unverifiable' } -SecretAccount $sa)['Path'] | Should Be 'Change' }
    It 'Locked -> unlock, then Change' {
        $p = Get-CrApplyAccountPath -Probe @{ Outcome = 'Locked' } -SecretAccount $sa
        $p['Path'] | Should Be 'Change'
        $p['Unlock'] | Should Be $true
    }
    It 'BothFailed, BudgetExceeded and Disabled without a choice -> Skip' {
        foreach ($o in @('BothFailed', 'BudgetExceeded', 'Disabled')) {
            (Get-CrApplyAccountPath -Probe @{ Outcome = $o } -SecretAccount $sa)['Path'] | Should Be 'Skip'
        }
    }
    It 'operator choice Reset / Skip wins' {
        (Get-CrApplyAccountPath -Probe @{ Outcome = 'BothFailed'; Path = 'Reset' } -SecretAccount $sa)['Path'] | Should Be 'Reset'
        (Get-CrApplyAccountPath -Probe @{ Outcome = 'Old'; Path = 'Skip' } -SecretAccount $sa)['Path'] | Should Be 'Skip'
    }
    It 'no probe or no password -> Skip' {
        (Get-CrApplyAccountPath -Probe $null -SecretAccount $sa)['Path'] | Should Be 'Skip'
        (Get-CrApplyAccountPath -Probe @{ Outcome = 'Old' } -SecretAccount $null)['Path'] | Should Be 'Skip'
    }
}

Describe 'Invoke-CrApply' {
    Mock Get-CrUserInfo { @{ Success = $true; Win32Error = 0; Flags = 0x10201; BadPasswordCount = 0; PasswordAgeSeconds = 8640000 } }
    Mock Invoke-CrLogonTest { @{ Success = $true; Win32Error = 0 } }
    Mock Unlock-CrAccount { @{ Success = $true; Changed = $true; Win32Error = 0 } }
    Mock Invoke-CrPasswordRotation { @{ Success = $true; Win32Error = 0; Message = $null; Steps = @('Secret'); CcpRestoreFailed = $false; Warnings = @() } }
    Mock Set-CrAccountFlags { @{ Changed = $false; Success = $true; Win32Error = 0 } }
    Mock Invoke-CrGroupMembershipChange { , @() }
    Mock Grant-CrDependentRights { , @() }
    Mock Update-CrServiceCredentials { , @(@{ Name = 'MSSQLSERVER'; Success = $true; Win32Error = 0 }) }
    Mock Update-CrTaskCredentials { , @() }
    Mock Update-CrComPlusCredentials { , @() }
    Mock Invoke-CrAutoLogonAction { @{ Success = $true; Action = 'x'; Written = $true; Steps = @('done'); FailedStep = $null; Pending = @(); Error = $null } }
    Mock Add-CrJournalStep { }
    Mock Get-CrPathAllowSids { , @() }

    Context 'all Windows slots on the change path (IPT01-like)' {
        $state = New-CrTestState -Profile IPT01
        $pubSid = Get-CrTestUserSid $state 'PUB-User'
        $appSid = Get-CrTestUserSid $state 'ApplicationUser'
        $result = Invoke-TestApply -State $state -Slots @('BiCAAdmin', 'AppUserApplication', 'AutoLogon', 'BiCARemote')

        It 'processes the slots in ascending Order, BiCA Remote last' {
            (@($result['Slots'] | ForEach-Object { $_['Slot'] }) -join ',') | Should Be 'BiCAAdmin,AppUserApplication,AppUserBuiltinAdmin,AutoLogon,SQLApplication,SQLScript,SQLService,BiCARemote'
        }
        It 'completes every Windows slot' {
            foreach ($s in @('BiCAAdmin', 'AppUserApplication', 'AutoLogon', 'BiCARemote')) { (Get-TestSlot $result $s)['Status'] | Should Be 'Done' }
            (Get-TestSlot $result 'AppUserBuiltinAdmin')['Status'] | Should Be 'NotApplicable'
            (Get-TestSlot $result 'SQLApplication')['Status'] | Should Be 'Skipped'
        }
        It 'changes every account once with the change path' {
            Assert-MockCalled Invoke-CrPasswordRotation -Times 5 -Exactly -Scope Context
            Assert-MockCalled Invoke-CrPasswordRotation -Times 5 -Exactly -Scope Context -ParameterFilter { $Path -eq 'Change' }
        }
        It 'tests each new password once (no second verification for tested accounts)' {
            Assert-MockCalled Invoke-CrLogonTest -Times 5 -Exactly -Scope Context
        }
        It 'updates the services of the application user with the new secret' {
            Assert-MockCalled Update-CrServiceCredentials -Times 1 -Exactly -Scope Context -ParameterFilter {
                $Sid -eq $appSid -and [object]::ReferenceEquals($Secret, $global:CrTestSlotSecrets['AppUserApplication']['NewSecret'])
            }
        }
        It 'switches auto-logon to PUB-User with the auto-logon slot secret' {
            Assert-MockCalled Invoke-CrAutoLogonAction -Times 1 -Exactly -Scope Context -ParameterFilter {
                $Decision['Action'] -eq 'Switch' -and $Decision['TargetSid'] -eq $pubSid -and
                [object]::ReferenceEquals($Secret, $global:CrTestSlotSecrets['AutoLogon']['NewSecret'])
            }
        }
        It 'lists LOGINS follow-ups only for accounts with a LOGINS entry' {
            (Get-TestFindings $result 'FollowUp' 'LOGINS' 'BiCA Admin').Count | Should Be 1
            (Get-TestFindings $result 'FollowUp' 'LOGINS' 'PUB-User').Count | Should Be 0
        }
        It 'exits with 4 (follow-up required)' {
            $result['ExitCode'] | Should Be 4
        }
    }

    Context 're-apply (D20)' {
        $state = New-CrTestState -Profile IPT01
        $bicaSid = Get-CrTestUserSid $state 'BiCA Admin'
        $result = Invoke-TestApply -State $state -Slots @('BiCAAdmin') -ReapplySids @($bicaSid) -Only @('BiCAAdmin')

        It 'never calls the password change' {
            Assert-MockCalled Invoke-CrPasswordRotation -Times 0 -Exactly -Scope Context
        }
        It 'still verifies the account and enforces its flags' {
            Assert-MockCalled Invoke-CrLogonTest -Times 1 -Exactly -Scope Context
            Assert-MockCalled Set-CrAccountFlags -Times 1 -Exactly -Scope Context -ParameterFilter { $User['Name'] -eq 'BiCA Admin' }
        }
        It 'produces no LOGINS follow-up and exits with 0' {
            (Get-TestFindings $result 'FollowUp').Count | Should Be 0
            (Get-TestSlot $result 'BiCAAdmin')['Status'] | Should Be 'Done'
            $result['ExitCode'] | Should Be 0
        }
        It 'skips the check-mode fixes under -Only' {
            (Get-TestFindings $result 'Info' 'Check' $null '*not processed under -Only*').Count | Should Be 1
        }
    }

    Context 'already on the new password (New)' {
        $state = New-CrTestState -Profile IPT01
        $appSid = Get-CrTestUserSid $state 'ApplicationUser'
        $result = Invoke-TestApply -State $state -Slots @('AppUserApplication') -Outcomes @{ $appSid = 'New' } -Only @('AppUserApplication')

        It 'skips the secret step but rewrites the dependents' {
            Assert-MockCalled Invoke-CrPasswordRotation -Times 0 -Exactly -Scope Context
            Assert-MockCalled Update-CrServiceCredentials -Times 1 -Exactly -Scope Context -ParameterFilter { $Sid -eq $appSid }
        }
        It 'has no LOGINS follow-up' {
            (Get-TestFindings $result 'FollowUp' 'LOGINS').Count | Should Be 0
            $result['ExitCode'] | Should Be 0
        }
    }

    Context 'unverifiable probe (1385)' {
        $state = New-CrTestState -Profile IPT01
        $bicaSid = Get-CrTestUserSid $state 'BiCA Admin'
        $result = Invoke-TestApply -State $state -Slots @('BiCAAdmin') -Outcomes @{ $bicaSid = 'Unverifiable' } -Only @('BiCAAdmin')

        It 'uses the change path' {
            Assert-MockCalled Invoke-CrPasswordRotation -Times 1 -Exactly -Scope Context -ParameterFilter { $Path -eq 'Change' -and $User['Name'] -eq 'BiCA Admin' }
            (Get-TestSlot $result 'BiCAAdmin')['Status'] | Should Be 'Done'
        }
    }

    Context 'locked account' {
        $state = New-CrTestState -Profile IPT01
        (Get-CrTestUser $state 'BiCA Admin')['LockedOut'] = $true
        $bicaSid = Get-CrTestUserSid $state 'BiCA Admin'
        $result = Invoke-TestApply -State $state -Slots @('BiCAAdmin') -Outcomes @{ $bicaSid = 'Locked' } -Only @('BiCAAdmin')

        It 'unlocks first, then changes with an unlocked user record' {
            Assert-MockCalled Unlock-CrAccount -Times 1 -Exactly -Scope Context -ParameterFilter { $UserName -eq 'BiCA Admin' }
            Assert-MockCalled Invoke-CrPasswordRotation -Times 1 -Exactly -Scope Context -ParameterFilter { $Path -eq 'Change' -and -not $User['LockedOut'] }
            (Get-TestSlot $result 'BiCAAdmin')['Status'] | Should Be 'Done'
        }
    }

    Context 'both passwords failed, no operator choice' {
        $state = New-CrTestState -Profile IPT01
        $bicaSid = Get-CrTestUserSid $state 'BiCA Admin'
        $result = Invoke-TestApply -State $state -Slots @('BiCAAdmin') -Outcomes @{ $bicaSid = 'BothFailed' } -Only @('BiCAAdmin')

        It 'skips the slot without touching the account' {
            (Get-TestSlot $result 'BiCAAdmin')['Status'] | Should Be 'Skipped'
            Assert-MockCalled Invoke-CrPasswordRotation -Times 0 -Exactly -Scope Context
            Assert-MockCalled Set-CrAccountFlags -Times 0 -Exactly -Scope Context
        }
    }

    Context 'both passwords failed, operator chose reset' {
        $state = New-CrTestState -Profile IPT01
        $bicaSid = Get-CrTestUserSid $state 'BiCA Admin'
        $result = Invoke-TestApply -State $state -Slots @('BiCAAdmin') -Outcomes @{ $bicaSid = 'BothFailed' } -Paths @{ $bicaSid = 'Reset' } -Only @('BiCAAdmin')

        It 'resets the password and reports the DPAPI impact' {
            Assert-MockCalled Invoke-CrPasswordRotation -Times 1 -Exactly -Scope Context -ParameterFilter { $Path -eq 'Reset' }
            (Get-TestFindings $result 'HighImpact' 'Password' 'BiCA Admin' '*DPAPI*').Count | Should Be 1
        }
    }

    Context 'a failing slot stops at its step; the others continue' {
        Mock Invoke-CrPasswordRotation -ParameterFilter { $User['Name'] -eq 'BiCA Admin' } { @{ Success = $false; Win32Error = 2245; Message = 'rejected'; Steps = @(); CcpRestoreFailed = $false; Warnings = @() } }
        $state = New-CrTestState -Profile IPT01
        Add-CrTestGroupMember $state 'Power Users' @((Get-CrTestUserSid $state 'BiCA Admin'), (Get-CrTestUserSid $state 'BiCA Remote'))
        $bicaSid = Get-CrTestUserSid $state 'BiCA Admin'
        $remoteSid = Get-CrTestUserSid $state 'BiCA Remote'
        $result = Invoke-TestApply -State $state -Slots @('BiCAAdmin', 'BiCARemote') -Only @('BiCAAdmin', 'BiCARemote')

        It 'stops BiCA Admin at the secret step with the pending steps listed' {
            $s = Get-TestSlot $result 'BiCAAdmin'
            $s['Status'] | Should Be 'Failed'
            $s['FailedStep'] | Should Be 'Secret'
            (@($s['Pending']) -contains 'BiCA Admin: Secret, Dependents, Grants, Verify') | Should Be $true
            Assert-MockCalled Set-CrAccountFlags -Times 0 -Exactly -Scope Context -ParameterFilter { $User['Name'] -eq 'BiCA Admin' }
        }
        It 'completes BiCA Remote' {
            (Get-TestSlot $result 'BiCARemote')['Status'] | Should Be 'Done'
        }
        It 'removes groups only for the completed slot' {
            Assert-MockCalled Invoke-CrGroupMembershipChange -Times 1 -Exactly -Scope Context -ParameterFilter { $MemberSid -eq $remoteSid -and $RemoveGroupSids -contains 'S-1-5-32-547' }
            Assert-MockCalled Invoke-CrGroupMembershipChange -Times 0 -Exactly -Scope Context -ParameterFilter { $MemberSid -eq $bicaSid -and @($RemoveGroupSids).Count -gt 0 }
        }
        It 'exits with 1' {
            $result['ExitCode'] | Should Be 1
        }
    }

    Context 'rail: the running account stays in Administrators' {
        $state = New-CrTestState -Profile IPT01
        $pubSid = Get-CrTestUserSid $state 'PUB-User'
        Add-CrTestGroupMember $state 'Administrators' @($pubSid)
        $result = Invoke-TestApply -State $state -Slots @('AutoLogon') -Only @('AutoLogon') -RunningSid $pubSid

        It 'never removes it from Administrators' {
            Assert-MockCalled Invoke-CrGroupMembershipChange -Times 0 -Exactly -Scope Context -ParameterFilter { $RemoveGroupSids -contains 'S-1-5-32-544' }
            (Get-TestFindings $result 'Info' 'Groups' 'PUB-User' 'Rail:*').Count | Should BeGreaterThan 0
        }
    }

    Context 'rail: Administrators keeps an enabled member that is running or verified' {
        $state = New-CrTestState -Profile IPT01
        $winAutoSid = Get-CrTestUserSid $state 'WinAutoUser'
        $builtinSid = Get-CrTestUserSid $state 'Administrator'
        (Get-CrTestGroup $state 'Administrators')['MemberSids'] = @($builtinSid, $winAutoSid)
        $result = Invoke-TestApply -State $state -Slots @('AutoLogon') -Only @('AutoLogon')

        It 'does not remove the last enabled verified admin' {
            Assert-MockCalled Invoke-CrGroupMembershipChange -Times 0 -Exactly -Scope Context -ParameterFilter { $RemoveGroupSids -contains 'S-1-5-32-544' }
            (Get-TestFindings $result 'Info' 'Groups' 'WinAutoUser' 'Rail: stays in Administrators*').Count | Should Be 1
        }
    }

    Context 'the auto-logon step gets only the accounts verified in this run' {
        Mock Get-CrAutoLogonDecision { @{ Action = 'NoChange'; CurrentSid = $null; CurrentName = $null; TargetSid = $null; TargetName = $null; Reasons = @(); OperatorOptions = @(); HighImpact = @() } }
        Mock Invoke-CrPasswordRotation -ParameterFilter { $User['Name'] -eq 'BiCA Admin' } { @{ Success = $false; Win32Error = 86; Message = $null; Steps = @(); CcpRestoreFailed = $false; Warnings = @() } }
        $state = New-CrTestState -Profile IPT01
        $global:CrTestPubSid = Get-CrTestUserSid $state 'PUB-User'
        $winAutoSid = Get-CrTestUserSid $state 'WinAutoUser'
        $result = Invoke-TestApply -State $state -Slots @('BiCAAdmin', 'AutoLogon') -Outcomes @{ $winAutoSid = 'BothFailed' } -Only @('BiCAAdmin', 'AutoLogon')

        It 'passes exactly PUB-User as verified' {
            Assert-MockCalled Get-CrAutoLogonDecision -Times 1 -Exactly -Scope Context -ParameterFilter {
                @($VerifiedSids).Count -eq 1 -and $VerifiedSids[0] -eq $global:CrTestPubSid
            }
        }
        It 'reports the auto-logon slot as partial (one account skipped)' {
            (Get-TestSlot $result 'AutoLogon')['Status'] | Should Be 'Failed'
            (Get-TestSlot $result 'BiCAAdmin')['Status'] | Should Be 'Failed'
        }
    }

    Context 'ambiguous auto-logon with the operator choice TurnOff' {
        Mock Get-CrAutoLogonDecision { @{ Action = 'Ambiguous'; CurrentSid = 'S-1-5-21-1000-2000-4000-1001'; CurrentName = 'BiCA Admin'; TargetSid = $null; TargetName = $null; Reasons = @('test'); OperatorOptions = @('TurnOff', 'LeaveUnchanged'); HighImpact = @() } }
        $state = New-CrTestState -Profile IPT01
        $result = Invoke-TestApply -State $state -Slots @('BiCAAdmin') -Only @('BiCAAdmin') -AutoLogonChoice 'TurnOff'

        It 'turns auto-logon off without a secret' {
            Assert-MockCalled Invoke-CrAutoLogonAction -Times 1 -Exactly -Scope Context -ParameterFilter { $Decision['Action'] -eq 'TurnOff' -and $null -eq $Secret }
        }
    }

    Context 'a failing auto-logon step' {
        Mock Invoke-CrAutoLogonAction { @{ Success = $false; Action = 'Switch'; Written = $false; Steps = @(); FailedStep = 'LsaSecret'; Pending = @('Registry'); Error = 'failed' } }
        $state = New-CrTestState -Profile IPT01
        $result = Invoke-TestApply -State $state -Slots @('AutoLogon') -Only @('AutoLogon')

        It 'is reported with the failed step and exits with 1' {
            (Get-TestFindings $result 'Blocked' 'AutoLogon' $null '*at LsaSecret*').Count | Should Be 1
            $result['ExitCode'] | Should Be 1
        }
    }

    Context 'check-mode fixes without -Only (SM-like)' {
        $state = New-CrTestState -Profile SM
        $result = Invoke-TestApply -State $state -Slots @()

        It 'fixes flags and groups of the check-mode accounts' {
            Assert-MockCalled Set-CrAccountFlags -Scope Context -ParameterFilter { $User['Name'] -eq 'WinUser1' }
            Assert-MockCalled Invoke-CrGroupMembershipChange -Scope Context -ParameterFilter { $RemoveGroupSids -contains 'S-1-5-32-547' }
            (@($result['CheckFixes'] | ForEach-Object { $_['Id'] }) -contains 'WinUsers') | Should Be $true
        }
        It 'never touches a password' {
            Assert-MockCalled Invoke-CrPasswordRotation -Times 0 -Exactly -Scope Context
        }
    }

    Context 'check-mode fixes under -Only (SM-like)' {
        $state = New-CrTestState -Profile SM
        $result = Invoke-TestApply -State $state -Slots @('BiCAAdmin') -Only @('BiCAAdmin')

        It 'are skipped' {
            Assert-MockCalled Set-CrAccountFlags -Times 0 -Exactly -Scope Context -ParameterFilter { $User['Name'] -eq 'WinUser1' }
            @($result['CheckFixes']).Count | Should Be 0
        }
    }

    Context 'machine blocked' {
        $state = New-CrTestState -Profile IPT01
        $pf = @{ MachineBlocked = $true; BlockedSlots = @{}; Findings = @() }
        $result = Invoke-TestApply -State $state -Slots @('BiCAAdmin') -Preflight $pf

        It 'changes nothing and exits with 2' {
            Assert-MockCalled Invoke-CrPasswordRotation -Times 0 -Exactly -Scope Context
            Assert-MockCalled Invoke-CrAutoLogonAction -Times 0 -Exactly -Scope Context
            $result['ExitCode'] | Should Be 2
        }
    }

    Context 'blocked slot' {
        $state = New-CrTestState -Profile IPT01
        $pf = @{ MachineBlocked = $false; BlockedSlots = @{ BiCAAdmin = 'test block' }; Findings = @() }
        $result = Invoke-TestApply -State $state -Slots @('BiCAAdmin') -Preflight $pf -Only @('BiCAAdmin')

        It 'is reported as Blocked and not processed' {
            (Get-TestSlot $result 'BiCAAdmin')['Status'] | Should Be 'Blocked'
            Assert-MockCalled Invoke-CrPasswordRotation -Times 0 -Exactly -Scope Context
        }
    }
}

Describe 'Resolve-CrProbeDecisions' {
    Context 'both passwords failed, operator answers R' {
        Mock Read-CrHostLine { 'R' }
        Mock Invoke-CrCredentialProbe { throw 'must not probe again' }
        $state = New-CrTestState -Profile IPT01
        $config = New-CrTestConfig
        $resolved = Resolve-CrAccounts -Config $config -State $state
        $bicaSid = Get-CrTestUserSid $state 'BiCA Admin'
        $ss = New-TestSlotSecrets -Resolved $resolved -Slots @('BiCAAdmin')
        $probes = New-TestProbes -SlotSecrets $ss -Outcomes @{ $bicaSid = 'BothFailed' }
        $pf = @{ MachineBlocked = $false; BlockedSlots = @{}; Findings = @() }
        Resolve-CrProbeDecisions -State $state -Config $config -Resolved $resolved -Preflight $pf -SlotSecrets $ss -Probes $probes -Journal @{ Runs = @() } -RunId 'r' -Only @('BiCAAdmin')

        It 'stores the reset choice on the probe' {
            $probes[$bicaSid]['Path'] | Should Be 'Reset'
            Assert-MockCalled Read-CrHostLine -Times 1 -Exactly -Scope Context
        }
    }

    Context 'old password accepted' {
        Mock Read-CrHostLine { 'S' }
        $state = New-CrTestState -Profile IPT01
        $config = New-CrTestConfig
        $resolved = Resolve-CrAccounts -Config $config -State $state
        $bicaSid = Get-CrTestUserSid $state 'BiCA Admin'
        $ss = New-TestSlotSecrets -Resolved $resolved -Slots @('BiCAAdmin')
        $probes = New-TestProbes -SlotSecrets $ss
        $pf = @{ MachineBlocked = $false; BlockedSlots = @{}; Findings = @() }
        Resolve-CrProbeDecisions -State $state -Config $config -Resolved $resolved -Preflight $pf -SlotSecrets $ss -Probes $probes -Journal @{ Runs = @() } -RunId 'r' -Only @('BiCAAdmin')

        It 'asks nothing' {
            Assert-MockCalled Read-CrHostLine -Times 0 -Exactly -Scope Context
            $probes[$bicaSid].ContainsKey('Path') | Should Be $false
        }
    }
}

Describe 'Clear-CrSlotSecrets' {
    It 'disposes the new and the old secrets' {
        $new = New-Object System.Security.SecureString
        $old = New-Object System.Security.SecureString
        Clear-CrSlotSecrets -SlotSecrets @{ S = @{ Slot = 'S'; Skipped = $false; NewSecret = $new; Accounts = @(@{ Sid = 'S-1-5-21-1000-2000-3000-1001'; OldSecret = $old }) } }
        { $null = $new.Length } | Should Throw
        { $null = $old.Length } | Should Throw
    }
}
