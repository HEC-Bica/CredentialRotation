# Pester 3.4 tests for src\lib\Apply.ps1, account model v10 (PLAN sections 6 steps 6-11, 7.5, 8; D9, D11, D13, D20-D25).
# Synthetic machine state from Fixtures.ps1 (SM: SOP-Admin and PUB-User to be created; IPT01: all three exist);
# every building block of other modules is stubbed and mocked. Pester 3.4 leaks a Mock defined inside an It into
# later Its: mocks are only defined at Describe/Context level, each scenario runs once in its Context body and the
# Its assert with -Scope Context.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$lib = Join-Path $here '..\src\lib'
foreach ($m in @('Compat', 'Log', 'Config', 'Rights', 'Principals', 'AutoLogon', 'Plan', 'Apply')) { . (Join-Path $lib ($m + '.ps1')) }
. (Join-Path $here 'Fixtures.ps1')

# Stubs of the building blocks (CONTRACTS "M2/M3" and "v10"), defined after the libs so they replace the real ones.
function Get-CrUserInfo { param([string]$UserName) }
function Invoke-CrLogonTest { param([string]$UserName, $Secret, [string]$LogonType) }
function Unlock-CrAccount { param([string]$UserName) }
function Invoke-CrPasswordRotation { param($User, $OldSecret, $NewSecret, [string]$Path, $Journal, [string]$RunId) }
function Invoke-CrPasswordSet { param($User, $NewSecret, $Journal, [string]$RunId) }
function New-CrManagedAccount { param([string]$Name, $Secret, [string]$Comment, $Journal, [string]$RunId) }
function Enable-CrAccount { param($User) }
function Disable-CrAccount { param($User, $Journal, [string]$RunId) }
function Set-CrAccountFlags { param($User, $Role) }
function Invoke-CrGroupMembershipChange { param($State, [string]$MemberSid, [string[]]$AddGroupSids, [string[]]$RemoveGroupSids) }
function Grant-CrDependentRights { param([string]$Sid, [string[]]$Rights) }
function Update-CrServiceCredentials { param($State, [string]$Sid, $Secret) }
function Update-CrTaskCredentials { param($State, [string]$Sid, $Secret) }
function Update-CrComPlusCredentials { param($State, [string]$Sid, $Secret) }
function Move-CrServiceAccount { param($State, [string]$FromSid, [string]$ToAccount, $Secret) }
function Move-CrTaskAccount { param($State, [string]$FromSid, [string]$ToUserId, $Secret) }
function Move-CrComPlusIdentity { param($State, [string]$FromSid, [string]$ToIdentity, $Secret) }
function Invoke-CrAutoLogonAction { param($Decision, $State, $Secret) }
function Add-CrJournalStep { param($Journal, [string]$RunId, [string]$Sid, [string]$Step) }
function Read-CrHostLine { param([string]$Prompt) }
function Read-CrSecureHost { param([string]$Prompt) }
function Test-CrSecretEqual { param($A, $B) }
function Invoke-CrCredentialProbe { param($State, $Account, $OldSecret, $NewSecret, $Journal, [string]$RunId) }

# SIDs the New-CrManagedAccount mock hands out for created accounts (synthetic).
$global:CrTestNewSids = @{ 'SOP-Admin' = 'S-1-5-21-1000-2000-3000-1106'; 'PUB-User' = 'S-1-5-21-1000-2000-3000-1105'; 'ApplicationUser' = 'S-1-5-21-1000-2000-3000-1103' }

# Slot secrets as Read-CrSlotSecrets returns them (v10): old password only for existing Change accounts.
# The SecureStrings are empty (only identity matters here).
function New-TestSlotSecrets {
    param($Resolved, [string[]]$Slots, [string[]]$ReapplySids = @())
    $result = @{}
    foreach ($slot in $Slots) {
        $accounts = New-Object System.Collections.ArrayList
        foreach ($e in $Resolved) {
            if ($e['Slot'] -ne $slot -or $e['Mode'] -ne 'Rotate') { continue }
            foreach ($a in $e['Accounts']) {
                $old = $null
                if ($e['PasswordMode'] -eq 'Change' -and $a['Sid']) { $old = New-Object System.Security.SecureString }
                [void]$accounts.Add(@{ Sid = $a['Sid']; Name = $a['Name']; OldSecret = $old; Reapply = ($ReapplySids -contains $a['Sid'])
                                       PasswordMode = $e['PasswordMode']; Create = [bool]$a['ToCreate'] })
            }
        }
        $result[$slot] = @{ Slot = $slot; Label = $slot; Skipped = $false; Reason = $null; NewSecret = (New-Object System.Security.SecureString); Accounts = $accounts.ToArray(); Findings = @() }
    }
    return $result
}

# Probe results of the Change accounts (Old by default, Reapply for re-apply accounts).
function New-TestProbes {
    param($SlotSecrets, [hashtable]$Outcomes = @{}, [hashtable]$Paths = @{})
    $probes = @{}
    foreach ($k in @($SlotSecrets.Keys)) {
        foreach ($a in $SlotSecrets[$k]['Accounts']) {
            if ($a['PasswordMode'] -ne 'Change' -or -not $a['Sid']) { continue }
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
        $State, [string[]]$Slots = @('SOPAdmin', 'AppUser', 'PubUser'), [hashtable]$Outcomes = @{}, [hashtable]$Paths = @{},
        [string[]]$ReapplySids = @(), [string[]]$Only, [string]$RunningSid, $Preflight, [string]$AutoLogonChoice,
        [hashtable]$OtherDecisions = @{}, [hashtable]$DependentDecisions = @{}
    )
    $config = New-CrTestConfig
    $resolved = Resolve-CrAccounts -Config $config -State $State
    if (-not $RunningSid) { $RunningSid = Get-CrTestUserSid $State 'BiCA Remote' }
    if (-not $Preflight) { $Preflight = @{ MachineBlocked = $false; BlockedSlots = @{}; Findings = @() } }
    $ss = New-TestSlotSecrets -Resolved $resolved -Slots $Slots -ReapplySids $ReapplySids
    $probes = New-TestProbes -SlotSecrets $ss -Outcomes $Outcomes -Paths $Paths
    $global:CrTestSlotSecrets = $ss
    return Invoke-CrApply -State $State -Config $config -Resolved $resolved -Preflight $Preflight -Plan @{ Findings = @() } -SlotSecrets $ss `
        -Probes $probes -Journal @{ Runs = @() } -RunId 'test-run' -Only $Only -RunningSid $RunningSid -AutoLogonChoice $AutoLogonChoice `
        -OtherDecisions $OtherDecisions -DependentDecisions $DependentDecisions
}

function Get-TestSlot {
    param($Result, [string]$Slot)
    foreach ($s in $Result['Slots']) { if ($s['Slot'] -eq $Slot) { return $s } }
    return $null
}

function Get-TestDisable {
    param($Result, [string]$Name)
    foreach ($d in $Result['Disables']) { if ($d['Name'] -eq $Name) { return $d } }
    return $null
}

function Get-TestFindings {
    param($Result, [string]$Severity, [string]$Area, [string]$Account, [string]$Like)
    return @($Result['Findings'] | Where-Object {
        (-not $Severity -or $_['Severity'] -eq $Severity) -and (-not $Area -or $_['Area'] -eq $Area) -and
        (-not $Account -or $_['Account'] -eq $Account) -and (-not $Like -or $_['Message'] -like $Like)
    })
}

Describe 'Get-CrApplyAccountPath (Change accounts)' {
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
    It 'operator choice Set / Skip wins' {
        (Get-CrApplyAccountPath -Probe @{ Outcome = 'BothFailed'; Path = 'Set' } -SecretAccount $sa)['Path'] | Should Be 'Set'
        (Get-CrApplyAccountPath -Probe @{ Outcome = 'Old'; Path = 'Skip' } -SecretAccount $sa)['Path'] | Should Be 'Skip'
    }
}

Describe 'Get-CrApplyPreview / Get-CrApplyAccountFates (SM: accounts to create)' {
    $state = New-CrTestState -Profile SM
    $config = New-CrTestConfig
    $resolved = Resolve-CrAccounts -Config $config -State $state
    $ss = New-TestSlotSecrets -Resolved $resolved -Slots @('SOPAdmin', 'AppUser', 'PubUser')
    $probes = New-TestProbes -SlotSecrets $ss
    $pf = @{ MachineBlocked = $false; BlockedSlots = @{}; Findings = @() }
    $preview = Get-CrApplyPreview -Config $config -Resolved $resolved -Preflight $pf -SlotSecrets $ss -Probes $probes -Only $null
    $runningSid = Get-CrTestUserSid $state 'BiCA Remote'
    $others = @((Get-CrTestUser $state 'myftpuser'), (Get-CrTestUser $state 'OtherAdmin'))
    $fates = Get-CrApplyAccountFates -State $state -Resolved $resolved -RunningSid $runningSid -Only $null -Others $others
    $fate = @{}
    foreach ($f in $fates) { $fate[$f['Name']] = $f['Fate'] }

    It 'creates the missing accounts, sets SOP-Admin and changes ApplicationUser' {
        ((Find-CrApplyPreviewSlot $preview 'SOPAdmin')['Accounts'][0])['Path'] | Should Be 'Create'
        ((Find-CrApplyPreviewSlot $preview 'PubUser')['Accounts'][0])['Path'] | Should Be 'Create'
        ((Find-CrApplyPreviewSlot $preview 'AppUser')['Accounts'][0])['Path'] | Should Be 'Change'
        (Find-CrApplyPreviewSlot $preview 'SQLApplication')['Status'] | Should Be 'Skipped'
    }
    It 'lists the fate of every enabled account' {
        $fate['SOP-Admin'] | Should Be 'create'
        $fate['ApplicationUser'] | Should Be 'change'
        $fate['BiCA Admin'] | Should Be 'disable'
        $fate['BiCA Remote'] | Should Be 'disable'
        $fate['SP Admin'] | Should Be 'disable'
        $fate['OtherAdmin'] | Should Be 'ask'
        $fate['WinUser1'] | Should Be 'keep'
        $fate.ContainsKey('WinUser3') | Should Be $false
    }
}

Describe 'Invoke-CrApply' {
    Mock Get-CrUserInfo { @{ Success = $true; Win32Error = 0; Flags = 0x10201; BadPasswordCount = 0; PasswordAgeSeconds = 8640000 } }
    Mock Invoke-CrLogonTest { @{ Success = $true; Win32Error = 0 } }
    Mock Unlock-CrAccount { @{ Success = $true; Changed = $true; Win32Error = 0 } }
    Mock Invoke-CrPasswordRotation { @{ Success = $true; Win32Error = 0; Message = $null; Steps = @('Secret'); CcpRestoreFailed = $false; Warnings = @() } }
    Mock Invoke-CrPasswordSet { @{ Success = $true; Win32Error = 0; Message = $null; Steps = @('Secret'); Warnings = @() } }
    Mock New-CrManagedAccount { @{ Success = $true; Win32Error = 0; Message = $null; Name = $Name; Sid = $global:CrTestNewSids[$Name]; Steps = @('Created'); Warnings = @() } }
    Mock Enable-CrAccount { @{ Success = $true; Changed = $true; Win32Error = 0 } }
    Mock Disable-CrAccount { [void]$global:CrTestDisabled.Add([string]$User['Name']); @{ Success = $true; Changed = $true; Win32Error = 0 } }
    Mock Set-CrAccountFlags { @{ Changed = $false; Success = $true; Win32Error = 0 } }
    Mock Invoke-CrGroupMembershipChange {
        $l = New-Object System.Collections.ArrayList
        foreach ($g in @($AddGroupSids)) { if ($g) { [void]$l.Add(@{ GroupSid = $g; GroupName = $g; Action = 'Add'; Success = $true; Win32Error = 0 }) } }
        foreach ($g in @($RemoveGroupSids)) { if ($g) { [void]$l.Add(@{ GroupSid = $g; GroupName = $g; Action = 'Remove'; Success = $true; Win32Error = 0 }) } }
        , $l.ToArray()
    }
    Mock Grant-CrDependentRights { $l = New-Object System.Collections.ArrayList; foreach ($r in @($Rights)) { [void]$l.Add(@{ Right = $r; Success = $true; Win32Error = 0 }) }; , $l.ToArray() }
    Mock Update-CrServiceCredentials { , @(@{ Name = 'MSSQLSERVER'; Success = $true; Win32Error = 0 }) }
    Mock Update-CrTaskCredentials { , @() }
    Mock Update-CrComPlusCredentials { , @() }
    Mock Move-CrServiceAccount { , @(@{ Name = 'MovedService'; Success = $true; Win32Error = 0; Error = $null; FromAccount = 'old'; ToAccount = $ToAccount }) }
    Mock Move-CrTaskAccount { , @(@{ Path = '\MovedTask'; Success = $true; Error = $null; FromUserId = 'old'; ToUserId = $ToUserId; SaclDropped = $false; Warning = $null }) }
    Mock Move-CrComPlusIdentity { , @() }
    Mock Invoke-CrAutoLogonAction { @{ Success = $true; Action = $Decision['Action']; Written = $true; Steps = @('done'); FailedStep = $null; Pending = @(); Error = $null } }
    Mock Add-CrJournalStep { }

    Context 'IPT01: all accounts exist; set vs change; moves, disables, running account last' {
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile IPT01
        $sopSid = Get-CrTestUserSid $state 'SOP-Admin'
        $appSid = Get-CrTestUserSid $state 'ApplicationUser'
        $pubSid = Get-CrTestUserSid $state 'PUB-User'
        $bicaSid = Get-CrTestUserSid $state 'BiCA Admin'
        $sysSid = Get-CrTestUserSid $state 'SYS Admin'
        $result = Invoke-TestApply -State $state -DependentDecisions @{ $sysSid = 'Move' }

        It 'completes the three Windows slots; SQL slots are skipped' {
            foreach ($s in @('SOPAdmin', 'AppUser', 'PubUser')) { (Get-TestSlot $result $s)['Status'] | Should Be 'Done' }
            (Get-TestSlot $result 'SQLApplication')['Status'] | Should Be 'Skipped'
        }
        It 'sets SOP-Admin and PUB-User and changes ApplicationUser with its old password (D9)' {
            Assert-MockCalled Invoke-CrPasswordSet -Times 2 -Exactly -Scope Context
            Assert-MockCalled Invoke-CrPasswordSet -Times 1 -Exactly -Scope Context -ParameterFilter { $User['Sid'] -eq $sopSid }
            Assert-MockCalled Invoke-CrPasswordSet -Times 1 -Exactly -Scope Context -ParameterFilter { $User['Sid'] -eq $pubSid }
            Assert-MockCalled Invoke-CrPasswordRotation -Times 1 -Exactly -Scope Context -ParameterFilter { $Path -eq 'Change' -and $User['Sid'] -eq $appSid }
            Assert-MockCalled New-CrManagedAccount -Times 0 -Exactly -Scope Context
        }
        It 'adds SOP-Admin to Remote Desktop Users' {
            Assert-MockCalled Invoke-CrGroupMembershipChange -Times 1 -Exactly -Scope Context -ParameterFilter { $MemberSid -eq $sopSid -and @($AddGroupSids) -contains 'S-1-5-32-555' }
        }
        It 'moves the service of BiCA Admin to SOP-Admin with its new secret, after granting the service right' {
            Assert-MockCalled Grant-CrDependentRights -Times 1 -Exactly -Scope Context -ParameterFilter { $Sid -eq $sopSid -and @($Rights) -contains 'SeServiceLogonRight' }
            Assert-MockCalled Move-CrServiceAccount -Times 1 -Exactly -Scope Context -ParameterFilter {
                $FromSid -eq $bicaSid -and $ToAccount -eq '.\SOP-Admin' -and [object]::ReferenceEquals($Secret, $global:CrTestSlotSecrets['SOPAdmin']['NewSecret'])
            }
        }
        It 'moves the service of SYS Admin to ApplicationUser on the operator decision' {
            Assert-MockCalled Move-CrServiceAccount -Times 1 -Exactly -Scope Context -ParameterFilter { $FromSid -eq $sysSid -and $ToAccount -eq '.\ApplicationUser' }
        }
        It 'switches auto-logon to PUB-User with the PUB-User secret' {
            Assert-MockCalled Invoke-CrAutoLogonAction -Times 1 -Exactly -Scope Context -ParameterFilter {
                $Decision['Action'] -eq 'Switch' -and $Decision['TargetSid'] -eq $pubSid -and
                [object]::ReferenceEquals($Secret, $global:CrTestSlotSecrets['PubUser']['NewSecret'])
            }
        }
        It 'disables the replaced and retired accounts, the running account last' {
            $order = @($global:CrTestDisabled)
            $order.Count | Should Be 5
            $order[$order.Count - 1] | Should Be 'BiCA Remote'
            foreach ($n in @('BiCA Admin', 'Administrator', 'WinAutoUser', 'SYS Admin')) { ($order -contains $n) | Should Be $true }
            (Get-TestDisable $result 'BiCA Remote')['Status'] | Should Be 'Disabled'
        }
        It 'lists LOGINS follow-ups for the set and changed accounts with a LOGINS entry and the next logon' {
            (Get-TestFindings $result 'FollowUp' 'LOGINS' 'SOP-Admin').Count | Should Be 1
            (Get-TestFindings $result 'FollowUp' 'LOGINS' 'ApplicationUser').Count | Should Be 1
            (Get-TestFindings $result 'FollowUp' 'LOGINS' 'PUB-User').Count | Should Be 0
            (Get-TestFindings $result 'FollowUp' 'Accounts' 'BiCA Remote' '*Log on as SOP-Admin*').Count | Should Be 1
        }
        It 'exits with 4 (follow-up required)' {
            $result['ExitCode'] | Should Be 4
        }
    }

    Context 'SM: creation path, operator-kept accounts, task move to a created account' {
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile SM
        $winAutoSid = Get-CrTestUserSid $state 'WinAutoUser'
        $spSid = Get-CrTestUserSid $state 'SP Admin'
        $otherAdminSid = Get-CrTestUserSid $state 'OtherAdmin'
        $myftpSid = Get-CrTestUserSid $state 'myftpuser'
        $result = Invoke-TestApply -State $state -OtherDecisions @{ $otherAdminSid = 'Disable'; $myftpSid = 'Keep' } -DependentDecisions @{ $spSid = 'Keep' }

        It 'creates SOP-Admin and PUB-User with the slot secret instead of setting a password' {
            Assert-MockCalled New-CrManagedAccount -Times 1 -Exactly -Scope Context -ParameterFilter {
                $Name -eq 'SOP-Admin' -and [object]::ReferenceEquals($Secret, $global:CrTestSlotSecrets['SOPAdmin']['NewSecret'])
            }
            Assert-MockCalled New-CrManagedAccount -Times 1 -Exactly -Scope Context -ParameterFilter { $Name -eq 'PUB-User' }
            Assert-MockCalled Invoke-CrPasswordSet -Times 0 -Exactly -Scope Context
            @($result['CreatedSids']).Count | Should Be 2
        }
        It 'adds the created SOP-Admin to its role groups and verifies it' {
            Assert-MockCalled Invoke-CrGroupMembershipChange -Times 1 -Exactly -Scope Context -ParameterFilter {
                $MemberSid -eq $global:CrTestNewSids['SOP-Admin'] -and @($AddGroupSids) -contains 'S-1-5-32-544' -and @($AddGroupSids) -contains 'S-1-5-32-555'
            }
            (@($result['VerifiedSids']) -contains $global:CrTestNewSids['SOP-Admin']) | Should Be $true
        }
        It 'moves the password-stored task of WinAutoUser to the created PUB-User' {
            Assert-MockCalled Move-CrTaskAccount -Times 1 -Exactly -Scope Context -ParameterFilter { $FromSid -eq $winAutoSid -and $ToUserId -eq 'SM-TEST01\PUB-User' }
            Assert-MockCalled Grant-CrDependentRights -Times 1 -Exactly -Scope Context -ParameterFilter { $Sid -eq $global:CrTestNewSids['PUB-User'] -and @($Rights) -contains 'SeBatchLogonRight' }
        }
        It 'does not disable operator-kept accounts' {
            ($global:CrTestDisabled -contains 'SP Admin') | Should Be $false
            ($global:CrTestDisabled -contains 'myftpuser') | Should Be $false
            Assert-MockCalled Move-CrTaskAccount -Times 0 -Exactly -Scope Context -ParameterFilter { $FromSid -eq $spSid }
            (Get-TestDisable $result 'SP Admin')['Status'] | Should Be 'KeptEnabled'
        }
        It 'disables the replaced accounts and the account the operator chose, the running account last' {
            foreach ($n in @('BiCA Admin', 'WinAutoUser', 'OtherAdmin')) { ($global:CrTestDisabled -contains $n) | Should Be $true }
            ($global:CrTestDisabled -contains 'LocalAdm') | Should Be $false
            $global:CrTestDisabled[$global:CrTestDisabled.Count - 1] | Should Be 'BiCA Remote'
        }
        It 'turns auto-logon off on the SM machine and runs the check-mode fixes' {
            Assert-MockCalled Invoke-CrAutoLogonAction -Times 1 -Exactly -Scope Context -ParameterFilter { $Decision['Action'] -eq 'TurnOff' -and $null -eq $Secret }
            Assert-MockCalled Set-CrAccountFlags -Scope Context -ParameterFilter { $User['Name'] -eq 'WinUser1' }
            (@($result['CheckFixes'] | ForEach-Object { $_['Id'] }) -contains 'WinUsers') | Should Be $true
        }
        It 'lists a LOGINS follow-up for the created SOP-Admin' {
            (Get-TestFindings $result 'FollowUp' 'LOGINS' 'SOP-Admin').Count | Should Be 1
        }
    }

    Context 'the replacement fails its verification' {
        Mock Invoke-CrLogonTest -ParameterFilter { $UserName -eq 'SOP-Admin' } { @{ Success = $false; Win32Error = 1326 } }
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile IPT01
        $bicaSid = Get-CrTestUserSid $state 'BiCA Admin'
        $result = Invoke-TestApply -State $state -Slots @('SOPAdmin') -Only @('SOPAdmin')

        It 'stops the slot at the verify step' {
            (Get-TestSlot $result 'SOPAdmin')['Status'] | Should Be 'Failed'
            (Get-TestSlot $result 'SOPAdmin')['FailedStep'] | Should Be 'Verify'
        }
        It 'neither moves the dependents nor disables the replaced accounts' {
            Assert-MockCalled Move-CrServiceAccount -Times 0 -Exactly -Scope Context
            Assert-MockCalled Disable-CrAccount -Times 0 -Exactly -Scope Context
            (Get-TestDisable $result 'BiCA Admin')['Status'] | Should Be 'KeptEnabled'
            (Get-TestDisable $result 'BiCA Remote')['Status'] | Should Be 'KeptEnabled'
        }
        It 'exits with 1' {
            $result['ExitCode'] | Should Be 1
        }
    }

    Context 'the operator account cannot be verified with a logon (1385): the running account stays enabled' {
        Mock Invoke-CrLogonTest -ParameterFilter { $UserName -eq 'SOP-Admin' } { @{ Success = $false; Win32Error = 1385 } }
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile IPT01
        $result = Invoke-TestApply -State $state -Slots @('SOPAdmin') -Only @('SOPAdmin')

        It 'completes the slot (unverifiable is not a failure)' {
            (Get-TestSlot $result 'SOPAdmin')['Status'] | Should Be 'Done'
            (Get-TestFindings $result 'Info' 'Verify' 'SOP-Admin' '*could not be verified*').Count | Should Be 1
        }
        It 'keeps BiCA Admin and the running account enabled (D22, D25)' {
            Assert-MockCalled Disable-CrAccount -Times 0 -Exactly -Scope Context
            (Get-TestFindings $result 'HighImpact' 'Accounts' 'BiCA Remote' 'Your own account stays enabled*').Count | Should Be 1
        }
    }

    Context 'a failed dependent move keeps the old account enabled' {
        Mock Move-CrServiceAccount -ParameterFilter { $ToAccount -eq '.\SOP-Admin' } { , @(@{ Name = 'AppHelper'; Success = $false; Win32Error = 5; Error = 'access denied'; FromAccount = '.\BiCA Admin'; ToAccount = '.\SOP-Admin' }) }
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile IPT01
        $result = Invoke-TestApply -State $state -Slots @('SOPAdmin') -Only @('SOPAdmin')

        It 'does not disable BiCA Admin' {
            ($global:CrTestDisabled -contains 'BiCA Admin') | Should Be $false
            (Get-TestFindings $result 'Blocked' 'Accounts' 'BiCA Admin' 'Stays enabled*').Count | Should Be 1
        }
        It 'still disables the running account last (no dependents, SOP-Admin ready)' {
            @($global:CrTestDisabled) -join ',' | Should Be 'BiCA Remote'
        }
        It 'exits with 1' {
            $result['ExitCode'] | Should Be 1
        }
    }

    Context 'auto-logon left unchanged keeps its account enabled' {
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile IPT01
        # -Only SOPAdmin: PUB-User is not verified in this run, so the switch is ambiguous; no choice = leave unchanged.
        $result = Invoke-TestApply -State $state -Slots @('SOPAdmin') -Only @('SOPAdmin')

        It 'does not disable the auto-logon account and reports why' {
            Assert-MockCalled Invoke-CrAutoLogonAction -Times 0 -Exactly -Scope Context
            ($global:CrTestDisabled -contains 'BiCA Admin') | Should Be $false
            (Get-TestFindings $result 'HighImpact' 'Accounts' 'BiCA Admin' '*auto-logon as BiCA Admin breaks*').Count | Should Be 1
        }
        It 'still disables the running account last' {
            @($global:CrTestDisabled) -join ',' | Should Be 'BiCA Remote'
        }
    }

    Context 're-apply of ApplicationUser (D20) under -Only' {
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile IPT01
        $appSid = Get-CrTestUserSid $state 'ApplicationUser'
        $result = Invoke-TestApply -State $state -Slots @('AppUser') -ReapplySids @($appSid) -Only @('AppUser')

        It 'never changes or sets the password but rewrites the dependents' {
            Assert-MockCalled Invoke-CrPasswordRotation -Times 0 -Exactly -Scope Context
            Assert-MockCalled Invoke-CrPasswordSet -Times 0 -Exactly -Scope Context
            Assert-MockCalled Update-CrServiceCredentials -Times 1 -Exactly -Scope Context -ParameterFilter { $Sid -eq $appSid }
        }
        It 'still disables the replaced built-in Administrator' {
            @($global:CrTestDisabled) -join ',' | Should Be 'Administrator'
        }
        It 'has no LOGINS follow-up and exits with 0' {
            (Get-TestFindings $result 'FollowUp').Count | Should Be 0
            $result['ExitCode'] | Should Be 0
        }
        It 'skips the check-mode fixes and the retired accounts under -Only' {
            (Get-TestFindings $result 'Info' 'Check' $null '*not processed under -Only*').Count | Should Be 1
            Assert-MockCalled Move-CrServiceAccount -Times 0 -Exactly -Scope Context
        }
    }

    Context 'check-mode fixes and other accounts under -Only (SM)' {
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile SM
        $otherAdminSid = Get-CrTestUserSid $state 'OtherAdmin'
        $result = Invoke-TestApply -State $state -Slots @('PubUser') -Only @('PubUser') -OtherDecisions @{ $otherAdminSid = 'Disable' }

        It 'are skipped' {
            Assert-MockCalled Set-CrAccountFlags -Times 0 -Exactly -Scope Context -ParameterFilter { $User['Name'] -eq 'WinUser1' }
            @($result['CheckFixes']).Count | Should Be 0
            ($global:CrTestDisabled -contains 'OtherAdmin') | Should Be $false
            ($global:CrTestDisabled -contains 'SP Admin') | Should Be $false
        }
        It 'disables only the account replaced by the selected slot' {
            @($global:CrTestDisabled) -join ',' | Should Be 'WinAutoUser'
        }
    }

    Context 'ApplicationUser: both passwords failed, the operator chose set' {
        $state = New-CrTestState -Profile IPT01
        $appSid = Get-CrTestUserSid $state 'ApplicationUser'
        $result = Invoke-TestApply -State $state -Slots @('AppUser') -Only @('AppUser') -Outcomes @{ $appSid = 'BothFailed' } -Paths @{ $appSid = 'Set' }

        It 'sets the password and reports the DPAPI loss' {
            Assert-MockCalled Invoke-CrPasswordSet -Times 1 -Exactly -Scope Context -ParameterFilter { $User['Sid'] -eq $appSid }
            Assert-MockCalled Invoke-CrPasswordRotation -Times 0 -Exactly -Scope Context
            (Get-TestFindings $result 'HighImpact' 'Password' 'ApplicationUser' '*DPAPI*').Count | Should Be 1
        }
    }

    Context 'ApplicationUser: both passwords failed, no choice' {
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile IPT01
        $appSid = Get-CrTestUserSid $state 'ApplicationUser'
        $result = Invoke-TestApply -State $state -Slots @('AppUser') -Only @('AppUser') -Outcomes @{ $appSid = 'BothFailed' }

        It 'skips the slot and keeps the built-in Administrator enabled' {
            (Get-TestSlot $result 'AppUser')['Status'] | Should Be 'Skipped'
            Assert-MockCalled Invoke-CrPasswordRotation -Times 0 -Exactly -Scope Context
            Assert-MockCalled Disable-CrAccount -Times 0 -Exactly -Scope Context
        }
    }

    Context 'machine blocked' {
        $state = New-CrTestState -Profile IPT01
        $pf = @{ MachineBlocked = $true; BlockedSlots = @{}; Findings = @() }
        $result = Invoke-TestApply -State $state -Preflight $pf

        It 'changes nothing and exits with 2' {
            Assert-MockCalled Invoke-CrPasswordSet -Times 0 -Exactly -Scope Context
            Assert-MockCalled Disable-CrAccount -Times 0 -Exactly -Scope Context
            Assert-MockCalled Invoke-CrAutoLogonAction -Times 0 -Exactly -Scope Context
            $result['ExitCode'] | Should Be 2
        }
    }
}

Describe 'Resolve-CrProbeDecisions' {
    Context 'both passwords failed, operator answers S (set)' {
        Mock Read-CrHostLine { 'S' }
        Mock Invoke-CrCredentialProbe { throw 'must not probe again' }
        $state = New-CrTestState -Profile IPT01
        $config = New-CrTestConfig
        $resolved = Resolve-CrAccounts -Config $config -State $state
        $appSid = Get-CrTestUserSid $state 'ApplicationUser'
        $ss = New-TestSlotSecrets -Resolved $resolved -Slots @('AppUser')
        $probes = New-TestProbes -SlotSecrets $ss -Outcomes @{ $appSid = 'BothFailed' }
        $pf = @{ MachineBlocked = $false; BlockedSlots = @{}; Findings = @() }
        Resolve-CrProbeDecisions -State $state -Config $config -Resolved $resolved -Preflight $pf -SlotSecrets $ss -Probes $probes -Journal @{ Runs = @() } -RunId 'r' -Only @('AppUser')

        It 'stores the set choice on the probe' {
            $probes[$appSid]['Path'] | Should Be 'Set'
            Assert-MockCalled Read-CrHostLine -Times 1 -Exactly -Scope Context
        }
    }
}

Describe 'Read-CrDependentDecisions' {
    Context 'SYS Admin runs a service; the operator answers M' {
        Mock Read-CrHostLine { 'M' }
        $state = New-CrTestState -Profile IPT01
        $config = New-CrTestConfig
        $resolved = Resolve-CrAccounts -Config $config -State $state
        $sysSid = Get-CrTestUserSid $state 'SYS Admin'
        $plan = Get-CrApplyDisablePlan -State $state -Resolved $resolved -Preview @() -RunningSid 'S-1-5-21-1000-2000-4000-1002' -Only $null -OtherDecisions @{} -DependentDecisions @{}
        $decisions = Read-CrDependentDecisions -DisablePlan $plan -Resolved $resolved

        It 'asks once and records Move' {
            $decisions[$sysSid] | Should Be 'Move'
            Assert-MockCalled Read-CrHostLine -Times 1 -Exactly -Scope Context
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
