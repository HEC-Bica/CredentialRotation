# Pester 3.4 tests for src\lib\Apply.ps1, account model PLAN v10.4 (sections 6 steps 6-11, 7.5, 8; D9, D11, D12, D13,
# D20-D25). Synthetic machine state from Fixtures.ps1 (SM: no PUB-User, BiCA accounts managed, SP Admin retired; IPT01:
# every managed account exists, SOP-Admin and SYS Admin retired, the built-in Administrator replaced by ApplicationUser);
# every building block of other modules is stubbed and mocked. Pester 3.4 leaks a Mock defined inside an It into
# later Its: mocks are only defined at Describe/Context level, each scenario runs once in its Context body and the
# Its assert with -Scope Context.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$lib = Join-Path $here '..\src\lib'
# Journal.ps1 (Test-CrJournalStepInUnfinishedRun) and Secrets.ps1 (Test-CrProbeBudget) are used by Apply.ps1; their
# console, probe and journal-write functions are replaced by the stubs below.
foreach ($m in @('Compat', 'Log', 'Config', 'Rights', 'Principals', 'AutoLogon', 'Preflight', 'Plan', 'Journal', 'Secrets', 'Apply')) { . (Join-Path $lib ($m + '.ps1')) }
. (Join-Path $here 'Fixtures.ps1')

# Stubs of the building blocks (CONTRACTS 5 and 6.4), defined after the libs so they replace the real ones.
function Get-CrUserInfo { param([string]$UserName) }
function Invoke-CrLogonTest { param([string]$UserName, $Secret, [string]$LogonType) }
function Unlock-CrAccount { param([string]$UserName) }
function Invoke-CrPasswordRotation { param($User, $OldSecret, $NewSecret, [string]$Path, $Journal, [string]$RunId) }
function Invoke-CrPasswordSet { param($User, $NewSecret, $Journal, [string]$RunId) }
function New-CrManagedAccount { param([string]$Name, $Secret, [string]$Comment, $Journal, [string]$RunId) }
function Enable-CrAccount { param($User) }
function Disable-CrAccount { param($User, $Journal, [string]$RunId) }
function Set-CrAccountFlags { param($User, $Role) }
function Get-CrLocalGroups { param() }
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

# SIDs the New-CrManagedAccount mock hands out for created accounts (synthetic, unused RIDs of the SM fixture).
$global:CrTestNewSids = @{ 'BiCA Admin' = 'S-1-5-21-1000-2000-3000-1107'; 'BiCA Remote' = 'S-1-5-21-1000-2000-3000-1108'; 'ApplicationUser' = 'S-1-5-21-1000-2000-3000-1109' }

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

# A copy of $State.Groups with $MemberSid added to the group $GroupSid: what Get-CrLocalGroups reads after NetUserAdd
# put a created account into Users.
function New-TestGroupsWithMember {
    param($State, [string]$GroupSid, [string]$MemberSid)
    $list = New-Object System.Collections.ArrayList
    foreach ($g in @($State['Groups'])) {
        $members = New-Object System.Collections.ArrayList
        foreach ($m in @($g['MemberSids'])) { if ($m) { [void]$members.Add($m) } }
        if ($g['Sid'] -eq $GroupSid) { [void]$members.Add($MemberSid) }
        [void]$list.Add(@{ Name = $g['Name']; Sid = $g['Sid']; MemberSids = $members.ToArray(); Error = $null })
    }
    return , $list.ToArray()
}

# Removes ApplicationUser from the fixture (it is then created by the AppUser slot) together with its services,
# tasks and COM+ applications, so the scenario has no dependents of a missing account.
function Remove-TestAppUser {
    param($State)
    $oldSid = Get-CrTestUserSid $State 'ApplicationUser'
    Remove-CrTestUser -State $State -Name 'ApplicationUser'
    $State['Services'] = @(@($State['Services']) | Where-Object { $_ -is [hashtable] -and $_['StartNameSid'] -ne $oldSid })
    $State['Tasks'] = @(@($State['Tasks']) | Where-Object { $_ -is [hashtable] -and $_['UserSid'] -ne $oldSid })
    $State['ComPlus'] = @(@($State['ComPlus']) | Where-Object { $_ -is [hashtable] -and $_['IdentitySid'] -ne $oldSid })
}

# A service running as $Sid (synthetic), added to $State.Services.
function Add-TestService {
    param($State, [string]$Name, [string]$Sid, [string]$StartName)
    $svc = @{ Name = $Name; DisplayName = $Name; StartName = $StartName; StartNameSid = $Sid; StartMode = 'Auto'; State = 'Running'
              PathExecutable = ('C:\App\{0}.exe' -f $Name); DependentServices = @(); DependsOn = @() }
    $list = New-Object System.Collections.ArrayList
    foreach ($s in @($State['Services'])) { if ($s -is [hashtable]) { [void]$list.Add($s) } }
    [void]$list.Add($svc)
    $State['Services'] = $list.ToArray()
}

# Runs Invoke-CrApply on a fixture state; the slot secrets are kept in $global:CrTestSlotSecrets for the filters.
function Invoke-TestApply {
    param(
        $State, [string[]]$Slots = @('BiCAAdmin', 'AppUser', 'AutoLogon', 'BiCARemote'), [hashtable]$Outcomes = @{}, [hashtable]$Paths = @{},
        [string[]]$ReapplySids = @(), [string[]]$Only, [string]$RunningSid, $Preflight, [string]$AutoLogonChoice,
        [hashtable]$OtherDecisions = @{}, $Journal
    )
    $config = New-CrTestConfig
    $resolved = Resolve-CrAccounts -Config $config -State $State
    if (-not $RunningSid) { $RunningSid = Get-CrTestUserSid $State 'BiCA Remote' }
    if (-not $Preflight) { $Preflight = @{ MachineBlocked = $false; BlockedSlots = @{}; Findings = @() } }
    if (-not $Journal) { $Journal = @{ Runs = @() } }
    $ss = New-TestSlotSecrets -Resolved $resolved -Slots $Slots -ReapplySids $ReapplySids
    $probes = New-TestProbes -SlotSecrets $ss -Outcomes $Outcomes -Paths $Paths
    $global:CrTestSlotSecrets = $ss
    return Invoke-CrApply -State $State -Config $config -Resolved $resolved -Preflight $Preflight -Plan @{ Findings = @() } -SlotSecrets $ss `
        -Probes $probes -Journal $Journal -RunId 'test-run' -Only $Only -RunningSid $RunningSid -AutoLogonChoice $AutoLogonChoice `
        -OtherDecisions $OtherDecisions
}

# A context for Get-CrApplyMoveTarget: the target is verified in this run; -Runs are the journal's runs.
function New-TestMoveContext {
    param($State, [string]$TargetSid, $Runs, [string[]]$CreatedSids = @())
    $verified = New-Object System.Collections.ArrayList
    [void]$verified.Add($TargetSid)
    $created = New-Object System.Collections.ArrayList
    foreach ($s in $CreatedSids) { if ($s) { [void]$created.Add($s) } }
    $runList = New-Object System.Collections.ArrayList
    if ($Runs) { foreach ($r in @($Runs)) { if ($r) { [void]$runList.Add($r) } } }
    return @{
        State = $State; Journal = @{ Runs = $runList }; RunId = 'test-run'; EntrySids = @{}; Verified = $verified; Created = $created
        SlotSecrets = @{ AppUser = @{ Slot = 'AppUser'; NewSecret = (New-Object System.Security.SecureString) } }
    }
}

function Get-TestSlot {
    param($Result, [string]$Slot)
    foreach ($s in $Result['Slots']) { if ($s['Slot'] -eq $Slot) { return $s } }
    return $null
}

function Get-TestSlotOrder {
    param($Slots)
    $order = New-Object System.Collections.ArrayList
    foreach ($s in @($Slots)) { [void]$order.Add([string]$s['Slot']) }
    return ($order.ToArray() -join ',')
}

function Get-TestDisable {
    param($Result, [string]$Name)
    foreach ($d in $Result['Disables']) { if ($d['Name'] -eq $Name) { return $d } }
    return $null
}

function Get-TestPlanItem {
    param($Plan, [string]$Name)
    foreach ($i in @($Plan)) { if ($i -is [hashtable] -and $i['Name'] -eq $Name) { return $i } }
    return $null
}

function Get-TestEntry {
    param($Resolved, [string]$Id)
    foreach ($e in @($Resolved)) { if ($e -is [hashtable] -and $e['Id'] -eq $Id) { return $e } }
    return $null
}

# Unrolled by the pipeline: wrap calls in @() before .Count (a single finding is a hashtable).
function Get-TestFindings {
    param($Result, [string]$Severity, [string]$Area, [string]$Account, [string]$Like)
    return @($Result['Findings'] | Where-Object {
        (-not $Severity -or $_['Severity'] -eq $Severity) -and (-not $Area -or $_['Area'] -eq $Area) -and
        (-not $Account -or $_['Account'] -eq $Account) -and (-not $Like -or $_['Message'] -like $Like)
    })
}

$CrTestSlotOrder = 'BiCAAdmin,AppUser,AutoLogon,SQLApplication,SQLScript,SQLService,BiCARemote'

Describe 'Get-CrApplySlotDefinitions' {
    It 'orders the slots by Order: BiCAAdmin first, BiCARemote last (D25)' {
        Get-TestSlotOrder (Get-CrApplySlotDefinitions -Config (New-CrTestConfig)) | Should Be $CrTestSlotOrder
    }
}

Describe 'Find-CrApplyUserByName' {
    $state = New-CrTestState -Profile IPT01
    $bicaSid = Get-CrTestUserSid $state 'BiCA Admin'

    It 'ignores a ''.\'' prefix and the case of the name' {
        (Find-CrApplyUserByName -State $state -Name '.\Bica Admin')['Sid'] | Should Be $bicaSid
    }
    It 'ignores a computer prefix, also a stale one' {
        (Find-CrApplyUserByName -State $state -Name 'IPT01-TEST01\PUB-User')['Name'] | Should Be 'PUB-User'
        (Find-CrApplyUserByName -State $state -Name 'OLD-NAME01\BiCA Admin')['Sid'] | Should Be $bicaSid
    }
    It 'returns $null for an unknown or empty name' {
        $null -eq (Find-CrApplyUserByName -State $state -Name 'Nobody') | Should Be $true
        $null -eq (Find-CrApplyUserByName -State $state -Name '.\') | Should Be $true
        $null -eq (Find-CrApplyUserByName -State $state -Name '') | Should Be $true
    }
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

Describe 'Test-CrApplyBudget (strict D12 rule, v10.4)' {
    Mock Get-CrUserInfo { @{ Success = $global:CrTestInfoSuccess; Win32Error = 0; Flags = $global:CrTestUserFlags; BadPasswordCount = $global:CrTestBadCount } }
    $global:CrTestInfoSuccess = $true
    $global:CrTestUserFlags = 0x10201
    $global:CrTestBadCount = 0
    $threshold4 = @{ Policy = @{ LockoutThreshold = 4 } }

    It 'threshold 4: allows the attempt at counter 0 and 1 only (counter + 2 < threshold)' {
        $global:CrTestUserFlags = 0x10201
        foreach ($c in @(0, 1)) {
            $global:CrTestBadCount = $c
            (Test-CrApplyBudget -State $threshold4 -UserName 'A')['Ok'] | Should Be $true
        }
        foreach ($c in @(2, 3)) {
            $global:CrTestBadCount = $c
            $r = Test-CrApplyBudget -State $threshold4 -UserName 'A'
            $r['Ok'] | Should Be $false
            $r['Locked'] | Should Be $false
            $r['Reason'] | Should Match ('lockout budget: {0} of 4 bad attempts' -f $c)
        }
    }
    It 'threshold 0 (no lockout): always allowed' {
        $global:CrTestUserFlags = 0x10201
        $global:CrTestBadCount = 9
        (Test-CrApplyBudget -State @{ Policy = @{ LockoutThreshold = 0 } } -UserName 'A')['Ok'] | Should Be $true
    }
    It 'unknown threshold counts as 3: only counter 0 is allowed' {
        $global:CrTestUserFlags = 0x10201
        $global:CrTestBadCount = 0
        (Test-CrApplyBudget -State @{ Policy = @{ Error = 'x' } } -UserName 'A')['Ok'] | Should Be $true
        $global:CrTestBadCount = 1
        (Test-CrApplyBudget -State @{ Policy = @{ Error = 'x' } } -UserName 'A')['Ok'] | Should Be $false
    }
    It 'refuses a locked account' {
        $global:CrTestUserFlags = 0x10211
        $global:CrTestBadCount = 0
        $r = Test-CrApplyBudget -State $threshold4 -UserName 'A'
        $r['Ok'] | Should Be $false
        $r['Locked'] | Should Be $true
    }
    It 'refuses when the account cannot be read' {
        $global:CrTestUserFlags = 0x10201
        $global:CrTestInfoSuccess = $false
        $r = Test-CrApplyBudget -State $threshold4 -UserName 'A'
        $global:CrTestInfoSuccess = $true
        $r['Ok'] | Should Be $false
        $r['Reason'] | Should Match 'could not be read'
    }
}

Describe 'Get-CrApplyPreview / Get-CrApplyAccountFates (SM: BiCA Admin missing, WinAutoUser disabled)' {
    $state = New-CrTestState -Profile SM -OmitUsers 'BiCA Admin'
    (Get-CrTestUser $state 'WinAutoUser')['Disabled'] = $true
    $config = New-CrTestConfig
    $resolved = Resolve-CrAccounts -Config $config -State $state
    $ss = New-TestSlotSecrets -Resolved $resolved -Slots @('BiCAAdmin', 'AppUser', 'AutoLogon', 'BiCARemote')
    $probes = New-TestProbes -SlotSecrets $ss
    $pf = @{ MachineBlocked = $false; BlockedSlots = @{}; Findings = @() }
    $preview = Get-CrApplyPreview -Config $config -Resolved $resolved -Preflight $pf -SlotSecrets $ss -Probes $probes -Only $null
    $runningSid = Get-CrTestUserSid $state 'BiCA Remote'
    $others = @((Get-CrTestUser $state 'myftpuser'), (Get-CrTestUser $state 'OtherAdmin'))
    $fates = Get-CrApplyAccountFates -State $state -Resolved $resolved -RunningSid $runningSid -Only $null -Others $others
    $fate = @{}
    foreach ($f in $fates) { $fate[$f['Name']] = $f['Fate'] }
    $autoLogonAccounts = @((Find-CrApplyPreviewSlot $preview 'AutoLogon')['Accounts'])

    It 'lists the slots in Order, BiCARemote last (D25)' {
        Get-TestSlotOrder $preview | Should Be $CrTestSlotOrder
    }
    It 'creates the missing BiCA Admin, sets BiCA Remote and changes ApplicationUser; the SQL slots are skipped as unsupported' {
        $bica = (Find-CrApplyPreviewSlot $preview 'BiCAAdmin')['Accounts'][0]
        $bica['Name'] | Should Be 'BiCA Admin'
        $bica['Path'] | Should Be 'Create'
        ((Find-CrApplyPreviewSlot $preview 'BiCARemote')['Accounts'][0])['Path'] | Should Be 'Set'
        ((Find-CrApplyPreviewSlot $preview 'AppUser')['Accounts'][0])['Path'] | Should Be 'Change'
        (Find-CrApplyPreviewSlot $preview 'SQLApplication')['Status'] | Should Be 'Skipped'
        (Find-CrApplyPreviewSlot $preview 'SQLApplication')['Unsupported'] | Should Be $true
        [bool]((Find-CrApplyPreviewSlot $preview 'AppUser')['Unsupported']) | Should Be $false
    }
    It 'sets the disabled WinAutoUser without enabling it (D21)' {
        $autoLogonAccounts.Count | Should Be 1
        $autoLogonAccounts[0]['Name'] | Should Be 'WinAutoUser'
        $autoLogonAccounts[0]['Path'] | Should Be 'Set'
        $autoLogonAccounts[0]['Enable'] | Should Be $false
        $autoLogonAccounts[0]['StaysDisabled'] | Should Be $true
        Get-CrApplyPathText $autoLogonAccounts[0] | Should Match 'stays disabled'
    }
    It 'lists the fate of every enabled account and the account to create' {
        $fate['BiCA Admin'] | Should Be 'create'
        $fate['BiCA Remote'] | Should Be 'set'
        $fate['ApplicationUser'] | Should Be 'change'
        $fate['SP Admin'] | Should Be 'disable'
        $fate['OtherAdmin'] | Should Be 'ask'
        $fate['WinUser1'] | Should Be 'keep'
        $fate.ContainsKey('WinAutoUser') | Should Be $false
        $fate.ContainsKey('WinUser3') | Should Be $false
    }
    It 'Test-CrApplyEntryCreated: true only for the entry whose account is created in this run' {
        Test-CrApplyEntryCreated -Preview $preview -Entry (Get-TestEntry $resolved 'BiCAAdmin') | Should Be $true
        Test-CrApplyEntryCreated -Preview $preview -Entry (Get-TestEntry $resolved 'AppUser') | Should Be $false
        Test-CrApplyEntryCreated -Preview $preview -Entry $null | Should Be $false
    }
    It 'Get-CrApplyCreatedTargetReason names the created target and the account that keeps its dependents (D24)' {
        $reason = Get-CrApplyCreatedTargetReason -TargetName 'ApplicationUser' -Name 'LocalAdm'
        $reason | Should Match '^stays enabled: ApplicationUser is created in this run'
        $reason | Should Match 'migrate them manually'
    }
}

Describe 'Get-CrApplyDisablePlan: dependents of retired and other accounts always move to ApplicationUser (D24, v10.4)' {
    Context 'SM: the retired SP Admin (task), OtherAdmin (service) disabled by the operator, myftpuser kept' {
        $state = New-CrTestState -Profile SM
        $otherAdminSid = Get-CrTestUserSid $state 'OtherAdmin'
        $myftpSid = Get-CrTestUserSid $state 'myftpuser'
        Add-TestService -State $state -Name 'OtherService' -Sid $otherAdminSid -StartName '.\OtherAdmin'
        $config = New-CrTestConfig
        $resolved = Resolve-CrAccounts -Config $config -State $state
        $ss = New-TestSlotSecrets -Resolved $resolved -Slots @('BiCAAdmin', 'AppUser', 'AutoLogon', 'BiCARemote')
        $probes = New-TestProbes -SlotSecrets $ss
        $pf = @{ MachineBlocked = $false; BlockedSlots = @{}; Findings = @() }
        $preview = Get-CrApplyPreview -Config $config -Resolved $resolved -Preflight $pf -SlotSecrets $ss -Probes $probes -Only $null
        $plan = Get-CrApplyDisablePlan -State $state -Resolved $resolved -Preview $preview -RunningSid (Get-CrTestUserSid $state 'BiCA Remote') `
            -Only $null -OtherDecisions @{ $otherAdminSid = 'Disable'; $myftpSid = 'Keep' }
        $sp = Get-TestPlanItem $plan 'SP Admin'
        $other = Get-TestPlanItem $plan 'OtherAdmin'
        $kept = Get-TestPlanItem $plan 'myftpuser'

        It 'plans to disable the retired SP Admin and move its task to ApplicationUser' {
            $sp['Kind'] | Should Be 'Disable'
            $sp['HasDependents'] | Should Be $true
            $sp['MoveEntry']['Id'] | Should Be 'AppUser'
            $sp['Planned'] | Should Be $true
        }
        It 'does the same for the other account the operator disables (D23)' {
            $other['Kind'] | Should Be 'Other'
            $other['HasDependents'] | Should Be $true
            $other['MoveEntry']['Id'] | Should Be 'AppUser'
            $other['Planned'] | Should Be $true
        }
        It 'keeps the account the operator keeps' {
            $kept['Planned'] | Should Be $false
            $kept['Reason'] | Should Be 'kept enabled by the operator (D23)'
        }
        It 'has no operator decision on dependents any more' {
            foreach ($i in $plan) {
                $i.ContainsKey('NeedsDecision') | Should Be $false
                $i.ContainsKey('Decision') | Should Be $false
            }
        }
    }

    Context 'no application account is configured' {
        $state = New-CrTestState -Profile IPT01
        $config = New-CrTestConfig
        $accounts = New-Object System.Collections.ArrayList
        foreach ($a in $config['Accounts']) { if ($a['Id'] -ne 'AppUser') { [void]$accounts.Add($a) } }
        $config['Accounts'] = $accounts.ToArray()
        $resolved = Resolve-CrAccounts -Config $config -State $state
        $plan = Get-CrApplyDisablePlan -State $state -Resolved $resolved -Preview @() -RunningSid (Get-CrTestUserSid $state 'BiCA Remote') -Only $null -OtherDecisions @{}
        $sys = Get-TestPlanItem $plan 'SYS Admin'
        $sop = Get-TestPlanItem $plan 'SOP-Admin'

        It 'keeps the retired SYS Admin with a service enabled: there is nowhere to move it' {
            $sys['Planned'] | Should Be $false
            $null -eq $sys['MoveEntry'] | Should Be $true
            $sys['Reason'] | Should Match '^stays enabled: .*no application account'
        }
        It 'still plans to disable the retired SOP-Admin without dependents' {
            $sop['Planned'] | Should Be $true
        }
    }
}

Describe 'Get-CrApplyDisablePlan: dependents unknown (D24)' {
    Context 'the COM+ discovery failed' {
        $state = New-CrTestState -Profile IPT01 -Parts @{ ComPlus = @{ Error = 'x' } }
        $config = New-CrTestConfig
        $resolved = Resolve-CrAccounts -Config $config -State $state
        $sopSid = Get-CrTestUserSid $state 'SOP-Admin'
        $plan = Get-CrApplyDisablePlan -State $state -Resolved $resolved -Preview @() -RunningSid $sopSid -Only $null -OtherDecisions @{}

        It 'lists the accounts but plans to disable none of them' {
            @($plan).Count | Should Be 3
            foreach ($i in $plan) {
                $i['Planned'] | Should Be $false
                $i['Reason'] | Should Match '^stays enabled: its dependents are unknown'
                $i['Reason'] | Should Match 'ComPlus: x'
            }
        }
    }
}

Describe 'Get-CrApplyMoveTarget: never to an account the tool created (D24, v10.4)' {
    $state = New-CrTestState -Profile IPT01
    $config = New-CrTestConfig
    $resolved = Resolve-CrAccounts -Config $config -State $state
    $appSid = Get-CrTestUserSid $state 'ApplicationUser'
    $item = @{ Name = 'SYS Admin'; Sid = (Get-CrTestUserSid $state 'SYS Admin'); MoveEntry = (Get-CrApplyAppUserEntry -Resolved $resolved) }

    It 'refuses a target that an earlier unfinished run created (journal step Created)' {
        $ctx = New-TestMoveContext -State $state -TargetSid $appSid -Runs @(@{ RunId = 'earlier-run'; Finished = $false; Accounts = @{ $appSid = @('Created', 'Secret') } })
        $t = Get-CrApplyMoveTarget -Context $ctx -Item $item
        $t['Ok'] | Should Be $false
        $t['Reason'] | Should Match '^ApplicationUser was created by this tool'
        $t['Reason'] | Should Match 'migrate its dependents manually'
    }
    It 'refuses a target created in this run' {
        $ctx = New-TestMoveContext -State $state -TargetSid $appSid -Runs $null -CreatedSids @($appSid)
        $t = Get-CrApplyMoveTarget -Context $ctx -Item $item
        $t['Ok'] | Should Be $false
        $t['Reason'] | Should Match '^ApplicationUser was created by this tool'
    }
    It 'accepts it when the run that created it finished' {
        $ctx = New-TestMoveContext -State $state -TargetSid $appSid -Runs @(@{ RunId = 'earlier-run'; Finished = $true; Accounts = @{ $appSid = @('Created', 'Secret') } })
        $t = Get-CrApplyMoveTarget -Context $ctx -Item $item
        $t['Ok'] | Should Be $true
        $t['Sid'] | Should Be $appSid
        $t['Name'] | Should Be 'ApplicationUser'
        [object]::ReferenceEquals($t['Secret'], $ctx['SlotSecrets']['AppUser']['NewSecret']) | Should Be $true
    }
    It 'accepts it when an earlier unfinished run only set its password' {
        $ctx = New-TestMoveContext -State $state -TargetSid $appSid -Runs @(@{ RunId = 'earlier-run'; Finished = $false; Accounts = @{ $appSid = @('Secret') } })
        (Get-CrApplyMoveTarget -Context $ctx -Item $item)['Ok'] | Should Be $true
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

    Context 'IPT01 run as the retired SOP-Admin: set vs change, dependents in place and moved, disables, the running account last (D25)' {
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile IPT01
        $bicaSid = Get-CrTestUserSid $state 'BiCA Admin'
        $remoteSid = Get-CrTestUserSid $state 'BiCA Remote'
        $appSid = Get-CrTestUserSid $state 'ApplicationUser'
        $pubSid = Get-CrTestUserSid $state 'PUB-User'
        $winAutoSid = Get-CrTestUserSid $state 'WinAutoUser'
        $sysSid = Get-CrTestUserSid $state 'SYS Admin'
        $sopSid = Get-CrTestUserSid $state 'SOP-Admin'
        $result = Invoke-TestApply -State $state -RunningSid $sopSid

        It 'runs the slots in Order, BiCARemote last (D25); the SQL slots are skipped as unsupported' {
            Get-TestSlotOrder $result['Slots'] | Should Be $CrTestSlotOrder
            foreach ($s in @('BiCAAdmin', 'AppUser', 'AutoLogon', 'BiCARemote')) { (Get-TestSlot $result $s)['Status'] | Should Be 'Done' }
            (Get-TestSlot $result 'SQLApplication')['Status'] | Should Be 'Skipped'
            (Get-TestSlot $result 'SQLApplication')['Unsupported'] | Should Be $true
        }
        It 'sets BiCA Admin, PUB-User, WinAutoUser and BiCA Remote and changes ApplicationUser with its old password (D9)' {
            Assert-MockCalled Invoke-CrPasswordSet -Times 4 -Exactly -Scope Context
            Assert-MockCalled Invoke-CrPasswordSet -Times 1 -Exactly -Scope Context -ParameterFilter { $User['Sid'] -eq $bicaSid }
            Assert-MockCalled Invoke-CrPasswordSet -Times 1 -Exactly -Scope Context -ParameterFilter { $User['Sid'] -eq $pubSid }
            Assert-MockCalled Invoke-CrPasswordSet -Times 1 -Exactly -Scope Context -ParameterFilter { $User['Sid'] -eq $winAutoSid }
            Assert-MockCalled Invoke-CrPasswordSet -Times 1 -Exactly -Scope Context -ParameterFilter { $User['Sid'] -eq $remoteSid }
            Assert-MockCalled Invoke-CrPasswordRotation -Times 1 -Exactly -Scope Context -ParameterFilter { $Path -eq 'Change' -and $User['Sid'] -eq $appSid }
            Assert-MockCalled New-CrManagedAccount -Times 0 -Exactly -Scope Context
            Assert-MockCalled Enable-CrAccount -Times 0 -Exactly -Scope Context
        }
        It 'changes no group membership: the roles match (Remote Desktop Users of BiCA Remote is allowed, never added)' {
            Assert-MockCalled Invoke-CrGroupMembershipChange -Times 0 -Exactly -Scope Context
        }
        It 'updates the service of BiCA Admin in place with the BiCAAdmin secret, after granting the service right' {
            Assert-MockCalled Grant-CrDependentRights -Times 1 -Exactly -Scope Context -ParameterFilter { $Sid -eq $bicaSid -and @($Rights) -contains 'SeServiceLogonRight' }
            Assert-MockCalled Update-CrServiceCredentials -Times 1 -Exactly -Scope Context -ParameterFilter {
                $Sid -eq $bicaSid -and [object]::ReferenceEquals($Secret, $global:CrTestSlotSecrets['BiCAAdmin']['NewSecret'])
            }
            Assert-MockCalled Move-CrServiceAccount -Times 0 -Exactly -Scope Context -ParameterFilter { $FromSid -eq $bicaSid }
        }
        It 'always moves the service of the retired SYS Admin to ApplicationUser with its new secret (D24, v10.4)' {
            Assert-MockCalled Move-CrServiceAccount -Times 1 -Exactly -Scope Context
            Assert-MockCalled Move-CrServiceAccount -Times 1 -Exactly -Scope Context -ParameterFilter {
                $FromSid -eq $sysSid -and $ToAccount -eq '.\ApplicationUser' -and [object]::ReferenceEquals($Secret, $global:CrTestSlotSecrets['AppUser']['NewSecret'])
            }
            (Get-TestDisable $result 'SYS Admin')['MovedTo'] | Should Be 'ApplicationUser'
        }
        It 'switches auto-logon to PUB-User with the AutoLogon slot secret' {
            Assert-MockCalled Invoke-CrAutoLogonAction -Times 1 -Exactly -Scope Context -ParameterFilter {
                $Decision['Action'] -eq 'Switch' -and $Decision['TargetSid'] -eq $pubSid -and
                [object]::ReferenceEquals($Secret, $global:CrTestSlotSecrets['AutoLogon']['NewSecret'])
            }
        }
        It 'disables the replaced Administrator and the retired SYS Admin, the running SOP-Admin last (D25)' {
            $order = @($global:CrTestDisabled)
            $order.Count | Should Be 3
            $order[$order.Count - 1] | Should Be 'SOP-Admin'
            foreach ($n in @('Administrator', 'SYS Admin')) { ($order -contains $n) | Should Be $true }
            foreach ($n in @('BiCA Admin', 'BiCA Remote', 'PUB-User', 'WinAutoUser')) { ($order -contains $n) | Should Be $false }
            (Get-TestDisable $result 'SOP-Admin')['Status'] | Should Be 'Disabled'
        }
        It 'lists LOGINS follow-ups for the accounts with a LOGINS entry and the next logon as BiCA Remote' {
            @(Get-TestFindings $result 'FollowUp' 'LOGINS' 'BiCA Admin').Count | Should Be 1
            @(Get-TestFindings $result 'FollowUp' 'LOGINS' 'BiCA Remote').Count | Should Be 1
            @(Get-TestFindings $result 'FollowUp' 'LOGINS' 'ApplicationUser').Count | Should Be 1
            @(Get-TestFindings $result 'FollowUp' 'LOGINS' 'PUB-User').Count | Should Be 0
            @(Get-TestFindings $result 'FollowUp' 'LOGINS' 'WinAutoUser').Count | Should Be 0
            @(Get-TestFindings $result 'FollowUp' 'Accounts' 'SOP-Admin' '*Log on as BiCA Remote next time*').Count | Should Be 1
        }
        It 'lists the RDP follow-up only for the operator account BiCA Remote, whose password was set (PLAN 8, v10.4)' {
            @(Get-TestFindings $result 'FollowUp' 'RDP').Count | Should Be 1
            @(Get-TestFindings $result 'FollowUp' 'RDP' 'BiCA Remote' '*saved RDP credentials*').Count | Should Be 1
            @(Get-TestFindings $result 'FollowUp' 'RDP')[0]['Slot'] | Should Be 'BiCARemote'
        }
        It 'exits with 4 (follow-up required): the unsupported SQL slots do not count as not applied' {
            @($result['NotAppliedSlots']).Count | Should Be 0
            $result['ExitCode'] | Should Be 4
        }
    }

    Context 'SM: BiCA Admin missing (created), dependents updated in place, retired SP Admin moved, operator decisions (D23)' {
        Mock Get-CrLocalGroups { , $global:CrTestGroupsAfterCreate }
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile SM -OmitUsers 'BiCA Admin'
        $newSid = $global:CrTestNewSids['BiCA Admin']
        $global:CrTestGroupsAfterCreate = New-TestGroupsWithMember -State $state -GroupSid 'S-1-5-32-545' -MemberSid $newSid
        $remoteSid = Get-CrTestUserSid $state 'BiCA Remote'
        $appSid = Get-CrTestUserSid $state 'ApplicationUser'
        $winAutoSid = Get-CrTestUserSid $state 'WinAutoUser'
        $spSid = Get-CrTestUserSid $state 'SP Admin'
        $otherAdminSid = Get-CrTestUserSid $state 'OtherAdmin'
        $myftpSid = Get-CrTestUserSid $state 'myftpuser'
        $result = Invoke-TestApply -State $state -OtherDecisions @{ $otherAdminSid = 'Disable'; $myftpSid = 'Keep' }

        It 'creates the missing BiCA Admin with the BiCAAdmin slot secret (D21)' {
            Assert-MockCalled New-CrManagedAccount -Times 1 -Exactly -Scope Context
            Assert-MockCalled New-CrManagedAccount -Times 1 -Exactly -Scope Context -ParameterFilter {
                $Name -eq 'BiCA Admin' -and [object]::ReferenceEquals($Secret, $global:CrTestSlotSecrets['BiCAAdmin']['NewSecret'])
            }
            (@($result['CreatedSids']) -join ',') | Should Be $newSid
            (Get-TestSlot $result 'BiCAAdmin')['Status'] | Should Be 'Done'
        }
        It 'sets WinAutoUser and BiCA Remote and changes ApplicationUser; the created account is not set again' {
            Assert-MockCalled Invoke-CrPasswordSet -Times 2 -Exactly -Scope Context
            Assert-MockCalled Invoke-CrPasswordSet -Times 1 -Exactly -Scope Context -ParameterFilter { $User['Sid'] -eq $winAutoSid }
            Assert-MockCalled Invoke-CrPasswordSet -Times 1 -Exactly -Scope Context -ParameterFilter { $User['Sid'] -eq $remoteSid }
            Assert-MockCalled Invoke-CrPasswordRotation -Times 1 -Exactly -Scope Context -ParameterFilter { $User['Sid'] -eq $appSid }
        }
        It 're-reads the groups after the creation, adds BiCA Admin to Administrators and removes it from Users later' {
            Assert-MockCalled Get-CrLocalGroups -Times 1 -Exactly -Scope Context
            Assert-MockCalled Invoke-CrGroupMembershipChange -Times 1 -Exactly -Scope Context -ParameterFilter { $MemberSid -eq $newSid -and @($AddGroupSids) -contains 'S-1-5-32-544' }
            Assert-MockCalled Invoke-CrGroupMembershipChange -Times 1 -Exactly -Scope Context -ParameterFilter { $MemberSid -eq $newSid -and @($RemoveGroupSids) -contains 'S-1-5-32-545' }
            (@($result['VerifiedSids']) -contains $newSid) | Should Be $true
        }
        It 'reports that the created account has no Windows login in SQL Server' {
            @(Get-TestFindings $result 'Info' 'SQL' 'BiCA Admin' '*no Windows login in SQL Server*').Count | Should Be 1
        }
        It 'updates the task of WinAutoUser in place with the AutoLogon secret, after granting the batch right' {
            Assert-MockCalled Grant-CrDependentRights -Times 1 -Exactly -Scope Context -ParameterFilter { $Sid -eq $winAutoSid -and @($Rights) -contains 'SeBatchLogonRight' }
            Assert-MockCalled Update-CrTaskCredentials -Times 1 -Exactly -Scope Context -ParameterFilter {
                $Sid -eq $winAutoSid -and [object]::ReferenceEquals($Secret, $global:CrTestSlotSecrets['AutoLogon']['NewSecret'])
            }
            Assert-MockCalled Move-CrTaskAccount -Times 0 -Exactly -Scope Context -ParameterFilter { $FromSid -eq $winAutoSid }
        }
        It 'moves the task of the retired SP Admin to ApplicationUser with its new secret (D24, v10.4)' {
            Assert-MockCalled Move-CrTaskAccount -Times 1 -Exactly -Scope Context
            Assert-MockCalled Move-CrTaskAccount -Times 1 -Exactly -Scope Context -ParameterFilter {
                $FromSid -eq $spSid -and $ToUserId -eq 'SM-TEST01\ApplicationUser' -and
                [object]::ReferenceEquals($Secret, $global:CrTestSlotSecrets['AppUser']['NewSecret'])
            }
            (Get-TestDisable $result 'SP Admin')['MovedTo'] | Should Be 'ApplicationUser'
        }
        It 'does not disable the account the operator kept (D23)' {
            ($global:CrTestDisabled -contains 'myftpuser') | Should Be $false
            (Get-TestDisable $result 'myftpuser')['Status'] | Should Be 'KeptEnabled'
            (Get-TestDisable $result 'myftpuser')['Reason'] | Should Be 'kept enabled by the operator (D23)'
        }
        It 'disables the retired SP Admin and the account the operator chose (D22, D23); the managed accounts stay enabled' {
            (@($global:CrTestDisabled) -join ',') | Should Be 'SP Admin,OtherAdmin'
            (Get-TestDisable $result 'SP Admin')['Status'] | Should Be 'Disabled'
        }
        It 'turns auto-logon off on the SM machine and runs the check-mode fixes' {
            Assert-MockCalled Invoke-CrAutoLogonAction -Times 1 -Exactly -Scope Context -ParameterFilter { $Decision['Action'] -eq 'TurnOff' -and $null -eq $Secret }
            Assert-MockCalled Set-CrAccountFlags -Scope Context -ParameterFilter { $User['Name'] -eq 'WinUser1' }
            (@($result['CheckFixes'] | ForEach-Object { $_['Id'] }) -contains 'WinUsers') | Should Be $true
        }
        It 'lists LOGINS follow-ups for the created BiCA Admin, BiCA Remote and ApplicationUser, and the RDP follow-up for BiCA Remote' {
            @(Get-TestFindings $result 'FollowUp' 'LOGINS' 'BiCA Admin').Count | Should Be 1
            @(Get-TestFindings $result 'FollowUp' 'LOGINS' 'BiCA Remote').Count | Should Be 1
            @(Get-TestFindings $result 'FollowUp' 'LOGINS' 'ApplicationUser').Count | Should Be 1
            @(Get-TestFindings $result 'FollowUp' 'RDP').Count | Should Be 1
            @(Get-TestFindings $result 'FollowUp' 'RDP' 'BiCA Remote').Count | Should Be 1
        }
    }

    Context 'SM: ApplicationUser missing (created) while the enabled built-in Administrator runs a service (D24, v10.4)' {
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile SM
        Remove-TestAppUser -State $state
        $admin = Get-CrTestUser $state 'LocalAdm'
        $admin['Disabled'] = $false
        $admin['Flags'] = ([int]$admin['Flags']) -band (-bnot 0x2)
        Add-TestService -State $state -Name 'AdminService' -Sid ([string]$admin['Sid']) -StartName '.\LocalAdm'
        $newAppSid = $global:CrTestNewSids['ApplicationUser']
        $result = Invoke-TestApply -State $state

        It 'creates ApplicationUser and verifies it' {
            Assert-MockCalled New-CrManagedAccount -Times 1 -Exactly -Scope Context -ParameterFilter { $Name -eq 'ApplicationUser' }
            (@($result['CreatedSids']) -contains $newAppSid) | Should Be $true
            (@($result['VerifiedSids']) -contains $newAppSid) | Should Be $true
            (Get-TestSlot $result 'AppUser')['Status'] | Should Be 'Done'
        }
        It 'moves nothing to the created account' {
            Assert-MockCalled Move-CrServiceAccount -Times 0 -Exactly -Scope Context
            Assert-MockCalled Move-CrTaskAccount -Times 0 -Exactly -Scope Context
            Assert-MockCalled Move-CrComPlusIdentity -Times 0 -Exactly -Scope Context
        }
        It 'keeps the built-in Administrator enabled with its service and reports the manual migration' {
            $d = Get-TestDisable $result 'LocalAdm'
            $d['Status'] | Should Be 'KeptEnabled'
            $d['Reason'] | Should Match '^stays enabled: ApplicationUser is created in this run'
            @(Get-TestFindings $result 'Info' 'Accounts' 'LocalAdm' 'Not disabled: ApplicationUser is created in this run*').Count | Should Be 1
            @(Get-TestFindings $result 'FollowUp' 'Accounts' 'LocalAdm' 'Migrate the services, scheduled tasks and COM+ applications of this account manually*').Count | Should Be 1
        }
        It 'also keeps the retired SP Admin with its task enabled' {
            (Get-TestDisable $result 'SP Admin')['Status'] | Should Be 'KeptEnabled'
            (Get-TestDisable $result 'SP Admin')['Reason'] | Should Match '^stays enabled: ApplicationUser is created in this run'
        }
        It 'disables no account' {
            Assert-MockCalled Disable-CrAccount -Times 0 -Exactly -Scope Context
        }
    }

    Context 'IPT01: ApplicationUser missing (created): the Administrator without dependents is disabled, the retired SYS Admin with a service stays enabled (D24, v10.4)' {
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile IPT01
        Remove-TestAppUser -State $state
        $newAppSid = $global:CrTestNewSids['ApplicationUser']
        $result = Invoke-TestApply -State $state

        It 'creates and verifies ApplicationUser' {
            Assert-MockCalled New-CrManagedAccount -Times 1 -Exactly -Scope Context -ParameterFilter { $Name -eq 'ApplicationUser' }
            (@($result['VerifiedSids']) -contains $newAppSid) | Should Be $true
        }
        It 'disables the replaced Administrator (no dependents) and the retired SOP-Admin, but not SYS Admin' {
            (@($global:CrTestDisabled) -join ',') | Should Be 'Administrator,SOP-Admin'
        }
        It 'keeps SYS Admin enabled and does not move its service to the created account' {
            Assert-MockCalled Move-CrServiceAccount -Times 0 -Exactly -Scope Context
            (Get-TestDisable $result 'SYS Admin')['Status'] | Should Be 'KeptEnabled'
            (Get-TestDisable $result 'SYS Admin')['Reason'] | Should Match '^stays enabled: ApplicationUser is created in this run'
        }
    }

    Context 'IPT01 re-run: ApplicationUser was created by an earlier unfinished run (journal step Created, D11, D24)' {
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile IPT01
        $appSid = Get-CrTestUserSid $state 'ApplicationUser'
        $runs = New-Object System.Collections.ArrayList
        [void]$runs.Add(@{ RunId = 'earlier-run'; Finished = $false; Accounts = @{ $appSid = @('Created', 'Secret') } })
        $result = Invoke-TestApply -State $state -Journal @{ Runs = $runs }

        It 'does not move the service of SYS Admin to it and keeps SYS Admin enabled' {
            Assert-MockCalled Move-CrServiceAccount -Times 0 -Exactly -Scope Context
            (Get-TestDisable $result 'SYS Admin')['Status'] | Should Be 'KeptEnabled'
            @(Get-TestFindings $result 'HighImpact' 'Accounts' 'SYS Admin' 'Stays enabled (D24): *ApplicationUser was created by this tool*').Count | Should Be 1
        }
        It 'still disables the replaced Administrator and the retired SOP-Admin (no dependents)' {
            (@($global:CrTestDisabled) -join ',') | Should Be 'Administrator,SOP-Admin'
        }
    }

    Context 'a disabled WinAutoUser gets the new password, stays disabled and is not logon-tested (D21)' {
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile IPT01
        (Get-CrTestUser $state 'WinAutoUser')['Disabled'] = $true
        $pubSid = Get-CrTestUserSid $state 'PUB-User'
        $winAutoSid = Get-CrTestUserSid $state 'WinAutoUser'
        $result = Invoke-TestApply -State $state -Slots @('AutoLogon') -Only @('AutoLogon')

        It 'sets both auto-logon accounts and completes the slot' {
            Assert-MockCalled Invoke-CrPasswordSet -Times 2 -Exactly -Scope Context
            Assert-MockCalled Invoke-CrPasswordSet -Times 1 -Exactly -Scope Context -ParameterFilter { $User['Sid'] -eq $winAutoSid }
            (Get-TestSlot $result 'AutoLogon')['Status'] | Should Be 'Done'
        }
        It 'does not enable WinAutoUser' {
            Assert-MockCalled Enable-CrAccount -Times 0 -Exactly -Scope Context
        }
        It 'logon-tests PUB-User only and reports WinAutoUser as not verifiable' {
            Assert-MockCalled Invoke-CrLogonTest -Times 1 -Exactly -Scope Context -ParameterFilter { $UserName -eq 'PUB-User' }
            Assert-MockCalled Invoke-CrLogonTest -Times 0 -Exactly -Scope Context -ParameterFilter { $UserName -eq 'WinAutoUser' }
            (@($result['VerifiedSids']) -contains $pubSid) | Should Be $true
            (@($result['VerifiedSids']) -contains $winAutoSid) | Should Be $false
            @(Get-TestFindings $result 'Info' 'Verify' 'WinAutoUser' '*disabled, so it cannot be verified*').Count | Should Be 1
        }
        It 'switches auto-logon to PUB-User and disables nothing' {
            Assert-MockCalled Invoke-CrAutoLogonAction -Times 1 -Exactly -Scope Context -ParameterFilter { $Decision['Action'] -eq 'Switch' -and $Decision['TargetSid'] -eq $pubSid }
            Assert-MockCalled Disable-CrAccount -Times 0 -Exactly -Scope Context
        }
    }

    Context 'a disabled ApplicationUser: the operator chose set; it is enabled (EnableIfDisabled, D21)' {
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile IPT01
        (Get-CrTestUser $state 'ApplicationUser')['Disabled'] = $true
        $appSid = Get-CrTestUserSid $state 'ApplicationUser'
        $result = Invoke-TestApply -State $state -Slots @('AppUser') -Only @('AppUser') -Outcomes @{ $appSid = 'Disabled' } -Paths @{ $appSid = 'Set' }

        It 'sets the password, reports the DPAPI loss and enables the account afterwards' {
            Assert-MockCalled Invoke-CrPasswordSet -Times 1 -Exactly -Scope Context -ParameterFilter { $User['Sid'] -eq $appSid }
            Assert-MockCalled Invoke-CrPasswordRotation -Times 0 -Exactly -Scope Context
            Assert-MockCalled Enable-CrAccount -Times 1 -Exactly -Scope Context -ParameterFilter { $User['Sid'] -eq $appSid }
            @(Get-TestFindings $result 'HighImpact' 'Password' 'ApplicationUser' '*DPAPI*').Count | Should Be 1
            @(Get-TestFindings $result 'Info' 'Accounts' 'ApplicationUser' 'Account enabled').Count | Should Be 1
        }
        It 'verifies the enabled account and disables the replaced built-in Administrator' {
            Assert-MockCalled Invoke-CrLogonTest -Times 1 -Exactly -Scope Context -ParameterFilter { $UserName -eq 'ApplicationUser' }
            (@($result['VerifiedSids']) -contains $appSid) | Should Be $true
            (@($global:CrTestDisabled) -join ',') | Should Be 'Administrator'
        }
    }

    Context 'ApplicationUser set after both passwords failed: the lockout budget forbids the verification logon (counter 2 of 4, D12)' {
        Mock Get-CrUserInfo -ParameterFilter { $UserName -eq 'ApplicationUser' } { @{ Success = $true; Win32Error = 0; Flags = 0x10201; BadPasswordCount = 2; PasswordAgeSeconds = 8640000 } }
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile IPT01
        $appSid = Get-CrTestUserSid $state 'ApplicationUser'
        $result = Invoke-TestApply -State $state -Slots @('AppUser') -Only @('AppUser') -Outcomes @{ $appSid = 'BothFailed' } -Paths @{ $appSid = 'Set' }

        It 'sets the password but makes no logon attempt' {
            Assert-MockCalled Invoke-CrPasswordSet -Times 1 -Exactly -Scope Context -ParameterFilter { $User['Sid'] -eq $appSid }
            Assert-MockCalled Invoke-CrLogonTest -Times 0 -Exactly -Scope Context
            (Get-TestSlot $result 'AppUser')['Status'] | Should Be 'Done'
        }
        It 'reports ApplicationUser as not verified (lockout budget) with high impact' {
            (@($result['VerifiedSids']) -contains $appSid) | Should Be $false
            @(Get-TestFindings $result 'HighImpact' 'Verify' 'ApplicationUser' 'Not verified (lockout budget, D12): lockout budget: 2 of 4*').Count | Should Be 1
        }
        It 'keeps the replaced built-in Administrator enabled (D22)' {
            Assert-MockCalled Disable-CrAccount -Times 0 -Exactly -Scope Context
            (Get-TestDisable $result 'Administrator')['Status'] | Should Be 'KeptEnabled'
            @(Get-TestFindings $result 'HighImpact' 'Accounts' 'Administrator' 'Not disabled: its replacement ApplicationUser is not verified*').Count | Should Be 1
        }
        It 'ends with exit 1: the verification is still pending (re-run after the lockout window)' {
            $result['ExitCode'] | Should Be 1
        }
    }

    Context 'ApplicationUser set after both passwords failed: counter 1 of 4 still allows the verification logon (D12 boundary)' {
        Mock Get-CrUserInfo -ParameterFilter { $UserName -eq 'ApplicationUser' } { @{ Success = $true; Win32Error = 0; Flags = 0x10201; BadPasswordCount = 1; PasswordAgeSeconds = 8640000 } }
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile IPT01
        $appSid = Get-CrTestUserSid $state 'ApplicationUser'
        $result = Invoke-TestApply -State $state -Slots @('AppUser') -Only @('AppUser') -Outcomes @{ $appSid = 'BothFailed' } -Paths @{ $appSid = 'Set' }

        It 'verifies ApplicationUser with one logon' {
            Assert-MockCalled Invoke-CrLogonTest -Times 1 -Exactly -Scope Context -ParameterFilter { $UserName -eq 'ApplicationUser' }
            (@($result['VerifiedSids']) -contains $appSid) | Should Be $true
            @(Get-TestFindings $result 'HighImpact' 'Verify').Count | Should Be 0
        }
        It 'disables the replaced built-in Administrator' {
            (@($global:CrTestDisabled) -join ',') | Should Be 'Administrator'
        }
    }

    Context 'ApplicationUser fails its verification' {
        Mock Invoke-CrLogonTest -ParameterFilter { $UserName -eq 'ApplicationUser' } { @{ Success = $false; Win32Error = 1326 } }
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile IPT01
        $result = Invoke-TestApply -State $state

        It 'stops the AppUser slot at the verify step' {
            (Get-TestSlot $result 'AppUser')['Status'] | Should Be 'Failed'
            (Get-TestSlot $result 'AppUser')['FailedStep'] | Should Be 'Verify'
        }
        It 'neither moves dependents to it nor disables the account it replaces (D22, D24)' {
            Assert-MockCalled Move-CrServiceAccount -Times 0 -Exactly -Scope Context
            (Get-TestDisable $result 'Administrator')['Status'] | Should Be 'KeptEnabled'
            (Get-TestDisable $result 'SYS Admin')['Status'] | Should Be 'KeptEnabled'
            @(Get-TestFindings $result 'HighImpact' 'Accounts' 'SYS Admin' 'Stays enabled (D24)*').Count | Should Be 1
        }
        It 'still disables the retired SOP-Admin (no dependents)' {
            (@($global:CrTestDisabled) -join ',') | Should Be 'SOP-Admin'
        }
        It 'exits with 1' {
            $result['ExitCode'] | Should Be 1
        }
    }

    Context 'the operator account cannot be verified with a logon (1385): the running account stays enabled (D25)' {
        Mock Invoke-CrLogonTest -ParameterFilter { $UserName -eq 'BiCA Remote' } { @{ Success = $false; Win32Error = 1385 } }
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile IPT01
        $sopSid = Get-CrTestUserSid $state 'SOP-Admin'
        $result = Invoke-TestApply -State $state -RunningSid $sopSid

        It 'completes the BiCARemote slot (unverifiable is not a failure)' {
            (Get-TestSlot $result 'BiCARemote')['Status'] | Should Be 'Done'
            @(Get-TestFindings $result 'Info' 'Verify' 'BiCA Remote' '*could not be verified*').Count | Should Be 1
        }
        It 'keeps the running SOP-Admin enabled and says why' {
            @(Get-TestFindings $result 'HighImpact' 'Accounts' 'SOP-Admin' 'Your own account stays enabled (D25): BiCA Remote is not verified*').Count | Should Be 1
            (Get-TestDisable $result 'SOP-Admin')['Status'] | Should Be 'KeptEnabled'
        }
        It 'disables the replaced Administrator and the retired SYS Admin, whose service moved to ApplicationUser' {
            (@($global:CrTestDisabled) -join ',') | Should Be 'Administrator,SYS Admin'
        }
    }

    Context 'the operator account may not log on over RDP: the running account stays enabled (D25)' {
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile IPT01
        $remoteSid = Get-CrTestUserSid $state 'BiCA Remote'
        Add-CrTestRight -State $state -Right 'SeDenyRemoteInteractiveLogonRight' -Sids @($remoteSid)
        $sopSid = Get-CrTestUserSid $state 'SOP-Admin'
        $result = Invoke-TestApply -State $state -RunningSid $sopSid

        It 'verifies BiCA Remote on its new password' {
            (@($result['VerifiedSids']) -contains $remoteSid) | Should Be $true
        }
        It 'keeps the running SOP-Admin enabled: BiCA Remote has no effective remote-interactive logon right' {
            @(Get-TestFindings $result 'HighImpact' 'Accounts' 'SOP-Admin' 'Your own account stays enabled (D25): BiCA Remote is not allowed to log on over RDP*').Count | Should Be 1
            ($global:CrTestDisabled -contains 'SOP-Admin') | Should Be $false
        }
    }

    Context 'a failed dependent move keeps the retired account enabled (D24)' {
        Mock Move-CrServiceAccount -ParameterFilter { $ToAccount -eq '.\ApplicationUser' } { , @(@{ Name = 'LegacySync'; Success = $false; Win32Error = 5; Error = 'access denied'; FromAccount = '.\SYS Admin'; ToAccount = '.\ApplicationUser' }) }
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile IPT01
        $sysSid = Get-CrTestUserSid $state 'SYS Admin'
        $sopSid = Get-CrTestUserSid $state 'SOP-Admin'
        $result = Invoke-TestApply -State $state -RunningSid $sopSid

        It 'does not disable SYS Admin' {
            Assert-MockCalled Move-CrServiceAccount -Times 1 -Exactly -Scope Context -ParameterFilter { $FromSid -eq $sysSid }
            ($global:CrTestDisabled -contains 'SYS Admin') | Should Be $false
            @(Get-TestFindings $result 'Blocked' 'Accounts' 'SYS Admin' 'Stays enabled*').Count | Should Be 1
        }
        It 'still disables the replaced Administrator and, last, the running SOP-Admin (no dependents, BiCA Remote ready)' {
            (@($global:CrTestDisabled) -join ',') | Should Be 'Administrator,SOP-Admin'
        }
        It 'exits with 1' {
            $result['ExitCode'] | Should Be 1
        }
    }

    Context 'auto-logon left unchanged keeps its retired account enabled; the AutoLogon slot was skipped' {
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile IPT01
        $state['AutoLogon']['DefaultUserName'] = 'SOP-Admin'
        # No AutoLogon slot password: PUB-User is not on the new password, so the switch is ambiguous; no choice = leave unchanged.
        $result = Invoke-TestApply -State $state -Slots @('BiCAAdmin', 'AppUser', 'BiCARemote')

        It 'leaves the auto-logon unchanged (D13)' {
            Assert-MockCalled Invoke-CrAutoLogonAction -Times 0 -Exactly -Scope Context
            $result['AutoLogon']['Action'] | Should Be 'LeaveUnchanged'
        }
        It 'does not disable the auto-logon account and reports why' {
            ($global:CrTestDisabled -contains 'SOP-Admin') | Should Be $false
            @(Get-TestFindings $result 'HighImpact' 'Accounts' 'SOP-Admin' '*auto-logon as SOP-Admin breaks*').Count | Should Be 1
        }
        It 'still disables the replaced Administrator and the retired SYS Admin, whose service moved to ApplicationUser' {
            (@($global:CrTestDisabled) -join ',') | Should Be 'Administrator,SYS Admin'
        }
        It 'exits with 1: the selected AutoLogon slot was skipped by the operator (PLAN 6 step 11, v10.4)' {
            (Get-TestSlot $result 'AutoLogon')['Status'] | Should Be 'Skipped'
            (@($result['NotAppliedSlots']) -join ',') | Should Be 'AutoLogon'
            $result['ExitCode'] | Should Be 1
        }
    }

    Context 'the kept auto-logon account got a new password that could not be verified' {
        Mock Invoke-CrLogonTest -ParameterFilter { $UserName -eq 'PUB-User' } { @{ Success = $false; Win32Error = 1385 } }
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile IPT01
        $state['AutoLogon']['DefaultUserName'] = 'PUB-User'
        $result = Invoke-TestApply -State $state -Slots @('AutoLogon') -Only @('AutoLogon')

        It 'keeps the auto-logon as PUB-User unchanged and reports it broken until a re-run' {
            Assert-MockCalled Invoke-CrAutoLogonAction -Times 0 -Exactly -Scope Context
            $result['AutoLogon']['Action'] | Should Be 'NoChange'
            @(Get-TestFindings $result 'HighImpact' 'AutoLogon' 'PUB-User' 'Auto-logon broken until re-run*').Count | Should Be 1
        }
    }

    Context 'AutoLogon slot: the second account fails its password step, the first is still verified' {
        Mock Invoke-CrPasswordSet -ParameterFilter { $User['Name'] -eq 'WinAutoUser' } { @{ Success = $false; Win32Error = 5; Message = 'access denied'; Steps = @(); Warnings = @() } }
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile IPT01
        $pubSid = Get-CrTestUserSid $state 'PUB-User'
        $winAutoSid = Get-CrTestUserSid $state 'WinAutoUser'
        $result = Invoke-TestApply -State $state -Slots @('AutoLogon') -Only @('AutoLogon')

        It 'stops the slot at the password step' {
            (Get-TestSlot $result 'AutoLogon')['Status'] | Should Be 'Failed'
            (Get-TestSlot $result 'AutoLogon')['FailedStep'] | Should Be 'Secret'
        }
        It 'logon-tests PUB-User, which is already on the new password (Invoke-CrApplyVerifyOnNew)' {
            Assert-MockCalled Invoke-CrLogonTest -Times 1 -Exactly -Scope Context -ParameterFilter { $UserName -eq 'PUB-User' }
            Assert-MockCalled Invoke-CrLogonTest -Times 0 -Exactly -Scope Context -ParameterFilter { $UserName -eq 'WinAutoUser' }
            (@($result['VerifiedSids']) -contains $pubSid) | Should Be $true
            (@($result['VerifiedSids']) -contains $winAutoSid) | Should Be $false
            @(Get-TestFindings $result 'Info' 'Verify' 'PUB-User' 'Logon with the new password verified*').Count | Should Be 1
        }
        It 'can therefore switch the auto-logon to PUB-User' {
            Assert-MockCalled Invoke-CrAutoLogonAction -Times 1 -Exactly -Scope Context -ParameterFilter { $Decision['Action'] -eq 'Switch' -and $Decision['TargetSid'] -eq $pubSid }
        }
        It 'exits with 1' {
            $result['ExitCode'] | Should Be 1
        }
    }

    Context 'dependents unknown (COM+ discovery failed): nothing is disabled' {
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile IPT01 -Parts @{ ComPlus = @{ Error = 'x' } }
        $sopSid = Get-CrTestUserSid $state 'SOP-Admin'
        $result = Invoke-TestApply -State $state -RunningSid $sopSid

        It 'neither moves nor disables any account' {
            Assert-MockCalled Move-CrServiceAccount -Times 0 -Exactly -Scope Context
            Assert-MockCalled Disable-CrAccount -Times 0 -Exactly -Scope Context
        }
        It 'keeps every account of the disable plan enabled and says why' {
            foreach ($n in @('Administrator', 'SYS Admin', 'SOP-Admin')) {
                (Get-TestDisable $result $n)['Status'] | Should Be 'KeptEnabled'
                (Get-TestDisable $result $n)['Reason'] | Should Match 'dependents are unknown'
            }
            @(Get-TestFindings $result 'Info' 'Accounts' 'SOP-Admin' 'Your own account stays enabled: *dependents are unknown*').Count | Should Be 1
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
            (@($global:CrTestDisabled) -join ',') | Should Be 'Administrator'
        }
        It 'has no LOGINS or RDP follow-up and exits with 0' {
            @(Get-TestFindings $result 'FollowUp').Count | Should Be 0
            $result['ExitCode'] | Should Be 0
        }
        It 'skips the check-mode fixes and the retired accounts under -Only' {
            @(Get-TestFindings $result 'Info' 'Check' $null '*not processed under -Only*').Count | Should Be 1
            Assert-MockCalled Move-CrServiceAccount -Times 0 -Exactly -Scope Context
            ($global:CrTestDisabled -contains 'SOP-Admin') | Should Be $false
        }
    }

    Context 're-apply of ApplicationUser with a SQL slot selected: the unsupported SQL slot does not count (exit 0)' {
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile IPT01
        $appSid = Get-CrTestUserSid $state 'ApplicationUser'
        $result = Invoke-TestApply -State $state -Slots @('AppUser') -ReapplySids @($appSid) -Only @('AppUser', 'SQLApplication')

        It 'skips the SQL slot as unsupported and completes the AppUser slot' {
            (Get-TestSlot $result 'SQLApplication')['Status'] | Should Be 'Skipped'
            (Get-TestSlot $result 'SQLApplication')['Unsupported'] | Should Be $true
            (Get-TestSlot $result 'AppUser')['Status'] | Should Be 'Done'
        }
        It 'exits with 0' {
            @($result['NotAppliedSlots']).Count | Should Be 0
            $result['ExitCode'] | Should Be 0
        }
    }

    Context 'check-mode fixes, retired and other accounts under -Only (SM)' {
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile SM
        # An enabled built-in Administrator, so the selected AppUser slot has an account to disable.
        (Get-CrTestUser $state 'LocalAdm')['Disabled'] = $false
        $otherAdminSid = Get-CrTestUserSid $state 'OtherAdmin'
        $result = Invoke-TestApply -State $state -Slots @('AppUser') -Only @('AppUser') -OtherDecisions @{ $otherAdminSid = 'Disable' }

        It 'are skipped' {
            Assert-MockCalled Set-CrAccountFlags -Times 0 -Exactly -Scope Context -ParameterFilter { $User['Name'] -eq 'WinUser1' }
            @($result['CheckFixes']).Count | Should Be 0
            ($global:CrTestDisabled -contains 'OtherAdmin') | Should Be $false
            ($global:CrTestDisabled -contains 'SP Admin') | Should Be $false
        }
        It 'disables only the account replaced by the selected slot' {
            (@($global:CrTestDisabled) -join ',') | Should Be 'LocalAdm'
        }
    }

    Context 'ApplicationUser: both passwords failed, the operator chose set' {
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile IPT01
        $appSid = Get-CrTestUserSid $state 'ApplicationUser'
        $result = Invoke-TestApply -State $state -Slots @('AppUser') -Only @('AppUser') -Outcomes @{ $appSid = 'BothFailed' } -Paths @{ $appSid = 'Set' }

        It 'sets the password and reports the DPAPI loss' {
            Assert-MockCalled Invoke-CrPasswordSet -Times 1 -Exactly -Scope Context -ParameterFilter { $User['Sid'] -eq $appSid }
            Assert-MockCalled Invoke-CrPasswordRotation -Times 0 -Exactly -Scope Context
            @(Get-TestFindings $result 'HighImpact' 'Password' 'ApplicationUser' '*DPAPI*').Count | Should Be 1
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
        It 'exits with 1: the selected slot was not applied (PLAN 6 step 11, v10.4)' {
            (@($result['NotAppliedSlots']) -join ',') | Should Be 'AppUser'
            $result['ExitCode'] | Should Be 1
        }
    }

    Context 'a selected slot blocked by the preflight' {
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile IPT01
        $pf = @{ MachineBlocked = $false; BlockedSlots = @{ AppUser = 'Synthetic block reason' }; Findings = @() }
        $result = Invoke-TestApply -State $state -Slots @('AppUser') -Only @('AppUser') -Preflight $pf

        It 'changes nothing in the slot and keeps the built-in Administrator enabled' {
            (Get-TestSlot $result 'AppUser')['Status'] | Should Be 'Blocked'
            Assert-MockCalled Invoke-CrPasswordRotation -Times 0 -Exactly -Scope Context
            Assert-MockCalled Invoke-CrPasswordSet -Times 0 -Exactly -Scope Context
            Assert-MockCalled Disable-CrAccount -Times 0 -Exactly -Scope Context
            @(Get-TestFindings $result 'Blocked' 'Apply' $null 'Slot Blocked: Synthetic block reason').Count | Should Be 1
        }
        It 'exits with 1 and lists the slot as not applied (PLAN 6 step 11, v10.4)' {
            (@($result['NotAppliedSlots']) -join ',') | Should Be 'AppUser'
            $result['ExitCode'] | Should Be 1
        }
    }

    Context 'machine blocked' {
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
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

Describe 'Clear-CrSlotSecrets' {
    It 'disposes the new and the old secrets' {
        $new = New-Object System.Security.SecureString
        $old = New-Object System.Security.SecureString
        Clear-CrSlotSecrets -SlotSecrets @{ S = @{ Slot = 'S'; Skipped = $false; NewSecret = $new; Accounts = @(@{ Sid = 'S-1-5-21-1000-2000-3000-1001'; OldSecret = $old }) } }
        { $null = $new.Length } | Should Throw
        { $null = $old.Length } | Should Throw
    }
}

# The Describe blocks above have run; remove the globals the mocks and filters used, so they don't leak into the
# other test files of the same Invoke-Pester session.
foreach ($name in @('CrTestNewSids', 'CrTestSlotSecrets', 'CrTestDisabled', 'CrTestGroupsAfterCreate', 'CrTestBadCount', 'CrTestUserFlags', 'CrTestInfoSuccess')) {
    Remove-Variable -Name $name -Scope Global -ErrorAction SilentlyContinue
}
