# Pester 3.4 tests for src\lib\Apply.ps1, account model PLAN v10.6 (sections 6 steps 6-11, 7.5, 8; D9, D11, D12, D13,
# D20-D25, D28, D29). Synthetic machine state from Fixtures.ps1 (SM: no PUB-User, BiCA accounts replaced by SOP-Admin,
# SYS Admin retired; IPT01: SYS Admin and SYS-Admin retired, the built-in Administrator replaced by ApplicationUser; in
# both, SOP-Admin is missing and created unless a test adds it); every building block of other modules is stubbed and
# mocked. Pester 3.4 leaks a Mock defined inside an It into later Its: mocks are only defined at Describe/Context
# level, each scenario runs once in its Context body and the Its assert with -Scope Context.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$lib = Join-Path $here '..\src\lib'
# Journal.ps1 (Test-CrJournalStepInUnfinishedRun), Secrets.ps1 (Test-CrProbeBudget) and Sql.ps1 (Get-CrSqlAccessPlan) are
# used by Apply.ps1; their console, probe, journal-write and SQL Server functions are replaced by the stubs below.
foreach ($m in @('Compat', 'Log', 'Config', 'Rights', 'Principals', 'Sql', 'AutoLogon', 'Preflight', 'Plan', 'Journal', 'Secrets', 'Apply')) { . (Join-Path $lib ($m + '.ps1')) }
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
function Grant-CrSqlLoginAccess { param([string]$LoginName, [bool]$CreateLogin, [bool]$EnableLogin, [string[]]$Roles, [int]$MajorVersion) }
function Get-CrSqlLoginAccess { param([string]$Sid) }

# SIDs the New-CrManagedAccount mock hands out for created accounts (synthetic, unused RIDs of the SM fixture).
$global:CrTestNewSids = @{ 'SOP-Admin' = 'S-1-5-21-1000-2000-3000-1110'; 'ApplicationUser' = 'S-1-5-21-1000-2000-3000-1109' }

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
        $State, [string[]]$Slots = @('AppUser', 'AutoLogon', 'SOPAdmin'), [hashtable]$Outcomes = @{}, [hashtable]$Paths = @{},
        [string[]]$ReapplySids = @(), [string[]]$Only, [string]$RunningSid, $Preflight, [string]$AutoLogonChoice,
        [hashtable]$OtherDecisions = @{}, $Journal, $Config
    )
    if (-not $Config) { $Config = New-CrTestConfig }
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

$CrTestSlotOrder = 'AppUser,AutoLogon,SOPAdmin'

Describe 'Get-CrApplySlotDefinitions' {
    It 'orders the slots by Order: AppUser first, SOPAdmin last (D25)' {
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

Describe 'Get-CrApplyPreview / Get-CrApplyAccountFates (SM: SOP-Admin missing, WinAutoUser disabled)' {
    $state = New-CrTestState -Profile SM
    (Get-CrTestUser $state 'WinAutoUser')['Disabled'] = $true
    $config = New-CrTestConfig
    $resolved = Resolve-CrAccounts -Config $config -State $state
    $ss = New-TestSlotSecrets -Resolved $resolved -Slots @('AppUser', 'AutoLogon', 'SOPAdmin')
    $probes = New-TestProbes -SlotSecrets $ss
    $pf = @{ MachineBlocked = $false; BlockedSlots = @{}; Findings = @() }
    $preview = Get-CrApplyPreview -Config $config -Resolved $resolved -Preflight $pf -SlotSecrets $ss -Probes $probes -Only $null
    $runningSid = Get-CrTestUserSid $state 'BiCA Remote'
    $others = @((Get-CrTestUser $state 'myftpuser'), (Get-CrTestUser $state 'OtherAdmin'))
    $fates = Get-CrApplyAccountFates -State $state -Resolved $resolved -RunningSid $runningSid -Only $null -Others $others
    $fate = @{}
    foreach ($f in $fates) { $fate[$f['Name']] = $f['Fate'] }
    $autoLogonAccounts = @((Find-CrApplyPreviewSlot $preview 'AutoLogon')['Accounts'])

    It 'lists the slots in Order, SOPAdmin last (D25)' {
        Get-TestSlotOrder $preview | Should Be $CrTestSlotOrder
    }
    It 'creates the missing SOP-Admin and changes ApplicationUser; there are no BiCA slots and no SQL slots (D27, D28)' {
        $sop = (Find-CrApplyPreviewSlot $preview 'SOPAdmin')['Accounts'][0]
        $sop['Name'] | Should Be 'SOP-Admin'
        $sop['Path'] | Should Be 'Create'
        @((Find-CrApplyPreviewSlot $preview 'SOPAdmin')['Accounts']).Count | Should Be 1
        $null -eq (Find-CrApplyPreviewSlot $preview 'BiCARemote') | Should Be $true
        ((Find-CrApplyPreviewSlot $preview 'AppUser')['Accounts'][0])['Path'] | Should Be 'Change'
        $null -eq (Find-CrApplyPreviewSlot $preview 'SQLApplication') | Should Be $true
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
        $fate['SOP-Admin'] | Should Be 'create'
        $fate['BiCA Admin'] | Should Be 'disable'
        $fate['BiCA Remote'] | Should Be 'disable'
        $fate['ApplicationUser'] | Should Be 'change'
        $fate['SYS Admin'] | Should Be 'disable'
        $fate['OtherAdmin'] | Should Be 'ask'
        $fate['WinUser1'] | Should Be 'keep'
        $fate.ContainsKey('WinAutoUser') | Should Be $false
        $fate.ContainsKey('WinUser3') | Should Be $false
    }
    It 'says that the BiCA accounts are replaced by SOP-Admin and the running BiCA Remote goes last (D25)' {
        $details = @{}
        foreach ($f in $fates) { $details[$f['Name']] = $f['Detail'] }
        $details['BiCA Admin'] | Should Be 'replaced by SOP-Admin (D22); its dependents move there (D24)'
        $details['BiCA Remote'] | Should Be 'replaced by SOP-Admin (D22); its dependents move there (D24); your own account, disabled last (D25)'
    }
    It 'Test-CrApplyEntryCreated: true only for the entry whose account is created in this run' {
        Test-CrApplyEntryCreated -Preview $preview -Entry (Get-TestEntry $resolved 'SOPAdmin') | Should Be $true
        Test-CrApplyEntryCreated -Preview $preview -Entry (Get-TestEntry $resolved 'AppUser') | Should Be $false
        Test-CrApplyEntryCreated -Preview $preview -Entry $null | Should Be $false
    }
    It 'Get-CrApplyCreatedTargetReason names the created target and the account that keeps its dependents (D24)' {
        $reason = Get-CrApplyCreatedTargetReason -TargetName 'ApplicationUser' -Name 'LocalAdm'
        $reason | Should Match '^stays enabled: ApplicationUser is created in this run'
        $reason | Should Match 'migrate them manually'
    }
}

Describe 'Get-CrApplyAccountFates / Get-CrApplyDisablePlan: SP Admin kept untouched (v10.5), an existing SOP-Admin managed (v10.6)' {
    $state = New-CrTestState -Profile IPT01
    $sop = Add-CrTestUser -State $state -Name 'SOP-Admin' -Groups @('Administrators') -PasswordNeverExpires
    [void](Add-CrTestUser -State $state -Name 'SP Admin' -Groups @('Administrators') -PasswordNeverExpires)
    $config = New-CrTestConfig
    $resolved = Resolve-CrAccounts -Config $config -State $state
    $others = Get-CrOtherEnabledAccounts -State $state -Resolved $resolved
    $fates = Get-CrApplyAccountFates -State $state -Resolved $resolved -RunningSid (Get-CrTestUserSid $state 'BiCA Remote') -Only $null -Others $others
    $fate = @{}
    foreach ($f in $fates) { $fate[$f['Name']] = $f }
    $plan = Get-CrApplyDisablePlan -State $state -Resolved $resolved -Preview @() -RunningSid $sop.Sid -Only $null -OtherDecisions @{}

    It 'is not one of the other enabled accounts the operator is asked about (D23)' {
        @($others).Count | Should Be 0
    }
    It 'keeps SP Admin and says why, sets the password of SOP-Admin; the retired SYS Admin and SYS-Admin are disabled' {
        $fate['SP Admin']['Fate'] | Should Be 'keep'
        $fate['SP Admin']['Detail'] | Should Be 'kept untouched (config: Mode Keep)'
        $fate['SOP-Admin']['Fate'] | Should Be 'set'
        $fate['SOP-Admin']['Detail'] | Should Be 'managed account (slot SOPAdmin): password set (D9)'
        $fate['SYS Admin']['Fate'] | Should Be 'disable'
        $fate['SYS-Admin']['Fate'] | Should Be 'disable'
    }
    It 'leaves SOP-Admin and SP Admin out of the disable plan and plans the BiCA accounts, replaced by SOP-Admin' {
        $null -eq (Get-TestPlanItem $plan 'SOP-Admin') | Should Be $true
        $null -eq (Get-TestPlanItem $plan 'SP Admin') | Should Be $true
        $null -ne (Get-TestPlanItem $plan 'SYS-Admin') | Should Be $true
        foreach ($n in @('BiCA Admin', 'BiCA Remote')) {
            $i = Get-TestPlanItem $plan $n
            $i['Kind'] | Should Be 'Replaced'
            $i['ReplacementName'] | Should Be 'SOP-Admin'
            $i['ReplacementSlot'] | Should Be 'SOPAdmin'
            $i['Planned'] | Should Be $true
            $i['IsRunning'] | Should Be $false
        }
        (Get-TestPlanItem $plan 'BiCA Admin')['MoveEntry']['Id'] | Should Be 'SOPAdmin'
        (Get-TestPlanItem $plan 'BiCA Admin')['HasDependents'] | Should Be $true
    }
}

Describe 'Get-CrApplyDisablePlan: the SQL Server access and the logon rights of SOP-Admin (D28, D29)' {
    Context 'SQL Server stopped: the access of SOP-Admin is unknown' {
        $state = New-CrTestState -Profile SM
        $state.Sql.ServiceState = 'Stopped'
        $state.Sql.Connected = $false
        $state.Sql.Logins = @()
        $resolved = Resolve-CrAccounts -Config (New-CrTestConfig) -State $state
        $plan = Get-CrApplyDisablePlan -State $state -Resolved $resolved -Preview @() -RunningSid (Get-CrTestUserSid $state 'BiCA Remote') -Only $null -OtherDecisions @{}

        It 'keeps both BiCA accounts enabled and says why' {
            foreach ($n in @('BiCA Admin', 'BiCA Remote')) {
                $i = Get-TestPlanItem $plan $n
                $i['Planned'] | Should Be $false
                $i['Reason'] | Should Match '^stays enabled: the SQL Server access of SOP-Admin cannot be checked: the default SQL Server instance is not running'
            }
        }
        It 'still plans the other accounts' {
            (Get-TestPlanItem $plan 'SYS Admin')['Planned'] | Should Be $true
        }
    }

    Context 'the preflight says the tool cannot write to SQL Server' {
        $state = New-CrTestState -Profile SM
        $resolved = Resolve-CrAccounts -Config (New-CrTestConfig) -State $state
        $pf = @{ MachineBlocked = $false; BlockedSlots = @{}; Findings = @(); SqlWriteBlocked = 'write filter: master is protected' }
        $plan = Get-CrApplyDisablePlan -State $state -Resolved $resolved -Preview @() -RunningSid (Get-CrTestUserSid $state 'BiCA Remote') -Only $null -OtherDecisions @{} -Preflight $pf

        It 'keeps both BiCA accounts enabled' {
            foreach ($n in @('BiCA Admin', 'BiCA Remote')) {
                (Get-TestPlanItem $plan $n)['Reason'] | Should Be 'stays enabled: SOP-Admin cannot get the SQL Server access of the accounts it replaces: write filter: master is protected (D29)'
            }
        }
    }

    Context 'a created SOP-Admin would be denied local logon through Remote Desktop Users' {
        $state = New-CrTestState -Profile SM
        Add-CrTestRight -State $state -Right 'SeDenyInteractiveLogonRight' -Sids @('S-1-5-32-555')
        $resolved = Resolve-CrAccounts -Config (New-CrTestConfig) -State $state
        $plan = Get-CrApplyDisablePlan -State $state -Resolved $resolved -Preview @() -RunningSid (Get-CrTestUserSid $state 'BiCA Remote') -Only $null -OtherDecisions @{}

        It 'keeps BiCA Admin, which may log on locally, enabled (D28)' {
            $i = Get-TestPlanItem $plan 'BiCA Admin'
            $i['Planned'] | Should Be $false
            $i['Reason'] | Should Be 'stays enabled: SOP-Admin would not be allowed to log on locally as BiCA Admin can (logon right not granted, or denied; D28)'
        }
        It 'plans BiCA Remote, which is denied local logon itself' {
            (Get-TestPlanItem $plan 'BiCA Remote')['Planned'] | Should Be $true
        }
    }
}

Describe 'Get-CrApplyDisablePlan: dependents of retired and other accounts always move to ApplicationUser (D24, v10.4)' {
    Context 'SM: the retired SYS Admin (task), OtherAdmin (service) disabled by the operator, myftpuser kept' {
        $state = New-CrTestState -Profile SM
        $otherAdminSid = Get-CrTestUserSid $state 'OtherAdmin'
        $myftpSid = Get-CrTestUserSid $state 'myftpuser'
        Add-TestService -State $state -Name 'OtherService' -Sid $otherAdminSid -StartName '.\OtherAdmin'
        $config = New-CrTestConfig
        $resolved = Resolve-CrAccounts -Config $config -State $state
        $ss = New-TestSlotSecrets -Resolved $resolved -Slots @('AppUser', 'AutoLogon', 'SOPAdmin')
        $probes = New-TestProbes -SlotSecrets $ss
        $pf = @{ MachineBlocked = $false; BlockedSlots = @{}; Findings = @() }
        $preview = Get-CrApplyPreview -Config $config -Resolved $resolved -Preflight $pf -SlotSecrets $ss -Probes $probes -Only $null
        $plan = Get-CrApplyDisablePlan -State $state -Resolved $resolved -Preview $preview -RunningSid (Get-CrTestUserSid $state 'BiCA Remote') `
            -Only $null -OtherDecisions @{ $otherAdminSid = 'Disable'; $myftpSid = 'Keep' }
        $sysSm = Get-TestPlanItem $plan 'SYS Admin'
        $other = Get-TestPlanItem $plan 'OtherAdmin'
        $kept = Get-TestPlanItem $plan 'myftpuser'

        It 'plans to disable the retired SYS Admin and move its task to ApplicationUser' {
            $sysSm['Kind'] | Should Be 'Disable'
            $sysSm['HasDependents'] | Should Be $true
            $sysSm['MoveEntry']['Id'] | Should Be 'AppUser'
            $sysSm['Planned'] | Should Be $true
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
        $sysHyphen = Get-TestPlanItem $plan 'SYS-Admin'

        It 'keeps the retired SYS Admin with a service enabled: there is nowhere to move it' {
            $sys['Planned'] | Should Be $false
            $null -eq $sys['MoveEntry'] | Should Be $true
            $sys['Reason'] | Should Match '^stays enabled: .*no application account'
        }
        It 'still plans to disable the retired SYS-Admin without dependents' {
            $sysHyphen['Planned'] | Should Be $true
        }
    }
}

Describe 'Get-CrApplyDisablePlan: dependents unknown (D24)' {
    Context 'the COM+ discovery failed' {
        $state = New-CrTestState -Profile IPT01 -Parts @{ ComPlus = @{ Error = 'x' } }
        $config = New-CrTestConfig
        $resolved = Resolve-CrAccounts -Config $config -State $state
        $sysHyphenSid = Get-CrTestUserSid $state 'SYS-Admin'
        $plan = Get-CrApplyDisablePlan -State $state -Resolved $resolved -Preview @() -RunningSid $sysHyphenSid -Only $null -OtherDecisions @{}

        It 'lists the accounts (BiCA Admin, BiCA Remote, Administrator, SYS Admin, SYS-Admin) but plans to disable none of them' {
            @($plan).Count | Should Be 5
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
    Mock Grant-CrSqlLoginAccess {
        $steps = New-Object System.Collections.ArrayList
        if ($CreateLogin) { [void]$steps.Add('CreateLogin') }
        if ($EnableLogin) { [void]$steps.Add('EnableLogin') }
        foreach ($r in @($Roles)) { if ($r) { [void]$steps.Add('AddRole ' + $r) } }
        @{ Success = $true; Steps = $steps.ToArray(); FailedStep = $null; Error = $null }
    }
    Mock Get-CrSqlLoginAccess { @{ Found = $true; Name = 'TEST\SOP-Admin'; IsDisabled = $false; Roles = @('sysadmin'); Error = $null } }

    Context 'IPT01 run as the retired SYS-Admin: SOP-Admin created, set vs change, dependents moved, disables, the running account last (D25)' {
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile IPT01
        $bicaSid = Get-CrTestUserSid $state 'BiCA Admin'
        $appSid = Get-CrTestUserSid $state 'ApplicationUser'
        $pubSid = Get-CrTestUserSid $state 'PUB-User'
        $winAutoSid = Get-CrTestUserSid $state 'WinAutoUser'
        $sysSid = Get-CrTestUserSid $state 'SYS Admin'
        $sysHyphenSid = Get-CrTestUserSid $state 'SYS-Admin'
        $sopSid = $global:CrTestNewSids['SOP-Admin']
        $result = Invoke-TestApply -State $state -RunningSid $sysHyphenSid

        It 'runs the slots in Order, SOPAdmin last (D25); there are no BiCA and no SQL slots (D27, D28)' {
            Get-TestSlotOrder $result['Slots'] | Should Be $CrTestSlotOrder
            foreach ($s in @('AppUser', 'AutoLogon', 'SOPAdmin')) { (Get-TestSlot $result $s)['Status'] | Should Be 'Done' }
            $null -eq (Get-TestSlot $result 'SQLApplication') | Should Be $true
        }
        It 'creates SOP-Admin with the SOPAdmin slot secret, sets PUB-User and WinAutoUser and changes ApplicationUser (D9)' {
            Assert-MockCalled New-CrManagedAccount -Times 1 -Exactly -Scope Context
            Assert-MockCalled New-CrManagedAccount -Times 1 -Exactly -Scope Context -ParameterFilter {
                $Name -eq 'SOP-Admin' -and [object]::ReferenceEquals($Secret, $global:CrTestSlotSecrets['SOPAdmin']['NewSecret'])
            }
            Assert-MockCalled Invoke-CrPasswordSet -Times 2 -Exactly -Scope Context
            Assert-MockCalled Invoke-CrPasswordSet -Times 1 -Exactly -Scope Context -ParameterFilter { $User['Sid'] -eq $pubSid }
            Assert-MockCalled Invoke-CrPasswordSet -Times 1 -Exactly -Scope Context -ParameterFilter { $User['Sid'] -eq $winAutoSid }
            Assert-MockCalled Invoke-CrPasswordRotation -Times 1 -Exactly -Scope Context -ParameterFilter { $Path -eq 'Change' -and $User['Sid'] -eq $appSid }
            Assert-MockCalled Enable-CrAccount -Times 0 -Exactly -Scope Context
            (@($result['VerifiedSids']) -contains $sopSid) | Should Be $true
        }
        It 'adds SOP-Admin to Administrators and Remote Desktop Users (the optional helpers group is missing)' {
            Assert-MockCalled Invoke-CrGroupMembershipChange -Times 1 -Exactly -Scope Context
            Assert-MockCalled Invoke-CrGroupMembershipChange -Times 1 -Exactly -Scope Context -ParameterFilter {
                $MemberSid -eq $sopSid -and @($AddGroupSids) -contains 'S-1-5-32-544' -and @($AddGroupSids) -contains 'S-1-5-32-555' -and @($AddGroupSids).Count -eq 2
            }
        }
        It 'grants SOP-Admin the SQL Server login with sysadmin as the running account and verifies it (D29)' {
            Assert-MockCalled Grant-CrSqlLoginAccess -Times 1 -Exactly -Scope Context -ParameterFilter {
                $LoginName -eq 'IPT01-TEST01\SOP-Admin' -and $CreateLogin -and -not $EnableLogin -and (@($Roles) -join ',') -eq 'sysadmin' -and $MajorVersion -eq 10
            }
            Assert-MockCalled Get-CrSqlLoginAccess -Times 1 -Exactly -Scope Context -ParameterFilter { $Sid -eq $sopSid }
            @(Get-TestFindings $result 'Info' 'SQL' 'SOP-Admin' 'SQL Server: Windows login IPT01-TEST01\SOP-Admin created (D29)').Count | Should Be 1
            @(Get-TestFindings $result 'Info' 'SQL' 'SOP-Admin' 'SQL Server access verified: *the same as BiCA Admin (OLD-NAME01\BiCA Admin), BiCA Remote (OLD-NAME01\BiCA Remote) (D29)').Count | Should Be 1
            @(Get-TestFindings $result 'Info' 'SQL' 'SOP-Admin' '*no Windows login in SQL Server*').Count | Should Be 0
        }
        It 'neither updates nor moves the service of BiCA Admin: SOP-Admin is created in this run (D24)' {
            Assert-MockCalled Update-CrServiceCredentials -Times 0 -Exactly -Scope Context -ParameterFilter { $Sid -eq $bicaSid }
            Assert-MockCalled Move-CrServiceAccount -Times 0 -Exactly -Scope Context -ParameterFilter { $FromSid -eq $bicaSid }
            $d = Get-TestDisable $result 'BiCA Admin'
            $d['Status'] | Should Be 'KeptEnabled'
            $d['Reason'] | Should Match '^stays enabled: SOP-Admin is created in this run'
            @(Get-TestFindings $result 'FollowUp' 'Accounts' 'BiCA Admin' 'Migrate the services, scheduled tasks and COM+ applications of this account manually*').Count | Should Be 1
        }
        It 'always moves the service of the retired SYS Admin to ApplicationUser with its new secret (D24, v10.4)' {
            Assert-MockCalled Move-CrServiceAccount -Times 1 -Exactly -Scope Context
            Assert-MockCalled Move-CrServiceAccount -Times 1 -Exactly -Scope Context -ParameterFilter {
                $FromSid -eq $sysSid -and $ToAccount -eq '.\ApplicationUser' -and [object]::ReferenceEquals($Secret, $global:CrTestSlotSecrets['AppUser']['NewSecret'])
            }
            (Get-TestDisable $result 'SYS Admin')['MovedTo'] | Should Be 'ApplicationUser'
        }
        It 'switches auto-logon from BiCA Admin to PUB-User with the AutoLogon slot secret' {
            Assert-MockCalled Invoke-CrAutoLogonAction -Times 1 -Exactly -Scope Context -ParameterFilter {
                $Decision['Action'] -eq 'Switch' -and $Decision['TargetSid'] -eq $pubSid -and
                [object]::ReferenceEquals($Secret, $global:CrTestSlotSecrets['AutoLogon']['NewSecret'])
            }
        }
        It 'disables BiCA Remote, the replaced Administrator and the retired SYS Admin, the running SYS-Admin last (D25)' {
            (@($global:CrTestDisabled) -join ',') | Should Be 'BiCA Remote,Administrator,SYS Admin,SYS-Admin'
            (Get-TestDisable $result 'BiCA Remote')['Status'] | Should Be 'Disabled'
            (Get-TestDisable $result 'SYS-Admin')['Status'] | Should Be 'Disabled'
        }
        It 'lists LOGINS follow-ups for SOP-Admin (in place of the BiCA entries) and ApplicationUser, and the next logon as SOP-Admin' {
            $f = @(Get-TestFindings $result 'FollowUp' 'LOGINS' 'SOP-Admin')
            $f.Count | Should Be 1
            $f[0]['Detail'] | Should Be 'Replaces the LOGINS entries of: BiCA Admin, BiCA Remote'
            @(Get-TestFindings $result 'FollowUp' 'LOGINS' 'ApplicationUser').Count | Should Be 1
            @(Get-TestFindings $result 'FollowUp' 'LOGINS' 'BiCA Admin').Count | Should Be 0
            @(Get-TestFindings $result 'FollowUp' 'LOGINS' 'BiCA Remote').Count | Should Be 0
            @(Get-TestFindings $result 'FollowUp' 'LOGINS' 'PUB-User').Count | Should Be 0
            @(Get-TestFindings $result 'FollowUp' 'LOGINS' 'WinAutoUser').Count | Should Be 0
            @(Get-TestFindings $result 'FollowUp' 'Accounts' 'SYS-Admin' '*Log on as SOP-Admin next time*').Count | Should Be 1
        }
        It 'lists the RDP follow-up only for the operator account SOP-Admin (PLAN 8, v10.4)' {
            @(Get-TestFindings $result 'FollowUp' 'RDP').Count | Should Be 1
            @(Get-TestFindings $result 'FollowUp' 'RDP' 'SOP-Admin' '*saved RDP credentials*').Count | Should Be 1
            @(Get-TestFindings $result 'FollowUp' 'RDP')[0]['Slot'] | Should Be 'SOPAdmin'
        }
        It 'exits with 4 (follow-up required)' {
            @($result['NotAppliedSlots']).Count | Should Be 0
            $result['ExitCode'] | Should Be 4
        }
    }

    Context 'SM run as BiCA Remote: SOP-Admin created with its SQL login, BiCA Admin disabled, retired SYS Admin moved, operator decisions (D23), BiCA Remote last (D25)' {
        Mock Get-CrLocalGroups { , $global:CrTestGroupsAfterCreate }
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile SM
        $newSid = $global:CrTestNewSids['SOP-Admin']
        $global:CrTestGroupsAfterCreate = New-TestGroupsWithMember -State $state -GroupSid 'S-1-5-32-545' -MemberSid $newSid
        $bicaSid = Get-CrTestUserSid $state 'BiCA Admin'
        $remoteSid = Get-CrTestUserSid $state 'BiCA Remote'
        $appSid = Get-CrTestUserSid $state 'ApplicationUser'
        $winAutoSid = Get-CrTestUserSid $state 'WinAutoUser'
        $sysSmSid = Get-CrTestUserSid $state 'SYS Admin'
        $otherAdminSid = Get-CrTestUserSid $state 'OtherAdmin'
        $myftpSid = Get-CrTestUserSid $state 'myftpuser'
        $helpersSid = (Get-CrTestGroup $state 'Offer Remote Assistance Helpers').Sid
        $result = Invoke-TestApply -State $state -OtherDecisions @{ $otherAdminSid = 'Disable'; $myftpSid = 'Keep' }

        It 'creates the missing SOP-Admin with the SOPAdmin slot secret (D21, D28)' {
            Assert-MockCalled New-CrManagedAccount -Times 1 -Exactly -Scope Context
            Assert-MockCalled New-CrManagedAccount -Times 1 -Exactly -Scope Context -ParameterFilter {
                $Name -eq 'SOP-Admin' -and [object]::ReferenceEquals($Secret, $global:CrTestSlotSecrets['SOPAdmin']['NewSecret'])
            }
            (@($result['CreatedSids']) -join ',') | Should Be $newSid
            (Get-TestSlot $result 'SOPAdmin')['Status'] | Should Be 'Done'
        }
        It 'sets WinAutoUser and changes ApplicationUser; the BiCA accounts and the created account get no password step' {
            Assert-MockCalled Invoke-CrPasswordSet -Times 1 -Exactly -Scope Context
            Assert-MockCalled Invoke-CrPasswordSet -Times 1 -Exactly -Scope Context -ParameterFilter { $User['Sid'] -eq $winAutoSid }
            Assert-MockCalled Invoke-CrPasswordRotation -Times 1 -Exactly -Scope Context -ParameterFilter { $User['Sid'] -eq $appSid }
        }
        It 're-reads the groups after the creation, adds SOP-Admin to its three role groups and removes it from Users later' {
            Assert-MockCalled Get-CrLocalGroups -Times 1 -Exactly -Scope Context
            Assert-MockCalled Invoke-CrGroupMembershipChange -Times 1 -Exactly -Scope Context -ParameterFilter {
                $MemberSid -eq $newSid -and @($AddGroupSids) -contains 'S-1-5-32-544' -and @($AddGroupSids) -contains 'S-1-5-32-555' -and @($AddGroupSids) -contains $helpersSid
            }
            Assert-MockCalled Invoke-CrGroupMembershipChange -Times 1 -Exactly -Scope Context -ParameterFilter { $MemberSid -eq $newSid -and @($RemoveGroupSids) -contains 'S-1-5-32-545' }
            (@($result['VerifiedSids']) -contains $newSid) | Should Be $true
        }
        It 'grants the SQL Server login of SOP-Admin (D29) instead of reporting that it has none' {
            Assert-MockCalled Grant-CrSqlLoginAccess -Times 1 -Exactly -Scope Context -ParameterFilter { $LoginName -eq 'SM-TEST01\SOP-Admin' -and $CreateLogin }
            @(Get-TestFindings $result 'Info' 'SQL' 'SOP-Admin' '*no Windows login in SQL Server*').Count | Should Be 0
            @(Get-TestFindings $result 'Info' 'SQL' 'SOP-Admin' 'SQL Server access verified*').Count | Should Be 1
        }
        It 'updates the task of WinAutoUser in place with the AutoLogon secret, after granting the batch right' {
            Assert-MockCalled Grant-CrDependentRights -Times 1 -Exactly -Scope Context -ParameterFilter { $Sid -eq $winAutoSid -and @($Rights) -contains 'SeBatchLogonRight' }
            Assert-MockCalled Update-CrTaskCredentials -Times 1 -Exactly -Scope Context -ParameterFilter {
                $Sid -eq $winAutoSid -and [object]::ReferenceEquals($Secret, $global:CrTestSlotSecrets['AutoLogon']['NewSecret'])
            }
            Assert-MockCalled Move-CrTaskAccount -Times 0 -Exactly -Scope Context -ParameterFilter { $FromSid -eq $winAutoSid }
        }
        It 'moves the task of the retired SYS Admin to ApplicationUser with its new secret (D24, v10.4)' {
            Assert-MockCalled Move-CrTaskAccount -Times 1 -Exactly -Scope Context
            Assert-MockCalled Move-CrTaskAccount -Times 1 -Exactly -Scope Context -ParameterFilter {
                $FromSid -eq $sysSmSid -and $ToUserId -eq 'SM-TEST01\ApplicationUser' -and
                [object]::ReferenceEquals($Secret, $global:CrTestSlotSecrets['AppUser']['NewSecret'])
            }
            (Get-TestDisable $result 'SYS Admin')['MovedTo'] | Should Be 'ApplicationUser'
        }
        It 'does not disable the account the operator kept (D23)' {
            ($global:CrTestDisabled -contains 'myftpuser') | Should Be $false
            (Get-TestDisable $result 'myftpuser')['Status'] | Should Be 'KeptEnabled'
            (Get-TestDisable $result 'myftpuser')['Reason'] | Should Be 'kept enabled by the operator (D23)'
        }
        It 'disables BiCA Admin (no dependents), the retired SYS Admin and the account the operator chose (D22, D23), and the running BiCA Remote last (D25)' {
            (@($global:CrTestDisabled) -join ',') | Should Be 'BiCA Admin,SYS Admin,OtherAdmin,BiCA Remote'
            (Get-TestDisable $result 'SYS Admin')['Status'] | Should Be 'Disabled'
            (Get-TestDisable $result 'BiCA Admin')['Replacement'] | Should Be 'SOP-Admin'
            (Get-TestDisable $result 'BiCA Remote')['IsRunning'] | Should Be $true
            Assert-MockCalled Disable-CrAccount -Times 1 -Exactly -Scope Context -ParameterFilter { $User['Sid'] -eq $bicaSid }
            Assert-MockCalled Disable-CrAccount -Times 1 -Exactly -Scope Context -ParameterFilter { $User['Sid'] -eq $remoteSid }
            $result['RunningAccount']['Disabled'] | Should Be $true
        }
        It 'turns auto-logon off on the SM machine and runs the check-mode fixes' {
            Assert-MockCalled Invoke-CrAutoLogonAction -Times 1 -Exactly -Scope Context -ParameterFilter { $Decision['Action'] -eq 'TurnOff' -and $null -eq $Secret }
            Assert-MockCalled Set-CrAccountFlags -Scope Context -ParameterFilter { $User['Name'] -eq 'WinUser1' }
            (@($result['CheckFixes'] | ForEach-Object { $_['Id'] }) -contains 'WinUsers') | Should Be $true
        }
        It 'lists LOGINS follow-ups for SOP-Admin and ApplicationUser, the RDP follow-up for SOP-Admin and the next logon as SOP-Admin' {
            @(Get-TestFindings $result 'FollowUp' 'LOGINS' 'SOP-Admin').Count | Should Be 1
            @(Get-TestFindings $result 'FollowUp' 'LOGINS' 'ApplicationUser').Count | Should Be 1
            @(Get-TestFindings $result 'FollowUp' 'LOGINS' 'BiCA Admin').Count | Should Be 0
            @(Get-TestFindings $result 'FollowUp' 'RDP').Count | Should Be 1
            @(Get-TestFindings $result 'FollowUp' 'RDP' 'SOP-Admin').Count | Should Be 1
            @(Get-TestFindings $result 'FollowUp' 'Accounts' 'BiCA Remote' 'Your account BiCA Remote is disabled; this RDP session continues. Log on as SOP-Admin next time*').Count | Should Be 1
        }
        It 'exits with 4' {
            $result['ExitCode'] | Should Be 4
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
        # No SOPAdmin password: the BiCA accounts are not part of this scenario (their replacement slot is skipped).
        $result = Invoke-TestApply -State $state -Slots @('AppUser', 'AutoLogon')

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
            @(Get-TestFindings $result 'Info' 'Accounts' 'LocalAdm' 'Not disabled: stays enabled: ApplicationUser is created in this run*').Count | Should Be 1
            @(Get-TestFindings $result 'FollowUp' 'Accounts' 'LocalAdm' 'Migrate the services, scheduled tasks and COM+ applications of this account manually*').Count | Should Be 1
        }
        It 'also keeps the retired SYS Admin with its task enabled' {
            (Get-TestDisable $result 'SYS Admin')['Status'] | Should Be 'KeptEnabled'
            (Get-TestDisable $result 'SYS Admin')['Reason'] | Should Match '^stays enabled: ApplicationUser is created in this run'
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
        $result = Invoke-TestApply -State $state -Slots @('AppUser', 'AutoLogon')

        It 'creates and verifies ApplicationUser' {
            Assert-MockCalled New-CrManagedAccount -Times 1 -Exactly -Scope Context -ParameterFilter { $Name -eq 'ApplicationUser' }
            (@($result['VerifiedSids']) -contains $newAppSid) | Should Be $true
        }
        It 'disables the replaced Administrator (no dependents) and the retired SYS-Admin, but not SYS Admin' {
            (@($global:CrTestDisabled) -join ',') | Should Be 'Administrator,SYS-Admin'
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
        $result = Invoke-TestApply -State $state -Journal @{ Runs = $runs } -Slots @('AppUser', 'AutoLogon')

        It 'does not move the service of SYS Admin to it and keeps SYS Admin enabled' {
            Assert-MockCalled Move-CrServiceAccount -Times 0 -Exactly -Scope Context
            (Get-TestDisable $result 'SYS Admin')['Status'] | Should Be 'KeptEnabled'
            @(Get-TestFindings $result 'HighImpact' 'Accounts' 'SYS Admin' 'Stays enabled (D24): *ApplicationUser was created by this tool*').Count | Should Be 1
        }
        It 'still disables the replaced Administrator and the retired SYS-Admin (no dependents)' {
            (@($global:CrTestDisabled) -join ',') | Should Be 'Administrator,SYS-Admin'
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
        It 'still disables the retired SYS-Admin (no dependents) and, last, the running BiCA Remote (SOP-Admin is ready)' {
            (@($global:CrTestDisabled) -join ',') | Should Be 'SYS-Admin,BiCA Remote'
        }
        It 'exits with 1' {
            $result['ExitCode'] | Should Be 1
        }
    }

    Context 'the operator account cannot be verified with a logon (1385): the running account stays enabled (D25)' {
        Mock Invoke-CrLogonTest -ParameterFilter { $UserName -eq 'SOP-Admin' } { @{ Success = $false; Win32Error = 1385 } }
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile IPT01
        $sysHyphenSid = Get-CrTestUserSid $state 'SYS-Admin'
        $result = Invoke-TestApply -State $state -RunningSid $sysHyphenSid

        It 'completes the SOPAdmin slot (unverifiable is not a failure)' {
            (Get-TestSlot $result 'SOPAdmin')['Status'] | Should Be 'Done'
            @(Get-TestFindings $result 'Info' 'Verify' 'SOP-Admin' '*could not be verified*').Count | Should Be 1
        }
        It 'keeps the running SYS-Admin enabled and says why' {
            @(Get-TestFindings $result 'HighImpact' 'Accounts' 'SYS-Admin' 'Your own account stays enabled (D25): SOP-Admin is not verified*').Count | Should Be 1
            (Get-TestDisable $result 'SYS-Admin')['Status'] | Should Be 'KeptEnabled'
        }
        It 'keeps BiCA Remote enabled: its replacement is not verified (D22)' {
            (Get-TestDisable $result 'BiCA Remote')['Status'] | Should Be 'KeptEnabled'
            @(Get-TestFindings $result 'HighImpact' 'Accounts' 'BiCA Remote' 'Not disabled: its replacement SOP-Admin is not verified*').Count | Should Be 1
        }
        It 'disables the replaced Administrator and the retired SYS Admin, whose service moved to ApplicationUser' {
            (@($global:CrTestDisabled) -join ',') | Should Be 'Administrator,SYS Admin'
        }
    }

    Context 'the operator account may not log on over RDP: the running account and BiCA Remote stay enabled (D25, D28)' {
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile IPT01
        $sopSid = $global:CrTestNewSids['SOP-Admin']
        Add-CrTestRight -State $state -Right 'SeDenyRemoteInteractiveLogonRight' -Sids @($sopSid)
        $sysHyphenSid = Get-CrTestUserSid $state 'SYS-Admin'
        $result = Invoke-TestApply -State $state -RunningSid $sysHyphenSid

        It 'verifies the created SOP-Admin on its new password' {
            (@($result['VerifiedSids']) -contains $sopSid) | Should Be $true
        }
        It 'keeps the running SYS-Admin enabled: SOP-Admin has no effective remote-interactive logon right' {
            @(Get-TestFindings $result 'HighImpact' 'Accounts' 'SYS-Admin' 'Your own account stays enabled (D25): SOP-Admin is not allowed to log on over RDP*').Count | Should Be 1
            ($global:CrTestDisabled -contains 'SYS-Admin') | Should Be $false
        }
        It 'keeps BiCA Remote enabled: it may log on over RDP, SOP-Admin may not (D28)' {
            @(Get-TestFindings $result 'HighImpact' 'Accounts' 'BiCA Remote' 'Not disabled: its replacement SOP-Admin is not allowed to log on over RDP, which BiCA Remote is (D28)').Count | Should Be 1
            ($global:CrTestDisabled -contains 'BiCA Remote') | Should Be $false
        }
    }

    Context 'a failed dependent move keeps the retired account enabled (D24)' {
        Mock Move-CrServiceAccount -ParameterFilter { $ToAccount -eq '.\ApplicationUser' } { , @(@{ Name = 'LegacySync'; Success = $false; Win32Error = 5; Error = 'access denied'; FromAccount = '.\SYS Admin'; ToAccount = '.\ApplicationUser' }) }
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile IPT01
        $sysSid = Get-CrTestUserSid $state 'SYS Admin'
        $sysHyphenSid = Get-CrTestUserSid $state 'SYS-Admin'
        $result = Invoke-TestApply -State $state -RunningSid $sysHyphenSid

        It 'does not disable SYS Admin' {
            Assert-MockCalled Move-CrServiceAccount -Times 1 -Exactly -Scope Context -ParameterFilter { $FromSid -eq $sysSid }
            ($global:CrTestDisabled -contains 'SYS Admin') | Should Be $false
            @(Get-TestFindings $result 'Blocked' 'Accounts' 'SYS Admin' 'Stays enabled*').Count | Should Be 1
        }
        It 'still disables BiCA Remote, the replaced Administrator and, last, the running SYS-Admin (no dependents, SOP-Admin ready)' {
            (@($global:CrTestDisabled) -join ',') | Should Be 'BiCA Remote,Administrator,SYS-Admin'
        }
        It 'exits with 1' {
            $result['ExitCode'] | Should Be 1
        }
    }

    Context 'auto-logon left unchanged keeps its retired account enabled; the AutoLogon slot was skipped' {
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile IPT01
        $state['AutoLogon']['DefaultUserName'] = 'SYS-Admin'
        # No AutoLogon slot password: PUB-User is not on the new password, so the switch is ambiguous; no choice = leave unchanged.
        $result = Invoke-TestApply -State $state -Slots @('AppUser', 'SOPAdmin')

        It 'leaves the auto-logon unchanged (D13)' {
            Assert-MockCalled Invoke-CrAutoLogonAction -Times 0 -Exactly -Scope Context
            $result['AutoLogon']['Action'] | Should Be 'LeaveUnchanged'
        }
        It 'does not disable the auto-logon account and reports why' {
            ($global:CrTestDisabled -contains 'SYS-Admin') | Should Be $false
            @(Get-TestFindings $result 'HighImpact' 'Accounts' 'SYS-Admin' '*auto-logon as SYS-Admin breaks*').Count | Should Be 1
        }
        It 'still disables the replaced Administrator, the retired SYS Admin (service moved to ApplicationUser) and, last, the running BiCA Remote' {
            (@($global:CrTestDisabled) -join ',') | Should Be 'Administrator,SYS Admin,BiCA Remote'
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
        $sysHyphenSid = Get-CrTestUserSid $state 'SYS-Admin'
        $result = Invoke-TestApply -State $state -RunningSid $sysHyphenSid

        It 'neither moves nor disables any account' {
            Assert-MockCalled Move-CrServiceAccount -Times 0 -Exactly -Scope Context
            Assert-MockCalled Disable-CrAccount -Times 0 -Exactly -Scope Context
        }
        It 'keeps every account of the disable plan enabled and says why' {
            foreach ($n in @('Administrator', 'SYS Admin', 'SYS-Admin')) {
                (Get-TestDisable $result $n)['Status'] | Should Be 'KeptEnabled'
                (Get-TestDisable $result $n)['Reason'] | Should Match 'dependents are unknown'
            }
            @(Get-TestFindings $result 'Info' 'Accounts' 'SYS-Admin' 'Your own account stays enabled: *dependents are unknown*').Count | Should Be 1
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
            ($global:CrTestDisabled -contains 'SYS-Admin') | Should Be $false
        }
    }

    Context 're-apply of ApplicationUser with a SQL slot selected (config with SQL entries, D27): the unsupported SQL slot does not count (exit 0)' {
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile IPT01
        $appSid = Get-CrTestUserSid $state 'ApplicationUser'
        $result = Invoke-TestApply -State $state -Slots @('AppUser') -ReapplySids @($appSid) -Only @('AppUser', 'SQLApplication') -Config (New-CrTestSqlConfig)

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
            ($global:CrTestDisabled -contains 'SYS Admin') | Should Be $false
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

    Context 'SM: the SQL Server grant for SOP-Admin fails: the SOPAdmin slot stops and the BiCA accounts stay enabled (D29)' {
        Mock Grant-CrSqlLoginAccess { @{ Success = $false; Steps = @('CreateLogin'); FailedStep = 'AddRole sysadmin'; Error = 'permission denied' } }
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile SM
        $result = Invoke-TestApply -State $state

        It 'stops the SOPAdmin slot at its SqlAccess step and reports what was done' {
            $slot = Get-TestSlot $result 'SOPAdmin'
            $slot['Status'] | Should Be 'Failed'
            $slot['FailedStep'] | Should Be 'SqlAccess'
            (@($slot['Errors']) -join ' | ') | Should Match 'SQL Server step AddRole sysadmin failed: permission denied'
            @(Get-TestFindings $result 'Info' 'SQL' 'SOP-Admin' 'SQL Server: Windows login SM-TEST01\SOP-Admin created (D29)').Count | Should Be 1
            Assert-MockCalled Get-CrSqlLoginAccess -Times 0 -Exactly -Scope Context
        }
        It 'keeps BiCA Admin and the running BiCA Remote enabled' {
            ($global:CrTestDisabled -contains 'BiCA Admin') | Should Be $false
            ($global:CrTestDisabled -contains 'BiCA Remote') | Should Be $false
            (Get-TestDisable $result 'BiCA Admin')['Reason'] | Should Match 'the slot of its replacement SOP-Admin did not complete \(Failed\)'
            @(Get-TestFindings $result 'HighImpact' 'Accounts' 'BiCA Remote' 'Your own account stays enabled (D25): the slot of its replacement SOP-Admin did not complete*').Count | Should Be 1
        }
        It 'still disables the retired SYS Admin and exits with 1' {
            (@($global:CrTestDisabled) -join ',') | Should Be 'SYS Admin'
            $result['ExitCode'] | Should Be 1
        }
    }

    Context 'SM: SQL Server is stopped, so the access of the BiCA accounts is unknown (D29)' {
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile SM
        $state.Sql.ServiceState = 'Stopped'
        $state.Sql.Connected = $false
        $state.Sql.Logins = @()
        $result = Invoke-TestApply -State $state

        It 'grants nothing and stops the SOPAdmin slot at SqlAccess' {
            Assert-MockCalled Grant-CrSqlLoginAccess -Times 0 -Exactly -Scope Context
            (Get-TestSlot $result 'SOPAdmin')['FailedStep'] | Should Be 'SqlAccess'
            (@((Get-TestSlot $result 'SOPAdmin')['Errors']) -join ' | ') | Should Match 'cannot be checked: the default SQL Server instance is not running'
        }
        It 'keeps both BiCA accounts enabled, planned so before the run' {
            (Get-TestDisable $result 'BiCA Admin')['Status'] | Should Be 'KeptEnabled'
            (Get-TestDisable $result 'BiCA Admin')['Reason'] | Should Match '^stays enabled: the SQL Server access of SOP-Admin cannot be checked'
            ($global:CrTestDisabled -contains 'BiCA Remote') | Should Be $false
            $result['ExitCode'] | Should Be 1
        }
    }

    Context 'IPT01: an existing SOP-Admin whose login is sysadmin already (D29), its account taken over (D28)' {
        $global:CrTestDisabled = New-Object System.Collections.ArrayList
        $state = New-CrTestState -Profile IPT01
        $sop = Add-CrTestUser -State $state -Name 'SOP-Admin' -Groups @('Administrators', 'Remote Desktop Users') -PasswordNeverExpires -CannotChangePassword
        $state.Sql.Logins = @($state.Sql.Logins) + @(New-CrTestSqlLogin -Name 'IPT01-TEST01\SOP-Admin' -Type 'WINDOWS_LOGIN' -Sid $sop.Sid -Sysadmin)
        $bicaSid = Get-CrTestUserSid $state 'BiCA Admin'
        $result = Invoke-TestApply -State $state

        It 'sets the password of SOP-Admin and creates nothing' {
            Assert-MockCalled New-CrManagedAccount -Times 0 -Exactly -Scope Context
            Assert-MockCalled Invoke-CrPasswordSet -Times 1 -Exactly -Scope Context -ParameterFilter {
                $User['Sid'] -eq $sop.Sid -and [object]::ReferenceEquals($NewSecret, $global:CrTestSlotSecrets['SOPAdmin']['NewSecret'])
            }
        }
        It 'grants no SQL access: it is in place' {
            Assert-MockCalled Grant-CrSqlLoginAccess -Times 0 -Exactly -Scope Context
            Assert-MockCalled Get-CrSqlLoginAccess -Times 0 -Exactly -Scope Context
            @(Get-TestFindings $result 'Info' 'SQL' 'SOP-Admin' 'SQL Server access already in place*').Count | Should Be 1
            (Get-TestSlot $result 'SOPAdmin')['Status'] | Should Be 'Done'
        }
        It 'moves the service of BiCA Admin to the existing SOP-Admin with its new secret (D24)' {
            Assert-MockCalled Move-CrServiceAccount -Times 1 -Exactly -Scope Context -ParameterFilter {
                $FromSid -eq $bicaSid -and $ToAccount -eq '.\SOP-Admin' -and [object]::ReferenceEquals($Secret, $global:CrTestSlotSecrets['SOPAdmin']['NewSecret'])
            }
            (Get-TestDisable $result 'BiCA Admin')['MovedTo'] | Should Be 'SOP-Admin'
        }
        It 'disables BiCA Admin and, last, the running BiCA Remote' {
            (@($global:CrTestDisabled) -join ',') | Should Be 'BiCA Admin,Administrator,SYS Admin,SYS-Admin,BiCA Remote'
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
        # A method call, not .Length: PowerShell swallows exceptions thrown by property getters.
        { $null = $new.Copy() } | Should Throw
        { $null = $old.Copy() } | Should Throw
    }
}

# The Describe blocks above have run; remove the globals the mocks and filters used, so they don't leak into the
# other test files of the same Invoke-Pester session.
foreach ($name in @('CrTestNewSids', 'CrTestSlotSecrets', 'CrTestDisabled', 'CrTestGroupsAfterCreate', 'CrTestBadCount', 'CrTestUserFlags', 'CrTestInfoSuccess')) {
    Remove-Variable -Name $name -Scope Global -ErrorAction SilentlyContinue
}
