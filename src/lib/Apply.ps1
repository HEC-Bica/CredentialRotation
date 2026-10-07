# Apply.ps1 - slot sequencing, enforcement phase and exit code of -Apply, account model v10
# (docs/PLAN.md sections 6 steps 6-11, 7.5, 8, D7-D9, D11, D13, D16-D18, D20-D25; docs/dev/CONTRACTS.md
# "Apply.ps1 and the entry point" and "v10: account model").
# Secrets are SecureStrings. They are handed to the building blocks as -Secret/-OldSecret/-NewSecret and are
# never converted, compared, printed or logged here (D4). Findings and logs carry names, steps and error codes only.
# Invoke-CrApply keeps $State current while it works (created users, group changes, enabled/disabled accounts), so
# later steps (auto-logon decision, rails, D25 readiness of the operator account) judge the machine as changed.

#region Helpers

# Credential slots in ascending Order (PLAN 8).
function Get-CrApplySlotDefinitions {
    param($Config)
    $defs = ConvertTo-CrArray $Config['Credentials']
    $sorted = @($defs | Where-Object { $_ -is [hashtable] } | Sort-Object { [int]$_['Order'] })
    return , $sorted
}

function Test-CrApplySlotSelected {
    param([string]$Slot, [string[]]$Only)
    if (-not $Only -or @($Only).Count -eq 0) { return $true }
    return (@($Only) -contains $Slot)
}

function Test-CrApplyOnlyGiven {
    param([string[]]$Only)
    return [bool]($Only -and @($Only).Count -gt 0)
}

function Add-CrApplyFinding {
    param($Context, [string]$Severity, [string]$Area, [string]$Message, [string]$Slot, [string]$Account, [string]$Detail)
    $f = New-CrFinding -Severity $Severity -Area $Area -Message $Message -Slot $Slot -Account $Account -Detail $Detail
    [void]$Context['Findings'].Add($f)
    Write-CrLog ('Apply: {0} | {1} | {2} | {3} | {4} | {5}' -f $f['Severity'], $f['Area'], $f['Slot'], $f['Account'], $f['Message'], $f['Detail'])
}

# Journal writes never stop the run; a failure is reported once (the probe order of a re-run falls back to old-first).
function Add-CrApplyJournalStep {
    param($Context, [string]$Sid, [string]$Step)
    if (-not $Sid) { return }
    try {
        Add-CrJournalStep -Journal $Context['Journal'] -RunId $Context['RunId'] -Sid $Sid -Step $Step
    } catch {
        if (-not $Context['JournalWarned']) {
            $Context['JournalWarned'] = $true
            Add-CrApplyFinding $Context 'Info' 'Journal' 'The run journal could not be written; a re-run tests the old password first' $null $null $_.Exception.Message
        }
    }
}

# Concatenates two values (arrays, scalars or $null) into one flat array.
function Join-CrApplyList {
    param($First, $Second)
    $list = New-Object System.Collections.ArrayList
    foreach ($x in (ConvertTo-CrArray $First)) { [void]$list.Add($x) }
    foreach ($x in (ConvertTo-CrArray $Second)) { [void]$list.Add($x) }
    return , $list.ToArray()
}

function Add-CrApplySid {
    param($List, [string]$Sid)
    if ($Sid -and ($List -notcontains $Sid)) { [void]$List.Add($Sid) }
}

function Find-CrApplyUser {
    param($State, [string]$Sid)
    if (-not $Sid) { return $null }
    foreach ($u in (ConvertTo-CrArray $State['Users'])) {
        if ($u -is [hashtable] -and [string]$u['Sid'] -eq $Sid) { return $u }
    }
    return $null
}

function Find-CrApplyUserByName {
    param($State, [string]$Name)
    if (-not $Name) { return $null }
    foreach ($u in (ConvertTo-CrArray $State['Users'])) {
        if ($u -is [hashtable] -and [string]$u['Name'] -ieq $Name) { return $u }
    }
    return $null
}

# The resolved account (@{ Name; Sid; User }) of an entry with this SID.
function Find-CrApplyResolvedAccount {
    param($Resolved, [string]$Sid)
    foreach ($e in (ConvertTo-CrArray $Resolved)) {
        if (-not ($e -is [hashtable])) { continue }
        foreach ($a in (ConvertTo-CrArray $e['Accounts'])) {
            if ($a -is [hashtable] -and $a['Sid'] -and [string]$a['Sid'] -eq $Sid) { return $a }
        }
    }
    return $null
}

# Rotate-mode Windows entries with a credential slot: the managed accounts (D21).
function Test-CrApplyManagedEntry {
    param($Entry)
    return [bool](($Entry -is [hashtable]) -and $Entry['Kind'] -eq 'Windows' -and $Entry['Mode'] -eq 'Rotate' -and $Entry['Slot'])
}

function Get-CrApplyPasswordMode {
    param($Entry)
    if ([string]$Entry['PasswordMode'] -eq 'Change') { return 'Change' }
    if (($Entry['Config'] -is [hashtable]) -and [string]$Entry['Config']['PasswordMode'] -eq 'Change') { return 'Change' }
    return 'Set'
}

# The display name of an entry's (first) account, also when it is still to be created.
function Get-CrApplyEntryAccountName {
    param($Entry)
    foreach ($a in (ConvertTo-CrArray $Entry['Accounts'])) { if ($a -is [hashtable] -and $a['Name']) { return [string]$a['Name'] } }
    if (($Entry['Config'] -is [hashtable]) -and $Entry['Config']['Name']) { return [string]$Entry['Config']['Name'] }
    return [string]$Entry['Id']
}

function Get-CrApplyEntryAccountSid {
    param($Entry)
    foreach ($a in (ConvertTo-CrArray $Entry['Accounts'])) { if ($a -is [hashtable] -and $a['Sid']) { return [string]$a['Sid'] } }
    return $null
}

# The managed entry that runs the application's dependents (Services/ScheduledTasks/ComPlus = 'Auto'): the target
# for dependents of retired accounts without a replacement when the operator chooses "move" (D24).
function Get-CrApplyAppUserEntry {
    param($Resolved)
    foreach ($e in (ConvertTo-CrArray $Resolved)) {
        if (-not (Test-CrApplyManagedEntry $e)) { continue }
        foreach ($k in @('Services', 'ScheduledTasks', 'ComPlus')) {
            if (Test-CrApplyManaged $e['Config'] $k) { return $e }
        }
    }
    return $null
}

# The operator account (D25): the managed entry that replaces the running account, else the managed entry whose
# role puts it into Administrators and Remote Desktop Users (SOP-Admin).
function Get-CrApplyOperatorEntry {
    param($Resolved, [string]$RunningSid)
    if ($RunningSid) {
        foreach ($e in (ConvertTo-CrArray $Resolved)) {
            if (-not (Test-CrApplyManagedEntry $e)) { continue }
            foreach ($r in (ConvertTo-CrArray $e['Replaced'])) {
                if ($r -is [hashtable] -and [string]$r['Sid'] -eq $RunningSid) { return $e }
            }
        }
    }
    foreach ($e in (ConvertTo-CrArray $Resolved)) {
        if (-not (Test-CrApplyManagedEntry $e)) { continue }
        $groups = @()
        if ($e['Role'] -is [hashtable]) { $groups = ConvertTo-CrArray $e['Role']['Groups'] }
        if (($groups -contains 'S-1-5-32-544') -and ($groups -contains 'S-1-5-32-555')) { return $e }
    }
    return $null
}

function Test-CrApplyManaged {
    param($EntryConfig, [string]$Key)
    return [bool](($EntryConfig -is [hashtable]) -and ([string]$EntryConfig[$Key] -eq 'Auto'))
}

# Dependents of an account, same filters as Plan.ps1 (PLAN 7.3, 7.4, 7.7).
function Get-CrApplyServices {
    param($State, [string]$Sid)
    $all = ConvertTo-CrArray $State['Services']
    $list = @($all | Where-Object { $_ -is [hashtable] -and $Sid -and $_['StartNameSid'] -eq $Sid })
    return , $list
}

# Password-stored scheduled tasks (LogonType 1 = password, 6 = interactive or password).
function Get-CrApplyTasks {
    param($State, [string]$Sid)
    $all = ConvertTo-CrArray $State['Tasks']
    $list = @($all | Where-Object { $_ -is [hashtable] -and $Sid -and $_['UserSid'] -eq $Sid -and (@(1, 6) -contains [int]$_['LogonType']) })
    return , $list
}

# Tasks of the account that store no password (S4U, interactive token, ...): nothing to move, but they stop
# working once the account is disabled.
function Get-CrApplyOtherTasks {
    param($State, [string]$Sid)
    $all = ConvertTo-CrArray $State['Tasks']
    $list = @($all | Where-Object { $_ -is [hashtable] -and $Sid -and $_['UserSid'] -eq $Sid -and (@(1, 6) -notcontains [int]$_['LogonType']) })
    return , $list
}

function Get-CrApplyComPlus {
    param($State, [string]$Sid)
    $all = ConvertTo-CrArray $State['ComPlus']
    $list = @($all | Where-Object { $_ -is [hashtable] -and $Sid -and $_['IdentitySid'] -eq $Sid -and $_['Activation'] -eq 'Server' })
    return , $list
}

function Get-CrApplyItemLabel {
    param($Item)
    if ($Item -is [hashtable]) {
        if ($Item['Name']) { return [string]$Item['Name'] }
        if ($Item['Path']) { return [string]$Item['Path'] }
    }
    return [string]$Item
}

function Get-CrApplyWin32Text {
    param([int]$Code)
    switch ($Code) {
        86 { return ' (the old password is wrong)' }
        1326 { return ' (wrong password)' }
        1327 { return ' (account restriction)' }
        1330 { return ' (password expired)' }
        1331 { return ' (account disabled)' }
        1385 { return ' (logon type not granted)' }
        1909 { return ' (account locked)' }
        2224 { return ' (the account already exists)' }
        2245 { return ' (rejected by the password policy: history, minimum age or complexity)' }
    }
    return ''
}

function Get-CrApplyResultText {
    param($Result, [string]$What)
    $code = 0
    $msg = $null
    if ($Result -is [hashtable]) {
        if ($null -ne $Result['Win32Error']) { $code = [int]$Result['Win32Error'] }
        if ($Result['Message']) { $msg = [string]$Result['Message'] } elseif ($Result['Error']) { $msg = [string]$Result['Error'] }
    } else {
        $msg = 'no result returned'
    }
    $text = '{0} failed' -f $What
    if ($code -ne 0) { $text = '{0} with error {1}{2}' -f $text, $code, (Get-CrApplyWin32Text $code) }
    if ($msg) { $text = '{0}: {1}' -f $text, $msg }
    return $text
}

# D12 before using the old password: re-read the account, refuse when locked or when fewer than two attempts remain.
function Test-CrApplyBudget {
    param($State, [string]$UserName)
    $r = @{ Ok = $false; Locked = $false; Reason = $null }
    $info = Get-CrUserInfo -UserName $UserName
    if (-not ($info -is [hashtable]) -or -not $info['Success']) {
        $code = 0
        if ($info -is [hashtable]) { $code = [int]$info['Win32Error'] }
        $r['Reason'] = 'the account could not be read before the attempt (error {0})' -f $code
        return $r
    }
    if (([int]$info['Flags'] -band 0x10) -ne 0) {
        $r['Locked'] = $true
        $r['Reason'] = 'the account is locked (again)'
        return $r
    }
    # An unknown threshold counts as 3, as in the probe (CONTRACTS "Secrets.ps1").
    $threshold = 3
    $policy = $State['Policy']
    if ($policy -is [hashtable] -and -not $policy['Error'] -and $null -ne $policy['LockoutThreshold']) { $threshold = [int]$policy['LockoutThreshold'] }
    $bad = [int]$info['BadPasswordCount']
    if ($threshold -gt 0 -and ($threshold - $bad) -lt 2) {
        $r['Reason'] = 'lockout budget: {0} of {1} bad attempts already counted (D12)' -f $bad, $threshold
        return $r
    }
    $r['Ok'] = $true
    return $r
}

# Marks the account unlocked in the user record (also the $State entry, which is the same hashtable).
function Set-CrApplyUserUnlocked {
    param($User)
    if (-not ($User -is [hashtable])) { return }
    $User['LockedOut'] = $false
    if ($null -ne $User['Flags']) { $User['Flags'] = ([int]$User['Flags']) -band (-bnot 0x10) }
}

function Set-CrApplyUserDisabled {
    param($User, [bool]$Disabled)
    if (-not ($User -is [hashtable])) { return }
    $User['Disabled'] = $Disabled
    if ($null -ne $User['Flags']) {
        if ($Disabled) { $User['Flags'] = ([int]$User['Flags']) -bor 0x2 } else { $User['Flags'] = ([int]$User['Flags']) -band (-bnot 0x2) }
    }
}

# Keeps $State.Groups in line with a group change that succeeded.
function Set-CrApplyStateMembership {
    param($State, [string]$GroupSid, [string]$MemberSid, [bool]$Member)
    foreach ($g in (ConvertTo-CrArray $State['Groups'])) {
        if (-not ($g -is [hashtable]) -or [string]$g['Sid'] -ne $GroupSid) { continue }
        $list = New-Object System.Collections.ArrayList
        foreach ($m in (ConvertTo-CrArray $g['MemberSids'])) { if ([string]$m -ne $MemberSid) { [void]$list.Add([string]$m) } }
        if ($Member) { [void]$list.Add($MemberSid) }
        $g['MemberSids'] = $list.ToArray()
    }
}

function Get-CrApplyGroupMembers {
    param($State, [string]$GroupSid)
    foreach ($g in (ConvertTo-CrArray $State['Groups'])) {
        if ($g -is [hashtable] -and [string]$g['Sid'] -eq $GroupSid) {
            $members = ConvertTo-CrArray $g['MemberSids']
            return , $members
        }
    }
    return , @()
}

# A user record for an account created in this run (CONTRACTS "Users"), added to $State.Users.
function Add-CrApplyCreatedUser {
    param($State, [string]$Name, [string]$Sid)
    $flags = 0x10241
    $info = $null
    try { $info = Get-CrUserInfo -UserName $Name } catch { $info = $null }
    if ($info -is [hashtable] -and $info['Success'] -and $null -ne $info['Flags']) { $flags = [int]$info['Flags'] }
    $rid = $null
    if ($Sid -match '-(\d+)$') { $rid = [int]$matches[1] }
    $user = @{
        Name = $Name; Sid = $Sid; Rid = $rid; FullName = ''; Flags = $flags; Disabled = (($flags -band 0x2) -ne 0)
        LockedOut = (($flags -band 0x10) -ne 0); PasswordNeverExpires = (($flags -band 0x10000) -ne 0)
        CannotChangePassword = (($flags -band 0x40) -ne 0); PasswordNotRequired = (($flags -band 0x20) -ne 0)
        PasswordAgeSeconds = 0; BadPasswordCount = 0
    }
    $list = New-Object System.Collections.ArrayList
    foreach ($u in (ConvertTo-CrArray $State['Users'])) { [void]$list.Add($u) }
    [void]$list.Add($user)
    $State['Users'] = $list.ToArray()
    return $user
}

# Logon test with the logon type of D16 (Select-CrProbeLogonType on the current $State). A type that is not
# clearly allowed, 1385, 1327 and 1331 prove nothing about the password: Skipped (Info, not a failure).
function Invoke-CrApplyLogonTest {
    param($Context, $Item, [System.Security.SecureString]$Secret)
    $r = @{ Ok = $false; Skipped = $false; Failed = $false; Message = $null }
    $sel = Select-CrProbeLogonType -UserSid $Item['Sid'] -State $Context['State']
    $type = $null
    if ($sel -is [hashtable] -and -not $sel['Fallback'] -and $sel['LogonType'] -and [string]$sel['LogonType'] -ne 'Unverifiable') { $type = [string]$sel['LogonType'] }
    if (-not $type) {
        $r['Skipped'] = $true
        $r['Message'] = 'No logon type is clearly allowed for this account (D16); the new password could not be verified with a logon'
        return $r
    }
    $t = Invoke-CrLogonTest -UserName $Item['UserName'] -Secret $Secret -LogonType $type
    if ($t -is [hashtable] -and $t['Success']) {
        $r['Ok'] = $true
        $r['Message'] = 'Logon with the new password verified ({0})' -f $type
        return $r
    }
    $code = 0
    if ($t -is [hashtable]) { $code = [int]$t['Win32Error'] }
    if (@(1385, 1327, 1331) -contains $code) {
        $r['Skipped'] = $true
        $r['Message'] = 'Logon type {0} refused with error {1}{2}; the new password could not be verified with a logon' -f $type, $code, (Get-CrApplyWin32Text $code)
        return $r
    }
    $r['Failed'] = $true
    $r['Message'] = 'logon test ({0}) failed with error {1}{2}' -f $type, $code, (Get-CrApplyWin32Text $code)
    return $r
}

function Test-CrApplyRightDenied {
    param($State, [string]$Sid, [string]$LogonType, [string]$DenyRight)
    $map = $State['Rights']
    if (-not ($map -is [hashtable])) { return $false }
    $token = Get-CrTokenSids -UserSid $Sid -State $State -LogonType $LogonType
    foreach ($s in (ConvertTo-CrArray $map[$DenyRight])) {
        if ((ConvertTo-CrArray $token) -contains $s) { return $true }
    }
    return $false
}

# Rights that services / password-stored tasks running as $Sid need and the account doesn't have (PLAN 7.3).
# Denied rights are never granted: returned in Denied. Returns @{ Need = @(); Denied = @() }.
function Get-CrApplyNeededRights {
    param($State, [string]$Sid, [int]$ServiceCount, [int]$TaskCount)
    $need = New-Object System.Collections.ArrayList
    $denied = New-Object System.Collections.ArrayList
    if ($ServiceCount -eq 0 -and $TaskCount -eq 0) { return @{ Need = @(); Denied = @() } }
    $eff = Get-CrEffectiveLogonRights -UserSid $Sid -State $State
    if ($ServiceCount -gt 0 -and -not $eff['Service']) {
        if (Test-CrApplyRightDenied -State $State -Sid $Sid -LogonType 'Service' -DenyRight 'SeDenyServiceLogonRight') {
            [void]$denied.Add('SeServiceLogonRight')
        } else {
            [void]$need.Add('SeServiceLogonRight')
        }
    }
    if ($TaskCount -gt 0 -and -not $eff['Batch']) {
        if (Test-CrApplyRightDenied -State $State -Sid $Sid -LogonType 'Batch' -DenyRight 'SeDenyBatchLogonRight') {
            [void]$denied.Add('SeBatchLogonRight')
        } else {
            [void]$need.Add('SeBatchLogonRight')
        }
    }
    return @{ Need = $need.ToArray(); Denied = $denied.ToArray() }
}

# Grants rights (adds only). Returns an array of error texts.
function Invoke-CrApplyGrantRights {
    param($Context, [string]$Sid, [string]$Name, [string[]]$Rights, [string]$Slot, [string]$Why)
    $errors = New-Object System.Collections.ArrayList
    if (@($Rights).Count -eq 0) { return , $errors.ToArray() }
    foreach ($res in (ConvertTo-CrArray (Grant-CrDependentRights -Sid $Sid -Rights $Rights))) {
        if (-not ($res -is [hashtable])) { continue }
        if ($res['Success']) {
            Add-CrApplyFinding $Context 'Info' 'Rights' ('Granted ' + $res['Right'] + ' (' + $Why + ')') $Slot $Name
        } else {
            [void]$errors.Add(('{0}: {1}' -f $Name, (Get-CrApplyResultText $res ('Granting ' + $res['Right']))))
        }
    }
    return , $errors.ToArray()
}

# Rail (PLAN 7.2): Administrators keeps at least one enabled member that is the running account or was verified in
# this run. Returns the reason a removal from Administrators (or a disable of an admin) is refused, or $null.
# -RunningCounts:$false when the running account itself is about to be disabled (D25).
function Get-CrApplyAdminRailReason {
    param($Context, [string]$RemoveSid, [bool]$RunningCounts = $true)
    $admins = Get-CrApplyGroupMembers -State $Context['State'] -GroupSid 'S-1-5-32-544'
    if ($admins -notcontains $RemoveSid) { return $null }
    foreach ($s in $admins) {
        if ($s -eq $RemoveSid) { continue }
        $isRunning = ($s -eq $Context['RunningSid'])
        if ($isRunning -and -not $RunningCounts) { continue }
        $isAnchor = $isRunning -or ($Context['Verified'] -contains $s)
        if (-not $isAnchor) { continue }
        $u = Find-CrApplyUser -State $Context['State'] -Sid $s
        if (-not $u -and $isRunning) { return $null }
        if ($u -and -not $u['Disabled']) { return $null }
    }
    return 'Administrators would keep no enabled member that is the running account or verified in this run'
}

# Group adds and removals of one account, rails applied to removals; keeps $State.Groups and RemovedAdmins current.
# Returns @{ Errors = @(); Pending = @() }.
function Invoke-CrApplyGroupChange {
    param($Context, [string]$Sid, [string]$Name, [string[]]$RemoveGroupSids, [string[]]$AddGroupSids, [string]$Slot)
    $out = @{ Errors = @(); Pending = @() }
    $errors = New-Object System.Collections.ArrayList
    $pending = New-Object System.Collections.ArrayList
    $remove = New-Object System.Collections.ArrayList
    foreach ($g in (ConvertTo-CrArray $RemoveGroupSids)) {
        if ($g -eq 'S-1-5-32-544') {
            $why = $null
            if ($Sid -eq $Context['RunningSid']) { $why = 'it is the running account' } else { $why = Get-CrApplyAdminRailReason -Context $Context -RemoveSid $Sid }
            if ($why) {
                Add-CrApplyFinding $Context 'Info' 'Groups' ('Rail: stays in Administrators: ' + $why) $Slot $Name
                continue
            }
        }
        [void]$remove.Add($g)
    }
    $add = ConvertTo-CrArray $AddGroupSids
    if ($remove.Count -eq 0 -and $add.Count -eq 0) { return $out }
    try {
        $results = ConvertTo-CrArray (Invoke-CrGroupMembershipChange -State $Context['State'] -MemberSid $Sid -AddGroupSids $add -RemoveGroupSids ($remove.ToArray()))
        foreach ($res in $results) {
            if (-not ($res -is [hashtable])) { continue }
            $gname = [string]$res['GroupName']
            if (-not $gname) { $gname = [string]$res['GroupSid'] }
            $isRemove = ($res['Action'] -eq 'Remove')
            $verb = 'Added to '
            if ($isRemove) { $verb = 'Removed from ' }
            if ($res['Success']) {
                Add-CrApplyFinding $Context 'Info' 'Groups' ($verb + $gname) $Slot $Name
                Set-CrApplyStateMembership -State $Context['State'] -GroupSid ([string]$res['GroupSid']) -MemberSid $Sid -Member (-not $isRemove)
                if ($isRemove -and $res['GroupSid'] -eq 'S-1-5-32-544') { Add-CrApplySid $Context['RemovedAdmins'] $Sid }
            } else {
                [void]$errors.Add(('{0}: {1}' -f $Name, (Get-CrApplyResultText $res ($verb + $gname))))
                [void]$pending.Add(('{0}: {1}{2}' -f $Name, $verb, $gname))
            }
        }
    } catch {
        [void]$errors.Add(('{0}: group change failed: {1}' -f $Name, $_.Exception.Message))
        [void]$pending.Add(('{0}: group changes' -f $Name))
    }
    $out['Errors'] = $errors.ToArray()
    $out['Pending'] = $pending.ToArray()
    return $out
}

function Copy-CrApplyDecision {
    param($Decision, [string]$Action)
    $c = @{}
    foreach ($k in @($Decision.Keys)) { $c[$k] = $Decision[$k] }
    $c['Action'] = $Action
    return $c
}

# The slot of the entry that carries the AutoLogon block (PUB-User, PLAN 5).
function Get-CrApplyAutoLogonSlot {
    param($Resolved)
    foreach ($e in (ConvertTo-CrArray $Resolved)) {
        if ($e -is [hashtable] -and $e['AutoLogon'] -and $e['Slot']) { return [string]$e['Slot'] }
    }
    return $null
}

# PLAN 7.5 "When": without -Only always; under -Only when the auto-logon slot is selected, or the current auto-logon
# account is managed or replaced by a selected slot (it changes or is disabled in this run).
function Test-CrApplyAutoLogonSelected {
    param($State, $Resolved, [string[]]$Only)
    if (-not (Test-CrApplyOnlyGiven $Only)) { return $true }
    $alSlot = Get-CrApplyAutoLogonSlot -Resolved $Resolved
    if ($alSlot -and (Test-CrApplySlotSelected -Slot $alSlot -Only $Only)) { return $true }
    $al = $State['AutoLogon']
    if (-not ($al -is [hashtable]) -or -not $al['DefaultUserName']) { return $false }
    $current = Find-CrApplyUserByName -State $State -Name ([string]$al['DefaultUserName'])
    if (-not $current) { return $false }
    foreach ($e in (ConvertTo-CrArray $Resolved)) {
        if (-not (Test-CrApplyManagedEntry $e)) { continue }
        if (-not (Test-CrApplySlotSelected -Slot ([string]$e['Slot']) -Only $Only)) { continue }
        foreach ($a in (Join-CrApplyList $e['Accounts'] $e['Replaced'])) {
            if ($a -is [hashtable] -and $a['Sid'] -and [string]$a['Sid'] -eq [string]$current['Sid']) { return $true }
        }
    }
    return $false
}

#endregion

#region Plan of the apply (shared by the summary before YES and Invoke-CrApply)

# Path of one Change-mode account (ApplicationUser) from its probe outcome and the operator's choice
# (PLAN 6 step 7, 8; D9, D11, D20). Returns @{ Path ('Change'|'Set'|'Reapply'|'New'|'Skip'); Unlock; Reason }.
function Get-CrApplyAccountPath {
    param($Probe, $SecretAccount)
    $r = @{ Path = 'Skip'; Unlock = $false; Reason = $null }
    if (-not ($SecretAccount -is [hashtable])) { $r['Reason'] = 'No password was entered for this account'; return $r }
    if (-not ($Probe -is [hashtable])) { $r['Reason'] = 'The account was not probed'; return $r }
    $reapply = [bool]$SecretAccount['Reapply']
    $outcome = [string]$Probe['Outcome']
    $choice = [string]$Probe['Path']
    if ($choice -eq 'Skip') { $r['Reason'] = 'Skipped by the operator'; return $r }
    if ($choice -eq 'Set' -or $choice -eq 'Reset') {
        $r['Path'] = 'Set'
        return $r
    }
    if ($outcome -eq 'Old') {
        if ($reapply) { $r['Path'] = 'Reapply' } else { $r['Path'] = 'Change' }
    } elseif ($outcome -eq 'Reapply') {
        $r['Path'] = 'Reapply'
    } elseif ($outcome -eq 'New') {
        $r['Path'] = 'New'
    } elseif ($outcome -eq 'Unverifiable') {
        if ($reapply) {
            $r['Reason'] = 'Re-apply cannot be verified: no logon type is allowed for this account (D16)'
        } else {
            # NetUserChangePassword validates the old password itself (one more budgeted attempt).
            $r['Path'] = 'Change'
        }
    } elseif ($outcome -eq 'Locked') {
        $r['Unlock'] = $true
        if ($reapply) { $r['Path'] = 'Reapply' } else { $r['Path'] = 'Change' }
    } elseif ($outcome -eq 'BothFailed') {
        $r['Reason'] = 'Neither the old nor the new password works and setting the password was not chosen'
    } elseif ($outcome -eq 'BudgetExceeded') {
        $r['Reason'] = 'Lockout budget exhausted (D12); no attempt was made and setting the password was not chosen'
    } elseif ($outcome -eq 'Disabled') {
        $r['Reason'] = 'The account is disabled: a change is impossible and setting the password was not chosen'
    } else {
        $r['Reason'] = 'Unknown probe outcome: ' + $outcome
    }
    return $r
}

function Get-CrApplyPathText {
    param($Account)
    $p = [string]$Account['Path']
    $text = $p
    if ($p -eq 'Create') { $text = 'Create (with the slot password, role groups and flags, D21)' }
    elseif ($p -eq 'Set') {
        $text = 'Set the password (D9)'
        if ($Account['PasswordMode'] -eq 'Change') { $text = 'Set the password (DPAPI-protected data of the account is lost)' }
    }
    elseif ($p -eq 'Change') { $text = 'Change (old password validated, DPAPI kept)' }
    elseif ($p -eq 'Reapply') { $text = 'Re-apply: password unchanged (D20)' }
    elseif ($p -eq 'New') { $text = 'Already on the new password (D11)' }
    elseif ($p -eq 'Skip') { $text = 'Skip: ' + $Account['Reason'] }
    if ($Account['Unlock']) { $text = 'Unlock, then ' + $text }
    if ($Account['Enable']) { $text = $text + '; enable the account' }
    return $text
}

# The secret entry (Read-CrSlotSecrets) of an account: by SID, or by name for an account that doesn't exist yet.
function Find-CrApplySecretAccount {
    param($SlotSecret, [string]$Sid, [string]$Name)
    if (-not ($SlotSecret -is [hashtable])) { return $null }
    foreach ($x in (ConvertTo-CrArray $SlotSecret['Accounts'])) {
        if (-not ($x -is [hashtable])) { continue }
        if ($Sid -and $x['Sid'] -and [string]$x['Sid'] -eq $Sid) { return $x }
    }
    foreach ($x in (ConvertTo-CrArray $SlotSecret['Accounts'])) {
        if (-not ($x -is [hashtable])) { continue }
        if ($Name -and [string]$x['Name'] -ieq $Name) { return $x }
    }
    return $null
}

# One entry per selected slot in ascending Order:
# @{ Slot; Order; Label; Status ('Apply'|'Blocked'|'NotApplicable'|'Skipped'); Reason;
#    Accounts = @(@{ Name; Sid; UserName; User; Entry; PasswordMode; Probe; Outcome; SecretAccount; Path; Unlock; Enable; Reason }) }.
# Path: 'Create' (missing account, D21), 'Set' (D9), or for Change accounts the probe path. Not logged: the
# SecretAccount references hold SecureStrings.
function Get-CrApplyPreview {
    param($Config, $Resolved, $Preflight, $SlotSecrets, $Probes, [string[]]$Only)
    $blocked = @{}
    if ($Preflight -is [hashtable] -and $Preflight['BlockedSlots'] -is [hashtable]) { $blocked = $Preflight['BlockedSlots'] }
    if (-not ($SlotSecrets -is [hashtable])) { $SlotSecrets = @{} }
    if (-not ($Probes -is [hashtable])) { $Probes = @{} }
    $list = New-Object System.Collections.ArrayList
    foreach ($def in (Get-CrApplySlotDefinitions -Config $Config)) {
        $slot = [string]$def['Slot']
        if (-not (Test-CrApplySlotSelected -Slot $slot -Only $Only)) { continue }
        $p = @{ Slot = $slot; Order = $def['Order']; Label = $def['Label']; Status = 'Apply'; Reason = $null; Accounts = @() }
        [void]$list.Add($p)

        $entries = New-Object System.Collections.ArrayList
        foreach ($e in (ConvertTo-CrArray $Resolved)) {
            if ($e -is [hashtable] -and [string]$e['Slot'] -eq $slot -and $e['Mode'] -eq 'Rotate') { [void]$entries.Add($e) }
        }
        $isSql = $false
        $hasError = $false
        $applicable = New-Object System.Collections.ArrayList
        foreach ($e in $entries) {
            if ($e['Kind'] -eq 'SqlLogin') { $isSql = $true }
            if ($e['Error']) { $hasError = $true }
            if (-not $e['NotApplicable'] -or $e['Create']) { [void]$applicable.Add($e) }
        }
        if ($isSql) { $p['Status'] = 'Skipped'; $p['Reason'] = 'SQL rotation is not available in this version'; continue }
        if ($blocked.ContainsKey($slot)) { $p['Status'] = 'Blocked'; $p['Reason'] = [string]$blocked[$slot]; continue }
        if ($hasError) { $p['Status'] = 'Blocked'; $p['Reason'] = 'Account data could not be read'; continue }
        if ($applicable.Count -eq 0) { $p['Status'] = 'NotApplicable'; $p['Reason'] = 'No account of this slot exists on this machine'; continue }
        $slotSecret = $SlotSecrets[$slot]
        if (-not ($slotSecret -is [hashtable]) -or $slotSecret['Skipped']) {
            $p['Status'] = 'Skipped'
            $p['Reason'] = 'No new password entered (skipped by the operator)'
            if ($slotSecret -is [hashtable] -and $slotSecret['Reason']) { $p['Reason'] = [string]$slotSecret['Reason'] }
            continue
        }

        $accounts = New-Object System.Collections.ArrayList
        foreach ($e in $applicable) {
            $mode = Get-CrApplyPasswordMode $e
            foreach ($acct in (ConvertTo-CrArray $e['Accounts'])) {
                if (-not ($acct -is [hashtable])) { continue }
                $sid = [string]$acct['Sid']
                $user = $acct['User']
                $userName = [string]$acct['Name']
                if ($user -is [hashtable] -and $user['Name']) { $userName = [string]$user['Name'] }
                $sa = Find-CrApplySecretAccount -SlotSecret $slotSecret -Sid $sid -Name $userName
                $probe = $null
                if ($sid) { $probe = $Probes[$sid] }
                $toCreate = [bool]($acct['ToCreate'] -or (-not $sid -and $e['Create']))
                $path = @{ Path = 'Set'; Unlock = $false; Reason = $null }
                if ($toCreate) {
                    $path['Path'] = 'Create'
                } elseif (-not $sid) {
                    $path = @{ Path = 'Skip'; Unlock = $false; Reason = 'The account does not exist and is not created by the configuration' }
                } elseif ($mode -eq 'Change') {
                    $path = Get-CrApplyAccountPath -Probe $probe -SecretAccount $sa
                }
                $enable = [bool](-not $toCreate -and ($user -is [hashtable]) -and $user['Disabled'] -and $path['Path'] -ne 'Skip')
                $outcome = $null
                if ($probe -is [hashtable]) { $outcome = [string]$probe['Outcome'] }
                [void]$accounts.Add(@{
                    Name = [string]$acct['Name']; Sid = $sid; UserName = $userName; User = $user; Entry = $e; PasswordMode = $mode
                    Probe = $probe; Outcome = $outcome; SecretAccount = $sa; Path = $path['Path']; Unlock = $path['Unlock']
                    Enable = $enable; Reason = $path['Reason']
                })
            }
        }
        $p['Accounts'] = $accounts.ToArray()
        $active = @($accounts | Where-Object { $_['Path'] -ne 'Skip' })
        if ($active.Count -eq 0) { $p['Status'] = 'Skipped'; $p['Reason'] = 'Every account of the slot is skipped' }
    }
    return , $list.ToArray()
}

function Find-CrApplyPreviewSlot {
    param($Preview, [string]$Slot)
    foreach ($p in (ConvertTo-CrArray $Preview)) { if ($p -is [hashtable] -and [string]$p['Slot'] -eq $Slot) { return $p } }
    return $null
}

# Accounts this run disables (D22-D25) and what blocks it. One item per account:
# @{ Sid; Name; User; Kind ('Replaced'|'Disable'|'Other'); IsRunning; ReplacementEntry; ReplacementName; ReplacementSlot;
#    Services; Tasks; ComPlus; OtherTasks; HasDependents; NeedsDecision; Decision ('Move'|'Keep'|$null);
#    MoveEntry (where the dependents go); Planned ($true = disabled if the conditions hold at the time); Reason }.
# Replaced accounts only for selected slots; Disable entries and operator-chosen others (D23) only without -Only.
# Dependents of an account without replacement move to the application account only on the operator's 'Move' (D24).
function Get-CrApplyDisablePlan {
    param($State, $Resolved, $Preview, [string]$RunningSid, [string[]]$Only, $OtherDecisions, $DependentDecisions)
    if (-not ($OtherDecisions -is [hashtable])) { $OtherDecisions = @{} }
    if (-not ($DependentDecisions -is [hashtable])) { $DependentDecisions = @{} }
    $items = New-Object System.Collections.ArrayList
    $seen = New-Object System.Collections.ArrayList
    $appEntry = Get-CrApplyAppUserEntry -Resolved $Resolved
    $onlyGiven = Test-CrApplyOnlyGiven $Only

    $candidates = New-Object System.Collections.ArrayList
    foreach ($e in (ConvertTo-CrArray $Resolved)) {
        if (-not (Test-CrApplyManagedEntry $e)) { continue }
        if (-not (Test-CrApplySlotSelected -Slot ([string]$e['Slot']) -Only $Only)) { continue }
        foreach ($r in (ConvertTo-CrArray $e['Replaced'])) {
            if (-not ($r -is [hashtable]) -or -not $r['Sid']) { continue }
            [void]$candidates.Add(@{ Kind = 'Replaced'; Sid = [string]$r['Sid']; Name = [string]$r['Name']; User = $r['User']; Enabled = $r['Enabled']; Entry = $e })
        }
    }
    if (-not $onlyGiven) {
        foreach ($e in (ConvertTo-CrArray $Resolved)) {
            if (-not ($e -is [hashtable]) -or $e['Mode'] -ne 'Disable' -or $e['Kind'] -ne 'Windows') { continue }
            foreach ($a in (ConvertTo-CrArray $e['Accounts'])) {
                if (-not ($a -is [hashtable]) -or -not $a['Sid']) { continue }
                [void]$candidates.Add(@{ Kind = 'Disable'; Sid = [string]$a['Sid']; Name = [string]$a['Name']; User = $a['User']; Enabled = $null; Entry = $e })
            }
        }
        foreach ($k in @($OtherDecisions.Keys)) {
            $u = Find-CrApplyUser -State $State -Sid ([string]$k)
            if (-not $u) { continue }
            [void]$candidates.Add(@{ Kind = 'Other'; Sid = [string]$k; Name = [string]$u['Name']; User = $u; Enabled = $null; Entry = $null; Choice = [string]$OtherDecisions[$k] })
        }
    }

    foreach ($c in $candidates) {
        $sid = $c['Sid']
        if ($seen -contains $sid) { continue }
        [void]$seen.Add($sid)
        $user = Find-CrApplyUser -State $State -Sid $sid
        if (-not $user) { $user = $c['User'] }
        if (-not ($user -is [hashtable])) { continue }
        if ($user['Disabled'] -or $c['Enabled'] -eq $false) { continue }
        $name = [string]$user['Name']
        $services = Get-CrApplyServices -State $State -Sid $sid
        $tasks = Get-CrApplyTasks -State $State -Sid $sid
        $complus = Get-CrApplyComPlus -State $State -Sid $sid
        $otherTasks = Get-CrApplyOtherTasks -State $State -Sid $sid
        $hasDeps = ($services.Count + $tasks.Count + $complus.Count) -gt 0
        $item = @{
            Sid = $sid; Name = $name; User = $user; Kind = $c['Kind']; IsRunning = ($sid -eq $RunningSid)
            ReplacementEntry = $null; ReplacementName = $null; ReplacementSlot = $null
            Services = $services; Tasks = $tasks; ComPlus = $complus; OtherTasks = $otherTasks; HasDependents = $hasDeps
            NeedsDecision = $false; Decision = $null; MoveEntry = $null; Planned = $true; Reason = $null
        }
        if ($c['Kind'] -eq 'Replaced') {
            $e = $c['Entry']
            $item['ReplacementEntry'] = $e
            $item['ReplacementName'] = Get-CrApplyEntryAccountName $e
            $item['ReplacementSlot'] = [string]$e['Slot']
            $item['MoveEntry'] = $e
            $p = Find-CrApplyPreviewSlot -Preview $Preview -Slot ([string]$e['Slot'])
            if ($p -and $p['Status'] -ne 'Apply') {
                $item['Planned'] = $false
                $item['Reason'] = 'stays enabled: the slot of its replacement {0} is {1} ({2})' -f $item['ReplacementName'], $p['Status'], $p['Reason']
            } elseif ($p) {
                foreach ($a in (ConvertTo-CrArray $p['Accounts'])) {
                    if ($a['Path'] -eq 'Skip') {
                        $item['Planned'] = $false
                        $item['Reason'] = 'stays enabled: its replacement {0} is skipped ({1})' -f $a['Name'], $a['Reason']
                    }
                }
            }
        } else {
            if ($c['Kind'] -eq 'Other' -and $c['Choice'] -ne 'Disable') {
                $item['Planned'] = $false
                $item['Reason'] = 'kept enabled by the operator (D23)'
            } elseif ($hasDeps) {
                $item['NeedsDecision'] = $true
                $item['Decision'] = $DependentDecisions[$sid]
                if ($item['Decision'] -eq 'Move' -and $appEntry) {
                    $item['MoveEntry'] = $appEntry
                } else {
                    $item['Planned'] = $false
                    $item['Reason'] = 'kept enabled: it runs services, scheduled tasks or COM+ applications and moving them was not chosen (D24)'
                    if (-not $item['Decision']) { $item['Reason'] = 'operator decision needed: move its dependents to the application account or keep the account enabled (D24)' }
                }
            }
        }
        [void]$items.Add($item)
    }
    return , $items.ToArray()
}

# What happens to each enabled local account (D21), for the list shown before the prompts.
# Returns an array of @{ Name; Sid; Fate ('keep'|'set'|'change'|'disable'|'ask'); Detail }, followed by the accounts
# to be created (Fate 'create', Sid $null).
function Get-CrApplyAccountFates {
    param($State, $Resolved, [string]$RunningSid, [string[]]$Only, $Others)
    $onlyGiven = Test-CrApplyOnlyGiven $Only
    $otherSids = New-Object System.Collections.ArrayList
    foreach ($o in (ConvertTo-CrArray $Others)) { if ($o -is [hashtable] -and $o['Sid']) { [void]$otherSids.Add([string]$o['Sid']) } }
    $fates = New-Object System.Collections.ArrayList
    foreach ($u in (ConvertTo-CrArray $State['Users'])) {
        if (-not ($u -is [hashtable]) -or $u['Disabled']) { continue }
        $sid = [string]$u['Sid']
        $fate = 'keep'
        $detail = 'not managed by the tool'
        $found = $false
        foreach ($e in (ConvertTo-CrArray $Resolved)) {
            if ($found -or -not ($e -is [hashtable]) -or $e['Kind'] -ne 'Windows') { continue }
            $inAccounts = $false
            foreach ($a in (ConvertTo-CrArray $e['Accounts'])) { if ($a -is [hashtable] -and [string]$a['Sid'] -eq $sid) { $inAccounts = $true } }
            if ($inAccounts) {
                $found = $true
                if ($e['Mode'] -eq 'Check') {
                    $fate = 'keep'; $detail = 'check mode: flags and groups are fixed, the password is not touched'
                    if ($onlyGiven) { $detail = 'check mode, not processed under -Only' }
                } elseif ($e['Mode'] -eq 'Disable') {
                    $fate = 'disable'; $detail = 'retired without replacement (D22)'
                    if ($onlyGiven) { $fate = 'keep'; $detail = 'retired account, not processed under -Only' }
                } elseif (Test-CrApplyManagedEntry $e) {
                    if (-not (Test-CrApplySlotSelected -Slot ([string]$e['Slot']) -Only $Only)) {
                        $fate = 'keep'; $detail = 'slot ' + $e['Slot'] + ' not selected'
                    } elseif ((Get-CrApplyPasswordMode $e) -eq 'Change') {
                        $fate = 'change'; $detail = 'managed account (slot ' + $e['Slot'] + '): password changed with its old password (D9)'
                    } else {
                        $fate = 'set'; $detail = 'managed account (slot ' + $e['Slot'] + '): password set (D9)'
                    }
                }
                continue
            }
            if (Test-CrApplyManagedEntry $e) {
                foreach ($r in (ConvertTo-CrArray $e['Replaced'])) {
                    if ($found -or -not ($r -is [hashtable]) -or [string]$r['Sid'] -ne $sid) { continue }
                    $found = $true
                    if (Test-CrApplySlotSelected -Slot ([string]$e['Slot']) -Only $Only) {
                        $fate = 'disable'
                        $detail = 'replaced by ' + (Get-CrApplyEntryAccountName $e) + ' (D22); its dependents move there (D24)'
                        if ($sid -eq $RunningSid) { $detail = $detail + '; your own account, disabled last (D25)' }
                    } else {
                        $fate = 'keep'; $detail = 'replaced by ' + (Get-CrApplyEntryAccountName $e) + ', slot ' + $e['Slot'] + ' not selected'
                    }
                }
            }
        }
        if (-not $found -and ($otherSids -contains $sid)) {
            if ($onlyGiven) { $fate = 'keep'; $detail = 'other account, not processed under -Only' } else { $fate = 'ask'; $detail = 'other account: you decide, disable or keep (D23)' }
        }
        if ($sid -eq $RunningSid -and $fate -eq 'keep' -and -not $found) { $detail = 'your own account' }
        [void]$fates.Add(@{ Name = [string]$u['Name']; Sid = $sid; Fate = $fate; Detail = $detail })
    }
    foreach ($e in (ConvertTo-CrArray $Resolved)) {
        if (-not (Test-CrApplyManagedEntry $e) -or -not $e['Create']) { continue }
        if (-not (Test-CrApplySlotSelected -Slot ([string]$e['Slot']) -Only $Only)) { continue }
        foreach ($a in (ConvertTo-CrArray $e['Accounts'])) {
            if (-not ($a -is [hashtable]) -or $a['Sid']) { continue }
            [void]$fates.Add(@{ Name = [string]$a['Name']; Sid = $null; Fate = 'create'; Detail = 'missing: created with the password of slot ' + $e['Slot'] + ' (D21)' })
        }
    }
    return , $fates.ToArray()
}

#endregion

#region Slot steps (PLAN 8, v10: create -> set/change -> enable -> grants -> own dependents -> verify)

# Marks the slot failed at $Step and lists what is done and pending per account.
function Stop-CrApplySlot {
    param($Context, $Result, $Items, [string]$Step, $Errors)
    $Result['Status'] = 'Failed'
    $Result['FailedStep'] = $Step
    $all = New-Object System.Collections.ArrayList
    foreach ($e in (ConvertTo-CrArray $Result['Errors'])) { [void]$all.Add($e) }
    foreach ($e in $Errors) { [void]$all.Add($e) }
    $Result['Errors'] = $all.ToArray()
    $pending = New-Object System.Collections.ArrayList
    foreach ($p in (ConvertTo-CrArray $Result['Pending'])) { [void]$pending.Add($p) }
    foreach ($it in $Items) {
        $left = New-Object System.Collections.ArrayList
        foreach ($s in $it['Steps']) { if ($it['DoneSteps'] -notcontains $s) { [void]$left.Add($s) } }
        if ($left.Count -gt 0) { [void]$pending.Add(('{0}: {1}' -f $it['Name'], (($left.ToArray()) -join ', '))) }
    }
    $Result['Pending'] = $pending.ToArray()
    $detail = 'Errors: ' + (($all.ToArray()) -join ' | ')
    if ($pending.Count -gt 0) { $detail = $detail + ' -- Pending: ' + (($pending.ToArray()) -join ' | ') }
    Add-CrApplyFinding $Context 'Blocked' 'Apply' ('Slot stopped at step ' + $Step + '; the other slots continue. Re-run with the same passwords to complete it.') $Result['Slot'] $null $detail
}

# Step 0: create the missing account (D21) with the slot password; it is then on the new secret.
function Invoke-CrApplyCreateStep {
    param($Context, $Item, [System.Security.SecureString]$NewSecret, [string]$Slot, $Errors)
    $name = [string]$Item['Name']
    Write-Host ('  {0}: create account ...' -f $name)
    $comment = 'Managed by CredentialRotation (' + [string]$Item['Entry']['Id'] + ')'
    $res = New-CrManagedAccount -Name $name -Secret $NewSecret -Comment $comment -Journal $Context['Journal'] -RunId $Context['RunId']
    if ($res -is [hashtable]) {
        foreach ($w in (ConvertTo-CrArray $res['Warnings'])) { if ($w) { Add-CrApplyFinding $Context 'Info' 'Accounts' ([string]$w) $Slot $name } }
    }
    if (-not ($res -is [hashtable]) -or -not $res['Success']) {
        [void]$Errors.Add(('{0}: {1}' -f $name, (Get-CrApplyResultText $res 'Creating the account')))
        return
    }
    $sid = $null
    if ($res['Sid']) { $sid = [string]$res['Sid'] } else { $sid = Resolve-CrNameToSid -Name $name }
    if (-not $sid) {
        [void]$Errors.Add(('{0}: the account was created, but its SID could not be resolved; re-run to complete it' -f $name))
        return
    }
    $user = Add-CrApplyCreatedUser -State $Context['State'] -Name $name -Sid $sid
    $Item['Sid'] = $sid
    $Item['User'] = $user
    $Item['UserName'] = $name
    $Context['EntrySids'][[string]$Item['Entry']['Id']] = $sid
    $Context['SlotOfSid'][$sid] = $Slot
    Add-CrApplySid $Context['Created'] $sid
    Add-CrApplySid $Context['Changed'] $sid
    Add-CrApplySid $Context['OnNew'] $sid
    # 'Secret': a re-run after a crash tests the new password first (the account never had another one).
    Add-CrApplyJournalStep $Context $sid 'Secret'
    [void]$Item['DoneSteps'].Add('Create')
    Add-CrApplyFinding $Context 'Info' 'Accounts' 'Account created with the slot password (D21)' $Slot $name
}

# Steps for the accounts of one slot. Modifies $Result; returns nothing.
function Invoke-CrApplySlotSteps {
    param($Context, $Result, $Items, [System.Security.SecureString]$NewSecret)
    $State = $Context['State']
    $slot = $Result['Slot']
    $errors = New-Object System.Collections.ArrayList

    # 0 create (D21). Stops at the first failure.
    foreach ($it in $Items) {
        if ($it['Path'] -ne 'Create') { continue }
        try {
            Invoke-CrApplyCreateStep -Context $Context -Item $it -NewSecret $NewSecret -Slot $slot -Errors $errors
        } catch {
            [void]$errors.Add(('{0}: creating the account failed: {1}' -f $it['Name'], $_.Exception.Message))
        }
        if ($errors.Count -gt 0) { break }
    }
    if ($errors.Count -gt 0) { Stop-CrApplySlot $Context $Result $Items 'Create' $errors; return }

    # 1 pre-steps (change path): unlock a locked account; re-apply validates the (unchanged) password once (PLAN 6 step 7).
    foreach ($it in $Items) {
        if (-not $it['Unlock'] -or @('Change', 'Reapply') -notcontains $it['Path']) { continue }
        try {
            $u = Unlock-CrAccount -UserName $it['UserName']
            if (-not ($u -is [hashtable]) -or -not $u['Success']) {
                [void]$errors.Add(('{0}: {1}' -f $it['Name'], (Get-CrApplyResultText $u 'Unlock')))
                break
            }
            Add-CrApplyJournalStep $Context $it['Sid'] 'Unlocked'
            Add-CrApplyFinding $Context 'Info' 'Accounts' 'Account unlocked' $slot $it['Name']
            Set-CrApplyUserUnlocked $it['User']
            $budget = Test-CrApplyBudget -State $State -UserName $it['UserName']
            if (-not $budget['Ok']) {
                [void]$errors.Add(('{0}: after unlocking, {1}; wait for the lockout window and re-run, or choose set or skip' -f $it['Name'], $budget['Reason']))
                break
            }
            if ($it['Path'] -eq 'Reapply') {
                $t = Invoke-CrApplyLogonTest -Context $Context -Item $it -Secret $NewSecret
                if (-not $t['Ok']) {
                    $why = $t['Message']
                    if ($t['Skipped']) { $why = 're-apply cannot be validated after unlocking: ' + $t['Message'] }
                    [void]$errors.Add(('{0}: {1}' -f $it['Name'], $why))
                    break
                }
            }
            [void]$it['DoneSteps'].Add('PreSteps')
            Add-CrApplyJournalStep $Context $it['Sid'] 'PreSteps'
        } catch {
            [void]$errors.Add(('{0}: pre-steps failed: {1}' -f $it['Name'], $_.Exception.Message))
            break
        }
    }
    if ($errors.Count -gt 0) { Stop-CrApplySlot $Context $Result $Items 'PreSteps' $errors; return }

    # 2 secret: set (D9) or change (ApplicationUser); none for Create / New / Reapply (D11, D20). Stops at the first failure.
    foreach ($it in $Items) {
        $path = [string]$it['Path']
        if ($path -eq 'Create') { continue }
        if ($path -eq 'New' -or $path -eq 'Reapply') {
            # The probe (or the pre-step) logged on with the new secret.
            Add-CrApplySid $Context['Verified'] $it['Sid']
            Add-CrApplySid $Context['OnNew'] $it['Sid']
            $msg = 'Already on the new password (D11): password not changed'
            if ($path -eq 'Reapply') { $msg = 'Re-apply: password unchanged (D20); dependents, groups and flags are still enforced' }
            Add-CrApplyFinding $Context 'Info' 'Password' $msg $slot $it['Name']
            continue
        }
        try {
            if ($path -eq 'Change') {
                $budget = Test-CrApplyBudget -State $State -UserName $it['UserName']
                if (-not $budget['Ok']) {
                    [void]$errors.Add(('{0}: password not changed: {1}' -f $it['Name'], $budget['Reason']))
                    break
                }
                Write-Host ('  {0}: change password ...' -f $it['Name'])
                $rot = Invoke-CrPasswordRotation -User $it['User'] -OldSecret $it['OldSecret'] -NewSecret $NewSecret -Path 'Change' -Journal $Context['Journal'] -RunId $Context['RunId']
                if ($rot -is [hashtable]) {
                    # Invoke-CrPasswordRotation does the CCP pre-step itself but leaves the PreSteps journal entry to Apply.
                    if (-not $it['Unlock'] -and ($rot['Success'] -or (ConvertTo-CrArray $rot['Steps']).Count -gt 0)) { Add-CrApplyJournalStep $Context $it['Sid'] 'PreSteps' }
                    foreach ($w in (ConvertTo-CrArray $rot['Warnings'])) { if ($w) { Add-CrApplyFinding $Context 'Info' 'Password' ([string]$w) $slot $it['Name'] } }
                    if ($rot['CcpRestoreFailed']) {
                        Add-CrApplyFinding $Context 'HighImpact' 'Flags' '"User cannot change password" could not be restored after the password step' $slot $it['Name']
                        $Result['Notes'] = Join-CrApplyList $Result['Notes'] ('{0}: "user cannot change password" could not be restored' -f $it['Name'])
                    }
                }
                $op = $rot
                $what = 'Password change'
            } else {
                Write-Host ('  {0}: set password ...' -f $it['Name'])
                $op = Invoke-CrPasswordSet -User $it['User'] -NewSecret $NewSecret -Journal $Context['Journal'] -RunId $Context['RunId']
                $what = 'Password set'
            }
            if (-not ($op -is [hashtable]) -or -not $op['Success']) {
                [void]$errors.Add(('{0}: {1}' -f $it['Name'], (Get-CrApplyResultText $op $what)))
                break
            }
            Set-CrApplyUserUnlocked $it['User']
            Add-CrApplySid $Context['Changed'] $it['Sid']
            Add-CrApplySid $Context['OnNew'] $it['Sid']
            [void]$it['DoneSteps'].Add('Secret')
            if ($path -eq 'Change') {
                Add-CrApplyFinding $Context 'Info' 'Password' 'Password changed (old password validated, DPAPI kept)' $slot $it['Name']
            } elseif ($it['PasswordMode'] -eq 'Change') {
                Add-CrApplyFinding $Context 'HighImpact' 'Password' 'Password set instead of changed: DPAPI-protected data of this account is no longer readable' $slot $it['Name']
            } else {
                Add-CrApplyFinding $Context 'Info' 'Password' 'Password set (D9)' $slot $it['Name']
            }
        } catch {
            [void]$errors.Add(('{0}: password step failed: {1}' -f $it['Name'], $_.Exception.Message))
            break
        }
    }
    if ($errors.Count -gt 0) { Stop-CrApplySlot $Context $Result $Items 'Secret' $errors; return }

    # 3 enable a managed account that exists but is disabled (CONTRACTS v10 "Accounts.ps1").
    foreach ($it in $Items) {
        if (-not $it['Enable']) { continue }
        try {
            $en = Enable-CrAccount -User $it['User']
            if (-not ($en -is [hashtable]) -or -not $en['Success']) {
                [void]$errors.Add(('{0}: {1}' -f $it['Name'], (Get-CrApplyResultText $en 'Enabling the account')))
                continue
            }
            Set-CrApplyUserDisabled $it['User'] $false
            [void]$it['DoneSteps'].Add('Enable')
            Add-CrApplyJournalStep $Context $it['Sid'] 'Enabled'
            Add-CrApplyFinding $Context 'Info' 'Accounts' 'Account enabled' $slot $it['Name']
        } catch {
            [void]$errors.Add(('{0}: enabling the account failed: {1}' -f $it['Name'], $_.Exception.Message))
        }
    }
    if ($errors.Count -gt 0) { Stop-CrApplySlot $Context $Result $Items 'Enable' $errors; return }

    # 4 grants: flags (PNE/CCP/PR), target groups added, rights its own dependents need. Removals come later (PLAN 8).
    foreach ($it in $Items) {
        $sid = $it['Sid']
        $before = $errors.Count
        try {
            $role = $it['Entry']['Role']
            if (-not ($role -is [hashtable])) { $role = @{} }
            $f = Set-CrAccountFlags -User $it['User'] -Role $role
            if (-not ($f -is [hashtable]) -or -not $f['Success']) {
                [void]$errors.Add(('{0}: {1}' -f $it['Name'], (Get-CrApplyResultText $f 'Setting the account flags')))
            } elseif ($f['Changed']) {
                Add-CrApplyFinding $Context 'Info' 'Flags' 'Account flags set as the role requires' $slot $it['Name']
            }
            $gp = Get-CrGroupPlan -State $State -Role $role -Sid $sid -RunningSid $Context['RunningSid']
            foreach ($n in (ConvertTo-CrArray $gp['Notes'])) { Add-CrApplyFinding $Context 'Info' 'Groups' $n $slot $it['Name'] }
            if (-not $gp['Skip']) {
                $add = ConvertTo-CrArray $gp['Add']
                if ($add.Count -gt 0) {
                    $g = Invoke-CrApplyGroupChange -Context $Context -Sid $sid -Name $it['Name'] -RemoveGroupSids @() -AddGroupSids $add -Slot $slot
                    foreach ($e in (ConvertTo-CrArray $g['Errors'])) { [void]$errors.Add($e) }
                }
            }
            $cfg = $it['Entry']['Config']
            $svcCount = 0
            $taskCount = 0
            if (Test-CrApplyManaged $cfg 'Services') { $svcCount = (Get-CrApplyServices -State $State -Sid $sid).Count }
            if (Test-CrApplyManaged $cfg 'ScheduledTasks') { $taskCount = (Get-CrApplyTasks -State $State -Sid $sid).Count }
            $rights = Get-CrApplyNeededRights -State $State -Sid $sid -ServiceCount $svcCount -TaskCount $taskCount
            foreach ($d in (ConvertTo-CrArray $rights['Denied'])) {
                Add-CrApplyFinding $Context 'HighImpact' 'Rights' ($d + ' is denied to this account; its dependents cannot log on (not changed, PLAN 7.3)') $slot $it['Name']
            }
            foreach ($e in (Invoke-CrApplyGrantRights -Context $Context -Sid $sid -Name $it['Name'] -Rights (ConvertTo-CrArray $rights['Need']) -Slot $slot -Why 'needed by its dependents')) { [void]$errors.Add($e) }
        } catch {
            [void]$errors.Add(('{0}: grants failed: {1}' -f $it['Name'], $_.Exception.Message))
        }
        if ($errors.Count -eq $before) {
            [void]$it['DoneSteps'].Add('Grants')
            Add-CrApplyJournalStep $Context $sid 'Grants'
        }
    }
    if ($errors.Count -gt 0) { Stop-CrApplySlot $Context $Result $Items 'Grants' $errors; return }

    # 5 own dependents: SCM -> tasks -> COM+, never restarted (D17). Every account's dependents are attempted.
    foreach ($it in $Items) {
        $sid = $it['Sid']
        $cfg = $it['Entry']['Config']
        $before = $errors.Count
        $kinds = @(
            @{ Key = 'Services'; Area = 'Services'; Found = (Get-CrApplyServices -State $State -Sid $sid); Ok = 'SCM credential updated, restart pending (D17): ' },
            @{ Key = 'ScheduledTasks'; Area = 'Tasks'; Found = (Get-CrApplyTasks -State $State -Sid $sid); Ok = 'Scheduled task re-registered with the new password: ' },
            @{ Key = 'ComPlus'; Area = 'ComPlus'; Found = (Get-CrApplyComPlus -State $State -Sid $sid); Ok = 'COM+ identity updated, restart pending (D17): ' }
        )
        foreach ($k in $kinds) {
            $found = ConvertTo-CrArray $k['Found']
            if ($found.Count -eq 0) { continue }
            if (-not (Test-CrApplyManaged $cfg $k['Key'])) {
                $labels = New-Object System.Collections.ArrayList
                foreach ($x in $found) { [void]$labels.Add((Get-CrApplyItemLabel $x)) }
                Add-CrApplyFinding $Context 'HighImpact' $k['Area'] ('Not updated, the configuration does not manage them (' + $k['Key'] + '); they keep the old password: ' + (($labels.ToArray()) -join ', ')) $slot $it['Name']
                continue
            }
            try {
                if ($k['Key'] -eq 'Services') {
                    $results = ConvertTo-CrArray (Update-CrServiceCredentials -State $State -Sid $sid -Secret $NewSecret)
                } elseif ($k['Key'] -eq 'ScheduledTasks') {
                    $results = ConvertTo-CrArray (Update-CrTaskCredentials -State $State -Sid $sid -Secret $NewSecret)
                } else {
                    $results = ConvertTo-CrArray (Update-CrComPlusCredentials -State $State -Sid $sid -Secret $NewSecret)
                }
                foreach ($res in $results) {
                    if (-not ($res -is [hashtable])) { continue }
                    $label = Get-CrApplyItemLabel $res
                    if ($res['Success']) {
                        Add-CrApplyFinding $Context 'Info' $k['Area'] ($k['Ok'] + $label) $slot $it['Name']
                    } else {
                        [void]$errors.Add(('{0}: {1}' -f $it['Name'], (Get-CrApplyResultText $res ($k['Area'] + ' ' + $label))))
                    }
                }
            } catch {
                [void]$errors.Add(('{0}: {1} update failed: {2}' -f $it['Name'], $k['Area'], $_.Exception.Message))
            }
        }
        if ($errors.Count -eq $before) {
            [void]$it['DoneSteps'].Add('Dependents')
            Add-CrApplyJournalStep $Context $sid 'Dependents'
        }
    }
    if ($errors.Count -gt 0) { Stop-CrApplySlot $Context $Result $Items 'Dependents' $errors; return }

    # 6 verify: one logon test per account with the D16 type; an unverifiable account is reported (Info), not failed.
    foreach ($it in $Items) {
        try {
            $t = Invoke-CrApplyLogonTest -Context $Context -Item $it -Secret $NewSecret
            if ($t['Failed']) {
                [void]$errors.Add(('{0}: verification failed: {1}' -f $it['Name'], $t['Message']))
                continue
            }
            if ($t['Ok']) {
                Add-CrApplySid $Context['Verified'] $it['Sid']
                Add-CrApplyFinding $Context 'Info' 'Verify' $t['Message'] $slot $it['Name']
                Add-CrApplyJournalStep $Context $it['Sid'] 'Verified'
            } elseif ($Context['Verified'] -contains $it['Sid']) {
                Add-CrApplyFinding $Context 'Info' 'Verify' ($t['Message'] + '; the credential probe already logged on with it') $slot $it['Name']
            } else {
                Add-CrApplyFinding $Context 'Info' 'Verify' ($t['Message'] + '. Accounts it replaces stay enabled (D22).') $slot $it['Name']
            }
            [void]$it['DoneSteps'].Add('Verify')
        } catch {
            [void]$errors.Add(('{0}: verification failed: {1}' -f $it['Name'], $_.Exception.Message))
        }
    }
    if ($errors.Count -gt 0) { Stop-CrApplySlot $Context $Result $Items 'Verify' $errors; return }
}

# LOGINS / IIS follow-ups for every account of the slot whose password was created, set or changed in this run
# (not for re-apply or "already on the new password").
function Add-CrApplyFollowUps {
    param($Context, $Items, [string]$Slot)
    foreach ($it in $Items) {
        if (-not $it['Sid'] -or $Context['Changed'] -notcontains $it['Sid']) { continue }
        if ($it['Entry']['LoginsEntry']) {
            Add-CrApplyFinding $Context 'FollowUp' 'LOGINS' 'Update the LOGINS registry entry with the new password (outside the tool)' $Slot $it['Name']
        }
        foreach ($f in (ConvertTo-CrArray $Context['Plan']['Findings'])) {
            if (-not ($f -is [hashtable])) { continue }
            if ($f['Severity'] -eq 'FollowUp' -and $f['Area'] -eq 'IIS' -and [string]$f['Account'] -ieq [string]$it['UserName']) {
                Add-CrApplyFinding $Context 'FollowUp' 'IIS' $f['Message'] $Slot $it['Name']
            }
        }
    }
}

function Invoke-CrApplySlot {
    param($Context, $Preview)
    $slot = [string]$Preview['Slot']
    $result = @{ Slot = $slot; Status = 'Done'; Pending = @(); Errors = @(); Done = @(); Notes = @(); Members = @(); FailedStep = $null; Reason = $null }
    Write-Host ('Slot {0} ...' -f $slot)
    $items = New-Object System.Collections.ArrayList
    $skipped = New-Object System.Collections.ArrayList
    foreach ($a in (ConvertTo-CrArray $Preview['Accounts'])) {
        if ($a['Path'] -eq 'Skip') {
            [void]$skipped.Add(('{0}: not processed ({1})' -f $a['Name'], $a['Reason']))
            Add-CrApplyFinding $Context 'Info' 'Password' ('Account skipped: ' + $a['Reason']) $slot $a['Name']
            continue
        }
        $steps = New-Object System.Collections.ArrayList
        if ($a['Path'] -eq 'Create') { [void]$steps.Add('Create') }
        if ($a['Unlock'] -and @('Change', 'Reapply') -contains $a['Path']) { [void]$steps.Add('PreSteps') }
        if (@('Change', 'Set') -contains $a['Path']) { [void]$steps.Add('Secret') }
        if ($a['Enable']) { [void]$steps.Add('Enable') }
        foreach ($s in @('Grants', 'Dependents', 'Verify')) { [void]$steps.Add($s) }
        $oldSecret = $null
        if ($a['SecretAccount'] -is [hashtable]) { $oldSecret = $a['SecretAccount']['OldSecret'] }
        if ($a['Sid']) {
            $Context['EntrySids'][[string]$a['Entry']['Id']] = [string]$a['Sid']
            $Context['SlotOfSid'][[string]$a['Sid']] = $slot
        }
        [void]$items.Add(@{
            Name = $a['Name']; Sid = $a['Sid']; UserName = $a['UserName']; User = $a['User']; Entry = $a['Entry']; Probe = $a['Probe']
            Path = $a['Path']; PasswordMode = $a['PasswordMode']; Unlock = $a['Unlock']; Enable = $a['Enable']; OldSecret = $oldSecret
            Steps = $steps; DoneSteps = (New-Object System.Collections.ArrayList)
        })
    }

    $newSecret = $null
    $slotSecret = $Context['SlotSecrets'][$slot]
    if ($slotSecret -is [hashtable]) { $newSecret = $slotSecret['NewSecret'] }
    if ($items.Count -gt 0) {
        if (-not $newSecret) {
            $noSecret = New-Object System.Collections.ArrayList
            [void]$noSecret.Add('No new password is available for this slot')
            Stop-CrApplySlot $Context $result $items 'Create' $noSecret
        } else {
            Invoke-CrApplySlotSteps -Context $Context -Result $result -Items $items -NewSecret $newSecret
        }
    }
    $members = New-Object System.Collections.ArrayList
    foreach ($it in $items) {
        if (-not $it['Sid']) { continue }
        [void]$members.Add(@{ Sid = $it['Sid']; Name = $it['Name']; UserName = $it['UserName']; Role = $it['Entry']['Role']; EntryId = $it['Entry']['Id'] })
    }
    $result['Members'] = $members.ToArray()
    Add-CrApplyFollowUps -Context $Context -Items $items -Slot $slot

    # Skipped accounts leave the slot incomplete (partial result).
    if ($skipped.Count -gt 0) {
        if ($items.Count -eq 0) {
            $result['Status'] = 'Skipped'
        } else {
            $result['Status'] = 'Failed'
            if (-not $result['FailedStep']) { $result['FailedStep'] = 'Skipped accounts' }
        }
        $result['Pending'] = Join-CrApplyList $result['Pending'] ($skipped.ToArray())
    }
    $done = New-Object System.Collections.ArrayList
    foreach ($it in $items) {
        if ($it['DoneSteps'].Count -gt 0) { [void]$done.Add(('{0}: {1}' -f $it['Name'], (($it['DoneSteps'].ToArray()) -join ', '))) }
    }
    $result['Done'] = $done.ToArray()
    Write-CrLog ('Apply: slot {0} {1}' -f $slot, $result['Status'])
    return $result
}

#endregion

#region Enforcement phase (PLAN 8: removals -> dependent moves -> auto-logon -> disabling -> check mode -> running account)

# 1 exclusive-group removals for completed slots (allow-lists via Get-CrGroupPlan, rails here).
function Invoke-CrApplyRemovals {
    param($Context, $Slots)
    foreach ($sr in $Slots) {
        if ($sr['Status'] -ne 'Done') { continue }
        foreach ($m in (ConvertTo-CrArray $sr['Members'])) {
            $role = $m['Role']
            if (-not ($role -is [hashtable])) { $role = @{} }
            try {
                $gp = Get-CrGroupPlan -State $Context['State'] -Role $role -Sid $m['Sid'] -RunningSid $Context['RunningSid']
            } catch {
                $sr['Status'] = 'Failed'
                $sr['FailedStep'] = 'Removals'
                $sr['Errors'] = Join-CrApplyList $sr['Errors'] ('{0}: group plan failed: {1}' -f $m['Name'], $_.Exception.Message)
                continue
            }
            if ($gp['Skip']) { continue }
            foreach ($rail in (ConvertTo-CrArray $gp['Rail'])) { Add-CrApplyFinding $Context 'Info' 'Groups' ('Rail: ' + $rail) $sr['Slot'] $m['Name'] }
            $remove = ConvertTo-CrArray $gp['Remove']
            if ($remove.Count -eq 0) { continue }
            $g = Invoke-CrApplyGroupChange -Context $Context -Sid $m['Sid'] -Name $m['Name'] -RemoveGroupSids $remove -AddGroupSids @() -Slot $sr['Slot']
            $errs = ConvertTo-CrArray $g['Errors']
            if ($errs.Count -gt 0) {
                $sr['Status'] = 'Failed'
                $sr['FailedStep'] = 'Removals'
                $sr['Errors'] = Join-CrApplyList $sr['Errors'] $errs
                $sr['Pending'] = Join-CrApplyList $sr['Pending'] $g['Pending']
                Add-CrApplyFinding $Context 'Blocked' 'Groups' 'Group removal failed (enforcement phase)' $sr['Slot'] $m['Name'] ($errs -join ' | ')
            }
        }
    }
}

function Find-CrApplySlotResult {
    param($Slots, [string]$Slot)
    foreach ($s in (ConvertTo-CrArray $Slots)) { if ($s -is [hashtable] -and [string]$s['Slot'] -eq $Slot) { return $s } }
    return $null
}

# Where the dependents of a disable item go: @{ Ok; Sid; Name; Secret; Reason }. Only to an account verified on
# its new password in this run (D24); the secret is the target slot's SecureString itself.
function Get-CrApplyMoveTarget {
    param($Context, $Item)
    $r = @{ Ok = $false; Sid = $null; Name = $null; Secret = $null; Reason = $null }
    $e = $Item['MoveEntry']
    if (-not ($e -is [hashtable])) { $r['Reason'] = 'no target account for its dependents'; return $r }
    $name = Get-CrApplyEntryAccountName $e
    $r['Name'] = $name
    $sid = $Context['EntrySids'][[string]$e['Id']]
    if (-not $sid) { $sid = Get-CrApplyEntryAccountSid $e }
    if (-not $sid -or $Context['Verified'] -notcontains $sid) {
        $r['Reason'] = '{0} is not verified on its new password in this run' -f $name
        return $r
    }
    $u = Find-CrApplyUser -State $Context['State'] -Sid $sid
    if (-not $u -or $u['Disabled']) { $r['Reason'] = '{0} is not enabled' -f $name; return $r }
    $slotSecret = $Context['SlotSecrets'][[string]$e['Slot']]
    if (-not ($slotSecret -is [hashtable]) -or -not $slotSecret['NewSecret']) {
        $r['Reason'] = 'the password of {0} is not available in this run' -f $name
        return $r
    }
    $r['Ok'] = $true
    $r['Sid'] = $sid
    $r['Name'] = [string]$u['Name']
    $r['Secret'] = $slotSecret['NewSecret']
    return $r
}

# 2 dependent moves (D24): services, password-stored tasks and COM+ identities of each account to be disabled go to
# its replacement (or, on the operator's choice, the application account). A failure keeps the account enabled.
function Invoke-CrApplyMoves {
    param($Context, $DisablePlan)
    $State = $Context['State']
    $computer = $env:COMPUTERNAME
    if ($State['Computer'] -is [hashtable] -and $State['Computer']['Name']) { $computer = [string]$State['Computer']['Name'] }
    foreach ($item in $DisablePlan) {
        if (-not $item['Planned']) { continue }
        $name = $item['Name']
        foreach ($t in (ConvertTo-CrArray $item['OtherTasks'])) {
            Add-CrApplyFinding $Context 'HighImpact' 'Tasks' ('Scheduled task runs as this account without a stored password (LogonType ' + $t['LogonType'] + '); it is not moved and stops running once the account is disabled: ' + $t['Path']) $null $name
        }
        if (-not $item['HasDependents']) { continue }
        $target = Get-CrApplyMoveTarget -Context $Context -Item $item
        $slot = $null
        if ($item['MoveEntry'] -is [hashtable]) { $slot = [string]$item['MoveEntry']['Slot'] }
        if (-not $target['Ok']) {
            $item['Blocked'] = 'its dependents cannot be moved: ' + $target['Reason']
            Add-CrApplyFinding $Context 'HighImpact' 'Accounts' ('Stays enabled (D24): ' + $item['Blocked']) $slot $name
            continue
        }
        $item['MovedTo'] = $target['Name']
        Write-Host ('Moving the dependents of {0} to {1} ...' -f $name, $target['Name'])
        $errors = New-Object System.Collections.ArrayList
        try {
            $services = ConvertTo-CrArray $item['Services']
            $tasks = ConvertTo-CrArray $item['Tasks']
            $rights = Get-CrApplyNeededRights -State $State -Sid $target['Sid'] -ServiceCount $services.Count -TaskCount $tasks.Count
            foreach ($d in (ConvertTo-CrArray $rights['Denied'])) {
                [void]$errors.Add(('{0} is denied to {1}; its dependents would not log on (not changed, PLAN 7.3)' -f $d, $target['Name']))
            }
            if ($errors.Count -eq 0) {
                foreach ($e in (Invoke-CrApplyGrantRights -Context $Context -Sid $target['Sid'] -Name $target['Name'] -Rights (ConvertTo-CrArray $rights['Need']) -Slot $slot -Why ('needed by the dependents moved from ' + $name))) { [void]$errors.Add($e) }
            }
            if ($errors.Count -eq 0) {
                $kinds = New-Object System.Collections.ArrayList
                if ($services.Count -gt 0) { [void]$kinds.Add('Services') }
                if ($tasks.Count -gt 0) { [void]$kinds.Add('Tasks') }
                if ((ConvertTo-CrArray $item['ComPlus']).Count -gt 0) { [void]$kinds.Add('ComPlus') }
                foreach ($kind in $kinds) {
                    $results = @()
                    $ok = ''
                    try {
                        if ($kind -eq 'Services') {
                            $results = ConvertTo-CrArray (Move-CrServiceAccount -State $State -FromSid $item['Sid'] -ToAccount ('.\' + $target['Name']) -Secret $target['Secret'])
                            $ok = 'Service moved to {0}, restart pending (D17): ' -f $target['Name']
                        } elseif ($kind -eq 'Tasks') {
                            $results = ConvertTo-CrArray (Move-CrTaskAccount -State $State -FromSid $item['Sid'] -ToUserId ($computer + '\' + $target['Name']) -Secret $target['Secret'])
                            $ok = 'Scheduled task moved to {0}: ' -f $target['Name']
                        } else {
                            $results = ConvertTo-CrArray (Move-CrComPlusIdentity -State $State -FromSid $item['Sid'] -ToIdentity $target['Name'] -Secret $target['Secret'])
                            $ok = 'COM+ identity moved to {0}, restart pending (D17): ' -f $target['Name']
                        }
                    } catch {
                        [void]$errors.Add(('{0} move failed: {1}' -f $kind, $_.Exception.Message))
                        continue
                    }
                    # COM+: after an adapter failure nothing of that call is saved, so no application counts as moved.
                    $anyFailed = $false
                    foreach ($res in $results) { if (-not ($res -is [hashtable]) -or -not $res['Success']) { $anyFailed = $true } }
                    foreach ($res in $results) {
                        if (-not ($res -is [hashtable])) { [void]$errors.Add(('{0} move: no result returned' -f $kind)); continue }
                        $label = Get-CrApplyItemLabel $res
                        if ($res['Success'] -and -not ($kind -eq 'ComPlus' -and $anyFailed)) {
                            $from = $res['FromAccount']
                            if (-not $from) { $from = $res['FromUserId'] }
                            if (-not $from) { $from = $res['FromIdentity'] }
                            if (-not $from) { $from = $name }
                            $to = $res['ToAccount']
                            if (-not $to) { $to = $res['ToUserId'] }
                            if (-not $to) { $to = $res['ToIdentity'] }
                            if (-not $to) { $to = $target['Name'] }
                            Add-CrApplyFinding $Context 'Info' $kind ($ok + $label + ' (' + $from + ' -> ' + $to + ')') $slot $name
                            if ($res['SaclDropped']) { Add-CrApplyFinding $Context 'HighImpact' $kind ('The audit settings (SACL) of the task could not be kept when it was moved: ' + $label) $slot $name }
                            foreach ($w in (Join-CrApplyList $res['Warning'] $res['Warnings'])) { if ($w) { Add-CrApplyFinding $Context 'HighImpact' $kind ([string]$w) $slot $name } }
                        } elseif ($res['Success']) {
                            [void]$errors.Add(('{0} {1}: not saved, another application of the same COM+ catalog call failed' -f $kind, $label))
                        } else {
                            [void]$errors.Add((Get-CrApplyResultText $res ($kind + ' ' + $label)))
                        }
                    }
                }
            }
        } catch {
            [void]$errors.Add(('moving the dependents failed: {0}' -f $_.Exception.Message))
        }
        if ($errors.Count -gt 0) {
            $item['MoveFailed'] = $true
            $Context['EnforcementFailed'] = $true
            Add-CrApplyFinding $Context 'Blocked' 'Accounts' ('Stays enabled: not every dependent could be moved to ' + $target['Name'] + ' (D24)') $slot $name (($errors.ToArray()) -join ' | ')
        } else {
            Add-CrApplyJournalStep $Context ([string]$item['Sid']) 'DependentsMoved'
        }
    }
}

# 3 the auto-logon step (D18, PLAN 7.5). Returns @{ Ran; Action; Success; Decision; FailedStep; Pending }.
function Invoke-CrApplyAutoLogonStep {
    param($Context, [string[]]$Only, [string]$Choice, [scriptblock]$Prompt)
    $State = $Context['State']
    $out = @{ Ran = $false; Action = $null; Success = $true; Decision = $null; FailedStep = $null; Pending = $null }
    if (-not (Test-CrApplyAutoLogonSelected -State $State -Resolved $Context['Resolved'] -Only $Only)) {
        Add-CrApplyFinding $Context 'Info' 'AutoLogon' 'Auto-logon step not selected under -Only' 'AutoLogon'
        return $out
    }
    $al = $State['AutoLogon']
    if (-not ($al -is [hashtable]) -or $al['Error']) {
        Add-CrApplyFinding $Context 'Info' 'AutoLogon' 'Auto-logon settings could not be read; the auto-logon step was not run' 'AutoLogon'
        return $out
    }
    # Accounts created in this run are in $State.Users by now; their names are passed too when they are verified.
    $createdNames = New-Object System.Collections.ArrayList
    foreach ($sid in $Context['Created']) {
        if ($Context['Verified'] -notcontains $sid) { continue }
        $u = Find-CrApplyUser -State $State -Sid $sid
        if ($u) { [void]$createdNames.Add([string]$u['Name']) }
    }
    $d = Get-CrAutoLogonDecision -State $State -Resolved $Context['Resolved'] -Config $Context['Config'] -VerifiedSids ($Context['Verified'].ToArray()) `
        -RemovedAdminSids ($Context['RemovedAdmins'].ToArray()) -CreatedTargetNames ([string[]]$createdNames.ToArray([string]))
    $out['Ran'] = $true
    $out['Decision'] = $d
    $detail = (ConvertTo-CrArray $d['Reasons']) -join '; '
    $action = [string]$d['Action']
    $exec = $null
    if ($action -eq 'Ambiguous') {
        $opts = ConvertTo-CrArray $d['OperatorOptions']
        $pick = $null
        if ($Choice -and ($opts -contains $Choice)) {
            $pick = $Choice
        } elseif ($Prompt) {
            $pick = [string](& $Prompt $d)
        }
        if (-not $pick -or ($opts -notcontains $pick)) { $pick = 'LeaveUnchanged' }
        Add-CrApplyFinding $Context 'Info' 'AutoLogon' ('Auto-logon: operator decision ' + $pick + ' (D13)') 'AutoLogon' $d['CurrentName'] $detail
        if ($pick -eq 'TurnOff' -or $pick -eq 'StandardizeCurrent') {
            $exec = Copy-CrApplyDecision $d $pick
        } else {
            $out['Action'] = 'LeaveUnchanged'
            if ($d['CurrentSid'] -and ($Context['Changed'] -contains $d['CurrentSid'])) {
                Add-CrApplyFinding $Context 'HighImpact' 'AutoLogon' ('Auto-logon broken until re-run: ' + $d['CurrentName'] + ' has a new password but the auto-logon settings were left unchanged; each boot costs one failed logon') 'AutoLogon' $d['CurrentName']
            }
            return $out
        }
    } elseif (@('Standardize', 'Switch', 'TurnOff') -contains $action) {
        $exec = $d
    } else {
        $out['Action'] = $action
        Add-CrApplyFinding $Context 'Info' 'AutoLogon' ('Auto-logon: ' + $action) 'AutoLogon' $d['CurrentName'] $detail
        return $out
    }

    $out['Action'] = $exec['Action']
    $alSecret = $null
    $targetSid = [string]$exec['TargetSid']
    $targetName = [string]$exec['TargetName']
    if ($exec['Action'] -eq 'StandardizeCurrent') { $targetSid = [string]$d['CurrentSid']; $targetName = [string]$d['CurrentName'] }
    if (-not $targetSid -and $targetName) {
        $tu = Find-CrApplyUserByName -State $State -Name $targetName
        if ($tu) { $targetSid = [string]$tu['Sid'] }
    }
    if ($exec['Action'] -ne 'TurnOff') {
        # PLAN 7.5 "Password source": only for a target verified on the new secret in this run (PUB-User's slot secret).
        if ($targetSid -and $Context['Verified'] -contains $targetSid) {
            $slot = $Context['SlotOfSid'][$targetSid]
            if ($slot -and $Context['SlotSecrets'][$slot] -is [hashtable]) { $alSecret = $Context['SlotSecrets'][$slot]['NewSecret'] }
        }
        if (-not $alSecret) {
            $out['Success'] = $false
            Add-CrApplyFinding $Context 'Blocked' 'AutoLogon' ('Auto-logon step not run: ' + $targetName + ' is not verified on the new password in this run') 'AutoLogon' $targetName $detail
            return $out
        }
    }
    Write-Host ('Auto-logon step: {0} ...' -f $exec['Action'])
    try {
        $res = Invoke-CrAutoLogonAction -Decision $exec -State $State -Secret $alSecret
    } catch {
        $res = @{ Success = $false; Steps = @(); FailedStep = $null; Pending = @(); Error = $_.Exception.Message }
    }
    $stepsText = ''
    if ($res -is [hashtable]) { $stepsText = (ConvertTo-CrArray $res['Steps']) -join ', ' }
    if ($res -is [hashtable] -and $res['Success']) {
        $who = $targetName
        $journalSid = $targetSid
        if ($exec['Action'] -eq 'TurnOff') { $who = $d['CurrentName']; $journalSid = $d['CurrentSid'] }
        $msg = 'Auto-logon standardized as ' + $who + ' (LSA secret, no plain text, effective at the next reboot)'
        if ($exec['Action'] -eq 'Switch') { $msg = 'Auto-logon switched from ' + $d['CurrentName'] + ' to ' + $who + ' (effective at the next reboot)' }
        if ($exec['Action'] -eq 'TurnOff') { $msg = 'Auto-logon turned off (was ' + $who + '); the machine waits at the logon screen after the next reboot' }
        Add-CrApplyFinding $Context 'Info' 'AutoLogon' $msg 'AutoLogon' $who $stepsText
        if ($journalSid) { Add-CrApplyJournalStep $Context ([string]$journalSid) 'AutoLogon' }
    } else {
        $out['Success'] = $false
        $err = $null
        $failedStep = $null
        $pendingText = ''
        if ($res -is [hashtable]) {
            $err = $res['Error']
            $failedStep = $res['FailedStep']
            $pendingText = (ConvertTo-CrArray $res['Pending']) -join ', '
        }
        $out['FailedStep'] = $failedStep
        $out['Pending'] = $pendingText
        $msg = 'Auto-logon step failed'
        if ($failedStep) { $msg = $msg + ' at ' + $failedStep }
        Add-CrApplyFinding $Context 'Blocked' 'AutoLogon' ($msg + ': ' + $err) 'AutoLogon' $d['CurrentName'] ('Steps done: ' + $stepsText + ' -- Pending: ' + $pendingText)
    }
    return $out
}

# Why a planned disable can't run now, or $null. Replaced accounts need an enabled, verified replacement (D22);
# moved dependents must all have moved (D24); the Administrators rail applies.
function Get-CrApplyDisableBlocker {
    param($Context, $Item, [bool]$RunningCounts = $true)
    if ($Item['Blocked']) { return [string]$Item['Blocked'] }
    if ($Item['MoveFailed']) { return 'not every dependent could be moved' }
    if ($Item['Kind'] -eq 'Replaced') {
        $e = $Item['ReplacementEntry']
        $sid = $Context['EntrySids'][[string]$e['Id']]
        if (-not $sid) { $sid = Get-CrApplyEntryAccountSid $e }
        $slotResult = Find-CrApplySlotResult -Slots $Context['SlotResults'] -Slot ([string]$e['Slot'])
        if ($slotResult -and $slotResult['Status'] -ne 'Done') { return ('the slot of its replacement {0} did not complete ({1})' -f $Item['ReplacementName'], $slotResult['Status']) }
        if (-not $sid -or $Context['Verified'] -notcontains $sid) { return ('its replacement {0} is not verified on its new password in this run' -f $Item['ReplacementName']) }
        $u = Find-CrApplyUser -State $Context['State'] -Sid $sid
        if (-not $u -or $u['Disabled']) { return ('its replacement {0} is not enabled' -f $Item['ReplacementName']) }
    }
    $rail = Get-CrApplyAdminRailReason -Context $Context -RemoveSid ([string]$Item['Sid']) -RunningCounts $RunningCounts
    if ($rail) { return ('rail: ' + $rail) }
    return $null
}

function Invoke-CrApplyDisableOne {
    param($Context, $Item)
    $why = 'replaced by ' + $Item['ReplacementName'] + ' (D22)'
    if ($Item['Kind'] -eq 'Disable') { $why = 'retired without replacement (D22)' }
    if ($Item['Kind'] -eq 'Other') { $why = 'operator decision (D23)' }
    try {
        $res = Disable-CrAccount -User $Item['User'] -Journal $Context['Journal'] -RunId $Context['RunId']
    } catch {
        $res = @{ Success = $false; Win32Error = 0; Message = $_.Exception.Message }
    }
    if ($res -is [hashtable] -and $res['Success']) {
        Set-CrApplyUserDisabled $Item['User'] $true
        $Item['Status'] = 'Disabled'
        Add-CrApplyFinding $Context 'Info' 'Accounts' ('Account disabled: ' + $why + '; groups and password unchanged') $Item['ReplacementSlot'] $Item['Name']
        return $true
    }
    $Item['Status'] = 'Failed'
    $Item['Reason'] = Get-CrApplyResultText $res 'Disabling the account'
    $Context['EnforcementFailed'] = $true
    Add-CrApplyFinding $Context 'Blocked' 'Accounts' $Item['Reason'] $Item['ReplacementSlot'] $Item['Name']
    return $false
}

# 4 disabling (D22, D23): every planned account except the running account.
function Invoke-CrApplyDisables {
    param($Context, $DisablePlan)
    foreach ($item in $DisablePlan) {
        if ($item['IsRunning']) { continue }
        if (-not $item['Planned']) {
            $item['Status'] = 'KeptEnabled'
            Add-CrApplyFinding $Context 'Info' 'Accounts' ('Not disabled: ' + $item['Reason']) $item['ReplacementSlot'] $item['Name']
            continue
        }
        $blocker = Get-CrApplyDisableBlocker -Context $Context -Item $item
        if ($blocker) {
            $item['Status'] = 'KeptEnabled'
            $item['Reason'] = 'stays enabled: ' + $blocker
            Add-CrApplyFinding $Context 'HighImpact' 'Accounts' ('Not disabled: ' + $blocker) $item['ReplacementSlot'] $item['Name']
            continue
        }
        [void](Invoke-CrApplyDisableOne -Context $Context -Item $item)
    }
}

# 6 the running account last (D25): only if the operator account (SOP-Admin) is enabled, in Administrators and Remote
# Desktop Users, and verified in this run. The RDP session continues; the next logon is as the operator account.
function Invoke-CrApplyRunningAccountStep {
    param($Context, $DisablePlan)
    $out = @{ Disabled = $false; Reason = $null }
    $item = $null
    foreach ($i in $DisablePlan) { if ($i['IsRunning']) { $item = $i } }
    if (-not $item) { return $out }
    if (-not $item['Planned']) {
        $item['Status'] = 'KeptEnabled'
        $out['Reason'] = $item['Reason']
        Add-CrApplyFinding $Context 'Info' 'Accounts' ('Your own account stays enabled: ' + $item['Reason']) $item['ReplacementSlot'] $item['Name']
        return $out
    }
    $why = $null
    $opEntry = Get-CrApplyOperatorEntry -Resolved $Context['Resolved'] -RunningSid $Context['RunningSid']
    $opName = 'SOP-Admin'
    if ($opEntry) { $opName = Get-CrApplyEntryAccountName $opEntry }
    if (-not $opEntry) {
        $why = 'no operator account is configured'
    } else {
        $opSid = $Context['EntrySids'][[string]$opEntry['Id']]
        if (-not $opSid) { $opSid = Get-CrApplyEntryAccountSid $opEntry }
        $opUser = Find-CrApplyUser -State $Context['State'] -Sid $opSid
        if (-not $opSid -or -not $opUser) { $why = $opName + ' does not exist' }
        elseif ($opUser['Disabled']) { $why = $opName + ' is not enabled' }
        elseif ((Get-CrApplyGroupMembers -State $Context['State'] -GroupSid 'S-1-5-32-544') -notcontains $opSid) { $why = $opName + ' is not in Administrators' }
        elseif ((Get-CrApplyGroupMembers -State $Context['State'] -GroupSid 'S-1-5-32-555') -notcontains $opSid) { $why = $opName + ' is not in Remote Desktop Users' }
        elseif ($Context['Verified'] -notcontains $opSid) { $why = $opName + ' is not verified on its new password in this run' }
    }
    if (-not $why) { $why = Get-CrApplyDisableBlocker -Context $Context -Item $item -RunningCounts $false }
    if ($why) {
        $item['Status'] = 'KeptEnabled'
        $item['Reason'] = 'stays enabled: ' + $why
        $out['Reason'] = $why
        Add-CrApplyFinding $Context 'HighImpact' 'Accounts' ('Your own account stays enabled (D25): ' + $why) $item['ReplacementSlot'] $item['Name']
        return $out
    }
    Write-Host ('Disabling your own account {0} (last step, D25) ...' -f $item['Name'])
    if (Invoke-CrApplyDisableOne -Context $Context -Item $item) {
        $out['Disabled'] = $true
        Add-CrApplyFinding $Context 'FollowUp' 'Accounts' ('Your account ' + $item['Name'] + ' is disabled; this RDP session continues. Log on as ' + $opName + ' next time and update saved RDP credentials.') $item['ReplacementSlot'] $item['Name']
    }
    return $out
}

# 5 check-mode accounts (PLAN 7.1): flags and exclusive groups, never the password. Not under -Only.
function Invoke-CrApplyCheckFixes {
    param($Context)
    $fixes = New-Object System.Collections.ArrayList
    foreach ($e in (ConvertTo-CrArray $Context['Resolved'])) {
        if (-not ($e -is [hashtable]) -or $e['Mode'] -ne 'Check' -or $e['Kind'] -ne 'Windows') { continue }
        if ($e['NotApplicable'] -or $e['Error']) { continue }
        $fix = @{ Id = $e['Id']; Status = 'Done'; Errors = @() }
        $errors = New-Object System.Collections.ArrayList
        $role = $e['Role']
        if (-not ($role -is [hashtable])) { $role = @{} }
        foreach ($acct in (ConvertTo-CrArray $e['Accounts'])) {
            if (-not ($acct -is [hashtable]) -or -not $acct['Sid']) { continue }
            $name = [string]$acct['Name']
            $sid = [string]$acct['Sid']
            try {
                $f = Set-CrAccountFlags -User $acct['User'] -Role $role
                if (-not ($f -is [hashtable]) -or -not $f['Success']) {
                    [void]$errors.Add(('{0}: {1}' -f $name, (Get-CrApplyResultText $f 'Setting the account flags')))
                } elseif ($f['Changed']) {
                    Add-CrApplyFinding $Context 'Info' 'Flags' 'Account flags set as the role requires (check mode)' $e['Id'] $name
                }
                $gp = Get-CrGroupPlan -State $Context['State'] -Role $role -Sid $sid -RunningSid $Context['RunningSid']
                foreach ($n in (ConvertTo-CrArray $gp['Notes'])) { Add-CrApplyFinding $Context 'Info' 'Groups' $n $e['Id'] $name }
                foreach ($rail in (ConvertTo-CrArray $gp['Rail'])) { Add-CrApplyFinding $Context 'Info' 'Groups' ('Rail: ' + $rail) $e['Id'] $name }
                if (-not $gp['Skip']) {
                    $g = Invoke-CrApplyGroupChange -Context $Context -Sid $sid -Name $name -RemoveGroupSids (ConvertTo-CrArray $gp['Remove']) -AddGroupSids (ConvertTo-CrArray $gp['Add']) -Slot $e['Id']
                    foreach ($x in (ConvertTo-CrArray $g['Errors'])) { [void]$errors.Add($x) }
                }
            } catch {
                [void]$errors.Add(('{0}: check-mode fix failed: {1}' -f $name, $_.Exception.Message))
            }
        }
        if ($errors.Count -gt 0) {
            $fix['Status'] = 'Failed'
            $fix['Errors'] = $errors.ToArray()
            Add-CrApplyFinding $Context 'Blocked' 'Check' ('Check-mode fixes failed for ' + $e['Id']) $e['Id'] $null (($errors.ToArray()) -join ' | ')
        }
        [void]$fixes.Add($fix)
    }
    return , $fixes.ToArray()
}

#endregion

#region Public

# Applies the confirmed plan (CONTRACTS "Apply.ps1 / entry point", v10). -Probes: hashtable SID -> probe result of the
# Change accounts, optionally with Path = 'Set'|'Skip' (operator choice before YES). -OtherDecisions: SID ->
# 'Disable'|'Keep' (Read-CrOtherAccountDecisions, D23). -DependentDecisions: SID -> 'Move'|'Keep' for accounts without
# a replacement that run dependents (D24). -AutoLogonChoice: the operator's choice for an ambiguous auto-logon made
# before YES; -AutoLogonPrompt: called with the decision when the step turns out ambiguous at runtime (D13).
# Returns @{ Findings; Slots; Disables; CheckFixes; AutoLogon; RunningAccount; ExitCode; ChangedSids; CreatedSids;
# VerifiedSids; RemovedAdminSids }. Exit code: 2 machine blocked, 1 any failure, 4 follow-ups, else 0.
function Invoke-CrApply {
    param(
        $State, $Config, $Resolved, $Preflight, $Plan, $SlotSecrets, $Probes, $Journal, [string]$RunId,
        [string[]]$Only, [string]$RunningSid, $OtherDecisions, $DependentDecisions,
        [string]$AutoLogonChoice, [scriptblock]$AutoLogonPrompt
    )
    if (-not $RunningSid) { $RunningSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value }
    if (-not ($Plan -is [hashtable])) { $Plan = @{ Findings = @() } }
    if (-not ($SlotSecrets -is [hashtable])) { $SlotSecrets = @{} }
    $ctx = @{
        State = $State; Config = $Config; Resolved = $Resolved; Plan = $Plan; SlotSecrets = $SlotSecrets
        Journal = $Journal; RunId = $RunId; RunningSid = $RunningSid
        Findings = (New-Object System.Collections.ArrayList)
        Verified = (New-Object System.Collections.ArrayList)     # logged on with the new password in this run
        OnNew = (New-Object System.Collections.ArrayList)        # on the new password (created, set, changed, D11, D20)
        Changed = (New-Object System.Collections.ArrayList)      # password created/set/changed: LOGINS follow-up
        Created = (New-Object System.Collections.ArrayList)
        RemovedAdmins = (New-Object System.Collections.ArrayList)
        EntrySids = @{}; SlotOfSid = @{}; SlotResults = @()
        JournalWarned = $false; EnforcementFailed = $false
    }
    $result = @{
        Findings = $ctx['Findings']; Slots = @(); Disables = @(); CheckFixes = @(); AutoLogon = $null; RunningAccount = $null
        ExitCode = 0; ChangedSids = @(); CreatedSids = @(); VerifiedSids = @(); RemovedAdminSids = @()
    }
    if ($Preflight -is [hashtable] -and $Preflight['MachineBlocked']) {
        Add-CrApplyFinding $ctx 'Blocked' 'Preflight' '-Apply is blocked on this machine; nothing was changed'
        $result['ExitCode'] = 2
        return $result
    }

    Write-CrLog ('Apply started, run {0}' -f $RunId)
    # Findings of the password prompts (Read-CrSlotSecrets: skipped slots, rejected passwords).
    foreach ($k in @($SlotSecrets.Keys)) {
        $ss = $SlotSecrets[$k]
        if (-not ($ss -is [hashtable])) { continue }
        foreach ($f in (ConvertTo-CrArray $ss['Findings'])) { if ($f -is [hashtable]) { [void]$ctx['Findings'].Add($f) } }
    }
    $preview = Get-CrApplyPreview -Config $Config -Resolved $Resolved -Preflight $Preflight -SlotSecrets $SlotSecrets -Probes $Probes -Only $Only
    # Planned before the slots run: the dependents and users as discovered by the audit.
    $disablePlan = Get-CrApplyDisablePlan -State $State -Resolved $Resolved -Preview $preview -RunningSid $RunningSid -Only $Only -OtherDecisions $OtherDecisions -DependentDecisions $DependentDecisions

    $slots = New-Object System.Collections.ArrayList
    foreach ($p in $preview) {
        if ($p['Status'] -eq 'Apply') {
            [void]$slots.Add((Invoke-CrApplySlot -Context $ctx -Preview $p))
            continue
        }
        $sev = 'Info'
        if ($p['Status'] -eq 'Blocked') { $sev = 'Blocked' }
        Add-CrApplyFinding $ctx $sev 'Apply' ('Slot ' + $p['Status'] + ': ' + $p['Reason']) $p['Slot']
        foreach ($a in (ConvertTo-CrArray $p['Accounts'])) {
            if ($a['Path'] -eq 'Skip') { Add-CrApplyFinding $ctx 'Info' 'Password' ('Account skipped: ' + $a['Reason']) $p['Slot'] $a['Name'] }
        }
        [void]$slots.Add(@{ Slot = $p['Slot']; Status = $p['Status']; Pending = @(); Errors = @(); Done = @(); Notes = @(); Members = @(); FailedStep = $null; Reason = $p['Reason'] })
    }
    $ctx['SlotResults'] = $slots.ToArray()

    # Enforcement phase, in this order (PLAN 8).
    Invoke-CrApplyRemovals -Context $ctx -Slots $slots
    Invoke-CrApplyMoves -Context $ctx -DisablePlan $disablePlan
    $result['AutoLogon'] = Invoke-CrApplyAutoLogonStep -Context $ctx -Only $Only -Choice $AutoLogonChoice -Prompt $AutoLogonPrompt
    Invoke-CrApplyDisables -Context $ctx -DisablePlan $disablePlan
    $fixes = @()
    if (-not (Test-CrApplyOnlyGiven $Only)) {
        $fixes = Invoke-CrApplyCheckFixes -Context $ctx
    } else {
        Add-CrApplyFinding $ctx 'Info' 'Check' 'Check-mode accounts, retired accounts and other accounts are not processed under -Only'
    }
    $result['RunningAccount'] = Invoke-CrApplyRunningAccountStep -Context $ctx -DisablePlan $disablePlan

    # Report: "locked: yes/no" per processed account (PLAN 6 step 11).
    foreach ($sr in $slots) {
        foreach ($m in (ConvertTo-CrArray $sr['Members'])) {
            $locked = 'unknown'
            try {
                $info = Get-CrUserInfo -UserName $m['UserName']
                if ($info -is [hashtable] -and $info['Success']) {
                    if (([int]$info['Flags'] -band 0x10) -ne 0) { $locked = 'yes' } else { $locked = 'no' }
                }
            } catch { }
            Add-CrApplyFinding $ctx 'Info' 'Accounts' ('Locked: ' + $locked) $sr['Slot'] $m['Name']
        }
    }

    $disables = New-Object System.Collections.ArrayList
    foreach ($i in $disablePlan) {
        $status = $i['Status']
        if (-not $status) { $status = 'KeptEnabled' }
        [void]$disables.Add(@{ Sid = $i['Sid']; Name = $i['Name']; Kind = $i['Kind']; Replacement = $i['ReplacementName']; MovedTo = $i['MovedTo']; IsRunning = $i['IsRunning']; Status = $status; Reason = $i['Reason'] })
    }

    $failed = [bool]$ctx['EnforcementFailed']
    foreach ($sr in $slots) { if ($sr['Status'] -eq 'Failed') { $failed = $true } }
    foreach ($fx in (ConvertTo-CrArray $fixes)) { if ($fx['Status'] -eq 'Failed') { $failed = $true } }
    if ($result['AutoLogon'] -and -not $result['AutoLogon']['Success']) { $failed = $true }
    $followUps = @($ctx['Findings'] | Where-Object { $_['Severity'] -eq 'FollowUp' })

    $result['Slots'] = $slots.ToArray()
    $result['Disables'] = $disables.ToArray()
    $result['CheckFixes'] = ConvertTo-CrArray $fixes
    $result['ChangedSids'] = $ctx['Changed'].ToArray()
    $result['CreatedSids'] = $ctx['Created'].ToArray()
    $result['VerifiedSids'] = $ctx['Verified'].ToArray()
    $result['RemovedAdminSids'] = $ctx['RemovedAdmins'].ToArray()
    if ($failed) { $result['ExitCode'] = 1 } elseif ($followUps.Count -gt 0) { $result['ExitCode'] = 4 } else { $result['ExitCode'] = 0 }
    Write-CrLog ('Apply finished with exit code {0}' -f $result['ExitCode'])
    return $result
}

# Probes the Change-mode accounts (ApplicationUser) of every slot that will be applied (PLAN 6 step 7; set and
# created accounts are not probed). Returns a hashtable SID -> probe result.
function Invoke-CrSlotProbes {
    param($State, $Config, $Resolved, $Preflight, $SlotSecrets, $Journal, [string]$RunId, [string[]]$Only)
    $probes = @{}
    $preview = Get-CrApplyPreview -Config $Config -Resolved $Resolved -Preflight $Preflight -SlotSecrets $SlotSecrets -Probes @{} -Only $Only
    foreach ($p in $preview) {
        if ($p['Status'] -ne 'Apply' -and -not ($p['Status'] -eq 'Skipped' -and @($p['Accounts']).Count -gt 0)) { continue }
        $slotSecret = $SlotSecrets[$p['Slot']]
        if (-not ($slotSecret -is [hashtable])) { continue }
        foreach ($a in (ConvertTo-CrArray $p['Accounts'])) {
            if ($a['PasswordMode'] -ne 'Change' -or -not $a['Sid'] -or $a['Path'] -eq 'Create') { continue }
            if (-not ($a['SecretAccount'] -is [hashtable])) { continue }
            $acct = Find-CrApplyResolvedAccount -Resolved $Resolved -Sid $a['Sid']
            Write-Host ('Checking the passwords of {0} ...' -f $a['Name'])
            $probe = Invoke-CrCredentialProbe -State $State -Account $acct -OldSecret $a['SecretAccount']['OldSecret'] -NewSecret $slotSecret['NewSecret'] -Journal $Journal -RunId $RunId
            $probes[[string]$a['Sid']] = $probe
            if ($probe -is [hashtable]) {
                Write-CrLog ('Probe {0}: {1} ({2}, error {3}, attempts {4})' -f $a['Name'], $probe['Outcome'], $probe['LogonType'], $probe['Win32Error'], $probe['Attempts'])
            }
        }
    }
    return $probes
}

# Single-letter operator choice through Read-CrHostLine (Secrets.ps1, mockable). Not for secrets.
# Asks at most 3 times; then the safe default (-Default, e.g. skip / keep / leave unchanged) is returned.
function Read-CrOperatorChoice {
    param([string]$Prompt, [string[]]$Choices, [string]$Default)
    for ($i = 0; $i -lt 3; $i++) {
        $a = ([string](Read-CrHostLine -Prompt $Prompt)).Trim().ToUpperInvariant()
        if (@($Choices) -contains $a) { return $a }
        Write-Host ('Please answer one of: {0}' -f (@($Choices) -join ', '))
    }
    Write-Host ('No valid answer; using {0}.' -f $Default)
    return $Default
}

# Disposes a replaced secret unless another account of the slots still references the same object.
function Clear-CrReplacedSecret {
    param($SlotSecrets, $Secret)
    if (-not ($Secret -is [System.Security.SecureString])) { return }
    foreach ($k in @($SlotSecrets.Keys)) {
        $s = $SlotSecrets[$k]
        if (-not ($s -is [hashtable])) { continue }
        if ([object]::ReferenceEquals($s['NewSecret'], $Secret)) { return }
        foreach ($a in (ConvertTo-CrArray $s['Accounts'])) {
            if ($a -is [hashtable] -and [object]::ReferenceEquals($a['OldSecret'], $Secret)) { return }
        }
    }
    try { $Secret.Dispose() } catch { }
}

# Operator decisions for the Change accounts before YES (D9, D13, PLAN 6 step 7): both passwords failed, lockout budget
# exhausted, disabled account, minimum password age not reached. Stores the choice on the probe (Path = 'Set'|'Skip')
# or re-probes.
function Resolve-CrProbeDecisions {
    param($State, $Config, $Resolved, $Preflight, $SlotSecrets, $Probes, $Journal, [string]$RunId, [string[]]$Only)
    $policy = $State['Policy']
    $minAge = [long]0
    $wait = 60
    if ($policy -is [hashtable]) {
        if ($policy['MinPasswordAgeSeconds']) { $minAge = [long]$policy['MinPasswordAgeSeconds'] }
        $w = [long]0
        foreach ($k in @('LockoutObservationSeconds', 'LockoutDurationSeconds')) { if ([long]$policy[$k] -gt $w) { $w = [long]$policy[$k] } }
        if ($w -gt 0) { $wait = [int]($w + 5) }
    }
    $dpapi = 'set the password (DPAPI-protected data of the account, e.g. SQL Server and application keys, saved credentials and EFS keys, is lost)'
    $preview = Get-CrApplyPreview -Config $Config -Resolved $Resolved -Preflight $Preflight -SlotSecrets $SlotSecrets -Probes $Probes -Only $Only
    foreach ($p in $preview) {
        $slotSecret = $SlotSecrets[$p['Slot']]
        if (-not ($slotSecret -is [hashtable]) -or $slotSecret['Skipped']) { continue }
        foreach ($a in (ConvertTo-CrArray $p['Accounts'])) {
            if ($a['PasswordMode'] -ne 'Change' -or -not $a['Sid']) { continue }
            $sid = [string]$a['Sid']
            $sa = $a['SecretAccount']
            if (-not ($sa -is [hashtable])) { continue }
            $name = $a['Name']
            $rounds = 0
            while ($rounds -lt 10) {
                $rounds++
                $probe = $Probes[$sid]
                if (-not ($probe -is [hashtable]) -or $probe['Path']) { break }
                $outcome = [string]$probe['Outcome']
                $user = Find-CrApplyUser -State $State -Sid $sid
                $tooYoung = ($minAge -gt 0 -and $user -and $null -ne $user['PasswordAgeSeconds'] -and [long]$user['PasswordAgeSeconds'] -lt $minAge)
                $c = $null
                if ($outcome -eq 'BothFailed') {
                    Write-Host ''
                    Write-Host ('{0}: neither the entered old password nor the new password works.' -f $name)
                    $c = Read-CrOperatorChoice -Prompt ('[E] enter the old password again, [S] ' + $dpapi + ', [K] skip this account') -Choices @('E', 'S', 'K') -Default 'K'
                } elseif ($outcome -eq 'BudgetExceeded') {
                    Write-Host ''
                    Write-Host ('{0}: the lockout budget allows no further password test now (D12).' -f $name)
                    $c = Read-CrOperatorChoice -Prompt ('[W] wait {0} seconds and test again, [S] {1}, [K] skip this account' -f $wait, $dpapi) -Choices @('W', 'S', 'K') -Default 'K'
                } elseif ($outcome -eq 'Disabled') {
                    Write-Host ''
                    Write-Host ('{0}: the account is disabled, so its old password cannot be validated.' -f $name)
                    $c = Read-CrOperatorChoice -Prompt ('[S] ' + $dpapi + ' and enable the account, [K] skip this account') -Choices @('S', 'K') -Default 'K'
                } elseif ($tooYoung -and (@('Old', 'Unverifiable', 'Locked') -contains $outcome) -and -not $sa['Reapply']) {
                    Write-Host ''
                    Write-Host ('{0}: the minimum password age is not reached, so a change is impossible today.' -f $name)
                    $c = Read-CrOperatorChoice -Prompt ('[S] ' + $dpapi + ', [K] skip this account') -Choices @('S', 'K') -Default 'K'
                } else {
                    break
                }
                if ($c -eq 'S') { $probe['Path'] = 'Set'; break }
                if ($c -eq 'K') { $probe['Path'] = 'Skip'; break }
                if ($c -eq 'W') {
                    Write-Host ('Waiting {0} seconds ...' -f $wait)
                    Start-Sleep -Seconds $wait
                }
                if ($c -eq 'E') {
                    $again = Read-CrSecureHost -Prompt ('Current (old) password of {0}' -f $name)
                    $previous = $sa['OldSecret']
                    $sa['OldSecret'] = $again
                    $sa['Reapply'] = [bool](Test-CrSecretEqual -A $again -B $slotSecret['NewSecret'])
                    Clear-CrReplacedSecret -SlotSecrets $SlotSecrets -Secret $previous
                }
                $acct = Find-CrApplyResolvedAccount -Resolved $Resolved -Sid $sid
                $Probes[$sid] = Invoke-CrCredentialProbe -State $State -Account $acct -OldSecret $sa['OldSecret'] -NewSecret $slotSecret['NewSecret'] -Journal $Journal -RunId $RunId
            }
        }
    }
}

# Operator decision per account without replacement that runs dependents (D24, O5): move them to the application
# account (ApplicationUser) or keep the account enabled. Returns a hashtable SID -> 'Move'|'Keep'.
function Read-CrDependentDecisions {
    param($DisablePlan, $Resolved)
    $decisions = @{}
    $appEntry = Get-CrApplyAppUserEntry -Resolved $Resolved
    foreach ($item in (ConvertTo-CrArray $DisablePlan)) {
        if (-not $item['NeedsDecision']) { continue }
        $deps = New-Object System.Collections.ArrayList
        foreach ($x in (Join-CrApplyList (Join-CrApplyList $item['Services'] $item['Tasks']) $item['ComPlus'])) { [void]$deps.Add((Get-CrApplyItemLabel $x)) }
        Write-Host ''
        Write-Host ('{0} is to be disabled but runs: {1}' -f $item['Name'], (($deps.ToArray()) -join ', '))
        if (-not $appEntry) {
            Write-Host '  No application account is configured to take them over; the account stays enabled.'
            $decisions[$item['Sid']] = 'Keep'
            continue
        }
        $appName = Get-CrApplyEntryAccountName $appEntry
        $c = Read-CrOperatorChoice -Prompt ('[M] move them to {0} (with its new password) and disable {1}, [K] keep {1} enabled' -f $appName, $item['Name']) -Choices @('M', 'K') -Default 'K'
        if ($c -eq 'M') { $decisions[$item['Sid']] = 'Move' } else { $decisions[$item['Sid']] = 'Keep' }
        Write-CrLog ('Dependents of {0}: operator decision {1}' -f $item['Name'], $decisions[$item['Sid']])
    }
    return $decisions
}

# The auto-logon decision the run is expected to reach (for the summary before YES and the operator's choice).
# Accounts the run creates are passed by name (-CreatedTargetNames); they count as verified, like the accounts the
# plan sets or changes. $null when the step does not run.
function Get-CrApplyAutoLogonPreview {
    param($State, $Config, $Resolved, $Preview, [string]$RunningSid, [string[]]$Only)
    if (-not (Test-CrApplyAutoLogonSelected -State $State -Resolved $Resolved -Only $Only)) { return $null }
    $al = $State['AutoLogon']
    if (-not ($al -is [hashtable]) -or $al['Error']) { return $null }
    $verified = New-Object System.Collections.ArrayList
    $created = New-Object System.Collections.ArrayList
    $removed = New-Object System.Collections.ArrayList
    foreach ($p in (ConvertTo-CrArray $Preview)) {
        if ($p['Status'] -ne 'Apply') { continue }
        $complete = $true
        foreach ($a in (ConvertTo-CrArray $p['Accounts'])) {
            if ($a['Path'] -eq 'Skip') { $complete = $false; continue }
            if ($a['Path'] -eq 'Create') { [void]$created.Add([string]$a['Name']) } elseif ($a['Sid']) { [void]$verified.Add([string]$a['Sid']) }
        }
        if (-not $complete) { continue }
        foreach ($a in (ConvertTo-CrArray $p['Accounts'])) {
            if (-not $a['Sid'] -or $a['Path'] -eq 'Create') { continue }
            $role = $a['Entry']['Role']
            if (-not ($role -is [hashtable])) { $role = @{} }
            $gp = Get-CrGroupPlan -State $State -Role $role -Sid $a['Sid'] -RunningSid $RunningSid
            if (-not $gp['Skip'] -and ((ConvertTo-CrArray $gp['Remove']) -contains 'S-1-5-32-544')) { [void]$removed.Add([string]$a['Sid']) }
        }
    }
    return (Get-CrAutoLogonDecision -State $State -Resolved $Resolved -Config $Config -VerifiedSids ($verified.ToArray()) -RemovedAdminSids ($removed.ToArray()) -CreatedTargetNames ([string[]]$created.ToArray([string])))
}

# Asks the operator for an ambiguous auto-logon decision (D13). Returns 'TurnOff'|'LeaveUnchanged'|'StandardizeCurrent'.
function Read-CrAutoLogonChoice {
    param($Decision)
    $opts = ConvertTo-CrArray $Decision['OperatorOptions']
    if ($opts.Count -eq 0) { return 'LeaveUnchanged' }
    Write-Host ''
    Write-Host ('Auto-logon needs your decision (current account: {0}):' -f $Decision['CurrentName'])
    foreach ($r in (ConvertTo-CrArray $Decision['Reasons'])) { Write-Host ('  - ' + $r) }
    $map = @{ T = 'TurnOff'; L = 'LeaveUnchanged'; C = 'StandardizeCurrent' }
    $letters = New-Object System.Collections.ArrayList
    $texts = New-Object System.Collections.ArrayList
    if ($opts -contains 'TurnOff') { [void]$letters.Add('T'); [void]$texts.Add('[T] turn auto-logon off') }
    if ($opts -contains 'LeaveUnchanged') { [void]$letters.Add('L'); [void]$texts.Add('[L] leave it unchanged') }
    if ($opts -contains 'StandardizeCurrent') { [void]$letters.Add('C'); [void]$texts.Add(('[C] standardize the current account {0}' -f $Decision['CurrentName'])) }
    $default = 'L'
    if ($letters -notcontains 'L') { $default = [string]$letters[0] }
    $c = Read-CrOperatorChoice -Prompt (($texts.ToArray()) -join ', ') -Choices ($letters.ToArray()) -Default $default
    return $map[$c]
}

# The enabled local accounts and what happens to each (D21), printed before the prompts.
function Write-CrApplyAccountOverview {
    param($Fates)
    Write-Host ''
    Write-Host '=============== LOCAL ACCOUNTS (enabled) ==============='
    foreach ($f in (ConvertTo-CrArray $Fates)) {
        if ($f['Fate'] -eq 'create') { continue }
        Write-Host ('  {0,-22} {1,-8} {2}' -f $f['Name'], $f['Fate'].ToUpperInvariant(), $f['Detail'])
    }
    $create = @((ConvertTo-CrArray $Fates) | Where-Object { $_['Fate'] -eq 'create' })
    if ($create.Count -gt 0) {
        Write-Host 'To be created:'
        foreach ($f in $create) { Write-Host ('  {0,-22} {1,-8} {2}' -f $f['Name'], 'CREATE', $f['Detail']) }
    }
    Write-Host '========================================================'
}

function Get-CrApplyDisableText {
    param($Item)
    $text = 'disable'
    if ($Item['Kind'] -eq 'Replaced') { $text = 'disable, replaced by ' + $Item['ReplacementName'] }
    elseif ($Item['Kind'] -eq 'Disable') { $text = 'disable, retired without replacement' }
    else { $text = 'disable, your decision' }
    if ($Item['IsRunning']) { $text = $text + '; your own account: LAST, only when the operator account is ready (D25)' }
    if (-not $Item['Planned']) { $text = 'not disabled: ' + $Item['Reason'] }
    return $text
}

# The summary shown before the decisions and YES (PLAN 6 step 8): creations, sets/changes, disables with replacements,
# dependent moves, the auto-logon step, the running account and all high-impact and ambiguous findings.
# Prints names and outcomes only.
function Write-CrApplySummary {
    param($Preview, $DisablePlan, $Plan, $AutoLogonDecision, [string[]]$Only)
    Write-Host ''
    Write-Host '=================== APPLY PLAN ==================='
    foreach ($p in (ConvertTo-CrArray $Preview)) {
        $label = ''
        if ($p['Label']) { $label = ' (' + $p['Label'] + ')' }
        if ($p['Status'] -eq 'Apply') {
            Write-Host ('Slot {0}{1}:' -f $p['Slot'], $label)
        } else {
            Write-Host ('Slot {0}{1}: {2} - {3}' -f $p['Slot'], $label, $p['Status'], $p['Reason'])
        }
        foreach ($a in (ConvertTo-CrArray $p['Accounts'])) {
            $outcome = ''
            if ($a['Outcome']) { $outcome = ' [probe: ' + $a['Outcome'] + ']' }
            Write-Host ('    {0,-22} {1}{2}' -f $a['Name'], (Get-CrApplyPathText $a), $outcome)
            if ($a['Probe'] -is [hashtable] -and $a['Probe']['Message']) { Write-Host ('        ' + $a['Probe']['Message']) }
        }
    }
    Write-Host ''
    $items = ConvertTo-CrArray $DisablePlan
    if ($items.Count -gt 0) {
        Write-Host 'Accounts to disable (groups and password unchanged, D22):'
        foreach ($i in $items) {
            Write-Host ('    {0,-22} {1}' -f $i['Name'], (Get-CrApplyDisableText $i))
            $deps = New-Object System.Collections.ArrayList
            foreach ($x in (Join-CrApplyList (Join-CrApplyList $i['Services'] $i['Tasks']) $i['ComPlus'])) { [void]$deps.Add((Get-CrApplyItemLabel $x)) }
            if ($deps.Count -gt 0) {
                $to = 'operator decides'
                if ($i['MoveEntry'] -is [hashtable] -and $i['Planned']) { $to = Get-CrApplyEntryAccountName $i['MoveEntry'] }
                Write-Host ('        dependents moved to {0} (D24): {1}' -f $to, (($deps.ToArray()) -join ', '))
            }
        }
        Write-Host ''
    }
    if ($AutoLogonDecision -is [hashtable]) {
        $line = 'Auto-logon step (after the group removals and moves): ' + $AutoLogonDecision['Action']
        if ($AutoLogonDecision['TargetName']) { $line = $line + ' -> ' + $AutoLogonDecision['TargetName'] }
        if ($AutoLogonDecision['CurrentName']) { $line = $line + ' (current: ' + $AutoLogonDecision['CurrentName'] + ')' }
        Write-Host $line
    } else {
        Write-Host 'Auto-logon step: not run in this selection.'
    }
    if (-not (Test-CrApplyOnlyGiven $Only)) {
        Write-Host 'Check-mode accounts: flags and exclusive groups are fixed after the disabling step.'
    } else {
        Write-Host 'Check-mode, retired and other accounts: not processed under -Only.'
    }
    $findings = ConvertTo-CrArray $Plan['Findings']
    $important = @($findings | Where-Object { $_ -is [hashtable] -and ($_['Severity'] -eq 'HighImpact' -or $_['Severity'] -eq 'Ambiguous') })
    if ($important.Count -gt 0) {
        Write-Host ''
        Write-Host ('High-impact and ambiguous items ({0}):' -f $important.Count)
        foreach ($f in $important) {
            $who = @($f['Slot'], $f['Account'] | Where-Object { $_ }) -join ' / '
            if ($who) { $who = '[' + $who + '] ' }
            Write-Host ('  - {0}: {1}{2}: {3}' -f $f['Severity'], $who, $f['Area'], $f['Message'])
        }
    }
    Write-Host ''
    Write-Host 'YES confirms, in this order: per slot the account creation, the password set or change, enabling, flags,'
    Write-Host 'group additions, logon rights and its own services/tasks/COM+ (no restarts, D17) and a logon test; then the'
    Write-Host 'group removals, the moves of dependents to the replacements, the auto-logon step, the disabling of the'
    Write-Host 'replaced and chosen accounts, the check-mode fixes and, last, the disabling of your own account (D25).'
    Write-Host '=================================================='
}

# Slot results, disables and the FOLLOW-UP REQUIRED section after the apply (PLAN 6 step 11).
function Write-CrApplyResult {
    param($Result)
    Write-Host ''
    Write-Host '=== Slot results ==='
    foreach ($s in (ConvertTo-CrArray $Result['Slots'])) {
        $line = '{0,-22} {1}' -f $s['Slot'], $s['Status']
        if ($s['FailedStep']) { $line = $line + ' (stopped at ' + $s['FailedStep'] + ')' }
        if ($s['Reason']) { $line = $line + ' - ' + $s['Reason'] }
        Write-Host $line
        foreach ($d in (ConvertTo-CrArray $s['Done'])) { Write-Host ('    done:    ' + $d) }
        foreach ($n in (ConvertTo-CrArray $s['Notes'])) { Write-Host ('    note:    ' + $n) }
        foreach ($e in (ConvertTo-CrArray $s['Errors'])) { Write-Host ('    error:   ' + $e) }
        foreach ($p in (ConvertTo-CrArray $s['Pending'])) { Write-Host ('    pending: ' + $p) }
    }
    $dis = ConvertTo-CrArray $Result['Disables']
    if ($dis.Count -gt 0) {
        Write-Host '=== Accounts to disable ==='
        foreach ($d in $dis) {
            $line = '{0,-22} {1}' -f $d['Name'], $d['Status']
            if ($d['MovedTo']) { $line = $line + ' (dependents moved to ' + $d['MovedTo'] + ')' }
            if ($d['Status'] -ne 'Disabled' -and $d['Reason']) { $line = $line + ' - ' + $d['Reason'] }
            Write-Host $line
        }
    }
    foreach ($fx in (ConvertTo-CrArray $Result['CheckFixes'])) {
        Write-Host ('{0,-22} {1} (check mode)' -f $fx['Id'], $fx['Status'])
        foreach ($e in (ConvertTo-CrArray $fx['Errors'])) { Write-Host ('    error:   ' + $e) }
    }
    $al = $Result['AutoLogon']
    if ($al -is [hashtable] -and $al['Ran']) {
        $state = 'OK'
        if (-not $al['Success']) { $state = 'FAILED' }
        Write-Host ('{0,-22} {1} ({2})' -f 'Auto-logon step', $al['Action'], $state)
        if ($al['FailedStep']) { Write-Host ('    failed at: ' + $al['FailedStep']) }
        if ($al['Pending']) { Write-Host ('    pending: ' + $al['Pending']) }
    }
    $all = ConvertTo-CrArray $Result['Findings']
    $follow = @($all | Where-Object { $_['Severity'] -eq 'FollowUp' })
    if ($follow.Count -gt 0) {
        Write-Host ''
        Write-Host '=== FOLLOW-UP REQUIRED ==='
        foreach ($f in $follow) { Write-Host ('- [{0} / {1}] {2}: {3}' -f $f['Slot'], $f['Account'], $f['Area'], $f['Message']) }
    }
}

# Disposes every SecureString of the slot secrets (end of the run, also after Ctrl+C).
function Clear-CrSlotSecrets {
    param($SlotSecrets)
    if (-not ($SlotSecrets -is [hashtable])) { return }
    foreach ($k in @($SlotSecrets.Keys)) {
        $s = $SlotSecrets[$k]
        if (-not ($s -is [hashtable])) { continue }
        if ($s['NewSecret'] -is [System.Security.SecureString]) { try { $s['NewSecret'].Dispose() } catch { } }
        foreach ($a in (ConvertTo-CrArray $s['Accounts'])) {
            if ($a -is [hashtable] -and $a['OldSecret'] -is [System.Security.SecureString]) { try { $a['OldSecret'].Dispose() } catch { } }
        }
    }
}

#endregion
