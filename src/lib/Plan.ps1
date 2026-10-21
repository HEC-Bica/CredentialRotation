# Plan.ps1 - desired vs actual -> findings (docs/PLAN.md sections 6 step 5, 7, 8, D21-D29; docs/dev/CONTRACTS.md)

# SIDs of the local groups that list $Sid as a direct member.
function Get-CrDirectGroupSids {
    param($State, [string]$Sid)
    $result = New-Object System.Collections.ArrayList
    foreach ($g in (ConvertTo-CrArray $State['Groups'])) {
        if ((ConvertTo-CrArray $g['MemberSids']) -contains $Sid) { [void]$result.Add($g['Sid']) }
    }
    return , $result.ToArray()
}

function Get-CrGroupName {
    param($State, [string]$Sid)
    foreach ($g in (ConvertTo-CrArray $State['Groups'])) {
        if ($g['Sid'] -eq $Sid) { return $g['Name'] }
    }
    $n = Resolve-CrSidToName $Sid
    if ($n) { return $n }
    return $Sid
}

# SIDs with an Allow rule on a folder (read-only). Separate function so tests can mock it.
function Get-CrPathAllowSids {
    param([string]$Path)
    $expanded = [Environment]::ExpandEnvironmentVariables($Path)
    if (-not (Test-Path -LiteralPath $expanded)) { return , @() }
    $acl = Get-CrDirectoryAcl -Path $expanded
    $sids = New-Object System.Collections.ArrayList
    foreach ($rule in @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))) {
        if ($rule.AccessControlType -eq 'Allow') { [void]$sids.Add($rule.IdentityReference.Value) }
    }
    return , $sids.ToArray()
}

# Returns a copy of $State without the given groups, for "what if the account were not in them" right
# checks (PLAN 6 step 5). The whole group is dropped: Users would otherwise still reach the token through
# its well-known members (Authenticated Users, INTERACTIVE).
function Copy-CrStateWithoutGroups {
    param($State, [string[]]$GroupSids)
    $copy = @{}
    foreach ($k in $State.Keys) { $copy[$k] = $State[$k] }
    $groups = New-Object System.Collections.ArrayList
    foreach ($g in (ConvertTo-CrArray $State['Groups'])) {
        if (@($GroupSids) -notcontains $g['Sid']) { [void]$groups.Add($g) }
    }
    $copy['Groups'] = $groups.ToArray()
    return $copy
}

# Group targets for one Windows account: adds, removals, and notes (PLAN 7.2).
function Get-CrGroupPlan {
    param($State, $Role, [string]$Sid, [string]$RunningSid)
    $plan = @{ Add = @(); Remove = @(); Notes = @(); Skip = $false; Rail = @() }
    $roleGroups = ConvertTo-CrArray $Role['Groups']
    if ($roleGroups.Count -eq 0) { return $plan }
    $targets = New-Object System.Collections.ArrayList
    $missing = New-Object System.Collections.ArrayList
    foreach ($ref in $roleGroups) {
        $r = Resolve-CrGroupReference -Reference $ref -State $State
        if ($r['Missing'] -and -not $r['Optional']) { [void]$missing.Add($ref); continue }
        foreach ($s in (ConvertTo-CrArray $r['Sids'])) { [void]$targets.Add($s) }
    }
    if ($missing.Count -gt 0) {
        $plan['Skip'] = $true
        $plan['Notes'] = @('Required group missing: ' + (($missing.ToArray()) -join ', ') + '; groups left unchanged')
        return $plan
    }
    $allowed = New-Object System.Collections.ArrayList
    foreach ($ref in (ConvertTo-CrArray $Role['AllowedExtraGroups'])) {
        $r = Resolve-CrGroupReference -Reference $ref -State $State
        foreach ($s in (ConvertTo-CrArray $r['Sids'])) { [void]$allowed.Add($s) }
    }
    $current = Get-CrDirectGroupSids -State $State -Sid $Sid
    $plan['Add'] = @($targets | Where-Object { @($current) -notcontains $_ } | Select-Object -Unique)
    if ($Role['ExclusiveGroups']) {
        $remove = New-Object System.Collections.ArrayList
        foreach ($g in $current) {
            if ($targets -contains $g) { continue }
            if ($allowed -contains $g) { continue }
            # Rails (PLAN 7.2): never remove the running account from Administrators.
            if ($g -eq 'S-1-5-32-544' -and $Sid -eq $RunningSid) {
                $plan['Rail'] = @($plan['Rail']) + @('running account stays in Administrators')
                continue
            }
            [void]$remove.Add($g)
        }
        $plan['Remove'] = $remove.ToArray()
    }
    return $plan
}

function Add-CrPlanFinding {
    param($Plan, [string]$Severity, [string]$Area, [string]$Message, [string]$Slot, [string]$Account, [string]$Detail)
    $f = New-CrFinding -Severity $Severity -Area $Area -Message $Message -Slot $Slot -Account $Account -Detail $Detail
    [void]$Plan['Findings'].Add($f)
    if ($Severity -eq 'Drift') { $Plan['Drift'] = $true }
}

# Windows refuses to change "user cannot change password" of a member of Administrators (NetUserSetInfo: 1322,
# ERROR_LAST_ADMIN, also when other administrators exist), so it is reported, not drift (Set-CrAccountFlags).
function Get-CrCcpNotSetText {
    return 'Not set: "user cannot change password"; Windows refuses that for members of Administrators (error 1322)'
}

function Add-CrAccountFlagFindings {
    param($Plan, $Role, $User, [string]$Slot, [bool]$InAdministrators)
    $name = $User['Name']
    if ($Role['PasswordNeverExpires'] -and -not $User['PasswordNeverExpires']) {
        Add-CrPlanFinding $Plan 'Drift' 'Flags' 'Set "password never expires"' $Slot $name
    }
    if ($Role['CannotChangePassword'] -and -not $User['CannotChangePassword']) {
        if ($InAdministrators) {
            Add-CrPlanFinding $Plan 'Info' 'Flags' (Get-CrCcpNotSetText) $Slot $name
        } else {
            Add-CrPlanFinding $Plan 'Drift' 'Flags' 'Set "user cannot change password"' $Slot $name
        }
    }
    if ($Role['PasswordRequired'] -and $User['PasswordNotRequired']) {
        Add-CrPlanFinding $Plan 'Drift' 'Flags' 'Clear "password not required" (UF_PASSWD_NOTREQD)' $Slot $name
    }
}

function Add-CrGroupFindings {
    param($Plan, $State, $Role, $User, [string]$Slot, [string]$RunningSid, $RemovedAdminSids)
    $name = $User['Name']
    $gp = Get-CrGroupPlan -State $State -Role $Role -Sid $User['Sid'] -RunningSid $RunningSid
    foreach ($n in (ConvertTo-CrArray $gp['Notes'])) { Add-CrPlanFinding $Plan 'Info' 'Groups' $n $Slot $name }
    if ($gp['Skip']) { return }
    foreach ($g in (ConvertTo-CrArray $gp['Add'])) {
        Add-CrPlanFinding $Plan 'Drift' 'Groups' ('Add to ' + (Get-CrGroupName $State $g)) $Slot $name
    }
    foreach ($g in (ConvertTo-CrArray $gp['Remove'])) {
        Add-CrPlanFinding $Plan 'Drift' 'Groups' ('Remove from ' + (Get-CrGroupName $State $g) + ' (enforcement phase)') $Slot $name
        if ($g -eq 'S-1-5-32-544') { [void]$RemovedAdminSids.Add($User['Sid']) }
    }
    foreach ($r in (ConvertTo-CrArray $gp['Rail'])) { Add-CrPlanFinding $Plan 'Info' 'Groups' ('Rail: ' + $r) $Slot $name }

    # Leaving Users (FTP users): check what depends on it (PLAN 6 step 5).
    if ((ConvertTo-CrArray $gp['Remove']) -contains 'S-1-5-32-545') {
        Add-CrUsersRemovalImpact -Plan $Plan -State $State -User $User -Slot $Slot -RemainingGroups (ConvertTo-CrArray $Role['Groups'])
    }
}

function Add-CrUsersRemovalImpact {
    param($Plan, $State, $User, [string]$Slot, $RemainingGroups)
    $name = $User['Name']
    $sid = $User['Sid']
    $after = Copy-CrStateWithoutGroups -State $State -GroupSids @('S-1-5-32-545')
    $before = Get-CrEffectiveLogonRights -UserSid $sid -State $State
    $now = Get-CrEffectiveLogonRights -UserSid $sid -State $after
    if ($before['Network'] -and -not $now['Network']) {
        Add-CrPlanFinding $Plan 'HighImpact' 'Groups' 'Leaving Users removes the network logon right (FTP logon would fail)' $Slot $name
    }
    $keep = New-Object System.Collections.ArrayList
    foreach ($s in @($sid, 'S-1-1-0', 'S-1-5-11')) { [void]$keep.Add($s) }
    foreach ($ref in $RemainingGroups) {
        $r = Resolve-CrGroupReference -Reference $ref -State $State
        foreach ($s in (ConvertTo-CrArray $r['Sids'])) { [void]$keep.Add($s) }
    }
    $iis = $State['Iis']
    if (-not $iis -or -not $iis['Installed']) { return }
    foreach ($vd in (ConvertTo-CrArray $iis['VirtualDirectories'])) {
        if ((ConvertTo-CrArray $vd['Protocols']) -notcontains 'ftp') { continue }
        if (-not $vd['PhysicalPath']) { continue }
        try {
            $allow = Get-CrPathAllowSids -Path $vd['PhysicalPath']
        } catch {
            Add-CrPlanFinding $Plan 'Info' 'Groups' ('Could not read the ACL of ' + $vd['PhysicalPath']) $Slot $name $_.Exception.Message
            continue
        }
        $viaUsersOnly = (@($allow) -contains 'S-1-5-32-545') -and -not (@($allow | Where-Object { $keep -contains $_ }).Count -gt 0)
        if ($viaUsersOnly) {
            Add-CrPlanFinding $Plan 'HighImpact' 'Groups' ('FTP folder access is granted only through Users: ' + $vd['Site'] + $vd['Path'] + ' -> ' + $vd['PhysicalPath']) $Slot $name
        }
    }
}

# Dependents of a rotated Windows account (PLAN 7.3, 7.4, 7.6, 7.7).
function Add-CrDependentFindings {
    param($Plan, $State, $Entry, $User, [string]$Slot)
    $name = $User['Name']
    $sid = $User['Sid']
    # Each kind is managed by its own config key (Services / ScheduledTasks / ComPlus = 'Auto').
    $cfg = $Entry['Config']
    $managedServices = (($cfg -is [hashtable]) -and [string]$cfg['Services'] -eq 'Auto')
    $managedTasks = (($cfg -is [hashtable]) -and [string]$cfg['ScheduledTasks'] -eq 'Auto')
    $managedComPlus = (($cfg -is [hashtable]) -and [string]$cfg['ComPlus'] -eq 'Auto')
    $allServices = ConvertTo-CrArray $State['Services']
    $allTasks = ConvertTo-CrArray $State['Tasks']
    $allComPlus = ConvertTo-CrArray $State['ComPlus']
    $services = @($allServices | Where-Object { $_['StartNameSid'] -eq $sid })
    $tasks = @($allTasks | Where-Object { $_['UserSid'] -eq $sid -and (@(1, 6) -contains [int]$_['LogonType']) })
    $complus = @($allComPlus | Where-Object { $_['IdentitySid'] -eq $sid -and $_['Activation'] -eq 'Server' })
    $rights = Get-CrEffectiveLogonRights -UserSid $sid -State $State

    foreach ($s in $services) {
        if ($managedServices) {
            Add-CrPlanFinding $Plan 'Info' 'Services' ('SCM credential update, restart pending (D17): ' + $s['Name']) $Slot $name
            if ($s['Name'] -eq 'MSSQLSERVER' -or $s['Name'] -like 'MSSQL$*') {
                Add-CrPlanFinding $Plan 'HighImpact' 'Services' ('SQL Server runs as this account; it starts with the new password at its next start: ' + $s['Name']) $Slot $name
            }
        } else {
            Add-CrPlanFinding $Plan 'HighImpact' 'Services' ('Service runs as this account but the configuration does not manage its dependents: ' + $s['Name']) $Slot $name
        }
    }
    if ($services.Count -gt 0) { Add-CrRightFinding $Plan $State $sid $name $Slot 'SeServiceLogonRight' 'SeDenyServiceLogonRight' $rights['Service'] }

    foreach ($t in $tasks) {
        $sev = 'Info'; $msg = 'Scheduled task re-registered with the new password: '
        if (-not $managedTasks) { $sev = 'HighImpact'; $msg = 'Scheduled task stores this account''s password but the configuration does not manage it: ' }
        Add-CrPlanFinding $Plan $sev 'Tasks' ($msg + $t['Path'] + ' (LogonType ' + $t['LogonType'] + ')') $Slot $name
    }
    if ($tasks.Count -gt 0) { Add-CrRightFinding $Plan $State $sid $name $Slot 'SeBatchLogonRight' 'SeDenyBatchLogonRight' $rights['Batch'] }

    foreach ($c in $complus) {
        $sev = 'Info'; $msg = 'COM+ identity updated, restart pending (D17): '
        if (-not $managedComPlus) { $sev = 'HighImpact'; $msg = 'COM+ application runs as this account but the configuration does not manage it: ' }
        Add-CrPlanFinding $Plan $sev 'ComPlus' ($msg + $c['Name']) $Slot $name
    }
    $allDcom = ConvertTo-CrArray $State['Dcom']
    foreach ($d in @($allDcom | Where-Object { $_['RunAsSid'] -eq $sid })) {
        Add-CrPlanFinding $Plan 'Info' 'Dcom' ('DCOM RunAs uses this account (report only): ' + $d['AppId'] + ' ' + $d['Name']) $Slot $name
    }
    $iis = $State['Iis']
    if ($iis -and $iis['Installed']) {
        $allPools = ConvertTo-CrArray $iis['AppPools']
        $allVdirs = ConvertTo-CrArray $iis['VirtualDirectories']
        foreach ($p in @($allPools | Where-Object { $_['UserSid'] -eq $sid })) {
            Add-CrPlanFinding $Plan 'FollowUp' 'IIS' ('Application pool identity to update manually in IIS Manager: ' + $p['Name']) $Slot $name
        }
        foreach ($v in @($allVdirs | Where-Object { $_['UserSid'] -eq $sid })) {
            Add-CrPlanFinding $Plan 'FollowUp' 'IIS' ('"Connect as" credential to update manually: ' + $v['Site'] + $v['Path']) $Slot $name
        }
    }
}

function Add-CrRightFinding {
    param($Plan, $State, [string]$Sid, [string]$Name, [string]$Slot, [string]$Right, [string]$DenyRight, $Effective)
    if ($Effective) { return }
    $denied = $false
    $rightsMap = $State['Rights']
    if ($rightsMap) {
        $tokenType = 'Service'
        if ($Right -eq 'SeBatchLogonRight') { $tokenType = 'Batch' }
        $token = Get-CrTokenSids -UserSid $Sid -State $State -LogonType $tokenType
        foreach ($s in (ConvertTo-CrArray $rightsMap[$DenyRight])) { if (@($token) -contains $s) { $denied = $true } }
    }
    if ($denied) {
        Add-CrPlanFinding $Plan 'HighImpact' 'Rights' ($Right + ' is denied to this account; its dependents cannot log on today. Rotation continues (PLAN 7.3).') $Slot $Name
    } else {
        Add-CrPlanFinding $Plan 'Drift' 'Rights' ('Grant ' + $Right + ' (needed by its dependents)') $Slot $Name
    }
}

# Password findings of an existing managed Windows account. D9 (v10): 'Set' accounts get no old-password
# probe; only 'Change' accounts (ApplicationUser) are changed with their validated old password.
function Add-CrWindowsRotationFindings {
    param($Plan, $State, $User, [string]$Slot, [string]$PasswordMode)
    $name = $User['Name']
    $policy = $State['Policy']
    if ($PasswordMode -ne 'Change') {
        Add-CrPlanFinding $Plan 'Info' 'Password' 'Password set (D9: no old password)' $Slot $name
        if ($User['LockedOut']) {
            Add-CrPlanFinding $Plan 'Info' 'Password' 'Account is locked; it is unlocked after YES' $Slot $name
        }
        return
    }
    Add-CrPlanFinding $Plan 'Info' 'Password' 'Password change with the old password (D9: keeps DPAPI data)' $Slot $name
    if ($User['Disabled']) {
        Add-CrPlanFinding $Plan 'HighImpact' 'Password' 'Account is disabled: reset instead of change (DPAPI data is lost)' $Slot $name
    }
    if ($User['LockedOut']) {
        Add-CrPlanFinding $Plan 'Info' 'Password' 'Account is locked; it is unlocked after YES and the old password is validated once' $Slot $name
    }
    if ($policy -and $policy['MinPasswordAgeSeconds'] -gt 0 -and $null -ne $User['PasswordAgeSeconds'] -and $User['PasswordAgeSeconds'] -lt $policy['MinPasswordAgeSeconds']) {
        Add-CrPlanFinding $Plan 'HighImpact' 'Password' 'Minimum password age not reached: reset instead of change (DPAPI impact) or skip' $Slot $name
    }
    $probe = Select-CrProbeLogonType -UserSid $User['Sid'] -State $State
    if (-not $probe['LogonType']) {
        # ForceGuest on and no other logon type allowed (D16): a Network logon could be mapped to Guest.
        Add-CrPlanFinding $Plan 'Info' 'Probe' 'The old password cannot be verified by a test logon (no usable logon type, D16)' $Slot $name `
            'Network logon is not used because ForceGuest is on; NetUserChangePassword itself validates the old password'
        return
    }
    $detail = $null
    if ($probe['Fallback']) { $detail = 'No logon type is clearly allowed; Network is used and error 1385 is interpreted (D16)' }
    Add-CrPlanFinding $Plan 'Info' 'Probe' ('Credential probe logon type: ' + $probe['LogonType']) $Slot $name $detail
}

# Everything on the machine that runs as $Sid (services, tasks, COM+, DCOM, IIS).
# Tasks = password-stored tasks (LogonType 1/6, movable, D24); OtherTasks = the account's other tasks.
function Get-CrAccountDependents {
    param($State, [string]$Sid)
    $d = @{ Services = @(); Tasks = @(); OtherTasks = @(); ComPlus = @(); Dcom = @(); AppPools = @(); VirtualDirectories = @() }
    if (-not $Sid) { return $d }
    $allServices = ConvertTo-CrArray $State['Services']
    $allTasks = ConvertTo-CrArray $State['Tasks']
    $allComPlus = ConvertTo-CrArray $State['ComPlus']
    $allDcom = ConvertTo-CrArray $State['Dcom']
    $d['Services'] = @($allServices | Where-Object { ($_ -is [hashtable]) -and $_['StartNameSid'] -eq $Sid })
    $d['Tasks'] = @($allTasks | Where-Object { ($_ -is [hashtable]) -and $_['UserSid'] -eq $Sid -and (@(1, 6) -contains [int]$_['LogonType']) })
    $d['OtherTasks'] = @($allTasks | Where-Object { ($_ -is [hashtable]) -and $_['UserSid'] -eq $Sid -and (@(1, 6) -notcontains [int]$_['LogonType']) })
    $d['ComPlus'] = @($allComPlus | Where-Object { ($_ -is [hashtable]) -and $_['IdentitySid'] -eq $Sid -and $_['Activation'] -eq 'Server' })
    $d['Dcom'] = @($allDcom | Where-Object { ($_ -is [hashtable]) -and $_['RunAsSid'] -eq $Sid })
    $iis = $State['Iis']
    if (($iis -is [hashtable]) -and $iis['Installed']) {
        $allPools = ConvertTo-CrArray $iis['AppPools']
        $allVdirs = ConvertTo-CrArray $iis['VirtualDirectories']
        $d['AppPools'] = @($allPools | Where-Object { ($_ -is [hashtable]) -and $_['UserSid'] -eq $Sid })
        $d['VirtualDirectories'] = @($allVdirs | Where-Object { ($_ -is [hashtable]) -and $_['UserSid'] -eq $Sid })
    }
    return $d
}

# Short text list of an account's dependents (for operator decisions), or $null.
function Get-CrDependentSummary {
    param($Dependents)
    $parts = New-Object System.Collections.ArrayList
    foreach ($s in $Dependents['Services']) { [void]$parts.Add('service ' + $s['Name']) }
    foreach ($t in $Dependents['Tasks']) { [void]$parts.Add('task ' + $t['Path']) }
    foreach ($t in $Dependents['OtherTasks']) { [void]$parts.Add('task ' + $t['Path']) }
    foreach ($c in $Dependents['ComPlus']) { [void]$parts.Add('COM+ ' + $c['Name']) }
    foreach ($x in $Dependents['Dcom']) { [void]$parts.Add('DCOM ' + $x['AppId']) }
    foreach ($p in $Dependents['AppPools']) { [void]$parts.Add('IIS pool ' + $p['Name']) }
    foreach ($v in $Dependents['VirtualDirectories']) { [void]$parts.Add('IIS ' + $v['Site'] + $v['Path']) }
    if ($parts.Count -eq 0) { return $null }
    return ($parts.ToArray() -join ', ')
}

# Name of the first account of the first managed Windows entry that matches $Test, or $Fallback.
function Get-CrManagedAccountName {
    param($Resolved, [scriptblock]$Test, [string]$Fallback)
    foreach ($e in (ConvertTo-CrArray $Resolved)) {
        if (-not ($e -is [hashtable]) -or $e['Kind'] -ne 'Windows' -or $e['Mode'] -ne 'Rotate') { continue }
        if (-not (& $Test $e)) { continue }
        foreach ($a in (ConvertTo-CrArray $e['Accounts'])) { if ($a['Name']) { return [string]$a['Name'] } }
    }
    return $Fallback
}

# The number of movable dependents of an account (services, password-stored tasks, COM+ server identities; D24).
function Get-CrMovableDependentCount {
    param($State, [string]$Sid)
    $deps = Get-CrAccountDependents -State $State -Sid $Sid
    return (@($deps['Services']).Count + @($deps['Tasks']).Count + @($deps['ComPlus']).Count)
}

# D24 (v10.4): an account created in this run has a new SID (no SQL login, ACLs or profile of the old account), so
# nothing is moved to it and the account whose dependents would move stays enabled.
function Add-CrCreatedTargetFinding {
    param($Plan, [string]$Name, [string]$Slot, [string]$TargetName, [bool]$SqlLoginGranted = $false)
    $detail = 'A created account has a new SID: no SQL login, ACLs or profile of ' + $Name
    # D29: an account with SqlAccess gets its SQL login in this run.
    if ($SqlLoginGranted) { $detail = 'A created account has a new SID: no ACLs or profile of ' + $Name + '; its SQL Server login is created in this run (D29). A later run moves them' }
    Add-CrPlanFinding $Plan 'HighImpact' 'Accounts' ('Not disabled: ' + $TargetName + ' is created in this run, so the services, scheduled tasks and COM+ applications of ' + $Name + ' are not moved to it; migrate them manually (D24)') $Slot $Name $detail
}

# D24: dependents of an account that is disabled in this run. Every movable item is a HighImpact
# "Move ... from <old> to <target>": the replacement, or for retired and other accounts the application account (v10.4),
# or the operator's account where there is no application account (v10.8, Get-CrDependentTargetEntry).
function Add-CrDisableDependentFindings {
    param($Plan, $State, [string]$Sid, [string]$Name, [string]$Slot, [string]$TargetName)
    $deps = Get-CrAccountDependents -State $State -Sid $Sid
    $items = New-Object System.Collections.ArrayList
    foreach ($s in $deps['Services']) { [void]$items.Add(@{ Area = 'Services'; Text = ('service ' + $s['Name']) }) }
    foreach ($t in $deps['Tasks']) { [void]$items.Add(@{ Area = 'Tasks'; Text = ('scheduled task ' + $t['Path']) }) }
    foreach ($c in $deps['ComPlus']) { [void]$items.Add(@{ Area = 'ComPlus'; Text = ('COM+ application ' + $c['Name']) }) }
    foreach ($item in $items) {
        Add-CrPlanFinding $Plan 'HighImpact' $item['Area'] ('Move ' + $item['Text'] + ' from ' + $Name + ' to ' + $TargetName + ' (D24)') $Slot $Name `
            ('Only to a verified ' + $TargetName + ' with its new password from this run; otherwise ' + $Name + ' stays enabled')
    }
    foreach ($t in $deps['OtherTasks']) {
        Add-CrPlanFinding $Plan 'HighImpact' 'Tasks' ('Scheduled task runs as ' + $Name + ' without a stored password (LogonType ' + $t['LogonType'] + '); it is not moved and stops running when the account is disabled: ' + $t['Path']) $Slot $Name
    }
    foreach ($x in $deps['Dcom']) {
        Add-CrPlanFinding $Plan 'Info' 'Dcom' ('DCOM RunAs uses ' + $Name + ', which is disabled in this run (report only): ' + $x['AppId'] + ' ' + $x['Name']) $Slot $Name
    }
    foreach ($p in $deps['AppPools']) {
        Add-CrPlanFinding $Plan 'FollowUp' 'IIS' ('Application pool identity uses ' + $Name + ', which is disabled in this run; update it manually in IIS Manager: ' + $p['Name']) $Slot $Name
    }
    foreach ($v in $deps['VirtualDirectories']) {
        Add-CrPlanFinding $Plan 'FollowUp' 'IIS' ('"Connect as" uses ' + $Name + ', which is disabled in this run; update it manually: ' + $v['Site'] + $v['Path']) $Slot $Name
    }
}

# D29 (v10.6): the SQL Server access that the entry's account gets from the accounts it replaces (Get-CrSqlAccessPlan).
function Add-CrSqlAccessFindings {
    param($Plan, $State, $Entry, [string]$Slot, $Preflight, [string]$RunningSid)
    $name = $null
    $sid = $null
    foreach ($a in (ConvertTo-CrArray $Entry['Accounts'])) {
        if (-not ($a -is [hashtable])) { continue }
        if (-not $name -and $a['Name']) { $name = [string]$a['Name'] }
        if (-not $sid -and $a['Sid']) { $sid = [string]$a['Sid'] }
    }
    if (-not $name) { $name = [string]$Entry['Id'] }
    $writeBlocked = $null
    if ($Preflight -is [hashtable]) { $writeBlocked = [string]$Preflight['SqlWriteBlocked'] }
    $sp = Get-CrSqlAccessPlan -State $State -Entry $Entry -TargetSid $sid -TargetName $name -WriteBlocked $writeBlocked -RunningSid $RunningSid
    foreach ($n in (ConvertTo-CrArray $sp['Notes'])) { Add-CrPlanFinding $Plan 'HighImpact' 'SQL' $n $Slot $name }
    if ($sp['Unknown']) {
        Add-CrPlanFinding $Plan 'HighImpact' 'SQL' ('The SQL Server access of ' + $name + ' cannot be checked: ' + $sp['Reason'] + ' (D29)') $Slot $name
        return
    }
    $sources = (ConvertTo-CrArray $sp['Sources']) -join ', '
    if (-not $sp['Needed']) {
        if ($sources) { Add-CrPlanFinding $Plan 'Info' 'SQL' ('SQL Server: ' + $name + ' has the access of ' + $sources + ' (D29)') $Slot $name }
        return
    }
    $parts = New-Object System.Collections.ArrayList
    if ($sp['CreateLogin']) { [void]$parts.Add('create the Windows login ' + $sp['LoginName']) }
    if ($sp['EnableLogin']) { [void]$parts.Add('enable the login ' + $sp['LoginName']) }
    $missing = ConvertTo-CrArray $sp['MissingRoles']
    if ($missing.Count -gt 0) { [void]$parts.Add('add it to the server role ' + ($missing -join ', ')) }
    Add-CrPlanFinding $Plan 'Drift' 'SQL' ('SQL Server: ' + (($parts.ToArray()) -join ', ')) $Slot $name `
        ('The same access as ' + $sources + ' (D29); written after its logon test, as the running account')
    if ($sp['Blocked']) {
        Add-CrPlanFinding $Plan 'HighImpact' 'SQL' ('The SQL Server access of ' + $name + ' cannot be granted now: ' + $sp['Reason'] + ' (D29)') $Slot $name
    }
}

# D22, D24, D25, D28, D29: accounts replaced by a managed entry.
function Add-CrReplacedFindings {
    param($Plan, $State, $Entry, [string]$Slot, [string]$RunningSid, [string]$OperatorName, $Preflight)
    $newName = $null
    foreach ($a in (ConvertTo-CrArray $Entry['Accounts'])) { if ($a['Name']) { $newName = [string]$a['Name']; break } }
    if (-not $newName) { $newName = [string]$Entry['Id'] }
    $created = Test-CrEntryCreated $Entry
    foreach ($r in (ConvertTo-CrArray $Entry['Replaced'])) {
        $name = [string]$r['Name']
        if (-not $r['Enabled']) {
            Add-CrPlanFinding $Plan 'Info' 'Accounts' ('Already disabled (replaced by ' + $newName + ')') $Slot $name
            continue
        }
        if ($created -and (Get-CrMovableDependentCount -State $State -Sid ([string]$r['Sid'])) -gt 0) {
            Add-CrCreatedTargetFinding -Plan $Plan -Name $name -Slot $Slot -TargetName $newName -SqlLoginGranted (Test-CrSqlAccessEntry $Entry)
            continue
        }
        $blocker = Get-CrReplacementBlocker -State $State -Entry $Entry -ReplacedSid ([string]$r['Sid']) -ReplacedName $name -Preflight $Preflight -RunningSid $RunningSid
        if ($blocker) {
            Add-CrPlanFinding $Plan 'HighImpact' 'Accounts' ('Not disabled: ' + $blocker) $Slot $name 'It keeps its current password; a re-run disables it once this is solved'
            continue
        }
        $isRunning = ($RunningSid -and ([string]$r['Sid'] -ieq $RunningSid))
        $detail = 'D22: disabled only after ' + $newName + ' is verified in this run'
        if (Test-CrSqlAccessEntry $Entry) { $detail = $detail + ' and has their SQL Server access (D29)' }
        $detail = $detail + '; groups and password stay unchanged'
        if ($isRunning) { $detail = $detail + '; the running account is disabled as the last step (D25)' }
        Add-CrPlanFinding $Plan 'Drift' 'Accounts' ('Disable ' + $name + ' (replaced by ' + $newName + ')') $Slot $name $detail
        if ($isRunning) {
            Add-CrPlanFinding $Plan 'HighImpact' 'Accounts' ('The running account ' + $name + ' is disabled at the end; log on as ' + $OperatorName + ' next time (D25)') $Slot $name
        }
        Add-CrDisableDependentFindings -Plan $Plan -State $State -Sid ([string]$r['Sid']) -Name $name -Slot $Slot -TargetName $newName
    }
}

# D22: Mode = 'Disable' entries (retired without replacement), and the accounts of an entry whose own account does not
# exist (Test-CrReplacedRetired, v10.8; $Why names the missing replacement). Their dependents move to $TargetName (D24).
function Add-CrDisableEntryFindings {
    param($Plan, $State, $Entry, [string]$RunningSid, [string]$OperatorName, [string]$TargetName, [bool]$TargetCreated,
          [bool]$TargetSqlLogin = $false, [string]$Why = 'no replacement')
    foreach ($m in (ConvertTo-CrArray $Entry['Missing'])) {
        Add-CrPlanFinding $Plan 'Info' 'Accounts' ('Account not found (nothing to disable): ' + $m) $null $m
    }
    foreach ($a in (ConvertTo-CrArray $Entry['Accounts'])) {
        $u = $a['User']
        $name = [string]$a['Name']
        if ($u -and $u['Disabled']) {
            Add-CrPlanFinding $Plan 'Info' 'Accounts' ('Already disabled (' + $Why + ', D22)') $null $name
            continue
        }
        if ($TargetCreated -and (Get-CrMovableDependentCount -State $State -Sid ([string]$a['Sid'])) -gt 0) {
            Add-CrCreatedTargetFinding -Plan $Plan -Name $name -Slot $null -TargetName $TargetName -SqlLoginGranted $TargetSqlLogin
            continue
        }
        $isRunning = ($RunningSid -and ([string]$a['Sid'] -ieq $RunningSid))
        $detail = 'D22: groups and password stay unchanged'
        if ($isRunning) { $detail = $detail + '; the running account is disabled as the last step (D25)' }
        Add-CrPlanFinding $Plan 'Drift' 'Accounts' ('Disable ' + $name + ' (' + $Why + ')') $null $name $detail
        if ($isRunning) {
            Add-CrPlanFinding $Plan 'HighImpact' 'Accounts' ('The running account ' + $name + ' is disabled at the end; log on as ' + $OperatorName + ' next time (D25)') $null $name
        }
        Add-CrDisableDependentFindings -Plan $Plan -State $State -Sid ([string]$a['Sid']) -Name $name -Slot $null -TargetName $TargetName
    }
}

# D23: every other enabled local account is put to the operator.
function Add-CrOtherAccountFindings {
    param($Plan, $State, $Resolved, [string]$TargetName, [bool]$TargetCreated)
    foreach ($u in (ConvertTo-CrArray (Get-CrOtherEnabledAccounts -State $State -Resolved $Resolved))) {
        $sid = [string]$u['Sid']
        $parts = New-Object System.Collections.ArrayList
        $groupNames = New-Object System.Collections.ArrayList
        foreach ($g in (ConvertTo-CrArray (Get-CrDirectGroupSids -State $State -Sid $sid))) { [void]$groupNames.Add([string](Get-CrGroupName $State $g)) }
        if ($groupNames.Count -gt 0) { [void]$parts.Add('member of: ' + ($groupNames.ToArray() -join ', ')) }
        $deps = Get-CrDependentSummary (Get-CrAccountDependents -State $State -Sid $sid)
        if ($deps -and $TargetCreated -and (Get-CrMovableDependentCount -State $State -Sid $sid) -gt 0) {
            # D24 (v10.4): no move to an account created in this run, so the account stays enabled even on "disable".
            [void]$parts.Add('dependents (' + $TargetName + ' is created in this run, so they are not moved and the account stays enabled even if you choose disable, D24): ' + $deps)
        } elseif ($deps) {
            [void]$parts.Add('dependents (moved to ' + $TargetName + ' if it is disabled, D24): ' + $deps)
        }
        $detail = $null
        if ($parts.Count -gt 0) { $detail = $parts.ToArray() -join '; ' }
        Add-CrPlanFinding $Plan 'Ambiguous' 'Accounts' ('Operator decides: disable or keep ' + $u['Name'] + ' (D23)') $null ([string]$u['Name']) $detail
    }
}

function Add-CrSqlFindings {
    param($Plan, $State, $Entry, $Login, [string]$Slot)
    $name = $Login['Name']
    Add-CrPlanFinding $Plan 'Info' 'SQL' 'Password rotation (ALTER LOGIN)' $Slot $name
    foreach ($role in (ConvertTo-CrArray $Entry['Config']['ServerRoles'])) {
        if ($role -eq 'sysadmin' -and -not $Login['IsSysadmin']) {
            Add-CrPlanFinding $Plan 'Drift' 'SQL' 'Add to sysadmin (D14)' $Slot $name
        }
    }
    if ($Login['IsLocked']) { Add-CrPlanFinding $Plan 'Info' 'SQL' 'Login is locked; UNLOCK is appended' $Slot $name }
    if ($Login['IsDisabled']) { Add-CrPlanFinding $Plan 'Info' 'SQL' 'Login is disabled (reported only)' $Slot $name }
    $detail = 'CHECK_POLICY=' + $Login['IsPolicyChecked'] + ', CHECK_EXPIRATION=' + $Login['IsExpirationChecked']
    Add-CrPlanFinding $Plan 'Info' 'SQL' 'Login policy settings' $Slot $name $detail
}

function Add-CrAutoLogonFindings {
    param($Plan, $State, $Config, $Resolved, $VerifiedSids, $RemovedAdminSids)
    $al = $State['AutoLogon']
    if (-not $al) { return }
    if ($al['Error']) {
        Add-CrPlanFinding $Plan 'Ambiguous' 'AutoLogon' 'Auto-logon settings could not be read; check them manually before rotating its account' 'AutoLogon' $null $al['Error']
        return
    }
    $d = Get-CrAutoLogonDecision -State $State -Resolved $Resolved -Config $Config -VerifiedSids $VerifiedSids -RemovedAdminSids $RemovedAdminSids
    $who = $d['CurrentName']
    $detail = (ConvertTo-CrArray $d['Reasons']) -join '; '
    switch ($d['Action']) {
        'Standardize' {
            if (Test-CrAutoLogonStandardized -State $State -TargetSid $d['TargetSid']) {
                Add-CrPlanFinding $Plan 'Info' 'AutoLogon' ('Auto-logon as ' + $d['TargetName'] + ' is standardized; the secret is rewritten after a rotation') 'AutoLogon' $who $detail
            } else {
                Add-CrPlanFinding $Plan 'Drift' 'AutoLogon' ('Standardize auto-logon as ' + $d['TargetName'] + ' (LSA secret, no plain text)') 'AutoLogon' $who $detail
            }
        }
        'Switch' {
            Add-CrPlanFinding $Plan 'Drift' 'AutoLogon' ('Switch auto-logon from ' + $who + ' to ' + $d['TargetName'] + ' (D18)') 'AutoLogon' $who $detail
        }
        'TurnOff' { Add-CrPlanFinding $Plan 'Drift' 'AutoLogon' ('Turn auto-logon off (D18; was ' + $who + ')') 'AutoLogon' $who $detail }
        'Ambiguous' {
            $opts = (ConvertTo-CrArray $d['OperatorOptions']) -join ' / '
            Add-CrPlanFinding $Plan 'Ambiguous' 'AutoLogon' ('Operator decision needed: ' + $opts) 'AutoLogon' $who $detail
        }
        default { Add-CrPlanFinding $Plan 'Info' 'AutoLogon' ('Auto-logon: ' + $d['Action']) 'AutoLogon' $who $detail }
    }
    foreach ($h in (ConvertTo-CrArray $d['HighImpact'])) { Add-CrPlanFinding $Plan 'HighImpact' 'AutoLogon' $h 'AutoLogon' $who }
    if ($al['DefaultPasswordPresent'] -and $d['Action'] -eq 'LeaveOff') {
        Add-CrPlanFinding $Plan 'Info' 'AutoLogon' 'A plain-text DefaultPassword exists while auto-logon is off (reported, not changed)' 'AutoLogon' $who
    }
}

# The slot of the entry with the AutoLogon block, or $null.
function Get-CrAutoLogonSlot {
    param($Resolved)
    foreach ($e in (ConvertTo-CrArray $Resolved)) {
        if ($e['AutoLogon']) { return $e['Slot'] }
    }
    return $null
}

# $true for the managed entry marked Operator: the operator's account (D25), SOP-Admin since v10.6.
function Test-CrOperatorEntry {
    param($Entry)
    if (-not ($Entry -is [hashtable])) { return $false }
    if ($Entry['Operator'] -eq $true) { return $true }
    return [bool](($Entry['Config'] -is [hashtable]) -and $Entry['Config']['Operator'] -eq $true)
}

# The operator's account (D25): the managed entry marked Operator. Returns its account name, or $Fallback.
function Get-CrOperatorAccountName {
    param($Resolved, [string]$Fallback)
    return (Get-CrManagedAccountName -Resolved $Resolved -Test { param($e) Test-CrOperatorEntry $e } -Fallback $Fallback)
}

# The application account (D24): the managed entry marked Application, i.e. ApplicationUser (v10.6; until v10.5 the
# only entry with Replaces). Dependents of retired and operator-disabled accounts move there (v10.4, O5 decided), or to
# the operator's account where it does not exist (v10.8, Get-CrDependentTargetEntry).
function Test-CrAppUserEntry {
    param($Entry)
    if (-not ($Entry -is [hashtable])) { return $false }
    if ($Entry['Application'] -eq $true) { return $true }
    return [bool](($Entry['Config'] -is [hashtable]) -and $Entry['Config']['Application'] -eq $true)
}

# $true for a managed entry whose account gets the SQL Server access of the accounts it replaces (D29, v10.6).
function Test-CrSqlAccessEntry {
    param($Entry)
    if (-not ($Entry -is [hashtable])) { return $false }
    if ([string]$Entry['SqlAccess'] -eq 'FromReplaced') { return $true }
    return [bool](($Entry['Config'] -is [hashtable]) -and [string]$Entry['Config']['SqlAccess'] -eq 'FromReplaced')
}

# D24 (v10.8): where the dependents of retired, operator-disabled and orphaned replaced accounts move: the application
# account (ApplicationUser) when it exists or is created, else the operator's account (SOP-Admin). The resolved entry,
# or $null.
function Get-CrDependentTargetEntry {
    param($Resolved)
    $operator = $null
    foreach ($e in (ConvertTo-CrArray $Resolved)) {
        if (-not ($e -is [hashtable]) -or $e['Kind'] -ne 'Windows' -or $e['Mode'] -ne 'Rotate' -or -not $e['Slot']) { continue }
        if ((Test-CrAppUserEntry $e) -and -not $e['NotApplicable']) { return $e }
        if (-not $operator -and (Test-CrOperatorEntry $e)) { $operator = $e }
    }
    return $operator
}

# The display name of an entry's (first) account, also when it is still to be created or does not exist.
function Get-CrEntryDisplayName {
    param($Entry)
    if (-not ($Entry -is [hashtable])) { return $null }
    foreach ($a in (ConvertTo-CrArray $Entry['Accounts'])) { if (($a -is [hashtable]) -and $a['Name']) { return [string]$a['Name'] } }
    if (($Entry['Config'] -is [hashtable]) -and $Entry['Config']['Name']) { return [string]$Entry['Config']['Name'] }
    return [string]$Entry['Id']
}

# v10.8: $true for a managed entry whose own account neither exists nor is created while accounts it replaces exist
# (ApplicationUser missing, built-in Administrator present). Those accounts are disabled like retired ones (D22) and
# their dependents move to Get-CrDependentTargetEntry (D24); like retired accounts, only without -Only.
function Test-CrReplacedRetired {
    param($Entry)
    if (-not ($Entry -is [hashtable]) -or $Entry['Kind'] -ne 'Windows' -or $Entry['Mode'] -ne 'Rotate') { return $false }
    if (-not $Entry['NotApplicable'] -or $Entry['Error']) { return $false }
    return ((ConvertTo-CrArray $Entry['Replaced']).Count -gt 0)
}

# Returns a copy of $State in which $MemberSid is also a member of $GroupSids (for "after the group adds" right checks).
function Copy-CrStateWithMember {
    param($State, [string]$MemberSid, [string[]]$GroupSids)
    $copy = @{}
    foreach ($k in $State.Keys) { $copy[$k] = $State[$k] }
    $groups = New-Object System.Collections.ArrayList
    foreach ($g in (ConvertTo-CrArray $State['Groups'])) {
        $members = @()
        if ($g -is [hashtable]) { $members = ConvertTo-CrArray $g['MemberSids'] }
        if (($g -is [hashtable]) -and (@($GroupSids) -contains [string]$g['Sid']) -and ($members -notcontains $MemberSid)) {
            $c = @{}
            foreach ($k in $g.Keys) { $c[$k] = $g[$k] }
            $list = New-Object System.Collections.ArrayList
            foreach ($m in $members) { [void]$list.Add($m) }
            [void]$list.Add($MemberSid)
            $c['MemberSids'] = $list.ToArray()
            [void]$groups.Add($c)
        } else {
            [void]$groups.Add($g)
        }
    }
    $copy['Groups'] = $groups.ToArray()
    return $copy
}

# v10.8: the state the auto-logon step is expected to see after the slots, for the audit and the summary before YES.
# The account of the auto-logon entry (PUB-User) that the run creates is added under the null SID S-1-0-0 with the groups
# its role adds; one it enables (EnableIfDisabled) is shown enabled. Returns @{ State; CreatedSid ($null if none) }.
# $Create: create the missing account; $EnableSids: the existing accounts that are enabled.
function Get-CrPlannedAutoLogonState {
    param($State, $Entry, [bool]$Create, [string[]]$EnableSids, [string]$RunningSid)
    $out = @{ State = $State; CreatedSid = $null }
    $enable = ConvertTo-CrArray $EnableSids
    if (-not ($Entry -is [hashtable]) -or (-not $Create -and $enable.Count -eq 0)) { return $out }
    $copy = @{}
    foreach ($k in $State.Keys) { $copy[$k] = $State[$k] }
    $users = New-Object System.Collections.ArrayList
    foreach ($u in (ConvertTo-CrArray $State['Users'])) {
        if (($u -is [hashtable]) -and $u['Disabled'] -and ($enable -contains [string]$u['Sid'])) {
            $c = @{}
            foreach ($k in $u.Keys) { $c[$k] = $u[$k] }
            $c['Disabled'] = $false
            if ($null -ne $c['Flags']) { $c['Flags'] = ([int]$c['Flags']) -band (-bnot 0x2) }
            [void]$users.Add($c)
        } else {
            [void]$users.Add($u)
        }
    }
    if ($Create) {
        $name = $null
        foreach ($a in (ConvertTo-CrArray $Entry['Accounts'])) { if (($a -is [hashtable]) -and $a['ToCreate'] -and $a['Name']) { $name = [string]$a['Name']; break } }
        if ($name) {
            $sid = 'S-1-0-0'
            [void]$users.Add(@{ Name = $name; Sid = $sid; Disabled = $false; LockedOut = $false; Planned = $true })
            $copy['Users'] = $users.ToArray()
            $role = $Entry['Role']
            if (-not ($role -is [hashtable])) { $role = @{} }
            $gp = Get-CrGroupPlan -State $copy -Role $role -Sid $sid -RunningSid $RunningSid
            $add = ConvertTo-CrArray $gp['Add']
            if (-not $gp['Skip'] -and $add.Count -gt 0) { $copy = Copy-CrStateWithMember -State $copy -MemberSid $sid -GroupSids $add }
            $out['CreatedSid'] = $sid
        }
    }
    $copy['Users'] = $users.ToArray()
    $out['State'] = $copy
    return $out
}

# D28 (v10.6): the logon types that $ReplacedSid may use and $ReplacementSid may not: 'Interactive' (local) and
# 'RemoteInteractive' (RDP), from the effective rights (granted and not denied). Comma-returned.
function Get-CrLogonGaps {
    param($State, [string]$ReplacementSid, [string]$ReplacedSid)
    $gaps = New-Object System.Collections.ArrayList
    if (-not $ReplacementSid -or -not $ReplacedSid) { return , $gaps.ToArray() }
    $old = Get-CrEffectiveLogonRights -UserSid $ReplacedSid -State $State
    $new = Get-CrEffectiveLogonRights -UserSid $ReplacementSid -State $State
    foreach ($t in @('Interactive', 'RemoteInteractive')) {
        if ($old[$t] -and -not $new[$t]) { [void]$gaps.Add($t) }
    }
    return , $gaps.ToArray()
}

function Get-CrLogonGapText {
    param($Gaps)
    $parts = New-Object System.Collections.ArrayList
    foreach ($g in (ConvertTo-CrArray $Gaps)) {
        if ($g -eq 'Interactive') { [void]$parts.Add('locally') } elseif ($g -eq 'RemoteInteractive') { [void]$parts.Add('over RDP') }
    }
    return (($parts.ToArray()) -join ' and ')
}

# D28: the logon gaps once the entry's account has its role groups (judged before the run). An account still to be
# created is represented by the null SID S-1-0-0, which holds no right of its own.
function Get-CrPlannedLogonGaps {
    param($State, $Entry, [string]$ReplacedSid, [string]$RunningSid)
    $sid = $null
    foreach ($a in (ConvertTo-CrArray $Entry['Accounts'])) { if (($a -is [hashtable]) -and $a['Sid']) { $sid = [string]$a['Sid']; break } }
    if (-not $sid) { $sid = 'S-1-0-0' }
    $role = $Entry['Role']
    if (-not ($role -is [hashtable])) { $role = @{} }
    $after = $State
    $gp = Get-CrGroupPlan -State $State -Role $role -Sid $sid -RunningSid $RunningSid
    $add = ConvertTo-CrArray $gp['Add']
    if (-not $gp['Skip'] -and $add.Count -gt 0) { $after = Copy-CrStateWithMember -State $State -MemberSid $sid -GroupSids $add }
    $gaps = Get-CrLogonGaps -State $after -ReplacementSid $sid -ReplacedSid $ReplacedSid
    return , $gaps
}

# D28, D29 (v10.6): why an account replaced by $Entry stays enabled in this run, judged before it starts, or $null:
# the replacement can't get the SQL Server access of the accounts it replaces (unknown or blocked), or, for the operator's
# account, it would not be allowed to log on locally or over RDP where the replaced account can.
function Get-CrReplacementBlocker {
    param($State, $Entry, [string]$ReplacedSid, [string]$ReplacedName, $Preflight, [string]$RunningSid)
    $newName = $null
    $newSid = $null
    foreach ($a in (ConvertTo-CrArray $Entry['Accounts'])) {
        if (-not ($a -is [hashtable])) { continue }
        if (-not $newName -and $a['Name']) { $newName = [string]$a['Name'] }
        if (-not $newSid -and $a['Sid']) { $newSid = [string]$a['Sid'] }
    }
    if (-not $newName) { $newName = [string]$Entry['Id'] }
    if (Test-CrSqlAccessEntry $Entry) {
        $writeBlocked = $null
        if ($Preflight -is [hashtable]) { $writeBlocked = [string]$Preflight['SqlWriteBlocked'] }
        $sp = Get-CrSqlAccessPlan -State $State -Entry $Entry -TargetSid $newSid -TargetName $newName -WriteBlocked $writeBlocked -RunningSid $RunningSid
        if ($sp['Unknown']) { return ('the SQL Server access of {0} cannot be checked: {1} (D29)' -f $newName, $sp['Reason']) }
        if ($sp['Needed'] -and $sp['Blocked']) { return ('{0} cannot get the SQL Server access of the accounts it replaces: {1} (D29)' -f $newName, $sp['Reason']) }
    }
    if (Test-CrOperatorEntry $Entry) {
        $gaps = Get-CrPlannedLogonGaps -State $State -Entry $Entry -ReplacedSid $ReplacedSid -RunningSid $RunningSid
        if ($gaps.Count -gt 0) {
            return ('{0} would not be allowed to log on {1} as {2} can (logon right not granted, or denied; D28)' -f $newName, (Get-CrLogonGapText $gaps), $ReplacedName)
        }
    }
    return $null
}

# $true if the entry's account is created in this run (a ToCreate placeholder, PLAN 8 step 0).
function Test-CrEntryCreated {
    param($Entry)
    if (-not ($Entry -is [hashtable])) { return $false }
    foreach ($a in (ConvertTo-CrArray $Entry['Accounts'])) { if (($a -is [hashtable]) -and $a['ToCreate']) { return $true } }
    return $false
}

# Slot of the managed account that auto-logon currently uses, or of the entry that replaces it, or $null.
function Get-CrCurrentAutoLogonAccountSlot {
    param($State, $Resolved)
    $al = $State['AutoLogon']
    if (-not $al -or -not $al['DefaultUserName']) { return $null }
    $current = [string]$al['DefaultUserName']
    $i = $current.LastIndexOf('\')
    if ($i -ge 0) { $current = $current.Substring($i + 1) }
    foreach ($e in (ConvertTo-CrArray $Resolved)) {
        # Retired replaced accounts (v10.8) are never processed under -Only.
        if ($e['Kind'] -ne 'Windows' -or -not $e['Slot'] -or (Test-CrReplacedRetired $e)) { continue }
        foreach ($a in (ConvertTo-CrArray $e['Accounts'])) {
            if ([string]$a['Name'] -ieq $current) { return $e['Slot'] }
        }
        foreach ($a in (ConvertTo-CrArray $e['Replaced'])) {
            if ([string]$a['Name'] -ieq $current) { return $e['Slot'] }
        }
    }
    return $null
}

function Test-CrSlotSelected {
    param([string]$Slot, [string[]]$Only)
    if (-not $Only -or @($Only).Count -eq 0) { return $true }
    return (@($Only) -contains $Slot)
}

function New-CrPlan {
    param($State, $Config, $Resolved, $Preflight, [string[]]$Only, [string]$RunningSid)
    if (-not $RunningSid) { $RunningSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value }
    $plan = @{ Findings = New-Object System.Collections.ArrayList; Drift = $false; HighImpact = @(); FollowUps = @() }

    if ($Preflight) {
        foreach ($f in (ConvertTo-CrArray $Preflight['Findings'])) {
            [void]$plan['Findings'].Add($f)
            if ($f['Severity'] -eq 'Drift') { $plan['Drift'] = $true }
        }
        if ($Preflight['MachineBlocked']) {
            Add-CrPlanFinding $plan 'Blocked' 'Preflight' '-Apply is blocked on this machine (see the preflight findings)'
        }
    }
    # Blocked slots are already reported as findings by Invoke-CrPreflight.
    $blockedSlots = @{}
    if ($Preflight -and $Preflight['BlockedSlots']) { $blockedSlots = $Preflight['BlockedSlots'] }

    foreach ($f in (ConvertTo-CrArray (Find-CrSidOverlap -Resolved $Resolved))) { [void]$plan['Findings'].Add($f) }
    foreach ($e in (ConvertTo-CrArray $State['Errors'])) {
        Add-CrPlanFinding $plan 'Info' 'Discovery' ('Discovery section failed: ' + $e['Section']) $null $null $e['Message']
    }

    $sql = $State['Sql']
    if ($sql -is [hashtable] -and $sql['Connected'] -and $sql['Error']) {
        Add-CrPlanFinding $plan 'Info' 'Discovery' 'Some SQL Server queries failed' $null $null $sql['Error']
    }
    foreach ($t in (ConvertTo-CrArray $State['Tasks'])) {
        if ($t -is [hashtable] -and $t['Error'] -and -not $t['UserSid']) {
            # Shown before YES: a task stored there with an account's password would keep the old one.
            Add-CrPlanFinding $plan 'HighImpact' 'Tasks' ('Scheduled task or folder could not be read; dependents there are unknown: ' + $t['Path']) $null $null $t['Error']
        }
    }
    $sqlInstalled = (($sql -is [hashtable]) -and $sql['DefaultInstancePresent'])

    # Accounts the run would put on the new secret and that can be verified (enabled; created accounts have no SID yet:
    # a created auto-logon account is added for the auto-logon decision, Get-CrPlannedAutoLogonState).
    $verified = New-Object System.Collections.ArrayList
    $removedAdmins = New-Object System.Collections.ArrayList # accounts leaving Administrators in this run
    $operatorName = Get-CrOperatorAccountName -Resolved $Resolved -Fallback 'the operator account'
    # D24 (v10.8): dependents of retired and operator-disabled accounts move to ApplicationUser, or to SOP-Admin without it.
    $depTarget = Get-CrDependentTargetEntry -Resolved $Resolved
    $depTargetName = 'the application user'
    if ($depTarget) { $depTargetName = Get-CrEntryDisplayName $depTarget }
    $depTargetCreated = [bool]($depTarget -and (Test-CrEntryCreated $depTarget))
    $depTargetSql = [bool]($depTarget -and (Test-CrSqlAccessEntry $depTarget))
    $onlyGiven = [bool]($Only -and @($Only).Count -gt 0)

    foreach ($entry in (ConvertTo-CrArray $Resolved)) {
        $slot = $entry['Slot']
        # D26 (v10.5): Mode = 'Keep' entries are never changed and not put to the operator (D23); one Info per account,
        # also under -Only.
        if ($entry['Mode'] -eq 'Keep') {
            foreach ($acct in (ConvertTo-CrArray $entry['Accounts'])) {
                Add-CrPlanFinding $plan 'Info' 'Accounts' 'Kept untouched (config: Mode Keep)' $null $acct['Name']
            }
            continue
        }
        $isCheck = ($entry['Mode'] -eq 'Check')
        $isDisable = ($entry['Mode'] -eq 'Disable')
        # Check-mode fixes and the disabling of retired accounts run only without -Only (PLAN 8).
        if (($isCheck -or $isDisable) -and $Only -and @($Only).Count -gt 0) { continue }
        if (-not $isCheck -and -not $isDisable -and -not (Test-CrSlotSelected -Slot $slot -Only $Only)) { continue }
        if ($entry['Error']) {
            # The account data couldn't be read, so "missing" would be a false statement.
            Add-CrPlanFinding $plan 'Blocked' 'Accounts' ('Account data could not be read for ' + $entry['Id']) $slot $null $entry['Error']
            continue
        }
        if ($isDisable) {
            Add-CrDisableEntryFindings -Plan $plan -State $State -Entry $entry -RunningSid $RunningSid -OperatorName $operatorName `
                -TargetName $depTargetName -TargetCreated $depTargetCreated -TargetSqlLogin $depTargetSql
            continue
        }
        foreach ($m in (ConvertTo-CrArray $entry['Missing'])) {
            Add-CrPlanFinding $plan 'Info' 'Accounts' ('Account not found (never created): ' + $m) $slot $m
        }
        if ($entry['NotApplicable']) {
            Add-CrPlanFinding $plan 'Info' 'Accounts' ('Not applicable on this machine: ' + $entry['Id']) $slot
            # v10.8: the accounts it replaces (the built-in Administrator without ApplicationUser) are retired.
            if ((Test-CrReplacedRetired $entry) -and -not $onlyGiven) {
                $why = 'its replacement ' + (Get-CrEntryDisplayName $entry) + ' does not exist'
                Add-CrDisableEntryFindings -Plan $plan -State $State -Entry @{ Missing = @(); Accounts = $entry['Replaced'] } -RunningSid $RunningSid `
                    -OperatorName $operatorName -TargetName $depTargetName -TargetCreated $depTargetCreated -TargetSqlLogin $depTargetSql -Why $why
            }
            continue
        }
        $slotBlocked = ($slot -and $blockedSlots.ContainsKey($slot))
        $role = $entry['Role']
        if (-not $role) { $role = @{} }
        $loginsDetail = $null
        $replacedNames = New-Object System.Collections.ArrayList
        foreach ($r in (ConvertTo-CrArray $entry['Replaced'])) { [void]$replacedNames.Add([string]$r['Name']) }
        if ($replacedNames.Count -gt 0) { $loginsDetail = 'Replaces the LOGINS entries of: ' + ($replacedNames.ToArray() -join ', ') }

        foreach ($acct in (ConvertTo-CrArray $entry['Accounts'])) {
            $u = $acct['User']
            if ($entry['Kind'] -eq 'SqlLogin') {
                Add-CrSqlFindings -Plan $plan -State $State -Entry $entry -Login $u -Slot $slot
            } elseif ($acct['ToCreate']) {
                # D21: created with the slot password, the role groups and flags (PLAN 8 step 0)
                Add-CrPlanFinding $plan 'Drift' 'Accounts' ('Create ' + $acct['Name']) $slot $acct['Name'] 'D21: created with the slot password, its role groups and flags'
                # An entry with SqlAccess gets its login in this run (D29, Add-CrSqlAccessFindings).
                if ($sqlInstalled -and -not (Test-CrSqlAccessEntry $entry)) {
                    Add-CrPlanFinding $plan 'Info' 'SQL' 'The created account has a new SID, so it has no Windows login in SQL Server (reported, PLAN 1.1)' $slot $acct['Name']
                }
                $newUser = @{ Name = [string]$acct['Name']; Sid = $null }
                Add-CrGroupFindings -Plan $plan -State $State -Role $role -User $newUser -Slot $slot -RunningSid $RunningSid -RemovedAdminSids (New-Object System.Collections.ArrayList)
            } else {
                if ($isCheck) {
                    if ($u['Disabled']) { Add-CrPlanFinding $plan 'Info' 'Accounts' 'Account is disabled (reported only)' $slot $u['Name'] }
                    if ($u['LockedOut']) { Add-CrPlanFinding $plan 'Info' 'Accounts' 'Account is locked (reported only)' $slot $u['Name'] }
                } else {
                    # D21: only an entry with EnableIfDisabled is enabled (all managed entries since v10.8); the others stay disabled.
                    $staysDisabled = ($u['Disabled'] -and -not $entry['EnableIfDisabled'])
                    if ($u['Disabled'] -and $entry['EnableIfDisabled']) {
                        Add-CrPlanFinding $plan 'Drift' 'Accounts' 'Enable the account (D21)' $slot $u['Name']
                    } elseif ($staysDisabled) {
                        Add-CrPlanFinding $plan 'Info' 'Accounts' 'Account is disabled: it gets the new password but stays disabled (D21); a logon test is not possible' $slot $u['Name']
                    }
                    Add-CrWindowsRotationFindings -Plan $plan -State $State -User $u -Slot $slot -PasswordMode $entry['PasswordMode']
                    Add-CrDependentFindings -Plan $plan -State $State -Entry $entry -User $u -Slot $slot
                    if (-not $slotBlocked -and -not $staysDisabled) { [void]$verified.Add($acct['Sid']) }
                }
                Add-CrAccountFlagFindings -Plan $plan -Role $role -User $u -Slot $slot -InAdministrators (Test-CrIsAdmin -UserSid ([string]$u['Sid']) -State $State)
                # Only completed rotate slots leave Administrators before the auto-logon step (PLAN 8);
                # check-mode fixes run after it and blocked slots never complete.
                $adminSink = $removedAdmins
                if ($isCheck -or $slotBlocked) { $adminSink = New-Object System.Collections.ArrayList }
                Add-CrGroupFindings -Plan $plan -State $State -Role $role -User $u -Slot $slot -RunningSid $RunningSid -RemovedAdminSids $adminSink
            }
            if ($entry['LoginsEntry'] -and -not $isCheck) {
                Add-CrPlanFinding $plan 'FollowUp' 'LOGINS' 'Update the LOGINS registry entry after the rotation (outside the tool)' $slot $acct['Name'] $loginsDetail
            }
        }
        if ($entry['Kind'] -eq 'Windows' -and -not $isCheck) {
            if (Test-CrSqlAccessEntry $entry) { Add-CrSqlAccessFindings -Plan $plan -State $State -Entry $entry -Slot $slot -Preflight $Preflight -RunningSid $RunningSid }
            Add-CrReplacedFindings -Plan $plan -State $State -Entry $entry -Slot $slot -RunningSid $RunningSid -OperatorName $operatorName -Preflight $Preflight
        }
    }

    # D23: other enabled local accounts (operator decides before YES). Like check mode, only without -Only.
    # Unreadable account data is already reported by the per-entry Blocked findings.
    $usersError = Get-CrPrincipalPartError -Part $State['Users'] -Section 'Users'
    if (-not ($Only -and @($Only).Count -gt 0) -and -not $usersError) {
        Add-CrOtherAccountFindings -Plan $plan -State $State -Resolved $Resolved -TargetName $depTargetName -TargetCreated $depTargetCreated
    }

    # Under -Only the auto-logon step runs when the auto-logon slot or the slot of the
    # current auto-logon account is selected (PLAN 7.5).
    $runAutoLogon = Test-CrSlotSelected -Slot (Get-CrAutoLogonSlot -Resolved $Resolved) -Only $Only
    if (-not $runAutoLogon) {
        $currentSlot = Get-CrCurrentAutoLogonAccountSlot -State $State -Resolved $Resolved
        if ($currentSlot) { $runAutoLogon = Test-CrSlotSelected -Slot $currentSlot -Only $Only }
    }
    if ($runAutoLogon) {
        # v10.8: the auto-logon account (PUB-User) that its slot creates or enables counts as present, enabled and verified.
        $alState = $State
        $alEntry = Find-CrAutoLogonEntry -Resolved $Resolved
        $alSlot = $null
        if ($alEntry) { $alSlot = [string]$alEntry['Slot'] }
        if ($alEntry -and -not $alEntry['Error'] -and $alEntry['Mode'] -eq 'Rotate' -and (Test-CrSlotSelected -Slot $alSlot -Only $Only) -and
            -not ($alSlot -and $blockedSlots.ContainsKey($alSlot))) {
            $enableSids = New-Object System.Collections.ArrayList
            foreach ($a in (ConvertTo-CrArray $alEntry['Accounts'])) {
                if (($a -is [hashtable]) -and $a['Sid'] -and ($a['User'] -is [hashtable]) -and $a['User']['Disabled'] -and $alEntry['EnableIfDisabled']) { [void]$enableSids.Add([string]$a['Sid']) }
            }
            $planned = Get-CrPlannedAutoLogonState -State $State -Entry $alEntry -Create (Test-CrEntryCreated $alEntry) -EnableSids ($enableSids.ToArray()) -RunningSid $RunningSid
            $alState = $planned['State']
            if ($planned['CreatedSid']) { [void]$verified.Add($planned['CreatedSid']) }
        }
        Add-CrAutoLogonFindings -Plan $plan -State $alState -Config $Config -Resolved $Resolved -VerifiedSids $verified.ToArray() -RemovedAdminSids $removedAdmins.ToArray()
    }

    $plan['HighImpact'] = @($plan['Findings'] | Where-Object { $_['Severity'] -eq 'HighImpact' })
    $plan['FollowUps'] = @($plan['Findings'] | Where-Object { $_['Severity'] -eq 'FollowUp' })
    return $plan
}
