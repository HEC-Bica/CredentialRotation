# Groups.ps1 - local groups and their members (docs/PLAN.md section 7.2). Read side (M1) and membership changes by SID (M2).
# Members are read by SID through netapi32 (D5), never through ADSI Members(): on Windows Embedded
# Standard 7 that returns no name or SID for local-account members.

function Get-CrGroupErrorText {
    param($ErrorRecord)
    $ex = $ErrorRecord.Exception
    while ($ex.InnerException) { $ex = $ex.InnerException }
    return $ex.Message
}

# All local groups (CONTRACTS 4.1); returns an array of @{ Name; Sid; MemberSids; Error }.
# Throws if the groups can't be enumerated at all. A group whose members can't be read has Error set and
# MemberSids = @(); a group whose SID can't be resolved has Error set but keeps its members.
function Get-CrLocalGroups {
    param()
    $list = New-Object System.Collections.ArrayList
    foreach ($name in (ConvertTo-CrArray (Get-CrLocalGroupNames))) {
        $group = @{ Name = [string]$name; Sid = $null; MemberSids = @(); Error = $null }
        # Built-in groups (BUILTIN\...) resolve by the plain name once the <COMPUTER>\name attempt fails.
        $group['Sid'] = Resolve-CrNameToSid -Name ([string]$name)
        try {
            $group['MemberSids'] = ConvertTo-CrArray (Get-CrLocalGroupMemberSids -GroupName ([string]$name))
        } catch {
            $group['MemberSids'] = @()
            $group['Error'] = 'Members could not be read: ' + (Get-CrGroupErrorText $_)
        }
        if (-not $group['Sid']) {
            $msg = 'The group SID could not be resolved.'
            if ($group['Error']) { $group['Error'] = $msg + ' ' + $group['Error'] } else { $group['Error'] = $msg }
        }
        [void]$list.Add($group)
    }
    return , $list.ToArray()
}

#region Write side (M2, PLAN section 7.2; CONTRACTS 5.8)

# Internal: the $State.Groups entry with this SID, or $null.
function Find-CrGroupBySid {
    param($State, [string]$Sid)
    if (-not $Sid -or -not ($State -is [hashtable])) { return $null }
    $groups = $State['Groups']
    if ($null -eq $groups -or ($groups -is [hashtable])) { return $null }
    foreach ($g in (ConvertTo-CrArray $groups)) {
        if ($g -is [hashtable] -and $g['Sid'] -and ([string]$g['Sid'] -eq $Sid)) { return $g }
    }
    return $null
}

# Internal: one add or remove; never throws (an exception becomes a failed result).
function Invoke-CrOneGroupChange {
    param($State, [string]$MemberSid, [string]$GroupSid, [string]$Action)
    $r = @{ GroupSid = $GroupSid; GroupName = $null; Action = $Action; Success = $false; Win32Error = 0; Message = $null }
    $group = Find-CrGroupBySid -State $State -Sid $GroupSid
    if (-not $group -or -not $group['Name']) {
        $r['Message'] = ('The group {0} was not found among the local groups.' -f $GroupSid)
        return $r
    }
    $name = [string]$group['Name']
    $r['GroupName'] = $name
    try {
        if ($Action -eq 'Add') {
            $n = Add-CrLocalGroupMemberSid -GroupName $name -MemberSid $MemberSid
        } else {
            $n = Remove-CrLocalGroupMemberSid -GroupName $name -MemberSid $MemberSid
        }
        $r['Success'] = [bool]($n -and $n['Success'])
        if ($n) { $r['Win32Error'] = [int]$n['Win32Error'] }
        if (-not $r['Success']) {
            $verb = 'added to'
            if ($Action -ne 'Add') { $verb = 'removed from' }
            $r['Message'] = ('The account could not be {0} {1} (error {2}).' -f $verb, $name, $r['Win32Error'])
        }
    } catch {
        $r['Message'] = $_.Exception.Message
    }
    return $r
}

# Adds the member (by SID, NetLocalGroupAddMembers level 0, D5) to every group of AddGroupSids, then removes it from
# every group of RemoveGroupSids. Group names come from $State.Groups by SID; names are never parsed.
# One failure doesn't stop the others. Returns an array of @{ GroupSid; GroupName; Action ('Add'|'Remove');
# Success; Win32Error; Message }. Rails and allow-lists are the caller's job (Plan/Apply); $State is not updated.
function Invoke-CrGroupMembershipChange {
    param($State, [string]$MemberSid, [string[]]$AddGroupSids, [string[]]$RemoveGroupSids)
    if (-not $MemberSid) { throw 'Invoke-CrGroupMembershipChange: -MemberSid is required.' }
    $list = New-Object System.Collections.ArrayList
    foreach ($sid in (ConvertTo-CrArray $AddGroupSids)) {
        if (-not $sid) { continue }
        [void]$list.Add((Invoke-CrOneGroupChange -State $State -MemberSid $MemberSid -GroupSid ([string]$sid) -Action 'Add'))
    }
    foreach ($sid in (ConvertTo-CrArray $RemoveGroupSids)) {
        if (-not $sid) { continue }
        [void]$list.Add((Invoke-CrOneGroupChange -State $State -MemberSid $MemberSid -GroupSid ([string]$sid) -Action 'Remove'))
    }
    return , $list.ToArray()
}

#endregion
