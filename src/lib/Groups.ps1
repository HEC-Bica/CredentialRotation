# Groups.ps1 - local groups and their members (docs/PLAN.md section 7.2). M1: read side only.
# Members are read by SID through netapi32 (D5), never through ADSI Members(): on Windows Embedded
# Standard 7 that returns no name or SID for local-account members.

function Get-CrGroupErrorText {
    param($ErrorRecord)
    $ex = $ErrorRecord.Exception
    while ($ex.InnerException) { $ex = $ex.InnerException }
    return $ex.Message
}

# All local groups (CONTRACTS "Groups"); returns an array of @{ Name; Sid; MemberSids; Error }.
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
