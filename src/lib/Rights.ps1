# Rights.ps1 - token model, effective logon rights, D16 probe logon type (incl. the ForceGuest rule), admin check
# (docs/PLAN.md section 7.3, D16; docs/dev/CONTRACTS.md)

# The logon types with their grant and deny rights. RemoteInteractive is only reported; D16 never probes it.
function Get-CrLogonRightMap {
    return @(
        @{ Type = 'Network';           Grant = 'SeNetworkLogonRight';           Deny = 'SeDenyNetworkLogonRight' },
        @{ Type = 'Interactive';       Grant = 'SeInteractiveLogonRight';       Deny = 'SeDenyInteractiveLogonRight' },
        @{ Type = 'RemoteInteractive'; Grant = 'SeRemoteInteractiveLogonRight'; Deny = 'SeDenyRemoteInteractiveLogonRight' },
        @{ Type = 'Batch';             Grant = 'SeBatchLogonRight';             Deny = 'SeDenyBatchLogonRight' },
        @{ Type = 'Service';           Grant = 'SeServiceLogonRight';           Deny = 'SeDenyServiceLogonRight' }
    )
}

# Logon-type SIDs: NETWORK S-1-5-2, INTERACTIVE S-1-5-4, REMOTE INTERACTIVE S-1-5-14, BATCH S-1-5-3, SERVICE S-1-5-6,
# LOCAL S-1-2-0 and CONSOLE LOGON S-1-2-1 (interactive-type logons only).
function Get-CrLogonTypeSids {
    param([string]$LogonType)
    if ($LogonType -eq 'Network') { return , @('S-1-5-2') }
    if ($LogonType -eq 'Interactive') { return , @('S-1-5-4', 'S-1-2-0', 'S-1-2-1') }
    if ($LogonType -eq 'RemoteInteractive') { return , @('S-1-5-14', 'S-1-5-4', 'S-1-2-0') }
    if ($LogonType -eq 'Batch') { return , @('S-1-5-3') }
    if ($LogonType -eq 'Service') { return , @('S-1-5-6') }
    throw ('Unknown logon type: {0}' -f $LogonType)
}

function Get-CrRightsGroupList {
    param($State)
    $groups = $State['Groups']
    if ($null -eq $groups) { return , @() }
    if ($groups -is [hashtable]) {
        if ($groups.ContainsKey('Sid')) { return , @($groups) }
        return , @()
    }
    return , @($groups)
}

# SIDs holding a right; a failed Rights part gives an empty list.
function Get-CrRightSids {
    param($State, [string]$Right)
    $rights = $State['Rights']
    if (-not ($rights -is [hashtable])) { return , @() }
    if ($rights.ContainsKey('Error') -and $rights['Error']) { return , @() }
    return , (ConvertTo-CrArray $rights[$Right])
}

# The token SIDs of a logon of the given type (PLAN section 7.3). Comma-returned array: assign directly.
function Get-CrTokenSids {
    param([string]$UserSid, $State, [string]$LogonType)
    $token = New-Object System.Collections.ArrayList
    $typeSids = Get-CrLogonTypeSids -LogonType $LogonType
    foreach ($sid in (@($UserSid, 'S-1-1-0', 'S-1-5-11', 'S-1-5-113') + $typeSids)) {
        if ($sid -and ($token -notcontains $sid)) { [void]$token.Add($sid) }
    }
    # Local groups containing the account or any SID already in the token (well-known SIDs such as
    # Authenticated Users or INTERACTIVE in Users / Remote Desktop Users); repeat until nothing is added.
    $groups = Get-CrRightsGroupList $State
    $changed = $true
    while ($changed) {
        $changed = $false
        foreach ($group in $groups) {
            $groupSid = [string]$group['Sid']
            if (-not $groupSid -or ($token -contains $groupSid)) { continue }
            foreach ($member in (ConvertTo-CrArray $group['MemberSids'])) {
                if ($token -contains [string]$member) {
                    [void]$token.Add($groupSid)
                    $changed = $true
                    break
                }
            }
        }
    }
    if (($token -contains 'S-1-5-32-544') -and ($token -notcontains 'S-1-5-114')) { [void]$token.Add('S-1-5-114') }
    return , $token.ToArray()
}

function Test-CrAnySidInList {
    param($Sids, $List)
    foreach ($sid in $Sids) {
        if ($List -contains $sid) { return $true }
    }
    return $false
}

# @{ Network; Interactive; RemoteInteractive; Batch; Service }: granted to a token SID and denied to none.
function Get-CrEffectiveLogonRights {
    param([string]$UserSid, $State)
    $result = @{}
    foreach ($row in (Get-CrLogonRightMap)) {
        $token = Get-CrTokenSids -UserSid $UserSid -State $State -LogonType $row.Type
        $granted = Test-CrAnySidInList -Sids $token -List (Get-CrRightSids -State $State -Right $row.Grant)
        $denied = Test-CrAnySidInList -Sids $token -List (Get-CrRightSids -State $State -Right $row.Deny)
        $result[$row.Type] = ($granted -and -not $denied)
    }
    return $result
}

# $true only when the policy says ForceGuest = 1 (network logons of local accounts are mapped to Guest).
function Test-CrForceGuest {
    param($State)
    if (-not ($State -is [hashtable])) { return $false }
    $policy = $State['Policy']
    if (-not ($policy -is [hashtable])) { return $false }
    return ($policy['ForceGuest'] -eq $true)
}

# D16: first allowed of Network, Interactive, Batch, Service; otherwise Network with Fallback.
# ForceGuest (CONTRACTS "v10", D16): Network is never chosen, because Windows may map a local network logon to Guest,
# which would accept any password. Then the next allowed type is used; if there is none, LogonType = $null with
# Fallback = $true: the password can't be verified by a logon (callers treat it as unverifiable).
function Select-CrProbeLogonType {
    param([string]$UserSid, $State)
    $effective = Get-CrEffectiveLogonRights -UserSid $UserSid -State $State
    $forceGuest = Test-CrForceGuest -State $State
    foreach ($type in @('Network', 'Interactive', 'Batch', 'Service')) {
        if ($forceGuest -and ($type -eq 'Network')) { continue }
        if ($effective[$type]) { return @{ LogonType = $type; Fallback = $false } }
    }
    if ($forceGuest) { return @{ LogonType = $null; Fallback = $true } }
    return @{ LogonType = 'Network'; Fallback = $true }
}

# $true if the SID is a direct member of Administrators (S-1-5-32-544).
function Test-CrIsAdmin {
    param([string]$UserSid, $State)
    if (-not $UserSid) { return $false }
    foreach ($group in (Get-CrRightsGroupList $State)) {
        if ([string]$group['Sid'] -eq 'S-1-5-32-544') {
            return ((ConvertTo-CrArray $group['MemberSids']) -contains $UserSid)
        }
    }
    return $false
}

#region Write side (M2, PLAN section 7.3)

# The only rights the tool ever grants: what discovered dependents need (services, password-stored tasks).
function Get-CrGrantableRights {
    return , @('SeServiceLogonRight', 'SeBatchLogonRight')
}

# Grants dependent logon rights through LsaAddAccountRights (Grant-CrAccountRight; adds only, never removes).
# Throws before granting anything if a right other than SeServiceLogonRight / SeBatchLogonRight is asked for.
# Deny rights are never touched; a deny conflict is reported by the plan, not here.
# Returns an array of @{ Right; Success; Win32Error; Message }, one per distinct right; one failure doesn't stop the others.
function Grant-CrDependentRights {
    param([string]$Sid, [string[]]$Rights)
    if (-not $Sid) { throw 'Grant-CrDependentRights: -Sid is required.' }
    $allowed = Get-CrGrantableRights
    $wanted = New-Object System.Collections.ArrayList
    foreach ($right in (ConvertTo-CrArray $Rights)) {
        if (-not $right) { continue }
        $match = $null
        foreach ($a in $allowed) { if ($a -ieq [string]$right) { $match = $a } }
        if (-not $match) { throw ('Grant-CrDependentRights: the right {0} is not granted by this tool (only SeServiceLogonRight and SeBatchLogonRight).' -f $right) }
        if ($wanted -notcontains $match) { [void]$wanted.Add($match) }
    }
    $list = New-Object System.Collections.ArrayList
    foreach ($right in $wanted) {
        $r = @{ Right = $right; Success = $false; Win32Error = 0; Message = $null }
        try {
            $g = Grant-CrAccountRight -Sid $Sid -Right $right
            $r['Success'] = [bool]($g -and $g['Success'])
            if ($g) { $r['Win32Error'] = [int]$g['Win32Error'] }
            if (-not $r['Success']) { $r['Message'] = ('{0} could not be granted (error {1}).' -f $right, $r['Win32Error']) }
        } catch {
            $r['Message'] = $_.Exception.Message
        }
        [void]$list.Add($r)
    }
    return , $list.ToArray()
}

#endregion
