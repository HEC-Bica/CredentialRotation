# Principals.ps1 - selection rules, account resolution, SID overlap, group references
# (docs/PLAN.md sections 1.1 and 5, D5, D13, D21-D23; docs/dev/CONTRACTS.md)

# Returns the entries of an array part of $State; a failed part (@{ Error = ... }) or $null gives an empty array.
function Get-CrPrincipalPartList {
    param($Part)
    if ($null -eq $Part) { return , @() }
    if ($Part -is [hashtable]) {
        if ($Part.ContainsKey('Sid')) { return , @($Part) }
        return , @()
    }
    return , @($Part)
}

# Returns the error message of a failed part, or $null.
function Get-CrPrincipalPartError {
    param($Part, [string]$Section)
    if ($null -eq $Part) { return ('{0} not available' -f $Section) }
    if (($Part -is [hashtable]) -and -not $Part.ContainsKey('Sid') -and $Part['Error']) {
        return ('{0}: {1}' -f $Section, $Part['Error'])
    }
    return $null
}

function Get-CrMachineSidFromState {
    param($State)
    if (($State['Computer'] -is [hashtable]) -and $State['Computer']['MachineSid']) { return [string]$State['Computer']['MachineSid'] }
    return $null
}

function Find-CrUserByName {
    param($Users, [string]$Name)
    foreach ($user in $Users) {
        if ([string]$user['Name'] -ieq $Name) { return $user }
    }
    return $null
}

# Finds a local user by 'S-1-...' or 'RID-<n>' (machine SID + RID; falls back to the user's Rid if the machine SID is unknown).
function Find-CrUserBySidReference {
    param($Users, [string]$Reference, [string]$MachineSid)
    if ($Reference -match '^RID-(\d+)$') {
        $rid = [int]$matches[1]
        if ($MachineSid) {
            $Reference = '{0}-{1}' -f $MachineSid, $rid
        } else {
            foreach ($user in $Users) {
                if ($null -ne $user['Rid'] -and [int]$user['Rid'] -eq $rid) { return $user }
            }
            return $null
        }
    }
    foreach ($user in $Users) {
        if ([string]$user['Sid'] -ieq $Reference) { return $user }
    }
    return $null
}

function New-CrResolvedEntry {
    param($Entry)
    $kind = 'Windows'
    if ($Entry['Kind']) { $kind = [string]$Entry['Kind'] }
    $mode = 'Rotate'
    if ([string]$Entry['Mode'] -eq 'Check') { $mode = 'Check' }
    if ([string]$Entry['Mode'] -eq 'Disable') { $mode = 'Disable' }
    $autoLogonUser = $null
    if ($Entry.ContainsKey('AutoLogonUser') -and $null -ne $Entry['AutoLogonUser']) { $autoLogonUser = ConvertTo-CrArray $Entry['AutoLogonUser'] }
    # D9 (v10): Windows passwords are set unless the entry asks for a change
    $passwordMode = $null
    if ($kind -eq 'Windows' -and $mode -eq 'Rotate') {
        $passwordMode = 'Set'
        if ([string]$Entry['PasswordMode'] -eq 'Change') { $passwordMode = 'Change' }
    }
    return @{
        Id            = [string]$Entry['Id']
        Kind          = $kind
        Mode          = $mode
        RoleName      = $null
        Role          = $null
        Slot          = $null
        LoginsEntry   = ($Entry['LoginsEntry'] -eq $true)
        Accounts      = @()
        Missing       = @()
        Candidate     = $null
        NotApplicable = $true
        Create        = $false
        PasswordMode  = $passwordMode
        Replaced      = @()
        AutoLogon     = $Entry['AutoLogon']
        AutoLogonUser = $autoLogonUser
        Config        = $Entry
        Error         = $null
    }
}

# Replaced accounts of an entry (D22): existing accounts named in Replaces; 'RID-500' via the machine SID.
# Returns @(@{ Name; Sid; User; Enabled }) (comma-returned).
function Get-CrReplacedAccounts {
    param($Entry, $Users, [string]$MachineSid)
    $result = New-Object System.Collections.ArrayList
    if (-not $Entry.ContainsKey('Replaces')) { return , $result.ToArray() }
    $seen = New-Object System.Collections.ArrayList
    foreach ($item in (ConvertTo-CrArray $Entry['Replaces'])) {
        $reference = ([string]$item).Trim()
        if (-not $reference) { continue }
        $user = $null
        if ($reference -match '^RID-\d+$') {
            $user = Find-CrUserBySidReference -Users $Users -Reference $reference -MachineSid $MachineSid
        } else {
            $user = Find-CrUserByName -Users $Users -Name $reference
        }
        if (-not $user) { continue }
        $sid = [string]$user['Sid']
        if ($seen -contains $sid) { continue }
        [void]$seen.Add($sid)
        [void]$result.Add(@{ Name = [string]$user['Name']; Sid = $sid; User = $user; Enabled = (-not $user['Disabled']) })
    }
    return , $result.ToArray()
}

function Get-CrConfigRoleOrNull {
    param($Config, [string]$Name)
    if (-not $Name) { return $null }
    if (($Config['Roles'] -is [hashtable]) -and $Config['Roles'].ContainsKey($Name)) { return $Config['Roles'][$Name] }
    return $null
}

# Names that an entry selects explicitly (Name, Names, Replaces, candidate names, auto-logon user names).
function Get-CrExplicitNames {
    param($Entry)
    $names = New-Object System.Collections.ArrayList
    if ($Entry['Name']) { [void]$names.Add([string]$Entry['Name']) }
    if ($Entry.ContainsKey('Names')) { foreach ($n in (ConvertTo-CrArray $Entry['Names'])) { [void]$names.Add([string]$n) } }
    if ($Entry.ContainsKey('Replaces')) {
        foreach ($n in (ConvertTo-CrArray $Entry['Replaces'])) {
            if ($n -and ([string]$n -notmatch '^RID-\d+$')) { [void]$names.Add([string]$n) }
        }
    }
    if ($Entry.ContainsKey('Candidates')) {
        foreach ($c in (ConvertTo-CrArray $Entry['Candidates'])) {
            if (($c -is [hashtable]) -and $c['Name']) { [void]$names.Add([string]$c['Name']) }
        }
    }
    if ($Entry.ContainsKey('AutoLogonUser')) {
        foreach ($a in (ConvertTo-CrArray $Entry['AutoLogonUser'])) {
            if (($a -is [hashtable]) -and $a['Name']) { [void]$names.Add([string]$a['Name']) }
        }
    }
    return , $names.ToArray()
}

function Add-CrResolvedAccount {
    param($Accounts, [string]$Name, [string]$Sid, $User)
    foreach ($existing in $Accounts) {
        if ([string]$existing['Sid'] -ieq $Sid) { return }
    }
    [void]$Accounts.Add(@{ Name = $Name; Sid = $Sid; User = $User })
}

# Resolves the selection rules of every config entry to accounts (PLAN section 5 "Runtime resolution").
# Returns an array (comma-returned: assign directly, don't wrap the call in @()).
function Resolve-CrAccounts {
    param($Config, $State)
    $users = Get-CrPrincipalPartList $State['Users']
    $usersError = Get-CrPrincipalPartError -Part $State['Users'] -Section 'Users'
    $machineSid = Get-CrMachineSidFromState $State

    $logins = @()
    $sqlError = $null
    $sql = $State['Sql']
    if (-not ($sql -is [hashtable])) {
        $sqlError = 'SQL state not available'
    } else {
        if ($null -ne $sql['Logins']) { $logins = ConvertTo-CrArray $sql['Logins'] }
        if ($sql['Error']) {
            $sqlError = 'SQL: {0}' -f $sql['Error']
        } elseif (-not $sql['Connected']) {
            $sqlError = 'SQL: not connected to the default instance'
        }
    }

    $entries = ConvertTo-CrArray $Config['Accounts']
    $resolved = New-Object 'object[]' $entries.Count

    # Pass 1: everything except NamePattern selections
    for ($i = 0; $i -lt $entries.Count; $i++) {
        $entry = $entries[$i]
        if ($entry.ContainsKey('NamePattern') -and [string]$entry['Kind'] -ne 'SqlLogin') { continue }
        $r = New-CrResolvedEntry $entry
        $accounts = New-Object System.Collections.ArrayList
        $missing = New-Object System.Collections.ArrayList

        if ($r.Kind -eq 'SqlLogin') {
            $r.Error = $sqlError
            $loginName = [string]$entry['Name']
            $match = $null
            foreach ($login in $logins) {
                if (([string]$login['Type'] -eq 'SQL_LOGIN') -and ([string]$login['Name'] -ieq $loginName)) { $match = $login; break }
            }
            if ($match) {
                Add-CrResolvedAccount -Accounts $accounts -Name ([string]$match['Name']) -Sid ([string]$match['Sid']) -User $match
            } else {
                [void]$missing.Add($loginName)
            }
            if ($entry['Role']) { $r.RoleName = [string]$entry['Role'] }
            $r.Slot = $entry['Credential']
        } elseif ($entry.ContainsKey('Candidates')) {
            $r.Error = $usersError
            $candidates = ConvertTo-CrArray $entry['Candidates']
            for ($c = 0; $c -lt $candidates.Count; $c++) {
                $candidate = $candidates[$c]
                $user = $null
                if ($candidate['Name']) {
                    $user = Find-CrUserByName -Users $users -Name ([string]$candidate['Name'])
                } elseif ($candidate['Sid']) {
                    $user = Find-CrUserBySidReference -Users $users -Reference ([string]$candidate['Sid']) -MachineSid $machineSid
                }
                if ($user) {
                    Add-CrResolvedAccount -Accounts $accounts -Name ([string]$user['Name']) -Sid ([string]$user['Sid']) -User $user
                    $r.Candidate = $c
                    $r.RoleName = [string]$candidate['Role']
                    $r.Slot = $candidate['Credential']
                    break
                }
            }
            if ($null -eq $r.Candidate) {
                foreach ($candidate in $candidates) {
                    if ($candidate['Name']) { [void]$missing.Add([string]$candidate['Name']) } else { [void]$missing.Add([string]$candidate['Sid']) }
                }
            }
        } else {
            $r.Error = $usersError
            $names = @()
            if ($entry.ContainsKey('Names')) { $names = ConvertTo-CrArray $entry['Names'] } elseif ($entry['Name']) { $names = @([string]$entry['Name']) }
            foreach ($name in $names) {
                $user = Find-CrUserByName -Users $users -Name ([string]$name)
                if ($user) {
                    Add-CrResolvedAccount -Accounts $accounts -Name ([string]$user['Name']) -Sid ([string]$user['Sid']) -User $user
                } else {
                    [void]$missing.Add([string]$name)
                }
            }
            if ($entry['Role']) { $r.RoleName = [string]$entry['Role'] }
            $r.Slot = $entry['Credential']
            # D21: a managed account that doesn't exist is created. Only when the user list was read:
            # otherwise "missing" isn't known (the entry carries the Users error instead).
            if (($entry['Create'] -eq $true) -and ($r.Mode -eq 'Rotate') -and -not $usersError -and $missing.Count -gt 0) {
                foreach ($m in $missing) { [void]$accounts.Add(@{ Name = [string]$m; Sid = $null; User = $null; ToCreate = $true }) }
                $missing.Clear()
                $r.Create = $true
            }
        }
        if ($r.Kind -eq 'Windows' -and $r.Mode -eq 'Rotate') {
            $r.Replaced = Get-CrReplacedAccounts -Entry $entry -Users $users -MachineSid $machineSid
        }

        $r.Accounts = $accounts.ToArray()
        $r.Missing = $missing.ToArray()
        $r.NotApplicable = ($accounts.Count -eq 0)
        $r.Role = Get-CrConfigRoleOrNull -Config $Config -Name $r.RoleName
        $resolved[$i] = $r
    }

    # Pass 2: NamePattern, excluding accounts named explicitly by any other entry or resolved by a non-pattern entry
    for ($i = 0; $i -lt $entries.Count; $i++) {
        if ($null -ne $resolved[$i]) { continue }
        $entry = $entries[$i]
        $excludedNames = New-Object System.Collections.ArrayList
        $excludedSids = New-Object System.Collections.ArrayList
        for ($j = 0; $j -lt $entries.Count; $j++) {
            if ($j -eq $i -or [string]$entries[$j]['Kind'] -eq 'SqlLogin') { continue }
            foreach ($n in (Get-CrExplicitNames $entries[$j])) { [void]$excludedNames.Add($n) }
            if (($null -ne $resolved[$j]) -and -not $entries[$j].ContainsKey('NamePattern')) {
                foreach ($a in (ConvertTo-CrArray $resolved[$j].Accounts)) { if ($a['Sid']) { [void]$excludedSids.Add([string]$a['Sid']) } }
                foreach ($a in (ConvertTo-CrArray $resolved[$j].Replaced)) { if ($a['Sid']) { [void]$excludedSids.Add([string]$a['Sid']) } }
            }
        }

        $r = New-CrResolvedEntry $entry
        $r.Error = $usersError
        $accounts = New-Object System.Collections.ArrayList
        $pattern = [string]$entry['NamePattern']
        foreach ($user in $users) {
            $userName = [string]$user['Name']
            if (-not [System.Text.RegularExpressions.Regex]::IsMatch($userName, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) { continue }
            if ($excludedNames -contains $userName) { continue }
            if ($excludedSids -contains [string]$user['Sid']) { continue }
            Add-CrResolvedAccount -Accounts $accounts -Name $userName -Sid ([string]$user['Sid']) -User $user
        }
        if ($entry['Role']) { $r.RoleName = [string]$entry['Role'] }
        $r.Slot = $entry['Credential']
        $r.Accounts = $accounts.ToArray()
        $r.Missing = @()
        $r.NotApplicable = ($accounts.Count -eq 0)
        $r.Role = Get-CrConfigRoleOrNull -Config $Config -Name $r.RoleName
        $resolved[$i] = $r
    }

    return , $resolved
}

# D13: a SID claimed by two entries is an ambiguity. Returns an array of findings (comma-returned).
# Every selection counts as a claim: the accounts of managed, Check and Disable entries, and the accounts
# named in Replaces (claimed as '<Id> (replaces)', so an entry replacing its own account is reported too).
function Find-CrSidOverlap {
    param($Resolved)
    $findings = New-Object System.Collections.ArrayList
    $order = New-Object System.Collections.ArrayList
    $claims = @{}
    foreach ($r in (ConvertTo-CrArray $Resolved)) {
        if (-not ($r -is [hashtable])) { continue }
        $sets = @(
            @{ Label = [string]$r['Id']; Accounts = (ConvertTo-CrArray $r['Accounts']) },
            @{ Label = ('{0} (replaces)' -f $r['Id']); Accounts = (ConvertTo-CrArray $r['Replaced']) }
        )
        foreach ($set in $sets) {
            foreach ($a in $set['Accounts']) {
                if (-not $a['Sid']) { continue }
                $key = ('{0}|{1}' -f $r['Kind'], $a['Sid']).ToUpperInvariant()
                if (-not $claims.ContainsKey($key)) {
                    $claims[$key] = @{ Name = [string]$a['Name']; Sid = [string]$a['Sid']; Ids = (New-Object System.Collections.ArrayList); Slots = (New-Object System.Collections.ArrayList) }
                    [void]$order.Add($key)
                }
                $claim = $claims[$key]
                if ($claim.Ids -notcontains $set['Label']) {
                    [void]$claim.Ids.Add($set['Label'])
                    [void]$claim.Slots.Add(('{0} (slot {1})' -f $set['Label'], $r['Slot']))
                }
            }
        }
    }
    foreach ($key in $order) {
        $claim = $claims[$key]
        if ($claim.Ids.Count -lt 2) { continue }
        $message = 'Account ''{0}'' ({1}) is selected by more than one config entry: {2}. Fix the configuration.' -f $claim.Name, $claim.Sid, ($claim.Ids.ToArray() -join ', ')
        [void]$findings.Add((New-CrFinding -Severity 'Ambiguous' -Area 'Principals' -Account $claim.Name -Message $message -Detail ($claim.Slots.ToArray() -join '; ')))
    }
    return , $findings.ToArray()
}

# D23: the enabled local accounts that no entry selects (managed, replaced, Disable, Check).
# Disabled accounts (Guest, DefaultAccount, ...) never appear. Returns $State.Users entries (comma-returned).
function Get-CrOtherEnabledAccounts {
    param($State, $Resolved)
    $result = New-Object System.Collections.ArrayList
    $users = Get-CrPrincipalPartList $State['Users']
    $selected = New-Object System.Collections.ArrayList
    foreach ($r in (ConvertTo-CrArray $Resolved)) {
        if (-not ($r -is [hashtable]) -or $r['Kind'] -ne 'Windows') { continue }
        foreach ($a in (ConvertTo-CrArray $r['Accounts'])) { if ($a['Sid']) { [void]$selected.Add(([string]$a['Sid']).ToUpperInvariant()) } }
        foreach ($a in (ConvertTo-CrArray $r['Replaced'])) { if ($a['Sid']) { [void]$selected.Add(([string]$a['Sid']).ToUpperInvariant()) } }
    }
    foreach ($user in $users) {
        if (-not ($user -is [hashtable]) -or -not $user['Sid']) { continue }
        if ($user['Disabled']) { continue }
        if ($selected -contains ([string]$user['Sid']).ToUpperInvariant()) { continue }
        [void]$result.Add($user)
    }
    return , $result.ToArray()
}

# Resolves a group reference: 'S-1-...' (taken as is), 'RID-<n>' (machine SID + RID), 'Name:x' (must exist),
# 'Name:x?' (optional), 'Pattern:re' (every local group whose name matches, case-insensitive).
# Returns @{ Sids; Optional; Missing; Error }. Missing is $true only for a required group that doesn't exist.
function Resolve-CrGroupReference {
    param([string]$Reference, $State)
    $result = @{ Sids = @(); Optional = $false; Missing = $false; Error = $null }
    $groups = Get-CrPrincipalPartList $State['Groups']
    $groupsError = Get-CrPrincipalPartError -Part $State['Groups'] -Section 'Groups'

    if ($Reference -match '^S-1-\d+(-\d+)+$') {
        $result.Sids = @($Reference)
        return $result
    }
    if ($Reference -match '^RID-(\d+)$') {
        $machineSid = Get-CrMachineSidFromState $State
        if ($machineSid) {
            $result.Sids = @('{0}-{1}' -f $machineSid, $matches[1])
        } else {
            $result.Missing = $true
            $result.Error = 'Machine SID not available'
        }
        return $result
    }
    if ($Reference -match '^Name:(.+)$') {
        $name = $matches[1]
        if ($name.EndsWith('?')) {
            $result.Optional = $true
            $name = $name.Substring(0, $name.Length - 1)
        }
        foreach ($group in $groups) {
            if ([string]$group['Name'] -ieq $name) {
                $result.Sids = @([string]$group['Sid'])
                return $result
            }
        }
        $result.Error = $groupsError
        if (-not $result.Optional) { $result.Missing = $true }
        return $result
    }
    if ($Reference -match '^Pattern:(.+)$') {
        $pattern = $matches[1]
        $result.Optional = $true
        $result.Error = $groupsError
        $sids = New-Object System.Collections.ArrayList
        foreach ($group in $groups) {
            if ([System.Text.RegularExpressions.Regex]::IsMatch([string]$group['Name'], $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
                [void]$sids.Add([string]$group['Sid'])
            }
        }
        $result.Sids = $sids.ToArray()
        return $result
    }
    throw ('Unknown group reference: {0}' -f $Reference)
}
