# AutoLogon.ps1 - Winlogon auto-logon read side and the D18 decision (docs/PLAN.md section 7.5).
# Read-only: never reads the DefaultPassword value or the LSA secret, only whether the value exists.

#region Registry access (internal, mocked in tests)

# All values of a key as name -> @{ Value; Kind }; $null if the key can't be opened.
# The value of DefaultPassword is never read: only its presence is recorded (Value = $null).
function Get-CrAutoLogonKeyValues {
    param([string]$Path)
    try {
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
    } catch {
        return $null
    }
    $result = @{}
    foreach ($n in @($key.GetValueNames())) {
        if ($null -eq $n) { continue }
        if ($n -ieq 'DefaultPassword') {
            $result[$n] = @{ Value = $null; Kind = $null }
            continue
        }
        $kind = $null
        try { $kind = $key.GetValueKind($n).ToString() } catch { }
        $result[$n] = @{ Value = $key.GetValue($n); Kind = $kind }
    }
    return $result
}

# SIDs of loaded user hives that hold Sysinternals Autologon settings.
function Get-CrSysinternalsAutologonSids {
    $list = New-Object System.Collections.ArrayList
    foreach ($hive in @(Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue)) {
        if (-not $hive) { continue }
        $name = [string]$hive.PSChildName
        if ($name -match '_Classes$') { continue }
        $path = 'Registry::HKEY_USERS\' + $name + '\Software\Sysinternals\Autologon'
        if (Test-Path -LiteralPath $path) { [void]$list.Add($name) }
    }
    return , $list.ToArray()
}

#endregion

#region Helpers (internal)

function Get-CrAutoLogonText {
    param($Values, [string]$Name)
    if (-not $Values -or -not $Values.ContainsKey($Name)) { return $null }
    $v = $Values[$Name]['Value']
    if ($null -eq $v) { return $null }
    if ($v -is [array]) { return (@($v) -join ' ') }
    return [string]$v
}

function Test-CrAutoLogonTextSet {
    param($Values, [string]$Name)
    $t = Get-CrAutoLogonText -Values $Values -Name $Name
    return [bool]($t -and $t.Trim())
}

# Executable of a command line, without arguments (arguments may hold secrets, D4).
function Get-CrAutoLogonExecutable {
    param([string]$CommandLine)
    if (-not $CommandLine) { return $null }
    $c = $CommandLine.Trim()
    if (-not $c) { return $null }
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        if ($end -gt 0) { return $c.Substring(1, $end - 1) }
        return $c.Trim('"')
    }
    $m = [regex]::Match($c, '^(.+?\.(exe|com|bat|cmd|ps1|vbs|js))(\s|$)', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    return @($c -split '\s+')[0]
}

function Get-CrAutoLogonLeaf {
    param([string]$Path)
    if (-not $Path) { return '' }
    $p = $Path.Trim().Trim('"')
    $i = $p.LastIndexOf('\')
    if ($i -ge 0) { $p = $p.Substring($i + 1) }
    return $p
}

function Get-CrAutoLogonComputerName {
    param($State)
    $c = $State['Computer']
    if ($c -and $c['Name']) { return [string]$c['Name'] }
    return $env:COMPUTERNAME
}

# Local user by name, case-insensitive. A 'X\' prefix (computer, '.', stale name) is ignored:
# these are standalone workgroup machines, so the name is always resolved against local accounts.
function Find-CrAutoLogonLocalUser {
    param($State, [string]$Name)
    if (-not $Name) { return $null }
    $n = $Name.Trim()
    $i = $n.LastIndexOf('\')
    if ($i -ge 0) { $n = $n.Substring($i + 1) }
    if (-not $n) { return $null }
    foreach ($u in (ConvertTo-CrArray $State['Users'])) {
        if ($u -is [hashtable] -and $u['Name'] -and ([string]$u['Name'] -ieq $n)) { return $u }
    }
    return $null
}

function Find-CrAutoLogonUserBySid {
    param($State, [string]$Sid)
    if (-not $Sid) { return $null }
    foreach ($u in (ConvertTo-CrArray $State['Users'])) {
        if ($u -is [hashtable] -and $u['Sid'] -eq $Sid) { return $u }
    }
    return $null
}

# The resolved entry that carries the AutoLogon block (PLAN section 5).
function Find-CrAutoLogonEntry {
    param($Resolved)
    foreach ($e in (ConvertTo-CrArray $Resolved)) {
        if ($e -is [hashtable] -and $e['AutoLogon']) { return $e }
    }
    return $null
}

# Selection list: the entry's AutoLogonUser, else the config entry's, else the entry's accounts in order.
function Get-CrAutoLogonSelectionList {
    param($Entry, $Config)
    $list = ConvertTo-CrArray $Entry['AutoLogonUser']
    if ($list.Count -eq 0 -and $Config -and $Config['Accounts']) {
        foreach ($a in (ConvertTo-CrArray $Config['Accounts'])) {
            if ($a -is [hashtable] -and $a['AutoLogon'] -and $a['Id'] -eq $Entry['Id']) {
                $list = ConvertTo-CrArray $a['AutoLogonUser']
            }
        }
    }
    if ($list.Count -eq 0) {
        $tmp = New-Object System.Collections.ArrayList
        foreach ($acc in (ConvertTo-CrArray $Entry['Accounts'])) {
            if ($acc -is [hashtable] -and $acc['Name']) { [void]$tmp.Add(@{ Name = $acc['Name'] }) }
        }
        $list = ConvertTo-CrArray $tmp.ToArray()
    }
    return , $list
}

# PLAN section 7.5 usable-target rule: exists, enabled, not locked, interactive logon allowed (D16),
# not an admin (unless this run removes it from Administrators before the auto-logon step).
function Test-CrAutoLogonUsable {
    param($State, $User, $RemovedAdminSids)
    $reasons = New-Object System.Collections.ArrayList
    $r = @{ Usable = $false; Reasons = $reasons; AdminPending = $false; AdminRemoved = $false }
    if (-not $User) {
        [void]$reasons.Add('does not exist')
        return $r
    }
    $sid = [string]$User['Sid']
    if ($User['Disabled']) { [void]$reasons.Add('is disabled') }
    if ($User['LockedOut']) { [void]$reasons.Add('is locked out') }
    $rights = Get-CrEffectiveLogonRights -UserSid $sid -State $State
    if (-not ($rights -is [hashtable] -and $rights['Interactive'])) {
        [void]$reasons.Add('is not allowed interactive logon')
    }
    if (Test-CrIsAdmin -UserSid $sid -State $State) {
        if ((ConvertTo-CrArray $RemovedAdminSids) -contains $sid) {
            $r['AdminRemoved'] = $true
        } else {
            $r['AdminPending'] = $true
            [void]$reasons.Add('is a member of Administrators and this run does not remove it (its slot did not complete)')
        }
    }
    $r['Usable'] = ($reasons.Count -eq 0)
    return $r
}

function Get-CrAutoLogonDisplayName {
    param($User, [string]$Fallback)
    if ($User -and $User['Name']) { return [string]$User['Name'] }
    return $Fallback
}

#endregion

#region Public

function Get-CrAutoLogonState {
    $state = @{
        AutoAdminLogon                 = $null
        AutoAdminLogonKind             = $null
        DefaultUserName                = $null
        DefaultDomainName              = $null
        DefaultPasswordPresent         = $false
        AutoLogonCountPresent          = $false
        ForceAutoLogon                 = $null
        AutoLogonSidValue              = $null
        OtherMechanisms                = @()
        LegalNoticeCaptionSet          = $false
        LegalNoticeTextSet             = $false
        DevicePasswordLessBuildVersion = $null
        Error                          = $null
    }
    try {
        $wl = Get-CrAutoLogonKeyValues -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        if ($null -eq $wl) {
            $state['Error'] = 'The Winlogon key could not be opened.'
            return $state
        }

        if ($wl.ContainsKey('AutoAdminLogon')) {
            $state['AutoAdminLogon'] = Get-CrAutoLogonText -Values $wl -Name 'AutoAdminLogon'
            $state['AutoAdminLogonKind'] = $wl['AutoAdminLogon']['Kind']
        }
        $state['DefaultUserName'] = Get-CrAutoLogonText -Values $wl -Name 'DefaultUserName'
        $state['DefaultDomainName'] = Get-CrAutoLogonText -Values $wl -Name 'DefaultDomainName'
        $state['DefaultPasswordPresent'] = $wl.ContainsKey('DefaultPassword')
        $state['AutoLogonCountPresent'] = $wl.ContainsKey('AutoLogonCount')
        $state['ForceAutoLogon'] = Get-CrAutoLogonText -Values $wl -Name 'ForceAutoLogon'
        $state['AutoLogonSidValue'] = Get-CrAutoLogonText -Values $wl -Name 'AutoLogonSID'

        $pol = Get-CrAutoLogonKeyValues -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        $state['LegalNoticeCaptionSet'] = ((Test-CrAutoLogonTextSet -Values $wl -Name 'LegalNoticeCaption') -or
            (Test-CrAutoLogonTextSet -Values $pol -Name 'legalnoticecaption'))
        $state['LegalNoticeTextSet'] = ((Test-CrAutoLogonTextSet -Values $wl -Name 'LegalNoticeText') -or
            (Test-CrAutoLogonTextSet -Values $pol -Name 'legalnoticetext'))

        $pwLess = Get-CrAutoLogonKeyValues -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device'
        $state['DevicePasswordLessBuildVersion'] = Get-CrAutoLogonText -Values $pwLess -Name 'DevicePasswordLessBuildVersion'

        # Other mechanisms (PLAN section 7.5): shell replacement, extra Userinit programs, Sysinternals Autologon.
        $mech = New-Object System.Collections.ArrayList
        $shell = Get-CrAutoLogonText -Values $wl -Name 'Shell'
        if ($shell -and $shell.Trim()) {
            $exe = Get-CrAutoLogonExecutable $shell
            $leaf = Get-CrAutoLogonLeaf $exe
            if (@('explorer.exe', 'explorer') -notcontains $leaf.ToLowerInvariant()) {
                [void]$mech.Add(('Winlogon Shell is not explorer.exe: {0}' -f $exe))
            }
        }
        $userinit = Get-CrAutoLogonText -Values $wl -Name 'Userinit'
        if ($userinit) {
            foreach ($part in @($userinit -split ',')) {
                if (-not $part -or -not $part.Trim()) { continue }
                $exe = Get-CrAutoLogonExecutable $part
                $leaf = Get-CrAutoLogonLeaf $exe
                if (@('userinit.exe', 'userinit') -notcontains $leaf.ToLowerInvariant()) {
                    [void]$mech.Add(('Winlogon Userinit runs an additional program: {0}' -f $exe))
                }
            }
        }
        foreach ($sid in (ConvertTo-CrArray (Get-CrSysinternalsAutologonSids))) {
            if (-not $sid) { continue }
            [void]$mech.Add(('Sysinternals Autologon settings in the profile hive of {0}' -f $sid))
        }
        $state['OtherMechanisms'] = $mech.ToArray()
    } catch {
        $state['Error'] = $_.Exception.Message
    }
    return $state
}

# D18 decision, PLAN section 7.5. Read-only; the apply step (M2) acts on the result.
function Get-CrAutoLogonDecision {
    param(
        $State,
        $Resolved,
        $Config,
        [string[]]$VerifiedSids,
        [string[]]$RemovedAdminSids
    )
    $verified = ConvertTo-CrArray $VerifiedSids
    $removed = ConvertTo-CrArray $RemovedAdminSids
    $reasons = New-Object System.Collections.ArrayList
    $highImpact = New-Object System.Collections.ArrayList
    $options = New-Object System.Collections.ArrayList
    $d = @{
        Action = 'NoChange'; CurrentSid = $null; CurrentName = $null; TargetSid = $null; TargetName = $null
        Reasons = @(); OperatorOptions = @(); HighImpact = @()
    }

    $al = $State['AutoLogon']
    if (-not ($al -is [hashtable]) -or $al['Error']) {
        $msg = 'Auto-logon state could not be read'
        if ($al -is [hashtable] -and $al['Error']) { $msg = $msg + ': ' + $al['Error'] }
        [void]$reasons.Add($msg + '; the auto-logon policy is not evaluated.')
        $d['Reasons'] = $reasons.ToArray()
        return $d
    }
    $entry = Find-CrAutoLogonEntry -Resolved $Resolved
    if (-not $entry) {
        [void]$reasons.Add('No account entry with an AutoLogon block is configured; the auto-logon policy is not evaluated.')
        $d['Reasons'] = $reasons.ToArray()
        return $d
    }

    $computerName = Get-CrAutoLogonComputerName -State $State
    $isSm = $false
    if ($State['Computer'] -is [hashtable]) { $isSm = [bool]$State['Computer']['IsSm'] }

    # Current account (DefaultUserName, resolved against local users)
    $defUser = [string]$al['DefaultUserName']
    $current = Find-CrAutoLogonLocalUser -State $State -Name $defUser
    if ($current) {
        $d['CurrentSid'] = [string]$current['Sid']
        $d['CurrentName'] = [string]$current['Name']
    } elseif ($defUser) {
        $d['CurrentName'] = $defUser
    }
    $curName = $d['CurrentName']
    if (-not $curName) { $curName = '(none)' }

    # Values that are reported (not deciding)
    $domain = [string]$al['DefaultDomainName']
    if ($domain -and $domain.Trim() -and ($domain.Trim() -ine $computerName)) {
        [void]$reasons.Add(('DefaultDomainName "{0}" differs from the computer name "{1}" (mismatch).' -f $domain, $computerName))
    }
    if ($al['ForceAutoLogon'] -and ([string]$al['ForceAutoLogon']).Trim() -and ([string]$al['ForceAutoLogon']).Trim() -ne '0') {
        [void]$reasons.Add(('ForceAutoLogon is set ({0}).' -f $al['ForceAutoLogon']))
    }
    if ($al['LegalNoticeTextSet'] -and -not $al['LegalNoticeCaptionSet']) {
        [void]$reasons.Add('A legal-notice text without a caption is set (reported, not blocking).')
    } elseif ($al['LegalNoticeTextSet'] -or $al['LegalNoticeCaptionSet']) {
        [void]$reasons.Add('Legal-notice settings are present (reported, not blocking).')
    }
    if ($al['DevicePasswordLessBuildVersion'] -and ([string]$al['DevicePasswordLessBuildVersion']).Trim() -ne '0') {
        [void]$reasons.Add(('DevicePasswordLessBuildVersion = {0}.' -f $al['DevicePasswordLessBuildVersion']))
    }

    $aal = ''
    if ($null -ne $al['AutoAdminLogon']) { $aal = ([string]$al['AutoAdminLogon']).Trim() }
    $isOn = ($aal -eq '1')
    $isOff = ($aal -eq '' -or $aal -eq '0')
    $mechanisms = ConvertTo-CrArray $al['OtherMechanisms']

    $ambiguous = New-Object System.Collections.ArrayList
    foreach ($m in $mechanisms) { if ($m) { [void]$ambiguous.Add(('Non-Winlogon auto-logon mechanism: {0}' -f $m)) } }
    if (-not $isOn -and -not $isOff) {
        [void]$ambiguous.Add(('AutoAdminLogon has an unexpected value "{0}".' -f $aal))
    }

    # Off, nothing else: stays off.
    if ($isOff -and $ambiguous.Count -eq 0) {
        $d['Action'] = 'LeaveOff'
        [void]$reasons.Add('Auto-logon is off; it stays off.')
        if ($al['DefaultPasswordPresent']) {
            [void]$reasons.Add('A plain-text DefaultPassword is stored in the Winlogon key while auto-logon is off (reported, not changed).')
        }
        $d['Reasons'] = $reasons.ToArray()
        return $d
    }

    if ($al['DefaultPasswordPresent']) {
        [void]$reasons.Add('A plain-text DefaultPassword is stored in the Winlogon key.')
    }
    if ($al['AutoAdminLogonKind'] -eq 'DWord') {
        [void]$reasons.Add('AutoAdminLogon is a REG_DWORD (accepted; the standard form is REG_SZ "1").')
    }

    $intended = $null
    $target = $null
    $currentUsable = $null
    $isManaged = $false

    if ($isOn) {
        if ($al['AutoLogonCountPresent']) {
            [void]$ambiguous.Add('AutoLogonCount is present (count-limited auto-logon).')
        }
        if (-not $current) {
            [void]$ambiguous.Add(('The auto-logon account "{0}" cannot be resolved to a local account.' -f $defUser))
        }

        # Managed auto-logon accounts and the selected user (first usable of the selection list)
        $selection = Get-CrAutoLogonSelectionList -Entry $entry -Config $Config
        $managedSids = New-Object System.Collections.ArrayList
        foreach ($acc in (ConvertTo-CrArray $entry['Accounts'])) {
            if ($acc -is [hashtable] -and $acc['Sid']) { [void]$managedSids.Add([string]$acc['Sid']) }
        }
        # Only used on non-SM machines (SM machines keep or turn off, no selection).
        $selected = $null
        $selectionNotes = New-Object System.Collections.ArrayList
        $selectionAmbiguous = New-Object System.Collections.ArrayList
        foreach ($item in $selection) {
            if (-not ($item -is [hashtable]) -or -not $item['Name']) { continue }
            $u = Find-CrAutoLogonLocalUser -State $State -Name ([string]$item['Name'])
            if ($u -and ($managedSids -notcontains [string]$u['Sid'])) { [void]$managedSids.Add([string]$u['Sid']) }
            if ($selected -or $isSm) { continue }
            $usable = Test-CrAutoLogonUsable -State $State -User $u -RemovedAdminSids $removed
            if ($u -and $item['RequireEnabled'] -and $u['Disabled']) { $usable['Usable'] = $false }
            if ($usable['Usable']) {
                $selected = $u
            } else {
                [void]$selectionNotes.Add(('{0} is not a usable auto-logon target: {1}.' -f $item['Name'], (@($usable['Reasons']) -join ', ')))
                # A preferred account that is only unusable because it is still an admin (D13: ask, don't skip it)
                if ($usable['AdminPending'] -and @($usable['Reasons']).Count -eq 1) {
                    [void]$selectionAmbiguous.Add(('{0} is itself an admin and its slot did not complete in this run.' -f $u['Name']))
                }
            }
        }

        if ($current) {
            $isManaged = ($managedSids -contains [string]$current['Sid'])
            $currentUsable = Test-CrAutoLogonUsable -State $State -User $current -RemovedAdminSids $removed
            if ($isManaged -and $currentUsable['AdminPending']) {
                $msg = ('{0} is itself an admin and its slot did not complete in this run.' -f $current['Name'])
                if ($ambiguous -notcontains $msg) { [void]$ambiguous.Add($msg) }
            }
            $kind = 'another account'
            if ($isManaged) {
                $kind = 'a managed auto-logon account'
            } elseif ($currentUsable['AdminPending'] -or (Test-CrIsAdmin -UserSid ([string]$current['Sid']) -State $State)) {
                $kind = 'an admin'
            }
            [void]$reasons.Add(('Auto-logon is on as {0} ({1}).' -f $current['Name'], $kind))

            if ($isSm) {
                if ($isManaged) {
                    $target = $current
                    if ($currentUsable['Usable']) {
                        $intended = 'Standardize'
                        [void]$reasons.Add('SM machine: the auto-logon account is kept and standardized.')
                    } else {
                        [void]$ambiguous.Add(('The kept auto-logon account {0} is not usable: {1}.' -f $current['Name'], (@($currentUsable['Reasons']) -join ', ')))
                    }
                } else {
                    $intended = 'TurnOff'
                    [void]$reasons.Add('SM machine: auto-logon as an admin or any other account is turned off.')
                }
            } else {
                foreach ($n in $selectionNotes) { [void]$reasons.Add($n) }
                foreach ($a in $selectionAmbiguous) {
                    if ($ambiguous -notcontains $a) { [void]$ambiguous.Add($a) }
                }
                if (-not $selected) {
                    if ($isManaged -and -not $currentUsable['Usable']) {
                        [void]$ambiguous.Add(('The standardized auto-logon account {0} is not usable: {1}.' -f $current['Name'], (@($currentUsable['Reasons']) -join ', ')))
                    }
                    [void]$ambiguous.Add('No usable auto-logon target (PUB-User / WinAutoUser) exists for a switch.')
                } elseif ([string]$selected['Sid'] -eq [string]$current['Sid']) {
                    $target = $selected
                    $intended = 'Standardize'
                    [void]$reasons.Add(('{0} is the selected auto-logon user; it is standardized.' -f $selected['Name']))
                } else {
                    $target = $selected
                    $intended = 'Switch'
                    [void]$reasons.Add(('Auto-logon is switched to the selected user {0}.' -f $selected['Name']))
                }
            }
        }
    }

    if ($target) {
        $d['TargetSid'] = [string]$target['Sid']
        $d['TargetName'] = [string]$target['Name']
    }
    $currentVerified = [bool]($d['CurrentSid'] -and ($verified -contains $d['CurrentSid']))

    if ($ambiguous.Count -gt 0) {
        $d['Action'] = 'Ambiguous'
        foreach ($a in $ambiguous) { [void]$reasons.Add('Ambiguous: ' + $a) }
        [void]$options.Add('TurnOff')
        [void]$options.Add('LeaveUnchanged')
    } elseif ($intended -eq 'TurnOff') {
        $d['Action'] = 'TurnOff'
    } elseif ($intended -eq 'Standardize') {
        if ($verified -contains $d['TargetSid']) {
            $d['Action'] = 'Standardize'
        } else {
            $d['Action'] = 'NoChange'
            [void]$reasons.Add(('{0} is not changed in this run: the stored password is still valid, so standardize changes nothing.' -f $d['TargetName']))
        }
    } elseif ($intended -eq 'Switch') {
        if ($verified -contains $d['TargetSid']) {
            $d['Action'] = 'Switch'
        } else {
            $d['Action'] = 'Ambiguous'
            [void]$reasons.Add(('Ambiguous: switch to {0} impossible, it is not on the new secret in this run (slot skipped, failed or not selected).' -f $d['TargetName']))
            [void]$options.Add('TurnOff')
            [void]$options.Add('LeaveUnchanged')
            if ($isManaged -and $currentUsable -and $currentUsable['Usable'] -and $currentVerified) {
                [void]$options.Add('StandardizeCurrent')
            }
        }
    }

    switch ($d['Action']) {
        'Switch' {
            [void]$highImpact.Add(('Auto-logon is switched from {0} to {1} (next reboot): the console session then runs as a standard user; startup programs and per-user settings of {0} no longer apply.' -f $curName, $d['TargetName']))
        }
        'TurnOff' {
            [void]$highImpact.Add(('Auto-logon as {0} is turned off: after the next reboot the machine waits at the logon screen.' -f $curName))
        }
        'Ambiguous' {
            if ($isOn -and $currentVerified) {
                [void]$highImpact.Add(('Auto-logon broken until re-run: {0} gets a new password in this run, but the auto-logon step can only run after an operator decision; if it is left unchanged, each boot costs one failed logon.' -f $curName))
            }
        }
    }

    $d['Reasons'] = $reasons.ToArray()
    $d['OperatorOptions'] = $options.ToArray()
    $d['HighImpact'] = $highImpact.ToArray()
    return $d
}

# PLAN section 7.5 "Audit": the readable values match a standardized auto-logon for TargetSid.
function Test-CrAutoLogonStandardized {
    param($State, [string]$TargetSid)
    if (-not $TargetSid) { return $false }
    $al = $State['AutoLogon']
    if (-not ($al -is [hashtable]) -or $al['Error']) { return $false }
    if ([string]$al['AutoAdminLogon'] -ne '1' -or $al['AutoAdminLogonKind'] -ne 'String') { return $false }
    $name = [string]$al['DefaultUserName']
    if (-not $name -or $name.IndexOf('\') -ge 0) { return $false }
    $u = Find-CrAutoLogonLocalUser -State $State -Name $name
    if (-not $u -or [string]$u['Sid'] -ne $TargetSid) { return $false }
    $domain = [string]$al['DefaultDomainName']
    if (-not $domain -or ($domain -ine (Get-CrAutoLogonComputerName -State $State))) { return $false }
    if ($al['DefaultPasswordPresent']) { return $false }
    if ($al['AutoLogonCountPresent']) { return $false }
    return $true
}

#endregion
