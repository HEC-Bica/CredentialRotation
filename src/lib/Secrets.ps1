# Secrets.ps1 - password prompts, checks, the D23 decisions and the credential probe
# (docs/PLAN.md section 6 steps 6-7, D4, D9, D12, D15, D16, D20, D23; CONTRACTS "v10: account model").
# Secrets are SecureStrings only. This file never converts one to a managed string, never prints, logs or stores one;
# comparisons, lengths, complexity and logon tests go through the Native.ps1 wrappers over BSTRs.

# --- console input (separate functions so tests can mock them) -----------------------------------

function Read-CrSecureHost {
    param([string]$Prompt)
    return (Read-Host -Prompt $Prompt -AsSecureString)
}

function Read-CrHostLine {
    param([string]$Prompt)
    return (Read-Host -Prompt $Prompt)
}

# Exact 'YES' (case-sensitive), PLAN section 6 step 8.
function Confirm-CrYes {
    param([string]$Prompt)
    $answer = Read-CrHostLine -Prompt $Prompt
    return ([string]$answer -ceq 'YES')
}

# Y/N question; asks again on other input (at most 3 times), then counts as 'No'.
function Confirm-CrYesNo {
    param([string]$Prompt)
    for ($i = 0; $i -lt 3; $i++) {
        $answer = ([string](Read-CrHostLine -Prompt $Prompt)).Trim()
        if (($answer -ieq 'Y') -or ($answer -ieq 'YES')) { return $true }
        if (($answer -ieq 'N') -or ($answer -ieq 'NO')) { return $false }
        Write-Host 'Please answer Y or N.'
    }
    return $false
}

# --- password rules (D15) -------------------------------------------------------------------------

# Name tokens for the complexity emulation: split on , . - _ # space tab; tokens of 3+ characters,
# de-duplicated case-insensitively. Returns a string array (comma-returned: assign it, don't wrap it in @()).
function Get-CrNameTokens {
    param([string[]]$Names)
    $tokens = New-Object System.Collections.ArrayList
    if (-not $Names) { return , ([string[]]$tokens.ToArray([string])) }
    $separators = [char[]]@(',', '.', '-', '_', '#', ' ', "`t")
    foreach ($name in $Names) {
        if (-not $name) { continue }
        foreach ($part in $name.Split($separators)) {
            if ($part.Length -lt 3) { continue }
            $known = $false
            foreach ($t in $tokens) { if ([string]$t -ieq $part) { $known = $true; break } }
            if (-not $known) { [void]$tokens.Add($part) }
        }
    }
    return , ([string[]]$tokens.ToArray([string]))
}

# SitePasswordRules (MinLength, RequireComplexity) via Test-CrSecretComplexity. Reasons never name a token.
function Test-CrSiteRules {
    param([System.Security.SecureString]$Secret, $Config, [string[]]$Names)
    $minLength = 0
    $requireComplexity = $false
    $rules = $null
    if ($Config -is [hashtable]) { $rules = $Config['SitePasswordRules'] }
    if ($rules -is [hashtable]) {
        if ($null -ne $rules['MinLength']) { $minLength = [int]$rules['MinLength'] }
        $requireComplexity = ($rules['RequireComplexity'] -eq $true)
    }
    $tokens = Get-CrNameTokens -Names $Names
    $check = Test-CrSecretComplexity -Secret $Secret -MinLength $minLength -RequireComplexity $requireComplexity -Tokens $tokens
    $reasons = New-Object System.Collections.ArrayList
    if ($check['TooShort']) { [void]$reasons.Add(('shorter than the site minimum of {0} characters' -f $minLength)) }
    if ($requireComplexity) {
        if ([int]$check['Categories'] -lt 3) {
            [void]$reasons.Add(('uses {0} of 5 character categories (upper case, lower case, digits, symbols, other letters); the site rules require 3' -f [int]$check['Categories']))
        }
        if ($check['ContainsNameToken']) { [void]$reasons.Add('contains a part (3 or more characters) of an account name or full name of this slot') }
    }
    if (($reasons.Count -eq 0) -and ($check['Ok'] -ne $true)) { [void]$reasons.Add('does not meet the site password rules') }
    return @{ Ok = ($reasons.Count -eq 0); Reasons = $reasons.ToArray() }
}

# All checks of a new password for one slot: site rules, local policy per account, slot MaxLength.
# -ExtraNames: the slot's configured account names that don't exist on this machine. They count for the D15 name
# tokens too, so a site password that a sibling machine with that account would reject is rejected here as well.
function Get-CrNewSecretProblems {
    param([System.Security.SecureString]$NewSecret, $Config, $Accounts, $SlotDefinition, [string[]]$ExtraNames)
    $problems = New-Object System.Collections.ArrayList
    $names = New-Object System.Collections.ArrayList
    foreach ($a in $Accounts) {
        if ($a['Name']) { [void]$names.Add([string]$a['Name']) }
        if (($a['User'] -is [hashtable]) -and $a['User']['FullName']) { [void]$names.Add([string]$a['User']['FullName']) }
    }
    foreach ($n in (ConvertTo-CrArray $ExtraNames)) { if ($n) { [void]$names.Add([string]$n) } }
    $site = Test-CrSiteRules -Secret $NewSecret -Config $Config -Names ([string[]]$names.ToArray([string]))
    foreach ($r in (ConvertTo-CrArray $site['Reasons'])) { [void]$problems.Add([string]$r) }
    foreach ($a in $Accounts) {
        # PLAN 6 step 6: only a policy verdict rejects the password. A failed call is a warning: Windows still checks
        # the policy when the password is set.
        $local = $null
        $callError = $null
        try {
            $local = Test-CrLocalPasswordPolicy -UserName ([string]$a['Name']) -Secret $NewSecret
            if (-not ($local -is [hashtable]) -or $null -eq $local['Status']) {
                $code = 0
                if ($local -is [hashtable]) { $code = [int]$local['Win32Error'] }
                $callError = 'error {0}' -f $code
            }
        } catch {
            $callError = $_.Exception.Message
        }
        if ($callError) {
            Write-Host ('Warning: the local password policy could not be pre-checked for {0} ({1}); Windows checks it when the password is set.' -f $a['Name'], $callError)
            Write-CrLog ('Local policy pre-check failed for {0}: {1}' -f $a['Name'], $callError) 'Warning'
            continue
        }
        if ($local['Ok'] -ne $true) {
            [void]$problems.Add(('rejected by the local password policy for {0} (status {1})' -f $a['Name'], $local['Status']))
        }
    }
    if (($SlotDefinition -is [hashtable]) -and ($null -ne $SlotDefinition['MaxLength'])) {
        $max = [int]$SlotDefinition['MaxLength']
        if ((Get-CrSecretLength -Secret $NewSecret) -gt $max) { [void]$problems.Add(('longer than {0} characters' -f $max)) }
    }
    return , $problems.ToArray()
}

# --- other enabled accounts (D23) -----------------------------------------------------------------

# Asks the operator, one account at a time, whether each other enabled local account is disabled or kept (D23).
# -Accounts: State user hashtables (Get-CrOtherEnabledAccounts) or resolved accounts; each needs Name and Sid.
# Returns a hashtable SID -> 'Disable'|'Keep'. Anything but a clear yes keeps the account (Confirm-CrYesNo: three
# unclear answers count as No). Asked before the password prompts (CONTRACTS "v10", entry point).
function Read-CrOtherAccountDecisions {
    param($Accounts)
    $result = @{}
    $list = New-Object System.Collections.ArrayList
    foreach ($a in (ConvertTo-CrArray $Accounts)) {
        if (-not ($a -is [hashtable])) { continue }
        $sid = [string]$a['Sid']
        if (-not $sid) { continue }
        if ($result.ContainsKey($sid)) { continue }
        $result[$sid] = 'Keep'
        [void]$list.Add($a)
    }
    if ($list.Count -eq 0) { return $result }

    Write-Host ''
    Write-Host ('Other enabled local accounts (D23): {0}. Decide for each one whether it is disabled at the end of this run or kept.' -f $list.Count)
    Write-Host 'Disabling only sets the "account disabled" flag; groups and password stay, so the account can be enabled again.'
    foreach ($a in $list) {
        $sid = [string]$a['Sid']
        $name = [string]$a['Name']
        if (-not $name) { $name = $sid }
        $fullName = $null
        if ($a['FullName']) {
            $fullName = [string]$a['FullName']
        } elseif (($a['User'] -is [hashtable]) -and $a['User']['FullName']) {
            $fullName = [string]$a['User']['FullName']
        }
        $label = $name
        if ($fullName -and ($fullName -ne $name)) { $label = '{0} ({1})' -f $name, $fullName }
        $disable = Confirm-CrYesNo -Prompt ('Disable the account {0}? (Y = disable, N = keep)' -f $label)
        if ($disable) { $result[$sid] = 'Disable' } else { $result[$sid] = 'Keep' }
        Write-CrLog ('Other enabled account {0} ({1}): operator decision {2} (D23)' -f $name, $sid, $result[$sid])
    }
    return $result
}

# --- slot prompts (PLAN section 6 step 6) --------------------------------------------------------

function New-CrSkippedSlotSecret {
    param([string]$Slot, [string]$Label, [string]$Reason, $Finding)
    $findings = @()
    if ($Finding) { $findings = @($Finding) }
    return @{ Slot = $Slot; Label = $Label; Skipped = $true; Reason = $Reason; NewSecret = $null; Accounts = @(); Findings = $findings }
}

function Write-CrPasswordHistoryNotice {
    param($State)
    $history = $null
    if (($State['Policy'] -is [hashtable]) -and ($null -ne $State['Policy']['PasswordHistoryLength'])) { $history = [int]$State['Policy']['PasswordHistoryLength'] }
    Write-Host ''
    Write-Host 'NOTE: machines with a password history reject previously used passwords, and the tool cannot check this in advance.'
    if ($null -ne $history) { Write-Host ('      Password history on this machine: {0}.' -f $history) }
    Write-Host '      Site passwords must never have been used before.'
}

# Rotate-mode Windows/SQL entries of a slot that resolved to at least one account (or one to be created).
function Get-CrSlotEntries {
    param($Resolved, [string]$Slot)
    $list = New-Object System.Collections.ArrayList
    foreach ($entry in (ConvertTo-CrArray $Resolved)) {
        if (-not ($entry -is [hashtable])) { continue }
        if ([string]$entry['Mode'] -ne 'Rotate') { continue }
        if ([string]$entry['Slot'] -ne $Slot) { continue }
        if ($entry['NotApplicable'] -eq $true) { continue }
        [void]$list.Add($entry)
    }
    return , $list.ToArray()
}

# PasswordMode of a resolved entry (CONTRACTS "v10"): 'Change' or 'Set' (default).
function Get-CrEntryPasswordMode {
    param($Entry)
    $mode = $null
    if ($Entry -is [hashtable]) {
        $mode = $Entry['PasswordMode']
        if ((-not $mode) -and ($Entry['Config'] -is [hashtable])) { $mode = $Entry['Config']['PasswordMode'] }
    }
    if ([string]$mode -eq 'Change') { return 'Change' }
    return 'Set'
}

# The account descriptor used by the prompts: @{ Name; Sid; User; PasswordMode; Create; NeedsOld; Disabled; Enable }.
# Create: the account doesn't exist and is created in this run (placeholder with ToCreate, or an entry with Create
# and an account without SID). NeedsOld: only an existing account with PasswordMode 'Change' (D9).
# Disabled: an existing disabled account; Enable: it is enabled in this run (entry EnableIfDisabled), else it stays
# disabled (D21: BiCA accounts, PUB-User, WinAutoUser).
function New-CrSlotAccount {
    param($Entry, $Account)
    $sid = $null
    if ($Account['Sid']) { $sid = [string]$Account['Sid'] }
    $create = (($Account['ToCreate'] -eq $true) -or (($Entry['Create'] -eq $true) -and (-not $sid)))
    $mode = Get-CrEntryPasswordMode -Entry $Entry
    $disabled = ((-not $create) -and ($Account['User'] -is [hashtable]) -and [bool]$Account['User']['Disabled'])
    $enable = ($disabled -and (($Entry['EnableIfDisabled'] -eq $true) -or
               (($Entry['Config'] -is [hashtable]) -and $Entry['Config']['EnableIfDisabled'] -eq $true)))
    return @{
        Name = [string]$Account['Name']; Sid = $sid; User = $Account['User']
        PasswordMode = $mode; Create = $create; NeedsOld = (($mode -eq 'Change') -and (-not $create))
        Disabled = $disabled; Enable = $enable
    }
}

function Get-CrSlotAccountDisplay {
    param($Account)
    if ($Account['Create']) { return ('{0} (will be created)' -f $Account['Name']) }
    if ($Account['Disabled'] -and $Account['Enable']) { return ('{0} (disabled, will be enabled)' -f $Account['Name']) }
    if ($Account['Disabled']) { return ('{0} (disabled, stays disabled)' -f $Account['Name']) }
    return [string]$Account['Name']
}

# Prompts one Windows slot. $Previous carries the last old password entered (for "same as previous").
# New password twice for every slot; the old password only for accounts with NeedsOld (D9: PasswordMode 'Change'
# and the account exists). Reapply (D20) only for those accounts. -ExtraTokenNames: see Get-CrNewSecretProblems.
function Read-CrOneSlotSecret {
    param($SlotDefinition, [string]$Label, $Accounts, $Config, [hashtable]$Previous, [string[]]$ExtraTokenNames)
    $slot = [string]$SlotDefinition['Slot']
    $nameList = New-Object System.Collections.ArrayList
    foreach ($a in $Accounts) { [void]$nameList.Add((Get-CrSlotAccountDisplay $a)) }
    $names = ($nameList.ToArray([string])) -join ', '

    Write-Host ''
    Write-Host ('Credential slot {0} [{1}]: {2}' -f $Label, $slot, $names)
    foreach ($a in $Accounts) {
        if ($a['Create']) {
            Write-Host ('  {0}: does not exist; it is created with this password.' -f $a['Name'])
        } elseif ($a['NeedsOld']) {
            Write-Host ('  {0}: the password is changed with its current password (keeps its DPAPI data, D9).' -f $a['Name'])
        } else {
            Write-Host ('  {0}: the password is set; its current password is not needed.' -f $a['Name'])
        }
        if ($a['Disabled'] -and $a['Enable']) {
            Write-Host ('  {0}: the account is disabled; it is enabled in this run.' -f $a['Name'])
        } elseif ($a['Disabled']) {
            Write-Host ('  {0}: the account is disabled; it gets the password but stays disabled.' -f $a['Name'])
        }
    }

    $newSecret = $null
    $skipReason = $null
    $maxTries = 3
    for ($try = 1; $try -le $maxTries; $try++) {
        $entrySecret = Read-CrSecureHost -Prompt ('New password for {0} ({1}); leave empty to skip this slot' -f $Label, $names)
        if (($null -eq $entrySecret) -or ($entrySecret.Length -eq 0)) {
            if ($null -ne $entrySecret) { $entrySecret.Dispose() }
            if (Confirm-CrYesNo -Prompt ('Skip this slot ({0})? (Y/N)' -f $Label)) {
                $skipReason = 'Skipped by the operator'
                break
            }
            continue
        }
        $repeatSecret = Read-CrSecureHost -Prompt ('Repeat the new password for {0}' -f $Label)
        $match = $false
        if ($null -ne $repeatSecret) {
            $match = [bool](Test-CrSecretEqual -A $entrySecret -B $repeatSecret)
            $repeatSecret.Dispose()
        }
        if (-not $match) {
            $entrySecret.Dispose()
            Write-Host 'The two entries do not match.'
            continue
        }
        $problems = Get-CrNewSecretProblems -NewSecret $entrySecret -Config $Config -Accounts $Accounts -SlotDefinition $SlotDefinition -ExtraNames $ExtraTokenNames
        if ($problems.Count -gt 0) {
            $entrySecret.Dispose()
            Write-Host 'The new password was not accepted:'
            foreach ($p in $problems) { Write-Host ('  - ' + $p) }
            continue
        }
        $newSecret = $entrySecret
        break
    }

    if ($null -eq $newSecret) {
        $finding = $null
        if (-not $skipReason) {
            $skipReason = ('No valid new password after {0} tries' -f $maxTries)
            $finding = New-CrFinding -Severity 'HighImpact' -Area 'Secret' -Slot $slot -Account $names -Message ('Slot skipped: {0}' -f $skipReason)
        } else {
            $finding = New-CrFinding -Severity 'Info' -Area 'Secret' -Slot $slot -Account $names -Message ('Slot skipped: {0}' -f $skipReason)
        }
        Write-Host ('Slot {0} skipped.' -f $Label)
        Write-CrLog ('Slot {0}: {1}' -f $slot, $skipReason)
        return (New-CrSkippedSlotSecret -Slot $slot -Label $Label -Reason $skipReason -Finding $finding)
    }

    # Old password only for existing Change accounts (D9), each account its own; "same as previous" copies the last one.
    $entries = New-Object System.Collections.ArrayList
    foreach ($a in $Accounts) {
        $accountName = [string]$a['Name']
        $oldSecret = $null
        $reapply = $false
        if ($a['NeedsOld']) {
            if ($null -ne $Previous['Secret']) {
                $question = 'Current password of {0}: same as the one entered for {1}? (Y/N)' -f $accountName, $Previous['Name']
                if (Confirm-CrYesNo -Prompt $question) { $oldSecret = $Previous['Secret'].Copy() }
            }
            if ($null -eq $oldSecret) {
                $oldSecret = Read-CrSecureHost -Prompt ('Current (old) password of {0}' -f $accountName)
                if ($null -eq $oldSecret) { $oldSecret = New-Object System.Security.SecureString }
            }
            $reapply = [bool](Test-CrSecretEqual -A $newSecret -B $oldSecret)
            if ($reapply) { Write-Host ('{0}: re-apply, password unchanged (D20).' -f $accountName) }
            $Previous['Secret'] = $oldSecret
            $Previous['Name'] = $accountName
        }
        [void]$entries.Add(@{
            Sid = $a['Sid']; Name = $accountName; OldSecret = $oldSecret; Reapply = $reapply
            PasswordMode = $a['PasswordMode']; Create = [bool]$a['Create']
        })
    }
    Write-CrLog ('Slot {0}: new password accepted for {1} account(s)' -f $slot, $entries.Count)
    return @{ Slot = $slot; Label = $Label; Skipped = $false; Reason = $null; NewSecret = $newSecret; Accounts = $entries.ToArray(); Findings = @() }
}

# Prompts every Rotate-mode Windows slot in ascending Order, honouring -Only and blocked slots.
# SQL slots are returned as skipped (M5). Slots without resolved accounts or outside -Only are not returned.
# -BlockedSlots: Preflight BlockedSlots (slot -> reason); those slots are returned as skipped without a prompt.
# Per slot: @{ Slot; Label; Skipped; Reason; NewSecret; Findings; Accounts = @(@{ Sid ($null for an account created
# in this run); Name; OldSecret ($null unless PasswordMode 'Change' and the account exists); Reapply; PasswordMode;
# Create }) }. Accounts to be created are included (CONTRACTS "v10"), so their names count for the D15 tokens.
function Read-CrSlotSecrets {
    param($Config, $Resolved, $State, [string[]]$Only, [hashtable]$BlockedSlots)
    $result = @{}
    $definitions = ConvertTo-CrArray $Config['Credentials']
    $sorted = @($definitions | Where-Object { $_ -is [hashtable] } | Sort-Object { [int]$_['Order'] })
    $previous = @{ Secret = $null; Name = $null }
    $noticeShown = $false
    foreach ($definition in $sorted) {
        $slot = [string]$definition['Slot']
        if ($Only -and ($Only -notcontains $slot)) { continue }
        $slotEntries = Get-CrSlotEntries -Resolved $Resolved -Slot $slot
        if ($slotEntries.Count -eq 0) { continue }
        $label = [string]$definition['Label']
        if (-not $label) { $label = $slot }

        $isSql = $false
        $accounts = New-Object System.Collections.ArrayList
        $seen = New-Object System.Collections.ArrayList
        $missingNames = New-Object System.Collections.ArrayList
        foreach ($entry in $slotEntries) {
            if ([string]$entry['Kind'] -eq 'SqlLogin') { $isSql = $true }
            foreach ($m in (ConvertTo-CrArray $entry['Missing'])) { if ($m) { [void]$missingNames.Add([string]$m) } }
            foreach ($a in (ConvertTo-CrArray $entry['Accounts'])) {
                if (-not ($a -is [hashtable])) { continue }
                $key = [string]$a['Sid']
                if (-not $key) { $key = 'name:' + ([string]$a['Name']).ToUpperInvariant() }
                if ($key -eq 'name:') { continue }
                if ($seen -contains $key) { continue }
                [void]$seen.Add($key)
                [void]$accounts.Add((New-CrSlotAccount -Entry $entry -Account $a))
            }
        }
        if ($isSql) {
            $result[$slot] = New-CrSkippedSlotSecret -Slot $slot -Label $label -Reason 'SQL rotation not available in this version' `
                -Finding (New-CrFinding -Severity 'Info' -Area 'Secret' -Slot $slot -Message 'SQL rotation not available in this version')
            continue
        }
        if ($BlockedSlots -and $BlockedSlots.ContainsKey($slot)) {
            $result[$slot] = New-CrSkippedSlotSecret -Slot $slot -Label $label -Reason ('Blocked: {0}' -f $BlockedSlots[$slot])
            continue
        }
        if ($accounts.Count -eq 0) { continue }
        if (-not $noticeShown) {
            Write-CrPasswordHistoryNotice -State $State
            $noticeShown = $true
        }
        $result[$slot] = Read-CrOneSlotSecret -SlotDefinition $definition -Label $label -Accounts ($accounts.ToArray()) -Config $Config -Previous $previous `
            -ExtraTokenNames ([string[]]$missingNames.ToArray([string]))
    }
    return $result
}

# --- credential probe (PLAN section 6 step 7, D12, D16) ------------------------------------------

# LockoutThreshold from the machine policy; -1 when unknown.
function Get-CrProbeLockoutThreshold {
    param($State)
    $policy = $State['Policy']
    if (($policy -is [hashtable]) -and (-not $policy['Error']) -and ($null -ne $policy['LockoutThreshold'])) { return [int]$policy['LockoutThreshold'] }
    return -1
}

# D12 (strict rule, confirmed 2026-10-08): attempt only without lockout (0) or when two more failures still stay
# below the threshold, i.e. counter + 2 < threshold (threshold 4: only at counter 0 or 1).
# An unknown threshold is treated as 3 (conservative: the lowest plausible setting).
function Test-CrProbeBudget {
    param([int]$Threshold, [int]$BadPasswordCount)
    if ($Threshold -eq 0) { return $true }
    if ($Threshold -lt 0) { $Threshold = 3 }
    return (($BadPasswordCount + 2) -lt $Threshold)
}

function Write-CrProbeLog {
    param($Result)
    $fallback = ''
    if ($Result['Fallback']) { $fallback = ' (fallback)' }
    $msg = 'Credential probe {0}: {1}; logon type {2}{3}; attempts {4}; Win32 error {5}' -f $Result['Name'], $Result['Outcome'], $Result['LogonType'], $fallback, $Result['Attempts'], $Result['Win32Error']
    if ($Result['Message']) { $msg = $msg + '; ' + $Result['Message'] }
    Write-CrLog $msg
}

# Probes one Windows account with its old and the new password. Outcomes: Old, New, Reapply, BothFailed,
# Unverifiable, Locked, BudgetExceeded, Disabled. Get-CrUserInfo is re-read before every attempt.
# Order: new first if an unfinished earlier run recorded this account's Secret step, else old first; the second
# test only if the first failed. When old equals new (D20) a single test decides Reapply / BothFailed.
# Only called for existing accounts with PasswordMode 'Change' (CONTRACTS "v10"); set accounts aren't probed.
# A logon type of $null (ForceGuest, no other allowed type) gives Unverifiable without an attempt.
function Invoke-CrCredentialProbe {
    param($State, $Account, [System.Security.SecureString]$OldSecret, [System.Security.SecureString]$NewSecret, $Journal, [string]$RunId)
    $sid = [string]$Account['Sid']
    $name = [string]$Account['Name']
    $logon = Select-CrProbeLogonType -UserSid $sid -State $State
    $result = @{
        Sid = $sid; Name = $name; Outcome = 'BothFailed'; LogonType = $logon['LogonType']; Fallback = ($logon['Fallback'] -eq $true)
        Win32Error = 0; Attempts = 0; Message = $null
    }
    $threshold = Get-CrProbeLockoutThreshold $State

    # No account yet (created in this run): there is no old password to probe (CONTRACTS "v10": Change accounts only).
    if (-not $sid) {
        $result['Outcome'] = 'Unverifiable'
        $result['Message'] = 'the account does not exist yet; no logon attempt'
        Write-CrProbeLog $result
        return $result
    }
    # ForceGuest without another allowed logon type (Select-CrProbeLogonType, D16): a logon proves nothing.
    if (-not $result['LogonType']) {
        $result['Outcome'] = 'Unverifiable'
        $result['Message'] = 'no logon type can verify a password (ForceGuest maps network logons to Guest, no other type is allowed); no logon attempt'
        Write-CrProbeLog $result
        return $result
    }

    $kinds = New-Object System.Collections.ArrayList
    $sameSecret = $false
    if (($null -ne $OldSecret) -and ($null -ne $NewSecret)) { $sameSecret = [bool](Test-CrSecretEqual -A $NewSecret -B $OldSecret) }
    if ($sameSecret) {
        [void]$kinds.Add('Reapply')
    } else {
        $newFirst = Test-CrJournalStepInUnfinishedRun -Journal $Journal -Sid $sid -Step 'Secret' -ExceptRunId $RunId
        if ($newFirst) { $order = @('New', 'Old') } else { $order = @('Old', 'New') }
        foreach ($k in $order) {
            if (($k -eq 'Old') -and ($null -eq $OldSecret)) { continue }
            if (($k -eq 'New') -and ($null -eq $NewSecret)) { continue }
            [void]$kinds.Add($k)
        }
    }

    $done = $false
    foreach ($kind in $kinds) {
        $info = Get-CrUserInfo -UserName $name
        if ((-not ($info -is [hashtable])) -or ($info['Success'] -ne $true)) {
            $result['Outcome'] = 'Unverifiable'
            if ($info -is [hashtable]) { $result['Win32Error'] = [int]$info['Win32Error'] }
            $result['Message'] = 'account information could not be read; no logon attempt'
            $done = $true
            break
        }
        $flags = [int]$info['Flags']
        if ((($flags -band 0x10) -ne 0) -or ($info['IsAccountLocked'] -eq $true)) {
            $result['Outcome'] = 'Locked'
            $done = $true
            break
        }
        if (($flags -band 0x2) -ne 0) {
            $result['Outcome'] = 'Disabled'
            $done = $true
            break
        }
        if (-not (Test-CrProbeBudget -Threshold $threshold -BadPasswordCount ([int]$info['BadPasswordCount']))) {
            $result['Outcome'] = 'BudgetExceeded'
            $result['Message'] = ('bad password count {0}, lockout threshold {1}' -f [int]$info['BadPasswordCount'], $threshold)
            $done = $true
            break
        }

        if ($kind -eq 'New') { $testSecret = $NewSecret } else { $testSecret = $OldSecret }
        $test = Invoke-CrLogonTest -UserName $name -Secret $testSecret -LogonType $result['LogonType']
        $testSecret = $null
        $result['Attempts'] = $result['Attempts'] + 1
        $code = 0
        if ($null -ne $test['Win32Error']) { $code = [int]$test['Win32Error'] }
        if ($test['Success'] -eq $true) {
            $result['Outcome'] = $kind
            $result['Win32Error'] = 0
            $done = $true
            break
        }
        $result['Win32Error'] = $code
        if (($code -eq 1330) -or ($code -eq 1907)) {
            # Password expired / must change: only reported for correct credentials.
            $result['Outcome'] = $kind
            $result['Message'] = 'password correct but expired or must be changed'
            $done = $true
            break
        }
        if (($code -eq 1385) -or ($code -eq 1327)) {
            # Logon type not granted / account restriction: proves nothing about the password; the change path validates it.
            $result['Outcome'] = 'Unverifiable'
            $done = $true
            break
        }
        if ($code -eq 1909) {
            $result['Outcome'] = 'Locked'
            $done = $true
            break
        }
        if ($code -eq 1331) {
            $result['Outcome'] = 'Disabled'
            $done = $true
            break
        }
    }
    if (-not $done) { $result['Outcome'] = 'BothFailed' }
    Write-CrProbeLog $result
    return $result
}
