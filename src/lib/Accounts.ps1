# Accounts.ps1 - local users (docs/PLAN.md section 7.1). Read side via ADSI WinNT; write side (M2) via the
# netapi32 wrappers of Native.ps1 with BSTR pointers, so a secret never becomes a managed string (D4).

# Internal: the raw ADSI user entries of the local computer. Separate so tests can mock it.
function Get-CrAdsiUserEntries {
    param([string]$ComputerName = $env:COMPUTERNAME)
    $computer = [ADSI]('WinNT://' + $ComputerName + ',computer')
    $list = New-Object System.Collections.ArrayList
    foreach ($child in $computer.psbase.Children) {
        if ($child.psbase.SchemaClassName -eq 'User') { [void]$list.Add($child) }
    }
    return , $list.ToArray()
}

# Internal: one ADSI property via InvokeGet; throws when the property can't be read. Separate so tests can mock it.
function Get-CrAdsiValue {
    param($Entry, [string]$Name)
    return $Entry.psbase.InvokeGet($Name)
}

function Get-CrAdsiErrorText {
    param($ErrorRecord)
    $ex = $ErrorRecord.Exception
    while ($ex.InnerException) { $ex = $ex.InnerException }
    return $ex.Message
}

# Internal: optional property; $null when it can't be read.
function Get-CrAdsiOptionalValue {
    param($Entry, [string]$Name)
    try { return Get-CrAdsiValue -Entry $Entry -Name $Name } catch { return $null }
}

# Converts one ADSI user entry into the CONTRACTS 4.1 Users hashtable (plus Error = $null). Throws if a required
# property (Name, objectSid, UserFlags) can't be read.
function ConvertTo-CrUserRecord {
    param($Entry)
    $name = [string](Get-CrAdsiValue -Entry $Entry -Name 'Name')
    $sid = ConvertTo-CrSidString (Get-CrAdsiValue -Entry $Entry -Name 'objectSid')
    if (-not $sid) { throw ('objectSid of user {0} could not be read' -f $name) }
    $flags = [int](Get-CrAdsiValue -Entry $Entry -Name 'UserFlags')

    $parts = $sid.Split('-')
    $rid = [int]$parts[$parts.Length - 1]

    $fullName = Get-CrAdsiOptionalValue -Entry $Entry -Name 'FullName'
    if ($null -ne $fullName) { $fullName = [string]$fullName }

    # IsAccountLocked reflects the lockout duration; the UF_LOCKOUT bit is the fallback.
    $locked = Get-CrAdsiOptionalValue -Entry $Entry -Name 'IsAccountLocked'
    if ($null -eq $locked) { $locked = [bool]($flags -band 0x10) } else { $locked = [bool]$locked }

    $age = Get-CrAdsiOptionalValue -Entry $Entry -Name 'PasswordAge'
    if ($null -ne $age) { $age = [long]$age }
    $bad = Get-CrAdsiOptionalValue -Entry $Entry -Name 'BadPasswordAttempts'
    if ($null -ne $bad) { $bad = [int]$bad }

    return @{
        Name                 = $name
        Sid                  = $sid
        Rid                  = $rid
        FullName             = $fullName
        Flags                = $flags
        Disabled             = [bool]($flags -band 0x2)
        LockedOut            = $locked
        PasswordNeverExpires = [bool]($flags -band 0x10000)
        CannotChangePassword = [bool]($flags -band 0x40)
        PasswordNotRequired  = [bool]($flags -band 0x20)
        PasswordAgeSeconds   = $age
        BadPasswordCount     = $bad
        Error                = $null
    }
}

# All local users (CONTRACTS 4.1); returns an array. A user that can't be read is returned with Error set
# and the other keys $null (Name if it could be read), so one failing user doesn't fail the others.
function Get-CrLocalUsers {
    param()
    $list = New-Object System.Collections.ArrayList
    foreach ($entry in (ConvertTo-CrArray (Get-CrAdsiUserEntries))) {
        try {
            [void]$list.Add((ConvertTo-CrUserRecord -Entry $entry))
        } catch {
            $message = Get-CrAdsiErrorText $_
            [void]$list.Add(@{
                Name                 = [string](Get-CrAdsiOptionalValue -Entry $entry -Name 'Name')
                Sid                  = $null
                Rid                  = $null
                FullName             = $null
                Flags                = $null
                Disabled             = $null
                LockedOut            = $null
                PasswordNeverExpires = $null
                CannotChangePassword = $null
                PasswordNotRequired  = $null
                PasswordAgeSeconds   = $null
                BadPasswordCount     = $null
                Error                = $message
            })
        }
    }
    return , $list.ToArray()
}

#region Write side (M2, PLAN sections 7.1 and 8; CONTRACTS 5.7)

# UF_* bits used by the write side (lmaccess.h):
# 0x2 UF_ACCOUNTDISABLE, 0x10 UF_LOCKOUT, 0x20 UF_PASSWD_NOTREQD, 0x40 UF_PASSWD_CANT_CHANGE (CCP),
# 0x10000 UF_DONT_EXPIRE_PASSWD (PNE)
#
# Account model (D9, D21, D22; CONTRACTS 5.7):
#   New-CrManagedAccount    creates a missing managed account with the slot password (journal 'Created')
#   Invoke-CrPasswordSet    sets the password (NetUserSetInfo 1003) of BiCA Admin / BiCA Remote / the auto-logon
#                           accounts (journal 'Secret')
#   Invoke-CrPasswordRotation  the change path (PasswordMode = 'Change', ApplicationUser) with CCP handling
#   Disable-CrAccount / Enable-CrAccount  UF_ACCOUNTDISABLE set / cleared (journal 'Disabled')

# Internal: records a run-journal step; never throws (a journal failure is returned as a warning, so it can't
# interrupt a half-done account change or the CCP restore). No journal ($null) = nothing recorded.
function Add-CrAccountJournalStep {
    param($Journal, [string]$RunId, [string]$Sid, [string]$Step, $Steps, $Warnings)
    [void]$Steps.Add($Step)
    if ($null -eq $Journal) { return }
    try {
        $null = Add-CrJournalStep -Journal $Journal -RunId $RunId -Sid $Sid -Step $Step
    } catch {
        [void]$Warnings.Add(('The run journal could not record step {0}: {1}' -f $Step, $_.Exception.Message))
    }
}

# Internal: text for a failed change/reset/set. Win32 codes only, never secret material (D4).
function Get-CrPasswordErrorText {
    param([int]$Win32Error, [string]$Path)
    $verb = 'change'
    if ($Path -eq 'Reset') { $verb = 'reset' }
    if ($Path -eq 'Set') { $verb = 'set' }
    switch ($Win32Error) {
        86 { return 'The old password is wrong (error 86).' }
        2245 { return ('The password {0} was rejected by the password policy: length, complexity, history or minimum age (error 2245).' -f $verb) }
        1909 { return 'The account is locked out (error 1909).' }
        5 { return ('The password {0} was denied (error 5).' -f $verb) }
    }
    return ('The password {0} failed (error {1}).' -f $verb, $Win32Error)
}

# Internal: the flags the role asks for (Admin, AdminRemote, User, WinUser, Ftp). Only sets PNE / CCP and clears
# NOTREQD when the role says so; an empty or missing role leaves the flags as they are. Never touches
# UF_ACCOUNTDISABLE (Enable-CrAccount / Disable-CrAccount) or UF_LOCKOUT (Unlock-CrAccount).
function Get-CrDesiredUserFlags {
    param([int]$Flags, $Role)
    $desired = $Flags
    if (-not ($Role -is [hashtable])) { return $desired }
    if ($Role['PasswordNeverExpires']) { $desired = $desired -bor 0x10000 }
    if ($Role['CannotChangePassword']) { $desired = $desired -bor 0x40 }
    if ($Role['PasswordRequired']) { $desired = $desired -band (-bnot 0x20) }
    return $desired
}

# Internal: sets UF_PASSWD_CANT_CHANGE again after a temporary clear. Re-reads the flags first (the change may
# have altered other bits) and falls back to the flags known before the change. Never throws.
function Restore-CrCannotChangePassword {
    param([string]$UserName, [int]$FallbackFlags)
    try {
        $base = $FallbackFlags
        $info = Get-CrUserInfo -UserName $UserName
        if ($info -and $info['Success']) { $base = [int]$info['Flags'] }
        $set = Set-CrUserFlags -UserName $UserName -Flags ($base -bor 0x40)
        return @{ Success = [bool]$set['Success']; Win32Error = [int]$set['Win32Error']; Error = $null }
    } catch {
        return @{ Success = $false; Win32Error = 0; Error = $_.Exception.Message }
    }
}

# Clears UF_LOCKOUT (0x10) via Set-CrUserFlags (CONTRACTS). Writes only when the account is locked.
# Returns @{ Success; Changed; Win32Error }.
function Unlock-CrAccount {
    param([string]$UserName)
    $info = Get-CrUserInfo -UserName $UserName
    if (-not ($info -and $info['Success'])) {
        $code = 0
        if ($info) { $code = [int]$info['Win32Error'] }
        return @{ Success = $false; Changed = $false; Win32Error = $code }
    }
    $flags = [int]$info['Flags']
    if (-not ($flags -band 0x10)) { return @{ Success = $true; Changed = $false; Win32Error = 0 } }
    $set = Set-CrUserFlags -UserName $UserName -Flags ($flags -band (-bnot 0x10))
    return @{ Success = [bool]$set['Success']; Changed = [bool]$set['Success']; Win32Error = [int]$set['Win32Error'] }
}

# Sets the account flags the role asks for (PNE 0x10000 and CCP 0x40 set; NOTREQD 0x20 cleared when PasswordRequired).
# Reads the current flags with Get-CrUserInfo and writes only when they differ. Works for every role; an empty role
# (no flag keys) or $null = no change. Returns @{ Changed; Success; Win32Error }.
function Set-CrAccountFlags {
    param($User, $Role)
    if (-not ($User -is [hashtable]) -or -not $User['Name']) { throw 'Set-CrAccountFlags: -User needs a Name.' }
    $name = [string]$User['Name']
    $info = Get-CrUserInfo -UserName $name
    if (-not ($info -and $info['Success'])) {
        $code = 0
        if ($info) { $code = [int]$info['Win32Error'] }
        return @{ Changed = $false; Success = $false; Win32Error = $code }
    }
    $current = [int]$info['Flags']
    $desired = Get-CrDesiredUserFlags -Flags $current -Role $Role
    if ($desired -eq $current) { return @{ Changed = $false; Success = $true; Win32Error = 0 } }
    $set = Set-CrUserFlags -UserName $name -Flags $desired
    return @{ Changed = [bool]$set['Success']; Success = [bool]$set['Success']; Win32Error = [int]$set['Win32Error'] }
}

# Internal: the pre-step shared by the change and the set path (PLAN sections 7.1 and 8, step 1): reads the flags,
# unlocks a locked account (journal 'Unlocked' when it was unlocked), then re-checks the lock state right before the
# password step; a relock stops here (1909). Returns @{ Ok; Flags (current flags); Win32Error; Message }.
function Invoke-CrUnlockPreStep {
    param($User, $Journal, [string]$RunId, $Steps, $Warnings)
    $name = [string]$User['Name']
    $sid = [string]$User['Sid']
    $info = Get-CrUserInfo -UserName $name
    if (-not ($info -and $info['Success'])) {
        $code = 0
        if ($info) { $code = [int]$info['Win32Error'] }
        return @{ Ok = $false; Flags = $null; Win32Error = $code
                  Message = ('The account information of {0} could not be read (error {1}).' -f $name, $code) }
    }
    $flags = [int]$info['Flags']
    if (-not (($flags -band 0x10) -or $User['LockedOut'])) {
        return @{ Ok = $true; Flags = $flags; Win32Error = 0; Message = $null }
    }

    $unlock = Unlock-CrAccount -UserName $name
    if (-not $unlock['Success']) {
        $code = [int]$unlock['Win32Error']
        return @{ Ok = $false; Flags = $flags; Win32Error = $code
                  Message = ('{0} is locked out and could not be unlocked (error {1}).' -f $name, $code) }
    }
    if ($unlock['Changed']) {
        Add-CrAccountJournalStep -Journal $Journal -RunId $RunId -Sid $sid -Step 'Unlocked' -Steps $Steps -Warnings $Warnings
    }
    # The lock state is re-checked right before the password step (PLAN section 7.1).
    $info = Get-CrUserInfo -UserName $name
    if (-not ($info -and $info['Success'])) {
        $code = 0
        if ($info) { $code = [int]$info['Win32Error'] }
        return @{ Ok = $false; Flags = $flags; Win32Error = $code
                  Message = ('The account information of {0} could not be read after unlocking (error {1}).' -f $name, $code) }
    }
    $flags = [int]$info['Flags']
    if ($flags -band 0x10) {
        return @{ Ok = $false; Flags = $flags; Win32Error = 1909
                  Message = ('{0} was locked out again right after unlocking; the slot stops.' -f $name) }
    }
    return @{ Ok = $true; Flags = $flags; Win32Error = 0; Message = $null }
}

# Internal: completes a failed Invoke-CrPasswordRotation result.
function Complete-CrRotationResult {
    param($Result, $Steps, $Warnings, [int]$Win32Error, [string]$Message)
    $Result['Win32Error'] = $Win32Error
    $Result['Message'] = $Message
    $Result['Steps'] = $Steps.ToArray()
    $Result['Warnings'] = $Warnings.ToArray()
    return $Result
}

# Pre-steps + password change/reset of one account (PLAN sections 7.1 and 8, steps 1-2; D9). Apply calls it with
# -Path 'Change' only (PasswordMode = 'Change', ApplicationUser); every set, including ApplicationUser's
# operator-chosen set (DPAPI loss), uses Invoke-CrPasswordSet.
#   1. unlock if locked (journal 'Unlocked'); the lock state is then re-checked and a relock stops here
#   2. change path only (PLAN section 8): clear CCP if set (journal 'CcpCleared'). 'PreSteps' is journaled by the caller.
#   3. Invoke-CrNetPasswordChange (old + new) or Invoke-CrNetPasswordReset (new)
#   4. CCP restored in 'finally', also when step 3 failed or threw (journal 'CcpRestored')
#   5. journal 'Secret' only when step 3 succeeded
# Returns @{ Success; Win32Error; Message; Steps = @(<steps done>); CcpRestoreFailed; Warnings = @() }.
# Success = the account is on the new secret. Secrets stay SecureStrings and go only to the Native wrappers (D4).
function Invoke-CrPasswordRotation {
    param(
        $User,
        [System.Security.SecureString]$OldSecret,
        [System.Security.SecureString]$NewSecret,
        [ValidateSet('Change', 'Reset')]
        [string]$Path,
        $Journal,
        [string]$RunId
    )
    if (-not ($User -is [hashtable]) -or -not $User['Name'] -or -not $User['Sid']) {
        throw 'Invoke-CrPasswordRotation: -User needs Name and Sid.'
    }
    if ($null -eq $NewSecret) { throw 'Invoke-CrPasswordRotation: the new secret is missing.' }
    if ($Path -eq 'Change' -and $null -eq $OldSecret) { throw 'Invoke-CrPasswordRotation: the change path needs the old secret.' }

    $name = [string]$User['Name']
    $sid = [string]$User['Sid']
    $steps = New-Object System.Collections.ArrayList
    $warnings = New-Object System.Collections.ArrayList
    $result = @{ Success = $false; Win32Error = 0; Message = $null; Steps = @(); CcpRestoreFailed = $false; Warnings = @() }

    # Pre-steps. A failure here leaves the password untouched and nothing to undo: CCP is cleared last.
    $pre = Invoke-CrUnlockPreStep -User $User -Journal $Journal -RunId $RunId -Steps $steps -Warnings $warnings
    if (-not $pre['Ok']) { return Complete-CrRotationResult $result $steps $warnings $pre['Win32Error'] $pre['Message'] }
    $flags = [int]$pre['Flags']

    $ccpCleared = $false
    if ($Path -eq 'Change' -and ($flags -band 0x40)) {
        $clear = Set-CrUserFlags -UserName $name -Flags ($flags -band (-bnot 0x40))
        if (-not $clear['Success']) {
            $code = [int]$clear['Win32Error']
            return Complete-CrRotationResult $result $steps $warnings $code ('"User cannot change password" of {0} could not be cleared (error {1}).' -f $name, $code)
        }
        $ccpCleared = $true
        $flags = $flags -band (-bnot 0x40)
        Add-CrAccountJournalStep -Journal $Journal -RunId $RunId -Sid $sid -Step 'CcpCleared' -Steps $steps -Warnings $warnings
    }

    # Password step; CCP is restored in 'finally' whatever happens (also on a throw or Ctrl+C).
    $op = $null
    $opError = $null
    try {
        if ($Path -eq 'Change') {
            $op = Invoke-CrNetPasswordChange -UserName $name -OldSecret $OldSecret -NewSecret $NewSecret
        } else {
            $op = Invoke-CrNetPasswordReset -UserName $name -NewSecret $NewSecret
        }
    } catch {
        $opError = $_.Exception.Message
    } finally {
        if ($ccpCleared) {
            $restore = Restore-CrCannotChangePassword -UserName $name -FallbackFlags $flags
            if ($restore['Success']) {
                Add-CrAccountJournalStep -Journal $Journal -RunId $RunId -Sid $sid -Step 'CcpRestored' -Steps $steps -Warnings $warnings
            } else {
                $result['CcpRestoreFailed'] = $true
                $why = ('error {0}' -f $restore['Win32Error'])
                if ($restore['Error']) { $why = $restore['Error'] }
                [void]$warnings.Add(('"User cannot change password" of {0} could not be set again ({1}); set it manually or re-run.' -f $name, $why))
            }
        }
    }

    if ($opError) {
        return Complete-CrRotationResult $result $steps $warnings 0 ('The password {0} of {1} could not run: {2}' -f $Path.ToLowerInvariant(), $name, $opError)
    }
    if (-not ($op -and $op['Success'])) {
        $code = 0
        if ($op) { $code = [int]$op['Win32Error'] }
        return Complete-CrRotationResult $result $steps $warnings $code ('{0}: {1}' -f $name, (Get-CrPasswordErrorText -Win32Error $code -Path $Path))
    }
    $result['Success'] = $true
    Add-CrAccountJournalStep -Journal $Journal -RunId $RunId -Sid $sid -Step 'Secret' -Steps $steps -Warnings $warnings
    return Complete-CrRotationResult $result $steps $warnings 0 $null
}

#endregion

#region Account model (D9, D21, D22; CONTRACTS 5.7)

# Internal: text for a failed NetUserAdd. Win32 / NET_API_STATUS codes only (D4).
function Get-CrCreateErrorText {
    param([int]$Win32Error, [string]$Name)
    switch ($Win32Error) {
        2224 { return ('The account {0} already exists (error 2224).' -f $Name) }
        2223 { return ('A local group named {0} exists, so the account cannot be created (error 2223).' -f $Name) }
        2245 { return ('The password for the new account {0} was rejected by the password policy: length or complexity (error 2245).' -f $Name) }
        5 { return ('Creating the account {0} was denied (error 5).' -f $Name) }
    }
    return ('The account {0} could not be created (error {1}).' -f $Name, $Win32Error)
}

# Creates a missing managed account (D21; PLAN section 8 step 0) with the slot password through New-CrLocalUser
# (NetUserAdd level 1: USER_PRIV_USER, PNE + CCP; groups and the other flags follow in the grants step).
# 2224 (already exists) is a failure with that code. On success the new SID is resolved by name and the journal
# records 'Created' for it. -Journal / -RunId are optional ($null = nothing recorded).
# Returns @{ Success; Win32Error; Message; Name; Sid; Steps = @(); Warnings = @() }.
function New-CrManagedAccount {
    param(
        [string]$Name,
        [System.Security.SecureString]$Secret,
        [string]$Comment = '',
        $Journal,
        [string]$RunId
    )
    if (-not $Name) { throw 'New-CrManagedAccount: -Name is empty.' }
    if ($null -eq $Secret) { throw 'New-CrManagedAccount: the secret is missing.' }

    $steps = New-Object System.Collections.ArrayList
    $warnings = New-Object System.Collections.ArrayList
    $result = @{ Success = $false; Win32Error = 0; Message = $null; Name = $Name; Sid = $null; Steps = @(); Warnings = @() }

    $op = $null
    try {
        $op = New-CrLocalUser -UserName $Name -Secret $Secret -Comment $Comment
    } catch {
        return Complete-CrRotationResult $result $steps $warnings 0 ('The account {0} could not be created: {1}' -f $Name, $_.Exception.Message)
    }
    if (-not ($op -and $op['Success'])) {
        $code = 0
        if ($op) { $code = [int]$op['Win32Error'] }
        return Complete-CrRotationResult $result $steps $warnings $code (Get-CrCreateErrorText -Win32Error $code -Name $Name)
    }

    $result['Success'] = $true
    $sid = $null
    try { $sid = Resolve-CrNameToSid -Name $Name } catch { $sid = $null }
    if ($sid) {
        $result['Sid'] = [string]$sid
        Add-CrAccountJournalStep -Journal $Journal -RunId $RunId -Sid $sid -Step 'Created' -Steps $steps -Warnings $warnings
    } else {
        [void]$steps.Add('Created')
        [void]$warnings.Add(('The account {0} was created, but its SID could not be resolved; the run journal has no entry for it.' -f $Name))
    }
    return Complete-CrRotationResult $result $steps $warnings 0 $null
}

# Sets the password of a managed set account (D9: BiCA Admin, BiCA Remote, PUB-User, WinAutoUser; PLAN section 8 steps 1-2):
#   1. unlock if locked (journal 'Unlocked'); the lock state is re-checked and a relock stops here
#   2. Invoke-CrNetPasswordReset (NetUserSetInfo 1003). No CCP handling: an administrative set ignores CCP.
#   3. journal 'Secret' only on success
# Returns @{ Success; Win32Error; Message; Steps = @(); Warnings = @() }. The secret stays a SecureString (D4).
function Invoke-CrPasswordSet {
    param(
        $User,
        [System.Security.SecureString]$NewSecret,
        $Journal,
        [string]$RunId
    )
    if (-not ($User -is [hashtable]) -or -not $User['Name'] -or -not $User['Sid']) {
        throw 'Invoke-CrPasswordSet: -User needs Name and Sid.'
    }
    if ($null -eq $NewSecret) { throw 'Invoke-CrPasswordSet: the new secret is missing.' }

    $name = [string]$User['Name']
    $sid = [string]$User['Sid']
    $steps = New-Object System.Collections.ArrayList
    $warnings = New-Object System.Collections.ArrayList
    $result = @{ Success = $false; Win32Error = 0; Message = $null; Steps = @(); Warnings = @() }

    $pre = Invoke-CrUnlockPreStep -User $User -Journal $Journal -RunId $RunId -Steps $steps -Warnings $warnings
    if (-not $pre['Ok']) { return Complete-CrRotationResult $result $steps $warnings $pre['Win32Error'] $pre['Message'] }

    $op = $null
    try {
        $op = Invoke-CrNetPasswordReset -UserName $name -NewSecret $NewSecret
    } catch {
        return Complete-CrRotationResult $result $steps $warnings 0 ('The password set of {0} could not run: {1}' -f $name, $_.Exception.Message)
    }
    if (-not ($op -and $op['Success'])) {
        $code = 0
        if ($op) { $code = [int]$op['Win32Error'] }
        return Complete-CrRotationResult $result $steps $warnings $code ('{0}: {1}' -f $name, (Get-CrPasswordErrorText -Win32Error $code -Path 'Set'))
    }
    $result['Success'] = $true
    Add-CrAccountJournalStep -Journal $Journal -RunId $RunId -Sid $sid -Step 'Secret' -Steps $steps -Warnings $warnings
    return Complete-CrRotationResult $result $steps $warnings 0 $null
}

# Internal: sets or clears UF_ACCOUNTDISABLE (0x2) and keeps every other bit. Writes only when it differs.
# Returns @{ Success; Changed; Win32Error; Message }.
function Set-CrAccountDisabledFlag {
    param([string]$UserName, [bool]$Disabled)
    $info = Get-CrUserInfo -UserName $UserName
    if (-not ($info -and $info['Success'])) {
        $code = 0
        if ($info) { $code = [int]$info['Win32Error'] }
        return @{ Success = $false; Changed = $false; Win32Error = $code
                  Message = ('The account information of {0} could not be read (error {1}).' -f $UserName, $code) }
    }
    $flags = [int]$info['Flags']
    if ($Disabled) { $desired = $flags -bor 0x2 } else { $desired = $flags -band (-bnot 0x2) }
    if ($desired -eq $flags) { return @{ Success = $true; Changed = $false; Win32Error = 0; Message = $null } }
    $set = Set-CrUserFlags -UserName $UserName -Flags $desired
    if ($set -and $set['Success']) { return @{ Success = $true; Changed = $true; Win32Error = 0; Message = $null } }
    $code = 0
    if ($set) { $code = [int]$set['Win32Error'] }
    $verb = 'enabled'
    if ($Disabled) { $verb = 'disabled' }
    return @{ Success = $false; Changed = $false; Win32Error = $code
              Message = ('{0} could not be {1} (error {2}).' -f $UserName, $verb, $code) }
}

# Disables an account (D22, D23, D25): UF_ACCOUNTDISABLE set, groups, password and other flags unchanged, so it can be
# re-enabled. Journal 'Disabled' when this call disabled it. An already disabled account = success, Changed $false.
# Returns @{ Success; Changed; Win32Error; Message; Steps = @(); Warnings = @() }.
function Disable-CrAccount {
    param($User, $Journal, [string]$RunId)
    if (-not ($User -is [hashtable]) -or -not $User['Name'] -or -not $User['Sid']) {
        throw 'Disable-CrAccount: -User needs Name and Sid.'
    }
    $steps = New-Object System.Collections.ArrayList
    $warnings = New-Object System.Collections.ArrayList
    $r = Set-CrAccountDisabledFlag -UserName ([string]$User['Name']) -Disabled $true
    if ($r['Changed']) {
        Add-CrAccountJournalStep -Journal $Journal -RunId $RunId -Sid ([string]$User['Sid']) -Step 'Disabled' -Steps $steps -Warnings $warnings
    }
    $r['Steps'] = $steps.ToArray()
    $r['Warnings'] = $warnings.ToArray()
    return $r
}

# Enables an account (UF_ACCOUNTDISABLE cleared): an existing disabled account of an entry with EnableIfDisabled
# (ApplicationUser) is enabled after its password step (CONTRACTS v10). An enabled account = success, Changed $false.
# Not journaled.
# Returns @{ Success; Changed; Win32Error; Message }.
function Enable-CrAccount {
    param($User)
    if (-not ($User -is [hashtable]) -or -not $User['Name']) { throw 'Enable-CrAccount: -User needs a Name.' }
    return Set-CrAccountDisabledFlag -UserName ([string]$User['Name']) -Disabled $false
}

#endregion
