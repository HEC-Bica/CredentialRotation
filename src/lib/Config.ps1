# Config.ps1 - load and validate the configuration file (docs/PLAN.md section 5, docs/dev/CONTRACTS.md)

# The allowed keys and values. Everything not listed here is a validation error.
function Get-CrConfigSchema {
    return @{
        TopKeys              = @('SchemaVersion', 'SitePasswordRules', 'Roles', 'Credentials', 'Accounts', 'OtherEnabledAccounts')
        RequiredTopKeys      = @('SchemaVersion', 'SitePasswordRules', 'Roles', 'Credentials', 'Accounts')
        OtherEnabledValues   = @('Ask')
        SitePasswordRuleKeys = @('MinLength', 'RequireComplexity')
        RoleKeys             = @('Groups', 'ExclusiveGroups', 'AllowedExtraGroups', 'PasswordNeverExpires',
                                 'CannotChangePassword', 'PasswordRequired', 'IfGroupMissing')
        RoleBoolKeys         = @('ExclusiveGroups', 'PasswordNeverExpires', 'CannotChangePassword', 'PasswordRequired')
        IfGroupMissingValues = @('ReportKeepGroups')
        CredentialKeys       = @('Slot', 'Order', 'Label', 'MaxLength')
        AccountKeys          = @('Id', 'Kind', 'Name', 'Names', 'NamePattern', 'Candidates', 'Role', 'Credential', 'Mode',
                                 'LoginsEntry', 'Services', 'ScheduledTasks', 'ComPlus', 'IisReport',
                                 'AutoLogonUser', 'AutoLogon', 'ServerRoles',
                                 'Create', 'Replaces', 'PasswordMode', 'Operator', 'EnableIfDisabled')
        WindowsOnlyKeys      = @('Names', 'NamePattern', 'Candidates', 'Role', 'Mode', 'Services', 'ScheduledTasks',
                                 'ComPlus', 'IisReport', 'AutoLogonUser', 'AutoLogon',
                                 'Create', 'Replaces', 'PasswordMode', 'Operator', 'EnableIfDisabled')
        SqlOnlyKeys          = @('ServerRoles')
        SelectionKeys        = @('Name', 'Names', 'NamePattern', 'Candidates')
        DependentKeys        = @('Services', 'ScheduledTasks', 'ComPlus', 'IisReport')
        DependentValues      = @('Auto')
        Kinds                = @('Windows', 'SqlLogin')
        ModeValues           = @('Check', 'Disable')
        PasswordModeValues   = @('Set', 'Change')
        # Keys of managed (rotated) entries; not valid on Check or Disable entries
        ManagedOnlyKeys      = @('Create', 'Replaces', 'PasswordMode', 'Operator', 'EnableIfDisabled')
        # A Disable entry only selects accounts by Name/Names (D22)
        DisableForbiddenKeys = @('NamePattern', 'Candidates', 'Role', 'Credential', 'LoginsEntry', 'Services', 'ScheduledTasks',
                                 'ComPlus', 'IisReport', 'AutoLogonUser', 'AutoLogon')
        CandidateKeys        = @('Name', 'Sid', 'Role', 'Credential')
        AutoLogonKeys        = @('Mode', 'RestrictedComputerPattern')
        AutoLogonModes       = @('IfAlreadyOn')
        AutoLogonUserKeys    = @('Name')
    }
}

function Import-CrConfig {
    param([string]$Path)
    if (-not $Path) { throw 'Import-CrConfig: no path given.' }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw ('Config file not found: {0}' -f $Path) }
    $full = (Resolve-Path -LiteralPath $Path).ProviderPath
    $directory = Split-Path -Parent $full
    $fileName = Split-Path -Leaf $full
    # PLAN 5, 9: Import-LocalizedData -UICulture en-US prefers a copy in en-US\ or en\, which is not the file whose
    # hash is displayed; such a copy is refused.
    foreach ($culture in @('en-US', 'en')) {
        $copy = Join-Path (Join-Path $directory $culture) $fileName
        if (Test-Path -LiteralPath $copy) { throw ('A copy of the config exists in a culture subfolder and would be loaded instead of {0}: {1}. Remove it.' -f $full, $copy) }
    }
    # Import-LocalizedData falls back to the base directory when there is no en-US subfolder (PLAN section 5).
    # -BindingVariable is mandatory in PS 2.0 (found by the first /PS2 audit; without it PS 2.0 prompts).
    $data = $null
    Import-LocalizedData -BindingVariable data -BaseDirectory $directory -FileName $fileName -UICulture en-US -ErrorAction Stop
    if (-not ($data -is [hashtable])) { throw ('Config file {0} does not contain a hashtable.' -f $full) }
    return $data
}

# The slot names of the config's Credentials, in file order (comma-returned).
function Get-CrConfigSlotNames {
    param($Config)
    $names = New-Object System.Collections.ArrayList
    if ($Config -is [hashtable]) {
        foreach ($c in (ConvertTo-CrArray $Config['Credentials'])) {
            if (($c -is [hashtable]) -and $c['Slot']) { [void]$names.Add([string]$c['Slot']) }
        }
    }
    return , $names.ToArray()
}

# The names given to -Only that are no slot of the config (case-insensitive), comma-returned; PLAN 8: unknown slot names
# are an error (exit 2), not an empty selection.
function Get-CrUnknownOnlySlots {
    param($Config, [string[]]$Only)
    $unknown = New-Object System.Collections.ArrayList
    $slots = Get-CrConfigSlotNames -Config $Config
    foreach ($o in (ConvertTo-CrArray $Only)) {
        if (-not $o) { continue }
        $found = $false
        foreach ($s in $slots) { if ($s -ieq [string]$o) { $found = $true } }
        if (-not $found) { [void]$unknown.Add([string]$o) }
    }
    return , $unknown.ToArray()
}

function Get-CrRole {
    param($Config, [string]$Name)
    if (-not ($Config -is [hashtable]) -or -not ($Config['Roles'] -is [hashtable])) { throw 'Get-CrRole: config has no Roles table.' }
    if (-not $Name -or -not $Config['Roles'].ContainsKey($Name)) { throw ('Unknown role: {0}' -f $Name) }
    return $Config['Roles'][$Name]
}

function Test-CrConfigIsInteger {
    param($Value)
    return (($Value -is [int]) -or ($Value -is [long]))
}

function Test-CrConfigIsSid {
    param($Value)
    if (-not ($Value -is [string])) { return $false }
    if ($Value -notmatch '^S-1-\d+(-\d+)+$') { return $false }
    try {
        [void](New-Object System.Security.Principal.SecurityIdentifier($Value))
        return $true
    } catch {
        return $false
    }
}

# Returns $null if the regex compiles (with IgnoreCase), otherwise the error message.
function Test-CrConfigRegex {
    param([string]$Pattern)
    try {
        [void](New-Object System.Text.RegularExpressions.Regex($Pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase))
        return $null
    } catch {
        $message = $_.Exception.Message
        if ($_.Exception.InnerException) { $message = $_.Exception.InnerException.Message }
        return $message
    }
}

function Test-CrConfigKeys {
    param($Table, [string[]]$Allowed, [string]$Where, $Errors)
    foreach ($key in @($Table.Keys)) {
        if ($Allowed -notcontains [string]$key) { [void]$Errors.Add(('{0}: unknown key ''{1}''.' -f $Where, $key)) }
    }
}

function Test-CrConfigBool {
    param($Table, [string]$Key, [string]$Where, $Errors)
    if ($Table.ContainsKey($Key) -and -not ($Table[$Key] -is [bool])) {
        [void]$Errors.Add(('{0}: {1} must be $true or $false.' -f $Where, $Key))
    }
}

function Test-CrConfigString {
    param($Value)
    return (($Value -is [string]) -and ($Value.Trim().Length -gt 0))
}

# Principal/group reference: S-1-..., RID-<n>, Name:<x>, Name:<x>?, Pattern:<re> (Pattern only when AllowPattern).
function Test-CrConfigGroupReference {
    param($Reference, [bool]$AllowPattern, [string]$Where, $Errors)
    if (-not ($Reference -is [string]) -or -not $Reference) {
        [void]$Errors.Add(('{0}: a group reference must be a non-empty string.' -f $Where))
        return
    }
    if ($Reference.StartsWith('S-', [System.StringComparison]::OrdinalIgnoreCase)) {
        if (-not (Test-CrConfigIsSid $Reference)) { [void]$Errors.Add(('{0}: invalid SID ''{1}''.' -f $Where, $Reference)) }
        return
    }
    if ($Reference -match '^RID-\d+$') { return }
    if ($Reference -match '^Name:(.*)$') {
        $name = $matches[1]
        if ($name.EndsWith('?')) { $name = $name.Substring(0, $name.Length - 1) }
        if (-not $name.Trim()) { [void]$Errors.Add(('{0}: empty group name in ''{1}''.' -f $Where, $Reference)) }
        return
    }
    if ($Reference -match '^Pattern:(.*)$') {
        $pattern = $matches[1]
        if (-not $AllowPattern) {
            [void]$Errors.Add(('{0}: ''{1}'': Pattern: is only valid in AllowedExtraGroups.' -f $Where, $Reference))
        }
        if (-not $pattern) {
            [void]$Errors.Add(('{0}: empty pattern in ''{1}''.' -f $Where, $Reference))
        } else {
            $regexError = Test-CrConfigRegex $pattern
            if ($regexError) { [void]$Errors.Add(('{0}: regex ''{1}'' does not compile: {2}' -f $Where, $pattern, $regexError)) }
        }
        return
    }
    [void]$Errors.Add(('{0}: unknown reference form ''{1}'' (expected S-1-..., RID-<n>, Name:<group>[?] or Pattern:<regex>).' -f $Where, $Reference))
}

function Test-CrConfigRoleRef {
    param($Config, $RoleName, [string]$Where, $Errors)
    if (-not (Test-CrConfigString $RoleName)) {
        [void]$Errors.Add(('{0}: Role must be a non-empty string.' -f $Where))
        return
    }
    if (($Config['Roles'] -is [hashtable]) -and -not $Config['Roles'].ContainsKey([string]$RoleName)) {
        [void]$Errors.Add(('{0}: unknown role ''{1}''.' -f $Where, $RoleName))
    }
}

function Test-CrConfigSlotRef {
    param($SlotName, $Slots, [string]$Where, $Errors)
    if (-not (Test-CrConfigString $SlotName)) {
        [void]$Errors.Add(('{0}: Credential must be a non-empty string.' -f $Where))
        return
    }
    if ($Slots -notcontains [string]$SlotName) {
        [void]$Errors.Add(('{0}: Credential ''{1}'' does not refer to an existing slot.' -f $Where, $SlotName))
    }
}

function Test-CrConfigRoles {
    param($Config, $Schema, $Errors)
    $roles = $Config['Roles']
    if (-not ($roles -is [hashtable])) {
        [void]$Errors.Add('Roles must be a hashtable.')
        return
    }
    foreach ($roleName in @($roles.Keys)) {
        $where = 'Role ''{0}''' -f $roleName
        $role = $roles[$roleName]
        if (-not ($role -is [hashtable])) {
            [void]$Errors.Add(('{0}: must be a hashtable.' -f $where))
            continue
        }
        Test-CrConfigKeys -Table $role -Allowed $Schema.RoleKeys -Where $where -Errors $Errors
        foreach ($key in $Schema.RoleBoolKeys) { Test-CrConfigBool -Table $role -Key $key -Where $where -Errors $Errors }
        foreach ($listKey in @('Groups', 'AllowedExtraGroups')) {
            if (-not $role.ContainsKey($listKey)) { continue }
            $allowPattern = ($listKey -eq 'AllowedExtraGroups')
            $refs = ConvertTo-CrArray $role[$listKey]
            if ($refs.Count -eq 0) { [void]$Errors.Add(('{0}: {1} is empty.' -f $where, $listKey)) }
            foreach ($ref in $refs) {
                Test-CrConfigGroupReference -Reference $ref -AllowPattern $allowPattern -Where ('{0} {1}' -f $where, $listKey) -Errors $Errors
            }
        }
        if ($role.ContainsKey('IfGroupMissing') -and ($Schema.IfGroupMissingValues -notcontains [string]$role['IfGroupMissing'])) {
            [void]$Errors.Add(('{0}: IfGroupMissing ''{1}'' is not one of: {2}.' -f $where, $role['IfGroupMissing'], ($Schema.IfGroupMissingValues -join ', ')))
        }
        if ($role.ContainsKey('ExclusiveGroups') -and $role['ExclusiveGroups'] -and -not $role.ContainsKey('Groups')) {
            [void]$Errors.Add(('{0}: ExclusiveGroups requires Groups.' -f $where))
        }
    }
}

# Returns the list of slot names (valid or not, for reference checks).
function Test-CrConfigCredentials {
    param($Config, $Schema, $Errors)
    $slots = New-Object System.Collections.ArrayList
    if (-not $Config.ContainsKey('Credentials')) { return , $slots.ToArray() }
    $orders = @{}
    $index = 0
    foreach ($credential in (ConvertTo-CrArray $Config['Credentials'])) {
        $index++
        $where = 'Credentials[{0}]' -f $index
        if (-not ($credential -is [hashtable])) {
            [void]$Errors.Add(('{0}: must be a hashtable.' -f $where))
            continue
        }
        if (Test-CrConfigString $credential['Slot']) { $where = 'Slot ''{0}''' -f $credential['Slot'] }
        Test-CrConfigKeys -Table $credential -Allowed $Schema.CredentialKeys -Where $where -Errors $Errors
        if (-not (Test-CrConfigString $credential['Slot'])) {
            [void]$Errors.Add(('{0}: Slot must be a non-empty string.' -f $where))
        } elseif ($slots -contains [string]$credential['Slot']) {
            [void]$Errors.Add(('{0}: duplicate slot.' -f $where))
        } else {
            [void]$slots.Add([string]$credential['Slot'])
        }
        if (-not (Test-CrConfigIsInteger $credential['Order'])) {
            [void]$Errors.Add(('{0}: Order must be an integer.' -f $where))
        } else {
            $orderKey = [string]$credential['Order']
            if ($orders.ContainsKey($orderKey)) {
                [void]$Errors.Add(('{0}: duplicate Order {1} (also used by {2}).' -f $where, $orderKey, $orders[$orderKey]))
            } else {
                $orders[$orderKey] = $where
            }
        }
        if ($credential.ContainsKey('Label') -and -not ($credential['Label'] -is [string])) {
            [void]$Errors.Add(('{0}: Label must be a string.' -f $where))
        }
        if ($credential.ContainsKey('MaxLength') -and (-not (Test-CrConfigIsInteger $credential['MaxLength']) -or $credential['MaxLength'] -lt 1)) {
            [void]$Errors.Add(('{0}: MaxLength must be a positive integer.' -f $where))
        }
    }
    return , $slots.ToArray()
}

# Keys of managed entries (CONTRACTS "v10: account model"): Create, Replaces, PasswordMode, Operator, EnableIfDisabled.
# $ReplacedBy maps upper-cased replaced names to the entry that replaces them (a name may be replaced once).
function Test-CrConfigManagedKeys {
    param($Schema, $Account, [string]$Where, [bool]$IsRotate, $ReplacedBy, $Errors)
    if (-not $IsRotate) {
        foreach ($key in $Schema.ManagedOnlyKeys) {
            if ($Account.ContainsKey($key)) {
                [void]$Errors.Add(('{0}: key ''{1}'' is not valid for Mode ''{2}''.' -f $Where, $key, $Account['Mode']))
            }
        }
        return
    }
    foreach ($key in @('Create', 'Operator', 'EnableIfDisabled')) { Test-CrConfigBool -Table $Account -Key $key -Where $Where -Errors $Errors }
    $singleName = ($Account.ContainsKey('Name') -and -not $Account.ContainsKey('Names') -and
                   -not $Account.ContainsKey('NamePattern') -and -not $Account.ContainsKey('Candidates'))
    if (($Account['Create'] -eq $true) -and -not $singleName) {
        [void]$Errors.Add(('{0}: Create requires a single Name.' -f $Where))
    }
    if (($Account['Operator'] -is [bool]) -and $Account['Operator'] -and -not $singleName) {
        [void]$Errors.Add(('{0}: Operator requires a single Name (the operator''s account, D25).' -f $Where))
    }
    # D21: the auto-logon accounts are never created.
    if (($Account['Create'] -eq $true) -and $Account.ContainsKey('AutoLogon')) {
        [void]$Errors.Add(('{0}: the auto-logon accounts are never created; Create is not valid with AutoLogon.' -f $Where))
    }
    if ($Account.ContainsKey('PasswordMode')) {
        if ($Schema.PasswordModeValues -notcontains [string]$Account['PasswordMode']) {
            [void]$Errors.Add(('{0}: PasswordMode must be one of: {1}.' -f $Where, ($Schema.PasswordModeValues -join ', ')))
        }
        if (-not $Account.ContainsKey('Credential')) {
            [void]$Errors.Add(('{0}: PasswordMode is only valid on Windows entries with a Credential.' -f $Where))
        }
    }
    if ($Account.ContainsKey('Replaces')) {
        if (-not $singleName) { [void]$Errors.Add(('{0}: Replaces requires a single Name (the replacement account).' -f $Where)) }
        $list = ConvertTo-CrArray $Account['Replaces']
        if ($list.Count -eq 0) { [void]$Errors.Add(('{0}: Replaces is empty.' -f $Where)) }
        foreach ($item in $list) {
            if (-not (Test-CrConfigString $item)) {
                [void]$Errors.Add(('{0}: every entry of Replaces must be a non-empty string.' -f $Where))
                continue
            }
            $text = ([string]$item).Trim()
            if (($text -match '^RID-') -and $text -ne 'RID-500') {
                [void]$Errors.Add(('{0}: Replaces ''{1}'': only RID-500 is supported as a RID reference.' -f $Where, $text))
                continue
            }
            if ($text -match '^S-1-') {
                [void]$Errors.Add(('{0}: Replaces ''{1}'': use an account name or RID-500, not a SID.' -f $Where, $text))
                continue
            }
            $key = $text.ToUpperInvariant()
            if ($ReplacedBy.ContainsKey($key)) {
                [void]$Errors.Add(('{0}: Replaces ''{1}'' is already replaced by {2}.' -f $Where, $text, $ReplacedBy[$key]))
            } else {
                $ReplacedBy[$key] = $Where
            }
        }
    }
}

function Test-CrConfigAccount {
    param($Config, $Schema, $Account, [string]$Where, $Slots, $Errors, $ReplacedBy)
    if ($null -eq $ReplacedBy) { $ReplacedBy = @{} }
    Test-CrConfigKeys -Table $Account -Allowed $Schema.AccountKeys -Where $Where -Errors $Errors

    $kind = $Account['Kind']
    if ($Schema.Kinds -notcontains [string]$kind) {
        [void]$Errors.Add(('{0}: Kind must be one of: {1}.' -f $Where, ($Schema.Kinds -join ', ')))
        return
    }
    $isWindowsKind = ($kind -eq 'Windows')
    $kindOnlyKeys = $Schema.SqlOnlyKeys
    if (-not $isWindowsKind) { $kindOnlyKeys = $Schema.WindowsOnlyKeys }
    foreach ($key in $kindOnlyKeys) {
        if ($Account.ContainsKey($key)) { [void]$Errors.Add(('{0}: key ''{1}'' is not valid for Kind ''{2}''.' -f $Where, $key, $kind)) }
    }

    $isCheck = $false
    $isDisable = $false
    if ($Account.ContainsKey('Mode')) {
        if ($Schema.ModeValues -notcontains [string]$Account['Mode']) {
            [void]$Errors.Add(('{0}: Mode ''{1}'' is not valid (only ''Check'' or ''Disable''; omit Mode to rotate).' -f $Where, $Account['Mode']))
        } elseif ([string]$Account['Mode'] -eq 'Disable') {
            $isDisable = $true
        } else {
            $isCheck = $true
        }
    }
    if ($isWindowsKind) {
        Test-CrConfigManagedKeys -Schema $Schema -Account $Account -Where $Where -IsRotate (-not $isCheck -and -not $isDisable) `
            -ReplacedBy $ReplacedBy -Errors $Errors
    }
    if ($isDisable) {
        foreach ($key in $Schema.DisableForbiddenKeys) {
            if ($Account.ContainsKey($key)) { [void]$Errors.Add(('{0}: key ''{1}'' is not valid for Mode ''Disable''.' -f $Where, $key)) }
        }
    }

    # Selection: exactly one rule
    $selection = @()
    foreach ($key in $Schema.SelectionKeys) { if ($Account.ContainsKey($key)) { $selection += $key } }
    if ($selection.Count -ne 1) {
        [void]$Errors.Add(('{0}: needs exactly one of Name, Names, NamePattern, Candidates (found {1}).' -f $Where, $selection.Count))
    }
    if ($Account.ContainsKey('Name') -and -not (Test-CrConfigString $Account['Name'])) {
        [void]$Errors.Add(('{0}: Name must be a non-empty string.' -f $Where))
    }
    if ($Account.ContainsKey('Names')) {
        $names = ConvertTo-CrArray $Account['Names']
        if ($names.Count -eq 0) { [void]$Errors.Add(('{0}: Names is empty.' -f $Where)) }
        foreach ($n in $names) {
            if (-not (Test-CrConfigString $n)) { [void]$Errors.Add(('{0}: every entry of Names must be a non-empty string.' -f $Where)) }
        }
    }
    if ($Account.ContainsKey('NamePattern')) {
        if (-not (Test-CrConfigString $Account['NamePattern'])) {
            [void]$Errors.Add(('{0}: NamePattern must be a non-empty string.' -f $Where))
        } else {
            $regexError = Test-CrConfigRegex $Account['NamePattern']
            if ($regexError) { [void]$Errors.Add(('{0}: NamePattern ''{1}'' does not compile: {2}' -f $Where, $Account['NamePattern'], $regexError)) }
        }
    }

    # Role and Credential: on the entry, or on each candidate
    if ($Account.ContainsKey('Candidates')) {
        foreach ($key in @('Role', 'Credential')) {
            if ($Account.ContainsKey($key)) { [void]$Errors.Add(('{0}: {1} belongs on each candidate, not on an entry with Candidates.' -f $Where, $key)) }
        }
        $candidates = ConvertTo-CrArray $Account['Candidates']
        if ($candidates.Count -eq 0) { [void]$Errors.Add(('{0}: Candidates is empty.' -f $Where)) }
        $ci = 0
        foreach ($candidate in $candidates) {
            $cWhere = '{0} candidate {1}' -f $Where, $ci
            $ci++
            if (-not ($candidate -is [hashtable])) {
                [void]$Errors.Add(('{0}: must be a hashtable.' -f $cWhere))
                continue
            }
            Test-CrConfigKeys -Table $candidate -Allowed $Schema.CandidateKeys -Where $cWhere -Errors $Errors
            $hasName = $candidate.ContainsKey('Name')
            $hasSid = $candidate.ContainsKey('Sid')
            if ($hasName -eq $hasSid) {
                [void]$Errors.Add(('{0}: needs exactly one of Name or Sid.' -f $cWhere))
            }
            if ($hasName -and -not (Test-CrConfigString $candidate['Name'])) {
                [void]$Errors.Add(('{0}: Name must be a non-empty string.' -f $cWhere))
            }
            if ($hasSid) {
                $sid = $candidate['Sid']
                if (-not (($sid -is [string]) -and (($sid -match '^RID-\d+$') -or (Test-CrConfigIsSid $sid)))) {
                    [void]$Errors.Add(('{0}: invalid SID ''{1}'' (expected S-1-... or RID-<n>).' -f $cWhere, $sid))
                }
            }
            Test-CrConfigRoleRef -Config $Config -RoleName $candidate['Role'] -Where $cWhere -Errors $Errors
            if ($isCheck) {
                if ($candidate.ContainsKey('Credential')) { [void]$Errors.Add(('{0}: Mode ''Check'' entries have no Credential.' -f $cWhere)) }
            } else {
                Test-CrConfigSlotRef -SlotName $candidate['Credential'] -Slots $Slots -Where $cWhere -Errors $Errors
            }
        }
    } elseif (-not $isDisable) {
        if ($isWindowsKind) {
            Test-CrConfigRoleRef -Config $Config -RoleName $Account['Role'] -Where $Where -Errors $Errors
        }
        if ($isCheck) {
            if ($Account.ContainsKey('Credential')) { [void]$Errors.Add(('{0}: Mode ''Check'' entries have no Credential.' -f $Where)) }
        } else {
            Test-CrConfigSlotRef -SlotName $Account['Credential'] -Slots $Slots -Where $Where -Errors $Errors
        }
    }

    Test-CrConfigBool -Table $Account -Key 'LoginsEntry' -Where $Where -Errors $Errors
    foreach ($key in $Schema.DependentKeys) {
        if ($Account.ContainsKey($key) -and ($Schema.DependentValues -notcontains [string]$Account[$key])) {
            [void]$Errors.Add(('{0}: {1} must be one of: {2}.' -f $Where, $key, ($Schema.DependentValues -join ', ')))
        }
    }
    if ($Account.ContainsKey('ServerRoles')) {
        foreach ($r in (ConvertTo-CrArray $Account['ServerRoles'])) {
            if (-not (Test-CrConfigString $r)) { [void]$Errors.Add(('{0}: every entry of ServerRoles must be a non-empty string.' -f $Where)) }
        }
    }

    # Auto-logon block (D18)
    $hasAutoLogon = $Account.ContainsKey('AutoLogon')
    $hasAutoLogonUser = $Account.ContainsKey('AutoLogonUser')
    if ($hasAutoLogon -ne $hasAutoLogonUser) {
        [void]$Errors.Add(('{0}: AutoLogon and AutoLogonUser must be set together.' -f $Where))
    }
    if ($hasAutoLogon) {
        $block = $Account['AutoLogon']
        if (-not ($block -is [hashtable])) {
            [void]$Errors.Add(('{0}: AutoLogon must be a hashtable.' -f $Where))
        } else {
            Test-CrConfigKeys -Table $block -Allowed $Schema.AutoLogonKeys -Where ('{0} AutoLogon' -f $Where) -Errors $Errors
            if ($Schema.AutoLogonModes -notcontains [string]$block['Mode']) {
                [void]$Errors.Add(('{0}: AutoLogon Mode must be one of: {1}.' -f $Where, ($Schema.AutoLogonModes -join ', ')))
            }
            if (-not (Test-CrConfigString $block['RestrictedComputerPattern'])) {
                [void]$Errors.Add(('{0}: AutoLogon RestrictedComputerPattern must be a non-empty string.' -f $Where))
            } else {
                $regexError = Test-CrConfigRegex $block['RestrictedComputerPattern']
                if ($regexError) { [void]$Errors.Add(('{0}: RestrictedComputerPattern ''{1}'' does not compile: {2}' -f $Where, $block['RestrictedComputerPattern'], $regexError)) }
            }
        }
    }
    if ($hasAutoLogonUser) {
        $selected = @()
        if ($Account.ContainsKey('Name')) { $selected += [string]$Account['Name'] }
        if ($Account.ContainsKey('Names')) { foreach ($n in (ConvertTo-CrArray $Account['Names'])) { $selected += [string]$n } }
        $list = ConvertTo-CrArray $Account['AutoLogonUser']
        if ($list.Count -eq 0) { [void]$Errors.Add(('{0}: AutoLogonUser is empty.' -f $Where)) }
        foreach ($item in $list) {
            if (-not ($item -is [hashtable])) {
                [void]$Errors.Add(('{0}: every AutoLogonUser entry must be a hashtable.' -f $Where))
                continue
            }
            Test-CrConfigKeys -Table $item -Allowed $Schema.AutoLogonUserKeys -Where ('{0} AutoLogonUser' -f $Where) -Errors $Errors
            if (-not (Test-CrConfigString $item['Name'])) {
                [void]$Errors.Add(('{0}: every AutoLogonUser entry needs a Name.' -f $Where))
            } elseif ($selected -notcontains [string]$item['Name']) {
                [void]$Errors.Add(('{0}: AutoLogonUser ''{1}'' is not selected by this entry''s Name/Names.' -f $Where, $item['Name']))
            }
        }
        # D18: every account of the entry is a managed auto-logon account (kept when active); one missing from the list
        # would count as "any other account" and be switched away or turned off.
        $listed = @()
        foreach ($item in $list) { if (($item -is [hashtable]) -and $item['Name']) { $listed += [string]$item['Name'] } }
        foreach ($n in $selected) {
            if ($listed -notcontains $n) { [void]$Errors.Add(('{0}: ''{1}'' is missing from AutoLogonUser (every account of the entry must be listed).' -f $Where, $n)) }
        }
    }
}

# Writes the error strings to the pipeline (unrolled); none means valid (PLAN section 5 "Validation").
# Callers wrap the call: $errors = @(Test-CrConfig -Config $c).
function Test-CrConfig {
    param($Config)
    $errors = New-Object System.Collections.ArrayList
    if (-not ($Config -is [hashtable])) {
        [void]$errors.Add('The configuration is not a hashtable.')
        return $errors.ToArray()
    }
    $schema = Get-CrConfigSchema
    Test-CrConfigKeys -Table $Config -Allowed $schema.TopKeys -Where 'Config' -Errors $errors
    foreach ($key in $schema.RequiredTopKeys) {
        if (-not $Config.ContainsKey($key)) { [void]$errors.Add(('Config: missing key ''{0}''.' -f $key)) }
    }
    # D23: optional, 'Ask' is the only value (and the behaviour when the key is absent)
    if ($Config.ContainsKey('OtherEnabledAccounts') -and ($schema.OtherEnabledValues -notcontains [string]$Config['OtherEnabledAccounts'])) {
        [void]$errors.Add(('Config: OtherEnabledAccounts ''{0}'' is not valid (only: {1}).' -f $Config['OtherEnabledAccounts'], ($schema.OtherEnabledValues -join ', ')))
    }

    if ($Config.ContainsKey('SchemaVersion') -and -not ((Test-CrConfigIsInteger $Config['SchemaVersion']) -and $Config['SchemaVersion'] -eq 1)) {
        [void]$errors.Add(('Config: unsupported SchemaVersion ''{0}'' (expected 1).' -f $Config['SchemaVersion']))
    }

    if ($Config.ContainsKey('SitePasswordRules')) {
        $rules = $Config['SitePasswordRules']
        if (-not ($rules -is [hashtable])) {
            [void]$errors.Add('SitePasswordRules must be a hashtable.')
        } else {
            Test-CrConfigKeys -Table $rules -Allowed $schema.SitePasswordRuleKeys -Where 'SitePasswordRules' -Errors $errors
            if ($rules.ContainsKey('MinLength') -and (-not (Test-CrConfigIsInteger $rules['MinLength']) -or $rules['MinLength'] -lt 1)) {
                [void]$errors.Add('SitePasswordRules: MinLength must be a positive integer.')
            }
            Test-CrConfigBool -Table $rules -Key 'RequireComplexity' -Where 'SitePasswordRules' -Errors $errors
        }
    }

    if ($Config.ContainsKey('Roles')) { Test-CrConfigRoles -Config $Config -Schema $schema -Errors $errors }
    $slots = Test-CrConfigCredentials -Config $Config -Schema $schema -Errors $errors

    if ($Config.ContainsKey('Accounts')) {
        $ids = @{}
        $replacedBy = @{}
        $autoLogonEntries = 0
        $operatorEntries = 0
        $autoLogonNames = New-Object System.Collections.ArrayList
        $disableNames = New-Object System.Collections.ArrayList
        $index = 0
        foreach ($account in (ConvertTo-CrArray $Config['Accounts'])) {
            $index++
            $where = 'Accounts[{0}]' -f $index
            if (-not ($account -is [hashtable])) {
                [void]$errors.Add(('{0}: must be a hashtable.' -f $where))
                continue
            }
            if (-not (Test-CrConfigString $account['Id'])) {
                [void]$errors.Add(('{0}: Id must be a non-empty string.' -f $where))
            } else {
                $where = 'Account ''{0}''' -f $account['Id']
                if ($ids.ContainsKey([string]$account['Id'])) {
                    [void]$errors.Add(('{0}: duplicate Id.' -f $where))
                } else {
                    $ids[[string]$account['Id']] = $true
                }
            }
            if ($account.ContainsKey('AutoLogon')) {
                $autoLogonEntries++
                foreach ($a in (ConvertTo-CrArray $account['AutoLogonUser'])) {
                    if (($a -is [hashtable]) -and $a['Name']) { [void]$autoLogonNames.Add([string]$a['Name']) }
                }
            }
            if (($account['Operator'] -is [bool]) -and $account['Operator']) { $operatorEntries++ }
            if ([string]$account['Mode'] -eq 'Disable') {
                if ($account['Name']) { [void]$disableNames.Add([string]$account['Name']) }
                foreach ($n in (ConvertTo-CrArray $account['Names'])) { if ($n) { [void]$disableNames.Add([string]$n) } }
            }
            Test-CrConfigAccount -Config $Config -Schema $schema -Account $account -Where $where -Slots $slots -Errors $errors -ReplacedBy $replacedBy
        }
        if ($autoLogonEntries -gt 1) { [void]$errors.Add('Accounts: only one entry may have an AutoLogon block.') }
        if ($operatorEntries -gt 1) { [void]$errors.Add('Accounts: only one entry may be the Operator account (D25).') }
        # D18, D22: the auto-logon accounts are never disabled, so they can't be replaced or retired.
        foreach ($n in $autoLogonNames) {
            if ($replacedBy.ContainsKey($n.ToUpperInvariant())) {
                [void]$errors.Add(('Accounts: the auto-logon account ''{0}'' must not be replaced ({1}).' -f $n, $replacedBy[$n.ToUpperInvariant()]))
            }
            foreach ($d in $disableNames) {
                if ($d -ieq $n) { [void]$errors.Add(('Accounts: the auto-logon account ''{0}'' must not be in a Disable entry.' -f $n)) }
            }
        }
    }
    return $errors.ToArray()
}
