# Config.ps1 - load and validate the configuration file (docs/PLAN.md section 5, docs/dev/CONTRACTS.md)

# The allowed keys and values. Everything not listed here is a validation error.
function Get-CrConfigSchema {
    return @{
        TopKeys              = @('SchemaVersion', 'SitePasswordRules', 'Roles', 'Credentials', 'Accounts')
        SitePasswordRuleKeys = @('MinLength', 'RequireComplexity')
        RoleKeys             = @('Groups', 'ExclusiveGroups', 'AllowedExtraGroups', 'PasswordNeverExpires',
                                 'CannotChangePassword', 'PasswordRequired', 'IfGroupMissing')
        RoleBoolKeys         = @('ExclusiveGroups', 'PasswordNeverExpires', 'CannotChangePassword', 'PasswordRequired')
        IfGroupMissingValues = @('ReportKeepGroups')
        CredentialKeys       = @('Slot', 'Order', 'Label', 'MaxLength')
        AccountKeys          = @('Id', 'Kind', 'Name', 'Names', 'NamePattern', 'Candidates', 'Role', 'Credential', 'Mode',
                                 'LoginsEntry', 'Services', 'ScheduledTasks', 'ComPlus', 'IisReport',
                                 'AutoLogonUser', 'AutoLogon', 'ServerRoles')
        WindowsOnlyKeys      = @('Names', 'NamePattern', 'Candidates', 'Role', 'Mode', 'Services', 'ScheduledTasks',
                                 'ComPlus', 'IisReport', 'AutoLogonUser', 'AutoLogon')
        SqlOnlyKeys          = @('ServerRoles')
        SelectionKeys        = @('Name', 'Names', 'NamePattern', 'Candidates')
        DependentKeys        = @('Services', 'ScheduledTasks', 'ComPlus', 'IisReport')
        DependentValues      = @('Auto')
        Kinds                = @('Windows', 'SqlLogin')
        ModeValues           = @('Check')
        CandidateKeys        = @('Name', 'Sid', 'Role', 'Credential')
        AutoLogonKeys        = @('Mode', 'RestrictedComputerPattern')
        AutoLogonModes       = @('IfAlreadyOn')
        AutoLogonUserKeys    = @('Name', 'RequireEnabled')
    }
}

function Import-CrConfig {
    param([string]$Path)
    if (-not $Path) { throw 'Import-CrConfig: no path given.' }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw ('Config file not found: {0}' -f $Path) }
    $full = (Resolve-Path -LiteralPath $Path).ProviderPath
    $directory = Split-Path -Parent $full
    $fileName = Split-Path -Leaf $full
    # Import-LocalizedData falls back to the base directory when there is no en-US subfolder (PLAN section 5).
    # -BindingVariable is mandatory in PS 2.0 (found by the first /PS2 audit; without it PS 2.0 prompts).
    $data = $null
    Import-LocalizedData -BindingVariable data -BaseDirectory $directory -FileName $fileName -UICulture en-US -ErrorAction Stop
    if (-not ($data -is [hashtable])) { throw ('Config file {0} does not contain a hashtable.' -f $full) }
    return $data
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

function Test-CrConfigAccount {
    param($Config, $Schema, $Account, [string]$Where, $Slots, $Errors)
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
    if ($Account.ContainsKey('Mode')) {
        if ($Schema.ModeValues -notcontains [string]$Account['Mode']) {
            [void]$Errors.Add(('{0}: Mode ''{1}'' is not valid (only ''Check''; omit Mode to rotate).' -f $Where, $Account['Mode']))
        } else {
            $isCheck = $true
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
    } else {
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
            Test-CrConfigBool -Table $item -Key 'RequireEnabled' -Where ('{0} AutoLogonUser' -f $Where) -Errors $Errors
            if (-not (Test-CrConfigString $item['Name'])) {
                [void]$Errors.Add(('{0}: every AutoLogonUser entry needs a Name.' -f $Where))
            } elseif ($selected -notcontains [string]$item['Name']) {
                [void]$Errors.Add(('{0}: AutoLogonUser ''{1}'' is not selected by this entry''s Name/Names.' -f $Where, $item['Name']))
            }
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
    foreach ($key in $schema.TopKeys) {
        if (-not $Config.ContainsKey($key)) { [void]$errors.Add(('Config: missing key ''{0}''.' -f $key)) }
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
        $autoLogonEntries = 0
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
            if ($account.ContainsKey('AutoLogon')) { $autoLogonEntries++ }
            Test-CrConfigAccount -Config $Config -Schema $schema -Account $account -Where $where -Slots $slots -Errors $errors
        }
        if ($autoLogonEntries -gt 1) { [void]$errors.Add('Accounts: only one entry may have an AutoLogon block.') }
    }
    return $errors.ToArray()
}
