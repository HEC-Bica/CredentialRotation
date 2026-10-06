# ComPlus.ps1 - COM+ applications and DCOM RunAs, read side (docs/PLAN.md section 7.7, docs/dev/CONTRACTS.md "ComPlus / Dcom")

# --- internal: external access (mocked in tests) ---

# Populated COM+ Applications collection as an array of catalog objects.
function Get-CrComPlusCatalogApplications {
    param()
    $catalog = New-Object -ComObject COMAdmin.COMAdminCatalog
    $apps = $catalog.GetCollection('Applications')
    [void]$apps.Populate()
    $list = New-Object System.Collections.ArrayList
    foreach ($a in $apps) { [void]$list.Add($a) }
    return , $list.ToArray()
}

# Registry views of HKLM\SOFTWARE\Classes\AppID (native and 32-bit).
function Get-CrDcomAppIdRoots {
    param()
    return , @('HKLM:\SOFTWARE\Classes\AppID', 'HKLM:\SOFTWARE\Wow6432Node\Classes\AppID')
}

# AppID keys below Root that have a RunAs value: array of @{ AppId; Name; RunAs }. Missing root = empty.
function Get-CrDcomAppIdEntries {
    param([string]$Root)
    $list = New-Object System.Collections.ArrayList
    if (-not (Test-Path -LiteralPath $Root)) { return , $list.ToArray() }
    foreach ($k in @(Get-ChildItem -LiteralPath $Root -ErrorAction SilentlyContinue)) {
        if ($null -eq $k) { continue }
        $runAs = $null
        try { $runAs = $k.GetValue('RunAs') } catch { }
        if ($null -eq $runAs) { continue }
        $name = $null
        try { $name = $k.GetValue('') } catch { }
        [void]$list.Add(@{ AppId = [string]$k.PSChildName; Name = [string]$name; RunAs = [string]$runAs })
    }
    return , $list.ToArray()
}

# --- internal: logic ---

function Get-CrCatalogValue {
    param($CatalogObject, [string]$Name)
    try { return $CatalogObject.Value($Name) } catch { return $null }
}

# Built-in identity strings of COM+ / DCOM, compared by string (PLAN 7.7): they must not be resolved,
# e.g. 'NT AUTHORITY\INTERACTIVE' would resolve to a SID.
function Test-CrComBuiltinIdentity {
    param([string]$Identity)
    if (-not $Identity) { return $true }
    $i = $Identity.Trim()
    if (-not $i) { return $true }
    return ($i -match '^(interactive user|localsystem|launching user|(nt authority\\)?(system|local ?service|network ?service|interactive))$')
}

function Get-CrComPlusActivationName {
    param($Activation)
    if ($null -eq $Activation) { return $null }
    $s = [string]$Activation
    if ($s -eq '0') { return 'Library' }
    if ($s -eq '1') { return 'Server' }
    return $s
}

function ConvertTo-CrComBool {
    param($Value)
    if ($null -eq $Value) { return $null }
    return [bool]$Value
}

# --- public ---

# All COM+ applications. IdentitySid is set for an account identity; $null for built-in identity tokens
# and identities that don't resolve. The plan layer uses server applications (Activation = 'Server') only.
function Get-CrComPlusApplications {
    param()
    $list = New-Object System.Collections.ArrayList
    $sidCache = @{}
    foreach ($a in (ConvertTo-CrArray (Get-CrComPlusCatalogApplications))) {
        if ($null -eq $a) { continue }
        $identity = Get-CrCatalogValue -CatalogObject $a -Name 'Identity'
        if ($null -ne $identity) { $identity = [string]$identity }
        $sid = $null
        if (-not (Test-CrComBuiltinIdentity -Identity $identity)) {
            $key = $identity.ToLowerInvariant()
            if (-not $sidCache.ContainsKey($key)) { $sidCache[$key] = Resolve-CrNameToSid -Name $identity }
            $sid = $sidCache[$key]
        }
        [void]$list.Add(@{
            Name        = [string]$a.Name
            Id          = [string]$a.Key
            Activation  = Get-CrComPlusActivationName (Get-CrCatalogValue -CatalogObject $a -Name 'Activation')
            Identity    = $identity
            IdentitySid = $sid
            IsEnabled   = ConvertTo-CrComBool (Get-CrCatalogValue -CatalogObject $a -Name 'IsEnabled')
            IsSystem    = ConvertTo-CrComBool (Get-CrCatalogValue -CatalogObject $a -Name 'IsSystem')
        })
    }
    return , $list.ToArray()
}

# DCOM AppIDs with a RunAs account, from both registry views, excluding 'Interactive User' and built-ins.
# View is the registry path of the view ('HKLM:\SOFTWARE\Classes\AppID' or the Wow6432Node one).
function Get-CrDcomRunAs {
    param()
    $list = New-Object System.Collections.ArrayList
    $sidCache = @{}
    foreach ($root in (ConvertTo-CrArray (Get-CrDcomAppIdRoots))) {
        foreach ($e in (ConvertTo-CrArray (Get-CrDcomAppIdEntries -Root $root))) {
            if ($null -eq $e) { continue }
            $runAs = [string]$e['RunAs']
            if (Test-CrComBuiltinIdentity -Identity $runAs) { continue }
            $key = $runAs.Trim().ToLowerInvariant()
            if (-not $sidCache.ContainsKey($key)) { $sidCache[$key] = Resolve-CrNameToSid -Name $runAs }
            $sid = $sidCache[$key]
            if (Test-CrBuiltinServiceSid -Sid $sid) { continue }
            [void]$list.Add(@{
                View     = [string]$root
                AppId    = [string]$e['AppId']
                Name     = [string]$e['Name']
                RunAs    = $runAs
                RunAsSid = $sid
            })
        }
    }
    return , $list.ToArray()
}
