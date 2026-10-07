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

# --- write side (M2/M3) ---

# --- internal: external access (mocked in tests) ---

# Populated COM+ Applications collection object (SaveChanges is called on it).
function Get-CrComPlusApplicationCollection {
    param()
    $catalog = New-Object -ComObject COMAdmin.COMAdminCatalog
    $apps = $catalog.GetCollection('Applications')
    [void]$apps.Populate()
    return , $apps
}

# Catalog objects of a populated collection as an array.
function Get-CrComPlusCollectionItems {
    param($Collection)
    $list = New-Object System.Collections.ArrayList
    foreach ($a in $Collection) { [void]$list.Add($a) }
    return , $list.ToArray()
}

# --- internal: logic ---

function Get-CrComPlusErrorText {
    param($ErrorRecord)
    $ex = $ErrorRecord.Exception
    while ($ex.InnerException) { $ex = $ex.InnerException }
    return $ex.Message
}

# Why a live catalog object must not be updated for Sid, or $null if it may.
function Test-CrComPlusLiveTarget {
    param($Application, [string]$Sid)
    if ((Get-CrComPlusActivationName (Get-CrCatalogValue -CatalogObject $Application -Name 'Activation')) -ne 'Server') {
        return 'Application is no longer a server application; not updated'
    }
    $identity = Get-CrCatalogValue -CatalogObject $Application -Name 'Identity'
    if ($null -ne $identity) { $identity = [string]$identity }
    if ((Test-CrComBuiltinIdentity -Identity $identity) -or ((Resolve-CrNameToSid -Name $identity) -ne $Sid)) {
        return 'Application identity changed since the audit; not updated'
    }
    return $null
}

# Sets the password - and with Identity also the identity - of every COM+ server application whose
# IdentitySid is Sid ($State.ComPlus), then calls SaveChanges once on the Applications collection.
# Identity = $null keeps each application's identity (password update). Applications are never shut
# down or started (D17). When the adapter failed after setting an identity, nothing is saved: that
# object would hold the new identity without its password; the other applications report
# "not saved". Returns an array of @{ Name; Success; Error; FromIdentity; ToIdentity }.
function Invoke-CrComPlusIdentityChange {
    param($State, [string]$Sid, [string]$Identity, [System.Security.SecureString]$Secret)
    $results = New-Object System.Collections.ArrayList
    $part = $State['ComPlus']
    if ($part -is [hashtable]) {
        [void]$results.Add(@{ Name = $null; Success = $false; Error = ('COM+ applications could not be read: ' + [string]$part['Error']); FromIdentity = $null; ToIdentity = $null })
        return , $results.ToArray()
    }
    $targets = New-Object System.Collections.ArrayList
    $all = ConvertTo-CrArray $part
    foreach ($a in $all) {
        if ($null -eq $a) { continue }
        if ($a['IdentitySid'] -ne $Sid -or $a['Activation'] -ne 'Server') { continue }
        [void]$targets.Add($a)
    }
    if ($targets.Count -eq 0) { return , $results.ToArray() }

    $collection = $null
    $items = @()
    try {
        $collection = Get-CrComPlusApplicationCollection
        $items = ConvertTo-CrArray (Get-CrComPlusCollectionItems -Collection $collection)
    } catch {
        $msg = 'COM+ catalog not available: ' + (Get-CrComPlusErrorText $_)
        foreach ($t in $targets) {
            $to = $Identity
            if (-not $to) { $to = [string]$t['Identity'] }
            [void]$results.Add(@{ Name = [string]$t['Name']; Success = $false; Error = $msg; FromIdentity = [string]$t['Identity']; ToIdentity = $to })
        }
        return , $results.ToArray()
    }

    $pending = New-Object System.Collections.ArrayList
    $dirtyFailure = $null
    foreach ($t in $targets) {
        $from = [string]$t['Identity']
        $to = $Identity
        if (-not $to) { $to = $from }
        $entry = @{ Name = [string]$t['Name']; Success = $false; Error = $null; FromIdentity = $from; ToIdentity = $to }
        [void]$results.Add($entry)
        $id = [string]$t['Id']
        $live = $null
        foreach ($i in $items) {
            if ($null -ne $i -and $id -and ([string]$i.Key -eq $id)) { $live = $i; break }
        }
        if ($null -eq $live) {
            $entry['Error'] = 'Application not found in the COM+ catalog; not updated'
            continue
        }
        $adapterCalled = $false
        try {
            $reason = Test-CrComPlusLiveTarget -Application $live -Sid $Sid
            if ($reason) {
                $entry['Error'] = $reason
                continue
            }
            $adapterCalled = $true
            if ($Identity) {
                $r = Set-CrComPlusPasswordAdapter -Application $live -Secret $Secret -Identity $Identity
            } else {
                $r = Set-CrComPlusPasswordAdapter -Application $live -Secret $Secret
            }
            if ($r['Success']) {
                [void]$pending.Add($entry)
            } else {
                $entry['Error'] = $r['Error']
                if ($r['IdentitySet']) { $dirtyFailure = $entry['Name'] }
            }
        } catch {
            $entry['Error'] = Get-CrComPlusErrorText $_
            if ($Identity -and $adapterCalled) { $dirtyFailure = $entry['Name'] }
        }
    }

    if ($pending.Count -gt 0) {
        if ($dirtyFailure) {
            $msg = 'Not saved: the identity of ' + $dirtyFailure + ' was changed but its password could not be set, so no COM+ change was saved'
            foreach ($p in $pending) { $p['Error'] = $msg }
        } else {
            try {
                [void]$collection.SaveChanges()
                foreach ($p in $pending) { $p['Success'] = $true }
            } catch {
                $msg = 'SaveChanges failed: ' + (Get-CrComPlusErrorText $_)
                foreach ($p in $pending) { $p['Error'] = $msg }
            }
        }
    }
    return , $results.ToArray()
}

# --- public ---

# Sets the new password on every COM+ server application whose IdentitySid is Sid ($State.ComPlus),
# then calls SaveChanges once on the Applications collection. Applications are never shut down or
# started (D17): the next activation logs on with the new password ("committed - restart pending").
# Returns an array of @{ Name; Success; Error; FromIdentity; ToIdentity }, one per application; an
# application is successful only when its password was set and SaveChanges succeeded. If
# $State.ComPlus failed to load, the only entry has Name = $null and Success = $false.
function Update-CrComPlusCredentials {
    param($State, [string]$Sid, [System.Security.SecureString]$Secret)
    if (-not $Sid) { throw 'Update-CrComPlusCredentials: Sid is required' }
    if ($null -eq $Secret) { throw 'Update-CrComPlusCredentials: no new password given' }
    return , (Invoke-CrComPlusIdentityChange -State $State -Sid $Sid -Identity $null -Secret $Secret)
}

# Moves every COM+ server application whose IdentitySid is FromSid to ToIdentity (plain account name,
# PLAN 7.7) with that account's password (D24): Identity, then Password via the adapter, then one
# SaveChanges. The live identity is re-checked before writing. Applications are never shut down or
# started (D17). Returns an array of @{ Name; Success; Error; FromIdentity; ToIdentity }, one per
# application (see Invoke-CrComPlusIdentityChange for the all-or-nothing save after an adapter failure).
function Move-CrComPlusIdentity {
    param($State, [string]$FromSid, [string]$ToIdentity, [System.Security.SecureString]$Secret)
    if (-not $FromSid) { throw 'Move-CrComPlusIdentity: FromSid is required' }
    if (-not $ToIdentity) { throw 'Move-CrComPlusIdentity: ToIdentity is required' }
    if ($null -eq $Secret) { throw 'Move-CrComPlusIdentity: no password of the new account given' }
    return , (Invoke-CrComPlusIdentityChange -State $State -Sid $FromSid -Identity $ToIdentity -Secret $Secret)
}
