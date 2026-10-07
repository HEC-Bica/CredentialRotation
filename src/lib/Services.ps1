# Services.ps1 - Windows services and their logon accounts, read side (docs/PLAN.md section 7.4, docs/dev/CONTRACTS.md "Services")
# Only the executable of PathName is kept, never its arguments (D4).

# --- internal: external access (mocked in tests) ---

function Get-CrServiceWmiObjects {
    param()
    return , @(Get-WmiObject -Class Win32_Service -ErrorAction Stop)
}

# All service controllers (for dependency names); read only.
function Get-CrServiceControllers {
    param()
    return , @(Get-Service -ErrorAction SilentlyContinue)
}

# --- internal: logic ---

# Executable path of a command line; arguments are dropped because they may contain secrets (D4).
function Get-CrExecutablePath {
    param([string]$CommandLine)
    if (-not $CommandLine) { return $null }
    $c = $CommandLine.Trim()
    if (-not $c) { return $null }
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        if ($end -gt 0) { return $c.Substring(1, $end - 1) }
        return $c.Substring(1)
    }
    $m = [regex]::Match($c, '^(.+?\.(exe|com|bat|cmd|ps1|vbs|js))(\s|$)', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    return ($c -split '\s+')[0]
}

# Name -> @{ DependentServices = @(); DependsOn = @() }
function Get-CrServiceDependencyMap {
    param()
    $map = @{}
    $controllers = ConvertTo-CrArray (Get-CrServiceControllers)
    foreach ($c in $controllers) {
        if ($null -eq $c) { continue }
        $name = [string]$c.Name
        if (-not $name) { continue }
        $dependents = New-Object System.Collections.ArrayList
        $dependsOn = New-Object System.Collections.ArrayList
        try {
            foreach ($d in (ConvertTo-CrArray $c.DependentServices)) {
                if ($null -ne $d -and $d.Name) { [void]$dependents.Add([string]$d.Name) }
            }
        } catch { }
        try {
            foreach ($d in (ConvertTo-CrArray $c.ServicesDependedOn)) {
                if ($null -ne $d -and $d.Name) { [void]$dependsOn.Add([string]$d.Name) }
            }
        } catch { }
        $map[$name.ToLowerInvariant()] = @{ DependentServices = $dependents.ToArray(); DependsOn = $dependsOn.ToArray() }
    }
    return $map
}

# --- public ---

# All services with a StartName. The plan layer filters by StartNameSid.
function Get-CrServices {
    param()
    $list = New-Object System.Collections.ArrayList
    $sidCache = @{}
    $deps = Get-CrServiceDependencyMap
    $services = ConvertTo-CrArray (Get-CrServiceWmiObjects)
    foreach ($s in $services) {
        if ($null -eq $s) { continue }
        $startName = [string]$s.StartName
        if (-not $startName) { continue }
        $key = $startName.ToLowerInvariant()
        if (-not $sidCache.ContainsKey($key)) { $sidCache[$key] = Resolve-CrNameToSid -Name $startName }
        $name = [string]$s.Name
        $dependents = @()
        $dependsOn = @()
        if ($name -and $deps.ContainsKey($name.ToLowerInvariant())) {
            $entry = $deps[$name.ToLowerInvariant()]
            $dependents = $entry['DependentServices']
            $dependsOn = $entry['DependsOn']
        }
        [void]$list.Add(@{
            Name              = $name
            DisplayName       = [string]$s.DisplayName
            StartName         = $startName
            StartNameSid      = $sidCache[$key]
            StartMode         = [string]$s.StartMode
            State             = [string]$s.State
            PathExecutable    = Get-CrExecutablePath -CommandLine ([string]$s.PathName)
            DependentServices = $dependents
            DependsOn         = $dependsOn
        })
    }
    return , $list.ToArray()
}

# --- write side (M2/M3, v10) ---

# Sets the logon account and password of every service whose StartNameSid is Sid ($State.Services).
# Account = $null keeps each service's StartName text (password update); otherwise every matching
# service gets Account (move, D24). Never starts, stops or restarts a service (D17).
# Returns an array of @{ Name; Success; Win32Error; Error; FromAccount; ToAccount }.
function Invoke-CrServiceLogonChange {
    param($State, [string]$Sid, [string]$Account, [System.Security.SecureString]$Secret)
    $results = New-Object System.Collections.ArrayList
    $part = $State['Services']
    if ($part -is [hashtable]) {
        [void]$results.Add(@{ Name = $null; Success = $false; Win32Error = $null; Error = ('Services could not be read: ' + [string]$part['Error']); FromAccount = $null; ToAccount = $Account })
        return , $results.ToArray()
    }
    $services = ConvertTo-CrArray $part
    foreach ($s in $services) {
        if ($null -eq $s) { continue }
        if ($s['StartNameSid'] -ne $Sid) { continue }
        $name = [string]$s['Name']
        $from = [string]$s['StartName']
        $to = $Account
        if (-not $to) { $to = $from }
        $entry = @{ Name = $name; Success = $false; Win32Error = $null; Error = $null; FromAccount = $from; ToAccount = $to }
        try {
            $r = Set-CrServiceLogonPassword -ServiceName $name -Account $to -Secret $Secret
            $entry['Success'] = [bool]$r['Success']
            $entry['Win32Error'] = $r['Win32Error']
        } catch {
            $ex = $_.Exception
            while ($ex.InnerException) { $ex = $ex.InnerException }
            $entry['Error'] = $ex.Message
        }
        [void]$results.Add($entry)
    }
    return , $results.ToArray()
}

# Updates the stored logon password of every service whose StartNameSid is Sid ($State.Services).
# The existing StartName text is passed unchanged. Services are never started, stopped or restarted
# (D17): the new password takes effect at the next start ("SCM updated - restart pending").
# Returns an array of @{ Name; Success; Win32Error; Error; FromAccount; ToAccount }, one entry per
# service; one failure doesn't stop the others. Error is $null, or the message when the wrapper threw.
# If $State.Services failed to load, the only entry has Name = $null and Success = $false.
function Update-CrServiceCredentials {
    param($State, [string]$Sid, [System.Security.SecureString]$Secret)
    if (-not $Sid) { throw 'Update-CrServiceCredentials: Sid is required' }
    if ($null -eq $Secret) { throw 'Update-CrServiceCredentials: no new password given' }
    return , (Invoke-CrServiceLogonChange -State $State -Sid $Sid -Account $null -Secret $Secret)
}

# Moves every service whose StartNameSid is FromSid to ToAccount ('.\<name>') with that account's
# password (D24): ChangeServiceConfigW with the new StartName and password. Services are never
# started, stopped or restarted (D17). The caller grants SeServiceLogonRight to the new account.
# Returns an array of @{ Name; Success; Win32Error; Error; FromAccount; ToAccount }, one per service;
# one failure doesn't stop the others. If $State.Services failed to load, the only entry has
# Name = $null and Success = $false.
function Move-CrServiceAccount {
    param($State, [string]$FromSid, [string]$ToAccount, [System.Security.SecureString]$Secret)
    if (-not $FromSid) { throw 'Move-CrServiceAccount: FromSid is required' }
    if (-not $ToAccount) { throw 'Move-CrServiceAccount: ToAccount is required' }
    if ($null -eq $Secret) { throw 'Move-CrServiceAccount: no password of the new account given' }
    return , (Invoke-CrServiceLogonChange -State $State -Sid $FromSid -Account $ToAccount -Secret $Secret)
}
