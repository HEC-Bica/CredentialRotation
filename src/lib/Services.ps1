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
