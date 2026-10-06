# IisReport.ps1 - IIS application pool and virtual directory identities, report only
# (docs/PLAN.md section 7.6, docs/dev/CONTRACTS.md "Iis"). Read only: never calls CommitChanges.

# --- internal: external access (mocked in tests) ---

function Test-CrIisInstalled {
    param()
    return [bool](Get-Service -Name W3SVC -ErrorAction SilentlyContinue)
}

# 'Major.Minor' from HKLM\SOFTWARE\Microsoft\InetStp, or $null.
function Get-CrIisVersion {
    param()
    $root = 'HKLM:\SOFTWARE\Microsoft\InetStp'
    $major = Get-CrRegistryValue -Path $root -Name 'MajorVersion'
    if (-not $major['Exists']) { return $null }
    $minor = Get-CrRegistryValue -Path $root -Name 'MinorVersion'
    $minorValue = 0
    if ($minor['Exists']) { $minorValue = $minor['Value'] }
    return ('{0}.{1}' -f $major['Value'], $minorValue)
}

# Microsoft.Web.Administration.ServerManager, loaded by path from %windir%\System32\inetsrv.
function Get-CrIisServerManager {
    param()
    if (-not ('Microsoft.Web.Administration.ServerManager' -as [type])) {
        $dll = Join-Path $env:windir 'System32\inetsrv\Microsoft.Web.Administration.dll'
        if (-not (Test-Path -LiteralPath $dll)) { throw ('Microsoft.Web.Administration.dll not found: ' + $dll) }
        Add-Type -Path $dll
    }
    return (New-Object Microsoft.Web.Administration.ServerManager)
}

# --- internal: logic ---

function Resolve-CrIisUserSid {
    param([string]$UserName, [hashtable]$Cache)
    if (-not $UserName) { return $null }
    $key = $UserName.ToLowerInvariant()
    if (-not $Cache.ContainsKey($key)) { $Cache[$key] = Resolve-CrNameToSid -Name $UserName }
    return $Cache[$key]
}

function Get-CrIisSiteProtocols {
    param($Site)
    $protocols = New-Object System.Collections.ArrayList
    foreach ($b in (ConvertTo-CrArray $Site.Bindings)) {
        if ($null -eq $b) { continue }
        $p = [string]$b.Protocol
        if ($p -and -not ($protocols -contains $p)) { [void]$protocols.Add($p) }
    }
    return , $protocols.ToArray()
}

# --- public ---

# Not installed (no W3SVC service) = Installed $false and no Error.
# UserSid of a pool is resolved only for IdentityType SpecificUser (a stale UserName on a built-in identity isn't used).
function Get-CrIisIdentities {
    param()
    $result = @{
        Installed          = $false
        Version            = $null
        Error              = $null
        AppPools           = @()
        VirtualDirectories = @()
    }
    if (-not (Test-CrIisInstalled)) { return $result }
    $result['Installed'] = $true
    try { $result['Version'] = Get-CrIisVersion } catch { }

    $sm = $null
    $cache = @{}
    try {
        $sm = Get-CrIisServerManager
        $pools = New-Object System.Collections.ArrayList
        foreach ($p in (ConvertTo-CrArray $sm.ApplicationPools)) {
            if ($null -eq $p) { continue }
            $identityType = [string]$p.ProcessModel.IdentityType
            $userName = [string]$p.ProcessModel.UserName
            $sid = $null
            if ($identityType -eq 'SpecificUser') { $sid = Resolve-CrIisUserSid -UserName $userName -Cache $cache }
            [void]$pools.Add(@{
                Name         = [string]$p.Name
                IdentityType = $identityType
                UserName     = $userName
                UserSid      = $sid
            })
        }

        $vdirs = New-Object System.Collections.ArrayList
        foreach ($site in (ConvertTo-CrArray $sm.Sites)) {
            if ($null -eq $site) { continue }
            $protocols = Get-CrIisSiteProtocols -Site $site
            foreach ($app in (ConvertTo-CrArray $site.Applications)) {
                if ($null -eq $app) { continue }
                foreach ($vd in (ConvertTo-CrArray $app.VirtualDirectories)) {
                    if ($null -eq $vd) { continue }
                    $userName = [string]$vd.UserName
                    [void]$vdirs.Add(@{
                        Site         = [string]$site.Name
                        Application  = [string]$app.Path
                        Path         = [string]$vd.Path
                        PhysicalPath = [string]$vd.PhysicalPath
                        UserName     = $userName
                        UserSid      = Resolve-CrIisUserSid -UserName $userName -Cache $cache
                        Protocols    = $protocols
                    })
                }
            }
        }
        $result['AppPools'] = $pools.ToArray()
        $result['VirtualDirectories'] = $vdirs.ToArray()
    } catch {
        $result['Error'] = $_.Exception.Message
    } finally {
        if ($sm -is [System.IDisposable]) { try { $sm.Dispose() } catch { } }
    }
    return $result
}
