#Requires -Version 2.0
<#
.SYNOPSIS
    Read-only M0 inventory for the Credential Rotation tool (docs/PLAN.md, section 12).

.DESCRIPTION
    Collects the facts the plan still needs from the local machine and writes them to one JSON file.
    Runs on Windows PowerShell 2.0 (Windows 7 without WMF) and later.

    READ-ONLY. The script changes nothing on the machine and makes no logon attempts, so it can't
    cause lockouts. It never collects passwords, password hashes, LSA secrets, the Winlogon
    DefaultPassword value (only whether it exists), command-line arguments of services, tasks or
    Run entries, connection strings, or anything from HKLM\SOFTWARE\BICA\SYSTEM\LOGINS.

    Side effects:
    - secedit writes a temporary export file, which is deleted again, and a line in its own log.
    - Small helper classes are compiled in %TEMP%: the PowerShell 2.0 probe and the netapi32 group reader.
    - IIS and COM+ objects are opened for reading only; nothing is committed.
    - The write-filter tools (ewfmgr, fbwfmgr, uwfmgr) are only called with their display commands.

    Copy the script to C:\temp and run it from there, once per machine, from an elevated Windows
    PowerShell ("Run as administrator").

.PARAMETER OutputDirectory
    Folder for the JSON report. Defaults to the script's folder (C:\temp). Falls back to the Desktop
    if that folder is not writable.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\temp\Get-CRInventory.ps1
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$scriptVersion = '1.3'
$scriptPath    = $MyInvocation.MyCommand.Path
$computerName  = $env:COMPUTERNAME
$startedAt     = Get-Date
$report        = @{}
$sectionErrors = New-Object System.Collections.ArrayList

$principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Please run this script from an elevated PowerShell (Run as administrator).'
    exit 2
}

# Account names and patterns from docs/PLAN.md section 1.1
$managedNames = @{
    'BiCA Admin'      = 'Rotate: BiCA Admin'
    'BiCA Remote'     = 'Rotate: BiCA Remote'
    'ApplicationUser' = 'Rotate: application user (ApplicationUser)'
    'PUB-User'        = 'Rotate: auto-logon user (PUB-User)'
    'WinAutoUser'     = 'Rotate: auto-logon user (WinAutoUser)'
    'WinUser1'        = 'Check: WinUser'
    'WinUser2'        = 'Check: WinUser'
    'WinUser3'        = 'Check: WinUser'
}
$ftpPattern     = '(?i)^ftp|ftp$'
$sqlLoginNames  = @('SQLApplication', 'SQLScript', 'SQLService')
$customGroups   = @('CardCenters', 'Offer Remote Assistance Helpers')
$wantedRights   = @(
    'SeInteractiveLogonRight', 'SeRemoteInteractiveLogonRight', 'SeNetworkLogonRight',
    'SeBatchLogonRight', 'SeServiceLogonRight',
    'SeDenyInteractiveLogonRight', 'SeDenyRemoteInteractiveLogonRight', 'SeDenyNetworkLogonRight',
    'SeDenyBatchLogonRight', 'SeDenyServiceLogonRight'
)
$interestingServicePattern = '(?i)sql|ftp|w3svc|^was$|iisadmin|bica|msdtc|comsysapp'
$smComputerPattern = '^SM'          # D18: SM machines

# Group members by SID via netapi32 (plan D5). C# 2.0 only, so it also compiles under PowerShell 2.0.
# No single quotes allowed in this source: it is also embedded in the PowerShell 2.0 probe.
$netApiSource = @'
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

public static class CrNetApi
{
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetLocalGroupGetMembers(string serverName, string localGroupName, int level,
        out IntPtr bufPtr, int prefMaxLen, out int entriesRead, out int totalEntries, IntPtr resumeHandle);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buffer);

    public static string[] GetMemberSids(string groupName)
    {
        IntPtr buf;
        int read;
        int total;
        int rc = NetLocalGroupGetMembers(null, groupName, 0, out buf, -1, out read, out total, IntPtr.Zero);
        if (rc != 0) { throw new InvalidOperationException("NetLocalGroupGetMembers returned " + rc); }
        try
        {
            string[] sids = new string[read];
            for (int i = 0; i < read; i++)
            {
                IntPtr pSid = Marshal.ReadIntPtr(buf, i * IntPtr.Size);
                sids[i] = new SecurityIdentifier(pSid).Value;
            }
            return sids;
        }
        finally
        {
            NetApiBufferFree(buf);
        }
    }
}
'@

$netApiReady = $false
$netApiError = $null
try {
    if (-not ('CrNetApi' -as [type])) { Add-Type -TypeDefinition $netApiSource }
    $netApiReady = $true
} catch {
    $netApiError = $_.Exception.Message
}

#region Helpers

# InvokeMember wraps COM errors; the inner exception has the useful message.
function Get-ErrorText {
    param($ErrorRecord)
    $ex = $ErrorRecord.Exception
    while ($ex.InnerException) { $ex = $ex.InnerException }
    return $ex.Message
}

function Get-LocalGroupName {
    param([string]$Sid)
    $n = Resolve-SidToName $Sid
    if (-not $n) { return $null }
    return $n.Substring($n.IndexOf('\') + 1)
}

function Invoke-Section {
    param([string]$Name, [scriptblock]$Body)
    Write-Host ('Collecting {0} ...' -f $Name)
    try {
        $report[$Name] = & $Body
    } catch {
        [void]$sectionErrors.Add(@{ Section = $Name; Error = $_.Exception.Message })
        $report[$Name] = $null
    }
}

function Get-AdsiProp {
    param($Entry, [string]$Name)
    try { return $Entry.psbase.InvokeGet($Name) } catch { return $null }
}

function ConvertTo-SidString {
    param($Bytes)
    if ($null -eq $Bytes) { return $null }
    try { return (New-Object System.Security.Principal.SecurityIdentifier([byte[]]$Bytes, 0)).Value } catch { return $null }
}

function Resolve-SidToName {
    param([string]$Sid)
    if (-not $Sid) { return $null }
    try {
        return (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value
    } catch { return $null }
}

function Resolve-NameToSid {
    param([string]$Name)
    if (-not $Name) { return $null }
    $n = $Name.Trim()
    if (-not $n) { return $null }
    if ($n -match '^S-1-') { return $n }
    if ($n -ieq 'LocalSystem') { return 'S-1-5-18' }
    if ($n.StartsWith('.\')) { $n = $computerName + $n.Substring(1) }
    try {
        return (New-Object System.Security.Principal.NTAccount($n)).Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch { return $null }
}

function Test-BuiltinSid {
    param([string]$Sid)
    if (-not $Sid) { return $false }
    return (@('S-1-5-18', 'S-1-5-19', 'S-1-5-20') -contains $Sid) -or $Sid.StartsWith('S-1-5-80-') -or $Sid.StartsWith('S-1-5-82-')
}

# Executable path only; arguments are dropped because they may contain secrets.
function Get-ExecutablePath {
    param([string]$CommandLine)
    if (-not $CommandLine) { return $null }
    $c = $CommandLine.Trim()
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        if ($end -gt 0) { return $c.Substring(1, $end - 1) }
    }
    $m = [regex]::Match($c, '^(.+?\.(exe|com|bat|cmd|ps1|vbs|js))(\s|$)', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    return ($c -split '\s+')[0]
}

function Get-RegValues {
    param([string]$Path)
    try { return Get-ItemProperty -LiteralPath $Path } catch { return $null }
}

function Get-AccountClassification {
    param([string]$Name, [string]$Sid)
    $labels = New-Object System.Collections.ArrayList
    if ($Sid -and $Sid -match '-500$') { [void]$labels.Add('Built-in Administrator (RID 500)') }
    foreach ($k in $managedNames.Keys) {
        if ($Name -ieq $k) { [void]$labels.Add($managedNames[$k]) }
    }
    if ($Name -match $ftpPattern) { [void]$labels.Add('Check: FTP user (name pattern)') }
    if ($labels.Count -eq 0) { return 'Other' }
    return ($labels -join '; ')
}

function Invoke-SqlQuery {
    param($Connection, [string]$Query)
    $cmd = $Connection.CreateCommand()
    $cmd.CommandText = $Query
    $cmd.CommandTimeout = 30
    $rows = New-Object System.Collections.ArrayList
    $reader = $cmd.ExecuteReader()
    try {
        while ($reader.Read()) {
            $row = @{}
            for ($i = 0; $i -lt $reader.FieldCount; $i++) {
                $v = $reader.GetValue($i)
                if ($v -is [System.DBNull]) { $v = $null }
                elseif ($v -is [byte[]]) { $v = '0x' + ([System.BitConverter]::ToString($v) -replace '-', '') }
                elseif ($v -is [datetime]) { $v = $v.ToString('s') }
                $row[$reader.GetName($i)] = $v
            }
            [void]$rows.Add($row)
        }
    } finally {
        $reader.Close()
    }
    return , $rows.ToArray()
}

function Get-CatalogValue {
    param($CatalogObject, [string]$Name)
    try { return $CatalogObject.Value($Name) } catch { return $null }
}

# Minimal JSON writer (ConvertTo-Json doesn't exist in PowerShell 2.0)
function ConvertTo-CrJsonString {
    param([string]$Text)
    $e = $Text.Replace('\', '\\').Replace('"', '\"').Replace("`r", '\r').Replace("`n", '\n').Replace("`t", '\t')
    if ($e -match '[\x00-\x1F]') {
        $sb = New-Object System.Text.StringBuilder
        foreach ($ch in $e.ToCharArray()) {
            if ([int]$ch -lt 32) { [void]$sb.AppendFormat('\u{0:x4}', [int]$ch) } else { [void]$sb.Append($ch) }
        }
        $e = $sb.ToString()
    }
    return '"' + $e + '"'
}

function ConvertTo-CrJson {
    param($Value, [int]$Indent = 0)
    if ($Indent -gt 20) { return '"<max depth>"' }
    $pad    = ' ' * (($Indent + 1) * 2)
    $padEnd = ' ' * ($Indent * 2)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [string] -or $Value -is [char] -or $Value -is [guid]) { return ConvertTo-CrJsonString ([string]$Value) }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [datetime]) { return ConvertTo-CrJsonString ($Value.ToString('s')) }
    if ($Value -is [enum]) { return ConvertTo-CrJsonString ($Value.ToString()) }
    if ($Value -is [byte] -or $Value -is [sbyte] -or $Value -is [int16] -or $Value -is [uint16] -or
        $Value -is [int] -or $Value -is [uint32] -or $Value -is [long] -or $Value -is [uint64] -or
        $Value -is [single] -or $Value -is [double] -or $Value -is [decimal]) {
        return ([System.IFormattable]$Value).ToString($null, [System.Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $items = @(foreach ($k in $Value.Keys) {
            $pad + (ConvertTo-CrJsonString ([string]$k)) + ': ' + (ConvertTo-CrJson $Value[$k] ($Indent + 1))
        })
        if ($items.Count -eq 0) { return '{}' }
        return "{`r`n" + ($items -join ",`r`n") + "`r`n$padEnd}"
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $items = @(foreach ($v in $Value) { $pad + (ConvertTo-CrJson $v ($Indent + 1)) })
        if ($items.Count -eq 0) { return '[]' }
        return "[`r`n" + ($items -join ",`r`n") + "`r`n$padEnd]"
    }
    return ConvertTo-CrJsonString ([string]$Value)
}

#endregion

#region Sections

Invoke-Section 'System' {
    $os  = Get-WmiObject -Class Win32_OperatingSystem
    $cs  = Get-WmiObject -Class Win32_ComputerSystem
    $ndp = 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP'
    $net35 = Get-RegValues "$ndp\v3.5"
    $net4  = Get-RegValues "$ndp\v4\Full"
    @{
        ComputerName      = $computerName
        IsSmMachine       = [bool]($computerName -match $smComputerPattern)
        OsCaption         = $os.Caption
        OsVersion         = $os.Version
        OsBuild           = $os.BuildNumber
        ServicePack       = $os.CSDVersion
        OsArchitecture    = $os.OSArchitecture
        OsLanguageLcid    = $os.OSLanguage
        MuiLanguages      = @($os.MUILanguages)
        UiCulture         = (Get-UICulture).Name
        Culture           = (Get-Culture).Name
        PartOfDomain      = $cs.PartOfDomain
        Workgroup         = $cs.Workgroup
        PSVersion         = $PSVersionTable.PSVersion.ToString()
        ClrVersion        = $PSVersionTable.CLRVersion.ToString()
        LanguageMode      = [string]$ExecutionContext.SessionState.LanguageMode
        DotNet35Installed = [bool]($net35 -and $net35.Install -eq 1)
        DotNet4Release    = $(if ($net4) { $net4.Release } else { $null })
        ExecutionPolicy   = @(Get-ExecutionPolicy -List | ForEach-Object {
                                @{ Scope = $_.Scope.ToString(); Policy = $_.ExecutionPolicy.ToString() } })
    }
}

Invoke-Section 'Session' {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $groupSids = @($id.Groups | ForEach-Object { $_.Value })
    # SESSIONNAME keeps its logon-time value after a reconnect; the token's logon SIDs don't.
    $logonKind = 'Other'
    if ($groupSids -contains 'S-1-5-14')    { $logonKind = 'RemoteInteractive (RDP)' }
    elseif ($groupSids -contains 'S-1-2-1') { $logonKind = 'Console' }
    elseif ($groupSids -contains 'S-1-5-4') { $logonKind = 'Interactive' }
    $driveType = $null
    if ($scriptPath -and $scriptPath -match '^[A-Za-z]:') {
        try { $driveType = (New-Object System.IO.DriveInfo($scriptPath.Substring(0, 1))).DriveType.ToString() } catch { }
    }
    @{
        User               = $id.Name
        UserSid            = $id.User.Value
        TokenGroupSids     = $groupSids
        LogonKind          = $logonKind
        SessionName        = $env:SESSIONNAME
        ScriptPath         = $scriptPath
        ScriptDriveType    = $driveType
        StartedFromUncPath = [bool]($scriptPath -like '\\*')
        ProcessIs64Bit     = ([IntPtr]::Size -eq 8)
        ProgramW6432       = $env:ProgramW6432
        NetApiHelper       = $(if ($netApiReady) { 'OK' } else { $netApiError })
    }
}

Invoke-Section 'PowerShell2Engine' {
    $ErrorActionPreference = 'Continue'
    $probe = @'
$r = @{}
$r.PSVersion = $PSVersionTable.PSVersion.ToString()
$r.Clr = $PSVersionTable.CLRVersion.ToString()
try { Add-Type -TypeDefinition 'public static class CrPs2Probe { public static int One() { return 1; } }'; $r.AddTypeCSharp = 'OK' } catch { $r.AddTypeCSharp = $_.Exception.Message }
try { Add-Type -AssemblyName System.Core; $null = New-Object System.Security.Cryptography.SHA256CryptoServiceProvider; $r.Sha256Csp = 'OK' } catch { $r.Sha256Csp = $_.Exception.Message }
try { $null = New-Object -ComObject Schedule.Service; $r.TaskSchedulerCom = 'OK' } catch { $r.TaskSchedulerCom = $_.Exception.Message }
try { $null = New-Object -ComObject COMAdmin.COMAdminCatalog; $r.ComAdminCom = 'OK' } catch { $r.ComAdminCom = $_.Exception.Message }
$mwa = Join-Path $env:windir 'System32\inetsrv\Microsoft.Web.Administration.dll'
if (Test-Path $mwa) { try { [void][Reflection.Assembly]::LoadFrom($mwa); $r.IisMwa = 'OK' } catch { $r.IisMwa = $_.Exception.Message } } else { $r.IisMwa = 'not installed' }
try { $null = [System.Data.SqlClient.SqlConnection]; $r.SqlClient = 'OK' } catch { $r.SqlClient = $_.Exception.Message }
# Group members of Administrators: ADSI (fails on Windows Embedded Standard 7 under PS 5.1) vs netapi32
$adm = $null
try { $adm = (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[1] } catch { }
try {
    $grp = [ADSI]('WinNT://' + $env:COMPUTERNAME + '/' + $adm + ',group')
    $n = 0; $ok = 0; $err = $null
    foreach ($m in @($grp.psbase.Invoke('Members'))) {
        $n++
        try { $null = $m.GetType().InvokeMember('objectSid', 'GetProperty', $null, $m, $null); $ok++ }
        catch { if (-not $err) { $e = $_.Exception; while ($e.InnerException) { $e = $e.InnerException }; $err = $e.Message } }
    }
    $r.GroupMembersAdsi = ('{0} of {1} read' -f $ok, $n) + $(if ($err) { '; ' + $err } else { '' })
} catch { $r.GroupMembersAdsi = $_.Exception.Message }
$netApiSource = '__NETAPI_SOURCE__'
try {
    Add-Type -TypeDefinition $netApiSource
    $sids = [CrNetApi]::GetMemberSids($adm)
    $named = @($sids | Where-Object { try { $null = (New-Object System.Security.Principal.SecurityIdentifier($_)).Translate([System.Security.Principal.NTAccount]); $true } catch { $false } })
    $r.GroupMembersNetApi = '{0} members, {1} with a name' -f $sids.Length, $named.Length
} catch { $r.GroupMembersNetApi = $_.Exception.Message }
# One short line per result, so console line wrapping can't cut results off
$r.GetEnumerator() | ForEach-Object {
    $v = [string]$_.Value -replace '[\r\n]', ' '
    if ($v.Length -gt 90) { $v = $v.Substring(0, 90) }
    'CRPS2:{0}={1}' -f $_.Key, $v
}
'@
    $probe = $probe.Replace('__NETAPI_SOURCE__', $netApiSource.Replace("'", "''"))
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($probe))
    $exe = Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $out = @(& $exe -Version 2 -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $encoded 2>&1 |
             ForEach-Object { [string]$_ })
    $parsed = @{}
    foreach ($line in @($out | Where-Object { $_ -like 'CRPS2:*' })) {
        $kv = @($line.Substring(6) -split '=', 2)
        if ($kv.Count -eq 2) { $parsed[$kv[0]] = $kv[1] }
    }
    @{
        Available = ($parsed.Count -gt 0)
        Results   = $parsed
        RawOutput = $(if ($parsed.Count -gt 0) { $null } else { $out })
    }
}

Invoke-Section 'PasswordAndLockoutPolicy' {
    $ErrorActionPreference = 'Continue'
    $tmp = Join-Path $env:TEMP ('cr-secedit-{0}.inf' -f [guid]::NewGuid())
    $systemAccess = @{}
    $rights = @{}
    try {
        $null = & secedit.exe /export /cfg $tmp /areas SECURITYPOLICY USER_RIGHTS /quiet 2>&1
        $section = ''
        foreach ($line in @(Get-Content -LiteralPath $tmp)) {
            if ($line -match '^\s*\[(.+)\]\s*$') { $section = $Matches[1]; continue }
            if ($line -notmatch '^\s*([^=]+?)\s*=\s*(.*)$') { continue }
            $key = $Matches[1]
            $value = $Matches[2]
            if ($section -eq 'System Access') {
                $systemAccess[$key] = $value
            } elseif ($section -eq 'Privilege Rights' -and $wantedRights -contains $key) {
                $rights[$key] = @($value -split ',' | Where-Object { $_.Trim() } | ForEach-Object {
                    $item = $_.Trim()
                    if ($item.StartsWith('*')) {
                        $s = $item.Substring(1)
                        @{ Sid = $s; Name = (Resolve-SidToName $s) }
                    } else {
                        @{ Sid = (Resolve-NameToSid $item); Name = $item }
                    }
                })
            }
        }
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }

    @{
        SeceditSystemAccess = $systemAccess
        UserRights          = $rights
        NetAccountsRaw      = @(& net.exe accounts 2>&1 | ForEach-Object { [string]$_ } | Where-Object { $_.Trim() })
    }
}

Invoke-Section 'LocalUsers' {
    $profiles = @{}
    foreach ($p in @(Get-WmiObject -Class Win32_UserProfile)) { $profiles[$p.SID] = $p.LocalPath }

    $computer = [ADSI]("WinNT://{0},computer" -f $computerName)
    $users = New-Object System.Collections.ArrayList
    foreach ($child in $computer.psbase.Children) {
        if ($child.psbase.SchemaClassName -ne 'User') { continue }

        $name  = [string](Get-AdsiProp $child 'Name')
        $sid   = ConvertTo-SidString (Get-AdsiProp $child 'objectSid')
        $flags = [int](Get-AdsiProp $child 'UserFlags')
        $pwAge = Get-AdsiProp $child 'PasswordAge'
        $last  = Get-AdsiProp $child 'LastLogin'

        $groupsViaMethod = @()
        try {
            $groupsViaMethod = @($child.psbase.Invoke('Groups') | ForEach-Object {
                $_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null) })
        } catch {
            $groupsViaMethod = @('ERROR: ' + $_.Exception.Message)
        }

        # DPAPI indicators: file counts only, never names or contents
        $profilePath = $null
        if ($sid) { $profilePath = $profiles[$sid] }
        $dpapi = $null
        if ($profilePath -and (Test-Path -LiteralPath $profilePath)) {
            $dpapi = @{}
            foreach ($rel in 'AppData\Roaming\Microsoft\Credentials', 'AppData\Local\Microsoft\Credentials',
                             'AppData\Roaming\Microsoft\Vault', 'AppData\Local\Microsoft\Vault',
                             'AppData\Roaming\Microsoft\Protect') {
                $full = Join-Path $profilePath $rel
                $count = 0
                if (Test-Path -LiteralPath $full) {
                    try {
                        $count = @(Get-ChildItem -LiteralPath $full -Force -Recurse -ErrorAction SilentlyContinue |
                                   Where-Object { -not $_.PSIsContainer }).Count
                    } catch { $count = -1 }
                }
                $dpapi[$rel] = $count
            }
        }

        [void]$users.Add(@{
            Name                       = $name
            Sid                        = $sid
            Classification             = Get-AccountClassification -Name $name -Sid $sid
            FullName                   = [string](Get-AdsiProp $child 'FullName')
            Description                = [string](Get-AdsiProp $child 'Description')
            Disabled                   = [bool]($flags -band 0x2)
            LockoutFlag                = [bool]($flags -band 0x10)
            IsAccountLocked            = Get-AdsiProp $child 'IsAccountLocked'
            PasswordNeverExpires       = [bool]($flags -band 0x10000)
            CannotChangePassword       = [bool]($flags -band 0x40)
            PasswordNotRequired        = [bool]($flags -band 0x20)
            UserFlags                  = ('0x{0:X}' -f $flags)
            PasswordAgeDays            = $(if ($null -ne $pwAge) { [math]::Round([double]$pwAge / 86400, 1) } else { $null })
            PasswordExpired            = Get-AdsiProp $child 'PasswordExpired'
            BadPasswordAttempts        = Get-AdsiProp $child 'BadPasswordAttempts'
            MaxBadPasswordsAllowed     = Get-AdsiProp $child 'MaxBadPasswordsAllowed'
            MinPasswordAgeSeconds      = Get-AdsiProp $child 'MinPasswordAge'
            AutoUnlockIntervalSeconds  = Get-AdsiProp $child 'AutoUnlockInterval'
            LockoutObservationSeconds  = Get-AdsiProp $child 'LockoutObservationInterval'
            LastLogin                  = $(if ($last) { ([datetime]$last).ToString('s') } else { $null })
            GroupsViaUserGroupsMethod  = $groupsViaMethod
            ProfilePath                = $profilePath
            DpapiIndicatorFileCounts   = $dpapi
        })
    }
    @{ Users = $users.ToArray() }
}

Invoke-Section 'LocalGroups' {
    $computer = [ADSI]("WinNT://{0},computer" -f $computerName)
    $groups = New-Object System.Collections.ArrayList
    foreach ($child in $computer.psbase.Children) {
        if ($child.psbase.SchemaClassName -ne 'Group') { continue }
        $groupName = [string](Get-AdsiProp $child 'Name')

        # Source 1: ADSI. Its member properties came back empty on Windows Embedded Standard 7.
        $members = New-Object System.Collections.ArrayList
        $adsiError = $null
        try {
            foreach ($m in @($child.psbase.Invoke('Members'))) {
                $path = $null
                $msid = $null
                try { $path = $m.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $m, $null) }
                catch { if (-not $adsiError) { $adsiError = 'ADsPath: ' + (Get-ErrorText $_) } }
                try { $msid = ConvertTo-SidString ($m.GetType().InvokeMember('objectSid', 'GetProperty', $null, $m, $null)) }
                catch { if (-not $adsiError) { $adsiError = 'objectSid: ' + (Get-ErrorText $_) } }
                [void]$members.Add(@{ AdsPath = $path; Sid = $msid; Name = (Resolve-SidToName $msid) })
            }
        } catch {
            $adsiError = 'Members: ' + (Get-ErrorText $_)
        }

        # Source 2: netapi32 by SID, as the tool will do it (plan D5)
        $netMembers = @()
        $netError = $null
        if ($netApiReady) {
            try {
                $netMembers = @(foreach ($s in [CrNetApi]::GetMemberSids($groupName)) { @{ Sid = $s; Name = (Resolve-SidToName $s) } })
            } catch {
                $netError = Get-ErrorText $_
            }
        } else {
            $netError = 'netapi32 helper not available: ' + $netApiError
        }

        [void]$groups.Add(@{
            Name           = $groupName
            Sid            = ConvertTo-SidString (Get-AdsiProp $child 'objectSid')
            Description    = [string](Get-AdsiProp $child 'Description')
            Members        = $members.ToArray()
            AdsiError      = $adsiError
            MembersNetApi  = $netMembers
            NetApiError    = $netError
        })
    }
    @{ Groups = $groups.ToArray() }
}

Invoke-Section 'Services' {
    $list = New-Object System.Collections.ArrayList
    foreach ($s in @(Get-WmiObject -Class Win32_Service)) {
        $startName = [string]$s.StartName
        $sid = Resolve-NameToSid $startName
        $isBuiltin = (-not $startName) -or (Test-BuiltinSid $sid) -or ($startName -match '^(NT AUTHORITY|NT SERVICE)\\')
        $interesting = (-not $isBuiltin) -or ($s.Name -match $interestingServicePattern) -or
                       ($s.DisplayName -match $interestingServicePattern) -or ($s.PathName -match '(?i)dllhost\.exe')
        if (-not $interesting) { continue }

        $svc = Get-Service -Name $s.Name -ErrorAction SilentlyContinue
        $comPlusId = $null
        $m = [regex]::Match([string]$s.PathName, '(?i)/processid:(\{[0-9a-f\-]+\})')
        if ($m.Success) { $comPlusId = $m.Groups[1].Value }

        [void]$list.Add(@{
            Name                 = $s.Name
            DisplayName          = $s.DisplayName
            StartName            = $startName
            StartNameSid         = $sid
            StartMode            = $s.StartMode
            State                = $s.State
            ExecutablePath       = Get-ExecutablePath $s.PathName
            ComPlusApplicationId = $comPlusId
            DependentServices    = @($(if ($svc) { $svc.DependentServices | ForEach-Object { $_.Name } }))
            DependsOn            = @($(if ($svc) { $svc.ServicesDependedOn | ForEach-Object { $_.Name } }))
        })
    }
    @{ Services = $list.ToArray() }
}

Invoke-Section 'ScheduledTasks' {
    $scheduler = New-Object -ComObject Schedule.Service
    $scheduler.Connect()
    $list = New-Object System.Collections.ArrayList
    $queue = New-Object System.Collections.Queue
    $queue.Enqueue($scheduler.GetFolder('\'))
    while ($queue.Count -gt 0) {
        $folder = $queue.Dequeue()
        foreach ($sub in @($folder.GetFolders(0))) { $queue.Enqueue($sub) }
        foreach ($task in @($folder.GetTasks(1))) {          # 1 = TASK_ENUM_HIDDEN
            try {
                $def = $task.Definition
                $taskPrincipal = $def.Principal
                $userId = [string]$taskPrincipal.UserId
                if (-not $userId) { continue }                # group-based principal
                $sid = Resolve-NameToSid $userId
                if (Test-BuiltinSid $sid) { continue }
                $actions = @(foreach ($a in @($def.Actions)) {
                    if ($a.Type -eq 0) { Get-ExecutablePath ([string]$a.Path) } else { 'ActionType ' + $a.Type }
                })
                [void]$list.Add(@{
                    Path              = $task.Path
                    Enabled           = $task.Enabled
                    State             = $task.State
                    UserId            = $userId
                    UserSid           = $sid
                    LogonType         = [int]$taskPrincipal.LogonType
                    RunLevel          = [int]$taskPrincipal.RunLevel
                    LastRunTime       = ([datetime]$task.LastRunTime).ToString('s')
                    LastTaskResult    = $task.LastTaskResult
                    ActionExecutables = $actions
                })
            } catch {
                [void]$list.Add(@{ Path = $task.Path; Error = $_.Exception.Message })
            }
        }
    }
    @{ Tasks = $list.ToArray() }
}

Invoke-Section 'AutoLogon' {
    $wl = Get-Item -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $names = @($wl.GetValueNames())
    $get = { param($n) if ($names -contains $n) { [string]$wl.GetValue($n) } else { '<absent>' } }
    $notSet = @('', '<absent>')

    # Current auto-logon account as SID, and whether it is an admin (plan D18)
    $defUser = & $get 'DefaultUserName'
    $defDomain = & $get 'DefaultDomainName'
    $defSid = $null
    if ($notSet -notcontains $defUser) {
        if ($notSet -notcontains $defDomain) { $defSid = Resolve-NameToSid ($defDomain + '\' + $defUser) }
        if (-not $defSid) { $defSid = Resolve-NameToSid ($computerName + '\' + $defUser) }
    }
    $defIsAdmin = $null
    if ($defSid -and $netApiReady) {
        try { $defIsAdmin = @([CrNetApi]::GetMemberSids((Get-LocalGroupName 'S-1-5-32-544'))) -contains $defSid } catch { }
    }

    # Only presence and emptiness of DefaultPassword; the value itself is never output.
    $dpPresent = $names -contains 'DefaultPassword'
    $dpEmpty = $null
    if ($dpPresent) { $dpEmpty = [string]::IsNullOrEmpty([string]$wl.GetValue('DefaultPassword')) }

    $pol = Get-RegValues 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $pwLess = Get-RegValues 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device'

    $sysinternals = New-Object System.Collections.ArrayList
    foreach ($hive in @(Get-ChildItem -LiteralPath 'Registry::HKEY_USERS')) {
        $key = Join-Path $hive.PSPath 'Software\Sysinternals\Autologon'
        if (Test-Path -LiteralPath $key) {
            $hiveSid = $hive.PSChildName -replace '_Classes$', ''
            [void]$sysinternals.Add(@{ HiveSid = $hiveSid; User = (Resolve-SidToName $hiveSid) })
        }
    }

    @{
        IsSmMachine                    = [bool]($computerName -match $smComputerPattern)
        AutoAdminLogon                 = & $get 'AutoAdminLogon'
        DefaultUserName                = $defUser
        DefaultDomainName              = $defDomain
        DefaultUserSid                 = $defSid
        DefaultUserIsAdmin             = $defIsAdmin
        AltDefaultUserName             = & $get 'AltDefaultUserName'
        DefaultPasswordValuePresent    = $dpPresent
        DefaultPasswordValueEmpty      = $dpEmpty
        AutoLogonCount                 = & $get 'AutoLogonCount'
        ForceAutoLogon                 = & $get 'ForceAutoLogon'
        AutoLogonSID                   = & $get 'AutoLogonSID'
        Shell                          = & $get 'Shell'
        Userinit                       = & $get 'Userinit'
        DisableCAD                     = & $get 'DisableCAD'
        LegalNoticeCaptionSet          = -not ($notSet -contains (& $get 'LegalNoticeCaption'))
        LegalNoticeTextSet             = -not ($notSet -contains (& $get 'LegalNoticeText'))
        PolicyLegalNoticeCaptionSet    = [bool]($pol -and $pol.legalnoticecaption)
        PolicyLegalNoticeTextSet       = [bool]($pol -and $pol.legalnoticetext)
        PolicyDontDisplayLastUserName  = $(if ($pol) { $pol.dontdisplaylastusername } else { $null })
        DevicePasswordLessBuildVersion = $(if ($pwLess) { $pwLess.DevicePasswordLessBuildVersion } else { $null })
        SysinternalsAutologonUsedBy    = $sysinternals.ToArray()
        LsaSecretDefaultPassword       = 'not checked (would require reading the secret)'
    }
}

Invoke-Section 'StartupAndSoftware' {
    $run = New-Object System.Collections.ArrayList
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                   'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                   'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
                   'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce') {
        if (-not (Test-Path -LiteralPath $k)) { continue }
        $item = Get-Item -LiteralPath $k
        foreach ($n in $item.GetValueNames()) {
            [void]$run.Add(@{ Key = $k; Name = $n; Executable = (Get-ExecutablePath ([string]$item.GetValue($n))) })
        }
    }

    # 'CommonStartup' is not a known folder name in .NET 2.0 (PowerShell 2.0)
    $startupFolder = $null
    try { $startupFolder = [Environment]::GetFolderPath('CommonStartup') } catch { }
    if (-not $startupFolder -and $env:ProgramData) {
        $startupFolder = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup'
    }
    $startupItems = @()
    if ($startupFolder -and (Test-Path -LiteralPath $startupFolder)) {
        $startupItems = @(Get-ChildItem -LiteralPath $startupFolder -Force | ForEach-Object { $_.Name })
    }

    $software = New-Object System.Collections.ArrayList
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                   'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall') {
        if (-not (Test-Path -LiteralPath $k)) { continue }
        foreach ($e in @(Get-ChildItem -LiteralPath $k)) {
            $dn = $e.GetValue('DisplayName')
            if (-not $dn) { continue }
            if ($e.GetValue('SystemComponent') -eq 1) { continue }
            [void]$software.Add(@{
                Name      = [string]$dn
                Version   = [string]$e.GetValue('DisplayVersion')
                Publisher = [string]$e.GetValue('Publisher')
            })
        }
    }

    @{
        RunEntries         = $run.ToArray()
        CommonStartupItems = $startupItems
        InstalledSoftware  = @($software.ToArray() | Sort-Object { $_['Name'] })
    }
}

Invoke-Section 'IIS' {
    $w3  = Get-Service -Name W3SVC  -ErrorAction SilentlyContinue
    $was = Get-Service -Name WAS    -ErrorAction SilentlyContinue
    $ftp = Get-Service -Name FTPSVC -ErrorAction SilentlyContinue
    $result = @{
        Installed = [bool]$w3
        W3SVC     = $(if ($w3)  { $w3.Status.ToString() }  else { $null })
        WAS       = $(if ($was) { $was.Status.ToString() } else { $null })
        FTPSVC    = $(if ($ftp) { $ftp.Status.ToString() } else { $null })
    }
    if (-not $w3) { return $result }

    $inetStp = Get-RegValues 'HKLM:\SOFTWARE\Microsoft\InetStp'
    if ($inetStp) { $result['Version'] = '{0}.{1}' -f $inetStp.MajorVersion, $inetStp.MinorVersion }

    try {
        Add-Type -Path (Join-Path $env:windir 'System32\inetsrv\Microsoft.Web.Administration.dll')
        $sm = New-Object Microsoft.Web.Administration.ServerManager
        $result['MwaLoaded'] = $true

        $pools = @(foreach ($p in $sm.ApplicationPools) {
            $state = $null
            try { $state = $p.State.ToString() } catch { $state = 'n/a' }
            $startMode = $null
            try { $startMode = [string]$p.GetAttributeValue('startMode') } catch { }
            @{
                Name                  = $p.Name
                State                 = $state
                IdentityType          = $p.ProcessModel.IdentityType.ToString()
                UserName              = $p.ProcessModel.UserName
                UserSid               = Resolve-NameToSid $p.ProcessModel.UserName
                StartMode             = $startMode
                AutoStart             = $p.AutoStart
                ManagedRuntimeVersion = $p.ManagedRuntimeVersion
                Enable32BitAppOnWin64 = $p.Enable32BitAppOnWin64
            }
        })

        $sites = @(foreach ($s in $sm.Sites) {
            $vdirs = @(foreach ($app in $s.Applications) {
                foreach ($vd in $app.VirtualDirectories) {
                    @{
                        Application       = $app.Path
                        ApplicationPool   = $app.ApplicationPoolName
                        VirtualDirectory  = $vd.Path
                        PhysicalPath      = $vd.PhysicalPath
                        ConnectAsUserName = $vd.UserName
                        ConnectAsUserSid  = Resolve-NameToSid $vd.UserName
                        LogonMethod       = $vd.LogonMethod.ToString()
                    }
                }
            })
            @{
                Name               = $s.Name
                Id                 = $s.Id
                Bindings           = @($s.Bindings | ForEach-Object { '{0}:{1}' -f $_.Protocol, $_.BindingInformation })
                VirtualDirectories = $vdirs
            }
        })
        $result['AppPools'] = $pools
        $result['Sites'] = $sites
    } catch {
        $result['MwaLoaded'] = $false
        $result['MwaError'] = $_.Exception.Message
    }

    try {
        $null = New-Object -ComObject Microsoft.ApplicationHost.WritableAdminManager
        $result['WritableAdminManagerCom'] = 'OK'
    } catch {
        $result['WritableAdminManagerCom'] = $_.Exception.Message
    }
    $result
}

Invoke-Section 'ComPlus' {
    $catalog = New-Object -ComObject COMAdmin.COMAdminCatalog
    $running = @{}
    try {
        $instances = $catalog.GetCollection('ApplicationInstances')
        $instances.Populate()
        foreach ($i in $instances) { $running[[string](Get-CatalogValue $i 'Application')] = $true }
    } catch { }

    $apps = $catalog.GetCollection('Applications')
    $apps.Populate()
    $list = New-Object System.Collections.ArrayList
    foreach ($a in $apps) {
        $activation = Get-CatalogValue $a 'Activation'
        $identity = [string](Get-CatalogValue $a 'Identity')
        [void]$list.Add(@{
            Name        = [string]$a.Name
            Id          = [string]$a.Key
            Activation  = $(switch ($activation) { 0 { 'Library' } 1 { 'Server' } default { [string]$activation } })
            Identity    = $identity
            IdentitySid = Resolve-NameToSid $identity
            IsSystem    = Get-CatalogValue $a 'IsSystem'
            IsEnabled   = Get-CatalogValue $a 'IsEnabled'
            Running     = [bool]$running[[string]$a.Key]
        })
    }
    @{ Applications = $list.ToArray() }
}

Invoke-Section 'DcomRunAs' {
    $list = New-Object System.Collections.ArrayList
    foreach ($root in 'HKLM:\SOFTWARE\Classes\AppID', 'HKLM:\SOFTWARE\Wow6432Node\Classes\AppID') {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($k in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
            $runAs = [string]$k.GetValue('RunAs')
            if (-not $runAs -or $runAs -ieq 'Interactive User') { continue }
            $sid = Resolve-NameToSid $runAs
            if (Test-BuiltinSid $sid) { continue }
            [void]$list.Add(@{
                View     = $root
                AppId    = $k.PSChildName
                Name     = [string]$k.GetValue('')
                RunAs    = $runAs
                RunAsSid = $sid
            })
        }
    }
    @{ Entries = $list.ToArray() }
}

Invoke-Section 'SqlServer' {
    $instances = New-Object System.Collections.ArrayList
    foreach ($base in 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server',
                      'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Microsoft SQL Server') {
        $namesKey = Join-Path $base 'Instance Names\SQL'
        if (-not (Test-Path -LiteralPath $namesKey)) { continue }
        $nk = Get-Item -LiteralPath $namesKey
        foreach ($instName in $nk.GetValueNames()) {
            $instId  = [string]$nk.GetValue($instName)
            $setup   = Get-RegValues (Join-Path $base "$instId\Setup")
            $server  = Get-RegValues (Join-Path $base "$instId\MSSQLServer")
            $svcName = $(if ($instName -eq 'MSSQLSERVER') { 'MSSQLSERVER' } else { 'MSSQL$' + $instName })
            $svc     = Get-WmiObject -Class Win32_Service -Filter ("Name='" + $svcName + "'")
            [void]$instances.Add(@{
                RegistryView   = $base
                Name           = $instName
                InstanceId     = $instId
                Version        = $(if ($setup) { $setup.Version } else { $null })
                PatchLevel     = $(if ($setup) { $setup.PatchLevel } else { $null })
                Edition        = $(if ($setup) { $setup.Edition } else { $null })
                LoginMode      = $(if ($server) { $server.LoginMode } else { $null })
                ServiceName    = $svcName
                ServiceState   = $(if ($svc) { $svc.State } else { $null })
                ServiceAccount = $(if ($svc) { $svc.StartName } else { $null })
            })
        }
    }
    $result = @{ Instances = $instances.ToArray(); DefaultInstance = $null }
    if (-not ($instances | Where-Object { $_['Name'] -eq 'MSSQLSERVER' })) { return $result }

    # Queries are plain SELECTs; LOGINPROPERTY needs SQL 2005 SP2+, hence the LoginsBasic fallback.
    $db = @{}
    $queries = @{
        Server            = "SELECT CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(128)) AS ProductVersion, CAST(SERVERPROPERTY('ProductLevel') AS nvarchar(128)) AS ProductLevel, CAST(SERVERPROPERTY('Edition') AS nvarchar(128)) AS Edition, CAST(SERVERPROPERTY('IsIntegratedSecurityOnly') AS int) AS IsIntegratedSecurityOnly, SUSER_SNAME() AS ConnectedAs, IS_SRVROLEMEMBER('sysadmin') AS ConnectedAsSysadmin"
        Logins            = "SELECT p.name, p.type_desc, p.is_disabled, p.sid, p.default_database_name, l.is_policy_checked, l.is_expiration_checked, CAST(LOGINPROPERTY(p.name, 'IsLocked') AS int) AS IsLocked, CAST(LOGINPROPERTY(p.name, 'BadPasswordCount') AS int) AS BadPasswordCount, CAST(LOGINPROPERTY(p.name, 'PasswordLastSetTime') AS datetime) AS PasswordLastSetTime, IS_SRVROLEMEMBER('sysadmin', p.name) AS IsSysadmin FROM sys.server_principals p LEFT JOIN sys.sql_logins l ON l.principal_id = p.principal_id WHERE p.type IN ('S','U','G') AND p.name NOT LIKE '##%' ORDER BY p.name"
        LoginsBasic       = "SELECT p.name, p.type_desc, p.is_disabled, p.sid FROM sys.server_principals p WHERE p.type IN ('S','U','G') AND p.name NOT LIKE '##%' ORDER BY p.name"
        ServerRoleMembers = "SELECT r.name AS role_name, m.name AS member_name, m.type_desc AS member_type FROM sys.server_role_members rm JOIN sys.server_principals r ON r.principal_id = rm.role_principal_id JOIN sys.server_principals m ON m.principal_id = rm.member_principal_id ORDER BY r.name, m.name"
        Credentials       = "SELECT name, credential_identity FROM sys.credentials"
        AgentProxies      = "SELECT p.name AS proxy_name, c.name AS credential_name, c.credential_identity, p.enabled FROM msdb.dbo.sysproxies p JOIN sys.credentials c ON c.credential_id = p.credential_id"
        AgentJobs         = "SELECT j.name AS job_name, SUSER_SNAME(j.owner_sid) AS owner_name, j.enabled FROM msdb.dbo.sysjobs j ORDER BY j.name"
        LinkedServers     = "SELECT s.name AS server_name, s.product, s.provider, s.data_source, lp.name AS local_login, ll.uses_self_credential, ll.remote_name FROM sys.servers s LEFT JOIN sys.linked_logins ll ON ll.server_id = s.server_id LEFT JOIN sys.server_principals lp ON lp.principal_id = ll.local_principal_id WHERE s.is_linked = 1"
    }
    $cn = New-Object System.Data.SqlClient.SqlConnection
    $cn.ConnectionString = 'Data Source=.;Initial Catalog=master;Integrated Security=SSPI;Pooling=false;Connect Timeout=15;Application Name=CR-Inventory (read-only)'
    try {
        $cn.Open()
        foreach ($q in @($queries.Keys)) {
            try { $db[$q] = Invoke-SqlQuery -Connection $cn -Query $queries[$q] }
            catch { $db[$q] = 'ERROR: ' + $_.Exception.Message }
        }
    } catch {
        $db['ConnectionError'] = $_.Exception.Message
    } finally {
        $cn.Dispose()
    }
    $result['DefaultInstance'] = $db
    $result
}

# Plan D19: EWF/FBWF (Windows Embedded Standard 7), UWF (Windows 10). Display commands only.
Invoke-Section 'WriteFilter' {
    $ErrorActionPreference = 'Continue'
    $sysDir = Join-Path $env:windir 'System32'
    if ([IntPtr]::Size -eq 4 -and (Test-Path -LiteralPath (Join-Path $env:windir 'sysnative'))) {
        $sysDir = Join-Path $env:windir 'sysnative'
    }
    $filterServices = @{}
    foreach ($svc in 'ewf', 'fbwf', 'uwfvol', 'uwfs') {
        $v = Get-RegValues ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $svc)
        $filterServices[$svc] = $(if ($v) { @{ Start = $v.Start } } else { 'not installed' })
    }
    $runTool = {
        param([string]$Exe, [string[]]$Arguments)
        $path = Join-Path $sysDir $Exe
        if (-not (Test-Path -LiteralPath $path)) { return 'not present' }
        return @(& $path $Arguments 2>&1 | ForEach-Object { [string]$_ } | Where-Object { $_.Trim() })
    }
    $uwfWmi = $null
    try {
        $uwfWmi = @(foreach ($f in @(Get-WmiObject -Namespace 'root\standardcimv2\embedded' -Class UWF_Filter -ErrorAction Stop)) {
            @{ CurrentEnabled = $f.CurrentEnabled; NextEnabled = $f.NextEnabled }
        })
    } catch {
        $uwfWmi = 'not available: ' + $_.Exception.Message
    }
    @{
        SystemDrive    = $env:SystemDrive
        FilterServices = $filterServices
        EwfMgr         = & $runTool 'ewfmgr.exe' @($env:SystemDrive)
        FbwfMgr        = & $runTool 'fbwfmgr.exe' @('/displayconfig')
        UwfMgr         = & $runTool 'uwfmgr.exe' @('get-config')
        UwfWmi         = $uwfWmi
    }
}

# Derived view: managed accounts and everything that references them
Invoke-Section 'ManagedOverview' {
    $users    = @(); if ($report['LocalUsers'])     { $users    = @($report['LocalUsers']['Users']) }
    $groups   = @(); if ($report['LocalGroups'])    { $groups   = @($report['LocalGroups']['Groups']) }
    $services = @(); if ($report['Services'])       { $services = @($report['Services']['Services']) }
    $tasks    = @(); if ($report['ScheduledTasks']) { $tasks    = @($report['ScheduledTasks']['Tasks']) }
    $complus  = @(); if ($report['ComPlus'])        { $complus  = @($report['ComPlus']['Applications']) }
    $dcom     = @(); if ($report['DcomRunAs'])      { $dcom     = @($report['DcomRunAs']['Entries']) }
    $pools = @(); $vdirs = @()
    if ($report['IIS'] -and $report['IIS']['AppPools']) { $pools = @($report['IIS']['AppPools']) }
    if ($report['IIS'] -and $report['IIS']['Sites'])    { $vdirs = @($report['IIS']['Sites'] | ForEach-Object { $_['VirtualDirectories'] }) }

    $accounts = @(foreach ($u in $users) {
        if ($u['Classification'] -eq 'Other') { continue }
        $sid = $u['Sid']
        @{
            Name                 = $u['Name']
            Classification       = $u['Classification']
            Sid                  = $sid
            Disabled             = $u['Disabled']
            IsAccountLocked      = $u['IsAccountLocked']
            PasswordNeverExpires = $u['PasswordNeverExpires']
            CannotChangePassword = $u['CannotChangePassword']
            PasswordAgeDays      = $u['PasswordAgeDays']
            BadPasswordAttempts  = $u['BadPasswordAttempts']
            Groups               = @($groups | Where-Object {
                                       (@($_['Members'] | Where-Object { $_['Sid'] -eq $sid }).Count -gt 0) -or
                                       (@($_['MembersNetApi'] | Where-Object { $_['Sid'] -eq $sid }).Count -gt 0) } |
                                   ForEach-Object { $_['Name'] })
            Services             = @($services | Where-Object { $_['StartNameSid'] -eq $sid } | ForEach-Object { $_['Name'] })
            ScheduledTasks       = @($tasks | Where-Object { $_['UserSid'] -eq $sid } | ForEach-Object { '{0} (LogonType {1})' -f $_['Path'], $_['LogonType'] })
            IisAppPools          = @($pools | Where-Object { $_['UserSid'] -eq $sid } | ForEach-Object { $_['Name'] })
            IisConnectAs         = @($vdirs | Where-Object { $_ -and $_['ConnectAsUserSid'] -eq $sid } | ForEach-Object { $_['VirtualDirectory'] })
            ComPlusApplications  = @($complus | Where-Object { $_['IdentitySid'] -eq $sid } | ForEach-Object { '{0} ({1})' -f $_['Name'], $_['Activation'] })
            DcomRunAs            = @($dcom | Where-Object { $_['RunAsSid'] -eq $sid } | ForEach-Object { $_['AppId'] })
        }
    })

    $missing = @($managedNames.Keys | Where-Object { $n = $_; -not ($users | Where-Object { $_['Name'] -ieq $n }) })
    $customGroupStatus = @{}
    foreach ($g in $customGroups) { $customGroupStatus[$g] = [bool]($groups | Where-Object { $_['Name'] -ieq $g }) }

    $sqlLogins = @()
    if ($report['SqlServer'] -and $report['SqlServer']['DefaultInstance'] -and
        $report['SqlServer']['DefaultInstance']['Logins'] -is [array]) {
        $sqlLogins = @($report['SqlServer']['DefaultInstance']['Logins'] | Where-Object { $sqlLoginNames -contains $_['name'] })
    }

    @{
        Accounts                = $accounts
        MissingExpectedNames    = $missing
        CustomGroupsPresent     = $customGroupStatus
        NonBuiltinLocalGroups   = @($groups | Where-Object { $_['Sid'] -notlike 'S-1-5-32-*' } | ForEach-Object { $_['Name'] })
        SqlManagedLogins        = $sqlLogins
        SqlManagedLoginsMissing = @($sqlLoginNames | Where-Object { $n = $_; -not ($sqlLogins | Where-Object { $_['name'] -eq $n }) })
    }
}

#endregion

#region Output

$report['Meta'] = @{
    ScriptVersion   = $scriptVersion
    StartedAt       = $startedAt.ToString('s')
    FinishedAt      = (Get-Date).ToString('s')
    DurationSeconds = [math]::Round(((Get-Date) - $startedAt).TotalSeconds, 1)
}
$report['SectionErrors'] = $sectionErrors.ToArray()

Write-Host 'Writing report ...'
$fileName = 'CR-Inventory_{0}_{1}.json' -f $computerName, (Get-Date -Format 'yyyyMMdd-HHmmss')
$json = ConvertTo-CrJson $report
$utf8 = New-Object System.Text.UTF8Encoding($false)
if (-not $OutputDirectory -and $scriptPath) { $OutputDirectory = Split-Path -Parent $scriptPath }
$target = $null
try {
    if (-not $OutputDirectory) { throw 'no output directory' }
    $target = Join-Path $OutputDirectory $fileName
    [System.IO.File]::WriteAllText($target, $json, $utf8)
} catch {
    $target = Join-Path ([Environment]::GetFolderPath('Desktop')) $fileName
    [System.IO.File]::WriteAllText($target, $json, $utf8)
}

Write-Host ''
Write-Host '=== Managed accounts ==='
if ($report['ManagedOverview']) {
    $report['ManagedOverview']['Accounts'] | ForEach-Object {
        $deps = @($_['Services']).Count + @($_['ScheduledTasks']).Count + @($_['IisAppPools']).Count +
                @($_['IisConnectAs']).Count + @($_['ComPlusApplications']).Count
        New-Object PSObject -Property @{
            Account  = $_['Name']
            Role     = $_['Classification']
            Disabled = $_['Disabled']
            Locked   = $_['IsAccountLocked']
            PNE      = $_['PasswordNeverExpires']
            CCP      = $_['CannotChangePassword']
            Groups   = ($_['Groups'] -join ', ')
            Deps     = $deps
        }
    } | Select-Object Account, Role, Disabled, Locked, PNE, CCP, Groups, Deps |
        Format-Table -AutoSize | Out-String -Width 220 | Write-Host
    Write-Host ('Missing expected accounts: {0}' -f (($report['ManagedOverview']['MissingExpectedNames']) -join ', '))
}
if ($sectionErrors.Count -gt 0) {
    Write-Host ''
    Write-Host '=== Sections with errors ==='
    $sectionErrors | ForEach-Object { Write-Host ('{0}: {1}' -f $_['Section'], $_['Error']) }
}
Write-Host ''
Write-Host ('Report written to: {0}' -f $target)
Write-Host 'Review the file, then send it back. It contains account names, SIDs, group memberships, services and installed software, but no passwords.'

#endregion
