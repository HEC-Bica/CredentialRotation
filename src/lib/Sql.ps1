# Sql.ps1 - SQL Server default instance, read side (docs/PLAN.md sections 6 step 2 and 7.9, docs/dev/CONTRACTS.md "Sql")
# Read-only SELECTs only. All query texts are constants (Get-CrSqlQueryText); nothing is built from external input.

# --- internal: external access (mocked in tests) ---

# Instances from 'Instance Names\SQL' in both registry views: array of @{ View; Name; InstanceId }.
function Get-CrSqlInstanceNames {
    param()
    $list = New-Object System.Collections.ArrayList
    foreach ($base in @('HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Microsoft SQL Server')) {
        $path = $base + '\Instance Names\SQL'
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $key = Get-Item -LiteralPath $path -ErrorAction Stop
        foreach ($n in @($key.GetValueNames())) {
            if (-not $n) { continue }
            [void]$list.Add(@{ View = $base; Name = [string]$n; InstanceId = [string]$key.GetValue($n) })
        }
    }
    return , $list.ToArray()
}

# Win32_Service of the default instance, or $null.
function Get-CrSqlServiceWmi {
    param()
    return (Get-WmiObject -Class Win32_Service -Filter "Name='MSSQLSERVER'" -ErrorAction Stop)
}

# Opens a non-pooled integrated connection to the default instance. The object is created without
# arguments and the connection string is set afterwards (PLAN 7.9). Disposed again if Open fails.
function Open-CrSqlConnection {
    param()
    $cn = New-Object System.Data.SqlClient.SqlConnection
    $cn.ConnectionString = 'Data Source=.;Initial Catalog=master;Integrated Security=SSPI;Pooling=false;Connect Timeout=15;Application Name=CredentialRotation (audit)'
    try {
        $cn.Open()
    } catch {
        try { $cn.Dispose() } catch { }
        throw
    }
    return $cn
}

function Close-CrSqlConnection {
    param($Connection)
    if ($null -eq $Connection) { return }
    try { $Connection.Close() } catch { }
    try { $Connection.Dispose() } catch { }
}

# Runs the constant query Name; rows as hashtables (column name -> value; DBNull -> $null, byte[] and datetime kept).
function Invoke-CrSqlQuery {
    param($Connection, [string]$Name)
    $text = Get-CrSqlQueryText -Name $Name
    $cmd = $Connection.CreateCommand()
    $rows = New-Object System.Collections.ArrayList
    try {
        $cmd.CommandText = $text
        $cmd.CommandTimeout = 30
        $reader = $cmd.ExecuteReader()
        try {
            while ($reader.Read()) {
                $row = @{}
                for ($i = 0; $i -lt $reader.FieldCount; $i++) {
                    $v = $reader.GetValue($i)
                    if ($v -is [System.DBNull]) { $v = $null }
                    $row[$reader.GetName($i)] = $v
                }
                [void]$rows.Add($row)
            }
        } finally {
            $reader.Close()
        }
    } finally {
        $cmd.Dispose()
    }
    return , $rows.ToArray()
}

# --- internal: logic ---

# Constant read-only queries. LOGINPROPERTY needs SQL 2005 SP2+, hence LoginsBasic as fallback.
# IsSysadmin: explicit sysadmin membership, else IS_SRVROLEMEMBER (covers membership through a Windows group).
function Get-CrSqlQueryText {
    param([string]$Name)
    $sysadmin = "CASE WHEN EXISTS (SELECT 1 FROM sys.server_role_members rm JOIN sys.server_principals r ON r.principal_id = rm.role_principal_id WHERE r.name = 'sysadmin' AND rm.member_principal_id = p.principal_id) THEN 1 ELSE IS_SRVROLEMEMBER('sysadmin', p.name) END AS IsSysadmin"
    switch ($Name) {
        'Server'       { return "SELECT CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(128)) AS ProductVersion, CAST(SERVERPROPERTY('Edition') AS nvarchar(128)) AS Edition, CAST(SERVERPROPERTY('IsIntegratedSecurityOnly') AS int) AS IsIntegratedSecurityOnly, SUSER_SNAME() AS ConnectedAs, IS_SRVROLEMEMBER('sysadmin') AS ConnectedAsSysadmin" }
        'Logins'       { return "SELECT p.name, p.type_desc, p.is_disabled, p.sid, l.is_policy_checked, l.is_expiration_checked, CAST(LOGINPROPERTY(p.name, 'IsLocked') AS int) AS IsLocked, CAST(LOGINPROPERTY(p.name, 'BadPasswordCount') AS int) AS BadPasswordCount, CAST(LOGINPROPERTY(p.name, 'PasswordLastSetTime') AS datetime) AS PasswordLastSetTime, $sysadmin FROM sys.server_principals p LEFT JOIN sys.sql_logins l ON l.principal_id = p.principal_id WHERE p.type IN ('S','U','G') AND p.name NOT LIKE '##%' ORDER BY p.name" }
        'LoginsBasic'  { return "SELECT p.name, p.type_desc, p.is_disabled, p.sid, l.is_policy_checked, l.is_expiration_checked, $sysadmin FROM sys.server_principals p LEFT JOIN sys.sql_logins l ON l.principal_id = p.principal_id WHERE p.type IN ('S','U','G') AND p.name NOT LIKE '##%' ORDER BY p.name" }
        'MasterFiles'  { return "SELECT physical_name FROM sys.master_files WHERE database_id = 1" }
        'AgentJobs'    { return "SELECT j.name, SUSER_SNAME(j.owner_sid) AS owner_name, j.enabled FROM msdb.dbo.sysjobs j ORDER BY j.name" }
        'Credentials'  { return "SELECT name, credential_identity FROM sys.credentials ORDER BY name" }
        'Proxies'      { return "SELECT p.name, c.name AS credential_name, c.credential_identity, p.enabled FROM msdb.dbo.sysproxies p JOIN sys.credentials c ON c.credential_id = p.credential_id ORDER BY p.name" }
        'LinkedLogins' { return "SELECT s.name AS server_name, lp.name AS local_login, ll.uses_self_credential, ll.remote_name FROM sys.servers s JOIN sys.linked_logins ll ON ll.server_id = s.server_id LEFT JOIN sys.server_principals lp ON lp.principal_id = ll.local_principal_id WHERE s.is_linked = 1 ORDER BY s.name" }
    }
    throw ('Unknown SQL query: ' + $Name)
}

function ConvertTo-CrSqlBool {
    param($Value)
    if ($null -eq $Value) { return $null }
    return [bool]$Value
}

function ConvertTo-CrSqlInt {
    param($Value)
    if ($null -eq $Value) { return $null }
    return [int]$Value
}

function ConvertTo-CrSqlHex {
    param($Bytes)
    if ($null -eq $Bytes) { return $null }
    return ('0x' + ([System.BitConverter]::ToString([byte[]]$Bytes) -replace '-', ''))
}

# Windows principals: SID string; SQL logins (and anything not convertible): '0x...' hex.
function ConvertTo-CrSqlLoginSid {
    param([string]$Type, $Bytes)
    if ($null -eq $Bytes) { return $null }
    if ($Type -eq 'WINDOWS_LOGIN' -or $Type -eq 'WINDOWS_GROUP') {
        $s = ConvertTo-CrSidString -Bytes $Bytes
        if ($s) { return $s }
    }
    return (ConvertTo-CrSqlHex -Bytes $Bytes)
}

function ConvertTo-CrSqlLogin {
    param([hashtable]$Row)
    $type = [string]$Row['type_desc']
    return @{
        Name                = [string]$Row['name']
        Type                = $type
        Sid                 = ConvertTo-CrSqlLoginSid -Type $type -Bytes $Row['sid']
        IsDisabled          = ConvertTo-CrSqlBool $Row['is_disabled']
        IsPolicyChecked     = ConvertTo-CrSqlBool $Row['is_policy_checked']
        IsExpirationChecked = ConvertTo-CrSqlBool $Row['is_expiration_checked']
        IsLocked            = ConvertTo-CrSqlBool $Row['IsLocked']
        BadPasswordCount    = ConvertTo-CrSqlInt $Row['BadPasswordCount']
        PasswordLastSetTime = $Row['PasswordLastSetTime']
        IsSysadmin          = ConvertTo-CrSqlBool $Row['IsSysadmin']
    }
}

# Runs one constant query; on failure records 'Name: message' in Errors and returns $null.
function Invoke-CrSqlQuerySafe {
    param($Connection, [string]$Name, [System.Collections.ArrayList]$Errors)
    try {
        return , (ConvertTo-CrArray (Invoke-CrSqlQuery -Connection $Connection -Name $Name))
    } catch {
        [void]$Errors.Add(($Name + ': ' + $_.Exception.Message))
        return $null
    }
}

# --- public ---

# Default instance only. Missing instance / stopped service = no Error (expected absence).
# Error collects the connection error and the errors of individual queries ('Query: message; ...').
function Get-CrSqlState {
    param()
    $result = @{
        DefaultInstancePresent   = $false
        ServiceName              = $null
        ServiceState             = $null
        ServiceAccount           = $null
        ServiceAccountSid        = $null
        OtherInstances           = @()
        Connected                = $false
        Error                    = $null
        MajorVersion             = $null
        ProductVersion           = $null
        Edition                  = $null
        IsExpress                = $null
        IsIntegratedSecurityOnly = $null
        ConnectedAs              = $null
        ConnectedAsSysadmin      = $null
        Logins                   = @()
        MasterFiles              = @()
        AgentJobs                = @()
        Credentials              = @()
        Proxies                  = @()
        LinkedLogins             = @()
    }
    $errors = New-Object System.Collections.ArrayList

    $others = New-Object System.Collections.ArrayList
    foreach ($inst in (ConvertTo-CrArray (Get-CrSqlInstanceNames))) {
        if ($null -eq $inst) { continue }
        $name = [string]$inst['Name']
        if ($name -eq 'MSSQLSERVER') {
            $result['DefaultInstancePresent'] = $true
        } elseif ($name -and -not ($others -contains $name)) {
            [void]$others.Add($name)
        }
    }
    $result['OtherInstances'] = $others.ToArray()
    if (-not $result['DefaultInstancePresent']) { return $result }

    $result['ServiceName'] = 'MSSQLSERVER'
    $svc = $null
    try {
        $svc = Get-CrSqlServiceWmi
    } catch {
        [void]$errors.Add(('Service: ' + $_.Exception.Message))
    }
    if ($null -ne $svc) {
        $result['ServiceState'] = [string]$svc.State
        $account = [string]$svc.StartName
        if ($account) {
            $result['ServiceAccount'] = $account
            $result['ServiceAccountSid'] = Resolve-CrNameToSid -Name $account
        }
    }

    if ($result['ServiceState'] -eq 'Running') {
        $cn = $null
        try {
            $cn = Open-CrSqlConnection
            $result['Connected'] = $true

            $rows = Invoke-CrSqlQuerySafe -Connection $cn -Name 'Server' -Errors $errors
            if ($null -ne $rows -and $rows.Length -gt 0) {
                $r = $rows[0]
                $pv = [string]$r['ProductVersion']
                $result['ProductVersion'] = $pv
                if ($pv -match '^(\d+)\.') { $result['MajorVersion'] = [int]$matches[1] }
                $edition = [string]$r['Edition']
                $result['Edition'] = $edition
                $result['IsExpress'] = [bool]($edition -match 'Express')
                $result['IsIntegratedSecurityOnly'] = ConvertTo-CrSqlBool $r['IsIntegratedSecurityOnly']
                $result['ConnectedAs'] = $r['ConnectedAs']
                $result['ConnectedAsSysadmin'] = ConvertTo-CrSqlBool $r['ConnectedAsSysadmin']
            }

            $rows = Invoke-CrSqlQuerySafe -Connection $cn -Name 'Logins' -Errors $errors
            if ($null -eq $rows) { $rows = Invoke-CrSqlQuerySafe -Connection $cn -Name 'LoginsBasic' -Errors $errors }
            if ($null -ne $rows) {
                $logins = New-Object System.Collections.ArrayList
                foreach ($r in $rows) { [void]$logins.Add((ConvertTo-CrSqlLogin -Row $r)) }
                $result['Logins'] = $logins.ToArray()
            }

            $rows = Invoke-CrSqlQuerySafe -Connection $cn -Name 'MasterFiles' -Errors $errors
            if ($null -ne $rows) {
                $files = New-Object System.Collections.ArrayList
                foreach ($r in $rows) { if ($r['physical_name']) { [void]$files.Add([string]$r['physical_name']) } }
                $result['MasterFiles'] = $files.ToArray()
            }

            $rows = Invoke-CrSqlQuerySafe -Connection $cn -Name 'AgentJobs' -Errors $errors
            if ($null -ne $rows) {
                $jobs = New-Object System.Collections.ArrayList
                foreach ($r in $rows) {
                    [void]$jobs.Add(@{ Name = [string]$r['name']; Owner = $r['owner_name']; Enabled = ConvertTo-CrSqlBool $r['enabled'] })
                }
                $result['AgentJobs'] = $jobs.ToArray()
            }

            $rows = Invoke-CrSqlQuerySafe -Connection $cn -Name 'Credentials' -Errors $errors
            if ($null -ne $rows) {
                $creds = New-Object System.Collections.ArrayList
                foreach ($r in $rows) {
                    [void]$creds.Add(@{ Name = [string]$r['name']; Identity = $r['credential_identity'] })
                }
                $result['Credentials'] = $creds.ToArray()
            }

            $rows = Invoke-CrSqlQuerySafe -Connection $cn -Name 'Proxies' -Errors $errors
            if ($null -ne $rows) {
                $proxies = New-Object System.Collections.ArrayList
                foreach ($r in $rows) {
                    [void]$proxies.Add(@{
                        Name               = [string]$r['name']
                        CredentialName     = $r['credential_name']
                        CredentialIdentity = $r['credential_identity']
                        Enabled            = ConvertTo-CrSqlBool $r['enabled']
                    })
                }
                $result['Proxies'] = $proxies.ToArray()
            }

            $rows = Invoke-CrSqlQuerySafe -Connection $cn -Name 'LinkedLogins' -Errors $errors
            if ($null -ne $rows) {
                $linked = New-Object System.Collections.ArrayList
                foreach ($r in $rows) {
                    [void]$linked.Add(@{
                        Server             = [string]$r['server_name']
                        LocalLogin         = $r['local_login']
                        UsesSelfCredential = ConvertTo-CrSqlBool $r['uses_self_credential']
                        RemoteName         = $r['remote_name']
                    })
                }
                $result['LinkedLogins'] = $linked.ToArray()
            }
        } catch {
            $label = 'Connect: '
            if ($result['Connected']) { $label = 'Read: ' }
            [void]$errors.Add(($label + $_.Exception.Message))
        } finally {
            Close-CrSqlConnection -Connection $cn
        }
    }

    if ($errors.Count -gt 0) { $result['Error'] = ($errors.ToArray() -join '; ') }
    return $result
}
