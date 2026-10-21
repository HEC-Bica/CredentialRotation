# Sql.ps1 - SQL Server default instance (docs/PLAN.md sections 6 step 2, 7.9 and D29, docs/dev/CONTRACTS.md "Sql")
# Read side: read-only SELECTs. All query texts are constants (Get-CrSqlQueryText); nothing is built from external input.
# Write side (D29, v10.6): the Windows login of the account that replaces others and its fixed server roles. Constant
# command texts (Get-CrSqlWriteText) whose names are parameters, quoted with QUOTENAME inside the batch. No passwords.
# Client (0.9.0): .NET SqlClient on PS 3+; on PS 2.0 ADO over SQLOLEDB, the OLE DB provider that ships with Windows
# (Get-CrSqlClientKind). Both connect to '.' with integrated security as the running account.

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

# Which client the SQL access uses: 'SqlClient' on PS 3+, 'Ado' on PS 2.0. Under CLR 2, SqlClient reads
# powershell.exe.config when it starts and fails where WMF 5.1 or .NET 4 put a .NET 4 section there (PLAN 10, seen on
# SM-QS-K1: "Unrecognized configuration section uri"). ADO is COM and doesn't read it.
function Get-CrSqlClientKind {
    param()
    if ($PSVersionTable.PSVersion.Major -lt 3) { return 'Ado' }
    return 'SqlClient'
}

# Opens a non-pooled integrated connection to the default instance. The object is created without
# arguments and the connection string is set afterwards (PLAN 7.9). Disposed again if Open fails.
function Open-CrSqlConnection {
    param()
    if ((Get-CrSqlClientKind) -eq 'Ado') { return , (Open-CrSqlAdoConnection) }
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

# The same over ADO (ADODB.Connection, provider SQLOLEDB; 'OLE DB Services=-2' turns pooling off). A failed Open throws
# an exception whose Data['CrSqlNumber'] is the SQL Server error number (18456 = login failed; Get-CrSqlErrorNumber).
function Open-CrSqlAdoConnection {
    param()
    $cn = New-Object -ComObject ADODB.Connection
    $cn.ConnectionTimeout = 15
    $cn.CommandTimeout = 30
    try {
        $cn.Open('Provider=SQLOLEDB;Data Source=.;Initial Catalog=master;Integrated Security=SSPI;OLE DB Services=-2;Application Name=CredentialRotation (audit)')
    } catch {
        $number = $null
        try {
            for ($i = 0; $i -lt $cn.Errors.Count; $i++) {
                $n = [int]$cn.Errors.Item($i).NativeError
                if ($n -ne 0) { $number = $n; break }
            }
        } catch { }
        $ex = New-Object System.Exception -ArgumentList (Get-CrInnermostMessage $_), $_.Exception
        if ($null -ne $number) { $ex.Data['CrSqlNumber'] = $number }
        Close-CrSqlConnection -Connection $cn
        throw $ex
    }
    return , $cn
}

function Close-CrSqlConnection {
    param($Connection)
    if ($null -eq $Connection) { return }
    try { $Connection.Close() } catch { }
    try { $Connection.Dispose() } catch { }
    if ($Connection -is [System.__ComObject]) { try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($Connection) } catch { } }
}

# Runs the command's reader; rows as hashtables (column name -> value; DBNull -> $null, byte[] and datetime kept).
function Read-CrSqlRows {
    param($Command)
    $rows = New-Object System.Collections.ArrayList
    $reader = $Command.ExecuteReader()
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
    return , $rows.ToArray()
}

# The rows of an ADO recordset as hashtables, like Read-CrSqlRows (NULL -> $null, varbinary as byte[]). Recordsets of
# statements without a result set (State 0 = closed) are skipped. Closes the recordset.
function Read-CrSqlAdoRows {
    param($Recordset)
    $rows = New-Object System.Collections.ArrayList
    $rs = $Recordset
    $guard = 0
    while ($null -ne $rs -and $rs.State -eq 0 -and $guard -lt 50) { $rs = $rs.NextRecordset(); $guard++ }
    if ($null -eq $rs -or $rs.State -eq 0) { return , $rows.ToArray() }
    try {
        $fields = $rs.Fields
        while (-not $rs.EOF) {
            $row = @{}
            for ($i = 0; $i -lt $fields.Count; $i++) {
                $f = $fields.Item($i)
                $v = $f.Value
                if ($v -is [System.DBNull]) { $v = $null }
                $row[[string]$f.Name] = $v
            }
            [void]$rows.Add($row)
            $rs.MoveNext()
        }
    } finally {
        try { $rs.Close() } catch { }
    }
    return , $rows.ToArray()
}

# The batch ADO runs for a constant text: SQLOLEDB binds parameters by position ('?'), so each parameter first becomes a
# variable of the batch and the constant text uses @<name> as with SqlClient. Parameter names are code constants.
function Get-CrSqlAdoCommandText {
    param([string]$Text, $Parameters)
    $prefix = 'SET NOCOUNT ON; '
    foreach ($p in (ConvertTo-CrArray $Parameters)) {
        $name = [string]$p['Name']
        if ($name -notmatch '^[A-Za-z]+$') { throw ('Invalid SQL parameter name: ' + $name) }
        $type = 'nvarchar(128)'
        if ([string]$p['Type'] -eq 'VarBinary') { $type = 'varbinary(85)' }
        $prefix = $prefix + ('DECLARE @{0} {1}; SET @{0} = ?; ' -f $name, $type)
    }
    return ($prefix + $Text)
}

# Runs a constant text over ADO with parameters @(@{ Name; Type ('NVarChar'|'VarBinary'); Value }) in their order.
# -Query: the rows (Read-CrSqlAdoRows); otherwise every result is read, so an error of a later statement still throws.
function Invoke-CrSqlAdoCommand {
    param($Connection, [string]$Text, $Parameters, [switch]$Query)
    $rows = @()
    $cmd = New-Object -ComObject ADODB.Command
    try {
        $cmd.ActiveConnection = $Connection
        $cmd.CommandType = 1                                                           # adCmdText
        $cmd.CommandTimeout = 30
        foreach ($p in (ConvertTo-CrArray $Parameters)) {
            if ([string]$p['Type'] -eq 'VarBinary') {
                $prm = $cmd.CreateParameter([string]$p['Name'], 204, 1, 85, $p['Value'])            # adVarBinary, input
            } else {
                $prm = $cmd.CreateParameter([string]$p['Name'], 202, 1, 128, [string]$p['Value'])   # adVarWChar, input
            }
            $cmd.Parameters.Append($prm)
        }
        $cmd.CommandText = Get-CrSqlAdoCommandText -Text $Text -Parameters $Parameters
        $rs = $cmd.Execute()
        if ($Query) {
            $rows = Read-CrSqlAdoRows -Recordset $rs
        } else {
            $guard = 0
            while ($null -ne $rs -and $guard -lt 50) { $rs = $rs.NextRecordset(); $guard++ }
        }
    } finally {
        try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($cmd) } catch { }
    }
    return , $rows
}

# Runs the constant query Name; rows as hashtables (Read-CrSqlRows).
function Invoke-CrSqlQuery {
    param($Connection, [string]$Name)
    $text = Get-CrSqlQueryText -Name $Name
    if ($Connection -is [System.__ComObject]) { return , (Invoke-CrSqlAdoCommand -Connection $Connection -Text $text -Parameters @() -Query) }
    $cmd = $Connection.CreateCommand()
    try {
        $cmd.CommandText = $text
        $cmd.CommandTimeout = 30
        $rows = Read-CrSqlRows -Command $cmd
    } finally {
        $cmd.Dispose()
    }
    return , $rows
}

# Runs one constant command text (Get-CrSqlWriteText) with parameters @(@{ Name; Type ('NVarChar'|'VarBinary'); Value }).
# -Query: returns the rows (Read-CrSqlRows); otherwise ExecuteNonQuery and an empty array.
function Invoke-CrSqlCommand {
    param($Connection, [string]$Text, $Parameters, [switch]$Query)
    if ($Connection -is [System.__ComObject]) { return , (Invoke-CrSqlAdoCommand -Connection $Connection -Text $Text -Parameters $Parameters -Query:$Query) }
    $cmd = $Connection.CreateCommand()
    $rows = @()
    try {
        $cmd.CommandText = $Text
        $cmd.CommandTimeout = 30
        foreach ($p in (ConvertTo-CrArray $Parameters)) {
            if ([string]$p['Type'] -eq 'VarBinary') {
                $sqlParameter = $cmd.Parameters.Add(('@' + $p['Name']), [System.Data.SqlDbType]::VarBinary, 85)
            } else {
                $sqlParameter = $cmd.Parameters.Add(('@' + $p['Name']), [System.Data.SqlDbType]::NVarChar, 128)
            }
            $sqlParameter.Value = $p['Value']
        }
        if ($Query) {
            $rows = Read-CrSqlRows -Command $cmd
        } else {
            [void]$cmd.ExecuteNonQuery()
        }
    } finally {
        $cmd.Dispose()
    }
    return , $rows
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
        # Explicit server role memberships (D29: the roles the replacing account gets)
        'ServerRoles'  { return "SELECT m.sid AS member_sid, m.type_desc AS member_type, r.name AS role_name FROM sys.server_role_members rm JOIN sys.server_principals r ON r.principal_id = rm.role_principal_id JOIN sys.server_principals m ON m.principal_id = rm.member_principal_id ORDER BY r.name" }
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
        ServerRoles         = $null
    }
}

# Sets ServerRoles (the names of its explicit server role memberships) on every login, from the rows of the ServerRoles
# query. Without those rows ServerRoles stays $null (unknown; callers fall back to IsSysadmin).
function Add-CrSqlLoginServerRoles {
    param($Logins, $Rows)
    $map = @{}
    foreach ($r in (ConvertTo-CrArray $Rows)) {
        if (-not ($r -is [hashtable]) -or -not $r['role_name']) { continue }
        $sid = ConvertTo-CrSqlLoginSid -Type ([string]$r['member_type']) -Bytes $r['member_sid']
        if (-not $sid) { continue }
        $key = $sid.ToUpperInvariant()
        if (-not $map.ContainsKey($key)) { $map[$key] = New-Object System.Collections.ArrayList }
        if ($map[$key] -notcontains [string]$r['role_name']) { [void]$map[$key].Add([string]$r['role_name']) }
    }
    foreach ($login in (ConvertTo-CrArray $Logins)) {
        if (-not ($login -is [hashtable])) { continue }
        $roles = @()
        if ($login['Sid'] -and $map.ContainsKey(([string]$login['Sid']).ToUpperInvariant())) {
            $roles = $map[([string]$login['Sid']).ToUpperInvariant()].ToArray()
        }
        $login['ServerRoles'] = $roles
    }
}

# The server roles of a login: ServerRoles when known, else 'sysadmin' if IsSysadmin (comma-returned).
function Get-CrSqlLoginRoles {
    param($Login)
    if (-not ($Login -is [hashtable])) { return , @() }
    if ($null -ne $Login['ServerRoles']) { return , (ConvertTo-CrArray $Login['ServerRoles']) }
    if ($Login['IsSysadmin']) { return , @('sysadmin') }
    return , @()
}

# Runs one constant query; on failure records 'Name: message' in Errors and returns $null.
function Invoke-CrSqlQuerySafe {
    param($Connection, [string]$Name, [System.Collections.ArrayList]$Errors)
    try {
        return , (ConvertTo-CrArray (Invoke-CrSqlQuery -Connection $Connection -Name $Name))
    } catch {
        [void]$Errors.Add(($Name + ': ' + (Get-CrInnermostMessage $_)))
        return $null
    }
}

# The SQL Server error number of a failed call (SqlException.Number, or Data['CrSqlNumber'] from ADO, e.g. 18456 =
# login failed), or $null. PowerShell wraps the SqlException of a method call, so the inner exceptions are searched.
# The number doesn't depend on the OS language, unlike the message.
function Get-CrSqlErrorNumber {
    param($ErrorRecord)
    $ex = $ErrorRecord
    if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ex = $ErrorRecord.Exception }
    while ($ex) {
        if ($ex.Data -and $ex.Data.Contains('CrSqlNumber')) { return [int]$ex.Data['CrSqlNumber'] }
        if ($ex.GetType().FullName -eq 'System.Data.SqlClient.SqlException') { return [int]$ex.Number }
        $ex = $ex.InnerException
    }
    return $null
}

# --- public ---

# Default instance only. Missing instance / stopped service = no Error (expected absence).
# Error collects the connection error and the errors of individual queries ('Query: message; ...').
# ConnectErrorNumber: the SQL Server error number of a failed connection (18456 = login failed), else $null.
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
        ConnectErrorNumber       = $null
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
        [void]$errors.Add(('Service: ' + (Get-CrInnermostMessage $_)))
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
                $rows = Invoke-CrSqlQuerySafe -Connection $cn -Name 'ServerRoles' -Errors $errors
                if ($null -ne $rows) { Add-CrSqlLoginServerRoles -Logins $result['Logins'] -Rows $rows }
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
            if ($result['Connected']) { $label = 'Read: ' } else { $result['ConnectErrorNumber'] = Get-CrSqlErrorNumber $_ }
            [void]$errors.Add(($label + (Get-CrInnermostMessage $_)))
        } finally {
            Close-CrSqlConnection -Connection $cn
        }
    }

    if ($errors.Count -gt 0) { $result['Error'] = ($errors.ToArray() -join '; ') }
    return $result
}

#region SQL access of a replacing account (D29, v10.6)

# The fixed server roles of SQL Server 2005-2017: the only roles the tool adds (comma-returned).
function Get-CrSqlFixedServerRoles {
    return , @('sysadmin', 'securityadmin', 'serveradmin', 'setupadmin', 'processadmin', 'diskadmin', 'dbcreator', 'bulkadmin')
}

# Constant command texts of the write side. @login and @role are parameters; dynamic statements quote them with QUOTENAME.
# Roles: sp_addsrvrolemember up to 2008 R2 (major 10), ALTER SERVER ROLE from 2012 (major 11), as in PLAN 7.9.
function Get-CrSqlWriteText {
    param([string]$Name, [int]$MajorVersion)
    switch ($Name) {
        'CreateWindowsLogin' { return "DECLARE @sql nvarchar(max); SET @sql = N'CREATE LOGIN ' + QUOTENAME(@login) + N' FROM WINDOWS'; EXEC (@sql);" }
        'EnableLogin'        { return "DECLARE @sql nvarchar(max); SET @sql = N'ALTER LOGIN ' + QUOTENAME(@login) + N' ENABLE'; EXEC (@sql);" }
        'AddServerRole' {
            if ($MajorVersion -ge 11) { return "DECLARE @sql nvarchar(max); SET @sql = N'ALTER SERVER ROLE ' + QUOTENAME(@role) + N' ADD MEMBER ' + QUOTENAME(@login); EXEC (@sql);" }
            return 'EXEC sp_addsrvrolemember @loginame = @login, @rolename = @role;'
        }
        'LoginBySid'         { return "SELECT p.name, p.is_disabled, r.name AS role_name FROM sys.server_principals p LEFT JOIN sys.server_role_members rm ON rm.member_principal_id = p.principal_id LEFT JOIN sys.server_principals r ON r.principal_id = rm.role_principal_id WHERE p.sid = @sid" }
    }
    throw ('Unknown SQL command: ' + $Name)
}

function ConvertTo-CrSqlSidBytes {
    param([string]$Sid)
    $s = New-Object System.Security.Principal.SecurityIdentifier($Sid)
    $bytes = New-Object byte[] ($s.BinaryLength)
    $s.GetBinaryForm($bytes, 0)
    return , $bytes
}

# The login of a Windows account on the default instance, by SID: @{ Found; Name; IsDisabled; Roles = @(); Error }.
function Get-CrSqlLoginAccess {
    param([string]$Sid)
    $r = @{ Found = $false; Name = $null; IsDisabled = $null; Roles = @(); Error = $null }
    $cn = $null
    try {
        $cn = Open-CrSqlConnection
        $parameters = @(@{ Name = 'sid'; Type = 'VarBinary'; Value = (ConvertTo-CrSqlSidBytes -Sid $Sid) })
        $rows = ConvertTo-CrArray (Invoke-CrSqlCommand -Connection $cn -Text (Get-CrSqlWriteText -Name 'LoginBySid') -Parameters $parameters -Query)
        $roles = New-Object System.Collections.ArrayList
        foreach ($row in $rows) {
            if (-not ($row -is [hashtable])) { continue }
            $r['Found'] = $true
            $r['Name'] = [string]$row['name']
            $r['IsDisabled'] = ConvertTo-CrSqlBool $row['is_disabled']
            if ($row['role_name'] -and ($roles -notcontains [string]$row['role_name'])) { [void]$roles.Add([string]$row['role_name']) }
        }
        $r['Roles'] = $roles.ToArray()
    } catch {
        $r['Error'] = Get-CrInnermostMessage $_
    } finally {
        Close-CrSqlConnection -Connection $cn
    }
    return $r
}

# Creates and completes a Windows login on the default instance: CREATE LOGIN (-CreateLogin), ALTER LOGIN ENABLE
# (-EnableLogin), then one membership per role of -Roles (fixed server roles only; adds, never removes). Runs as the
# running account (integrated). Stops at the first failure. Returns @{ Success; Steps = @(<done>); FailedStep; Error }.
function Grant-CrSqlLoginAccess {
    param([string]$LoginName, [bool]$CreateLogin, [bool]$EnableLogin, [string[]]$Roles, [int]$MajorVersion)
    if (-not $LoginName) { throw 'Grant-CrSqlLoginAccess: -LoginName is required.' }
    $fixed = Get-CrSqlFixedServerRoles
    foreach ($role in (ConvertTo-CrArray $Roles)) {
        if ($fixed -notcontains [string]$role) { throw ('Grant-CrSqlLoginAccess: {0} is not a fixed server role.' -f $role) }
    }
    $work = New-Object System.Collections.ArrayList
    if ($CreateLogin) { [void]$work.Add(@{ Step = 'CreateLogin'; Text = 'CreateWindowsLogin'; Role = $null }) }
    if ($EnableLogin) { [void]$work.Add(@{ Step = 'EnableLogin'; Text = 'EnableLogin'; Role = $null }) }
    foreach ($role in (ConvertTo-CrArray $Roles)) { [void]$work.Add(@{ Step = ('AddRole ' + $role); Text = 'AddServerRole'; Role = [string]$role }) }
    $out = @{ Success = $false; Steps = @(); FailedStep = $null; Error = $null }
    $steps = New-Object System.Collections.ArrayList
    $current = 'Connect'
    $cn = $null
    try {
        $cn = Open-CrSqlConnection
        foreach ($w in $work) {
            $current = [string]$w['Step']
            $parameters = New-Object System.Collections.ArrayList
            [void]$parameters.Add(@{ Name = 'login'; Type = 'NVarChar'; Value = $LoginName })
            if ($w['Role']) { [void]$parameters.Add(@{ Name = 'role'; Type = 'NVarChar'; Value = [string]$w['Role'] }) }
            [void](Invoke-CrSqlCommand -Connection $cn -Text (Get-CrSqlWriteText -Name $w['Text'] -MajorVersion $MajorVersion) -Parameters ($parameters.ToArray()))
            [void]$steps.Add($current)
        }
        $out['Success'] = $true
    } catch {
        $out['FailedStep'] = $current
        $out['Error'] = Get-CrInnermostMessage $_
    } finally {
        Close-CrSqlConnection -Connection $cn
    }
    $out['Steps'] = $steps.ToArray()
    return $out
}

# D29: what the account of a managed entry with SqlAccess needs on the default instance to have the SQL Server access of
# the accounts it replaces: their enabled Windows logins (by SID) and those logins' fixed server roles ('sysadmin' covers
# the others). -TargetSid is $null while the account is still to be created; -WriteBlocked is Preflight's reason why the
# tool can't write to the default instance now ($null when it can); -RunningSid only words the reason when the running
# account is the target itself and can't log on to SQL Server.
# Returns @{ Unknown; Needed; Blocked; Reason; LoginName; Login; CreateLogin; EnableLogin; Roles = @(); MissingRoles = @();
#            Sources = @('<account> (<login>)'); Notes = @(<report-only texts>) }. Unknown and Blocked come with Reason.
function Get-CrSqlAccessPlan {
    param($State, $Entry, [string]$TargetSid, [string]$TargetName, [string]$WriteBlocked, [string]$RunningSid)
    $p = @{
        Unknown = $false; Needed = $false; Blocked = $false; Reason = $null; LoginName = $null; Login = $null
        CreateLogin = $false; EnableLogin = $false; Roles = @(); MissingRoles = @(); Sources = @(); Notes = @()
    }
    $notes = New-Object System.Collections.ArrayList
    $computer = $env:COMPUTERNAME
    if (($State['Computer'] -is [hashtable]) -and $State['Computer']['Name']) { $computer = [string]$State['Computer']['Name'] }
    if ($TargetName) { $p['LoginName'] = $computer + '\' + $TargetName }
    $replaced = New-Object System.Collections.ArrayList
    foreach ($r in (ConvertTo-CrArray $Entry['Replaced'])) { if (($r -is [hashtable]) -and $r['Sid']) { [void]$replaced.Add($r) } }
    if ($replaced.Count -eq 0) { return $p }
    $replacedNames = New-Object System.Collections.ArrayList
    $enabledNames = New-Object System.Collections.ArrayList
    foreach ($r in $replaced) {
        [void]$replacedNames.Add([string]$r['Name'])
        if ($r['Enabled'] -ne $false) { [void]$enabledNames.Add([string]$r['Name']) }
    }
    $replacedText = ($replacedNames.ToArray()) -join ', '

    $sql = $State['Sql']
    if (-not ($sql -is [hashtable])) {
        $p['Unknown'] = $true
        $p['Reason'] = 'the SQL Server state is not available'
        return $p
    }
    # A failed discovery section is @{ Error = ... }: whether SQL Server is installed is unknown, not "absent".
    if (-not $sql.ContainsKey('DefaultInstancePresent')) {
        $p['Unknown'] = $true
        $p['Reason'] = 'the SQL Server discovery failed ({0})' -f $sql['Error']
        return $p
    }
    foreach ($inst in (ConvertTo-CrArray $sql['OtherInstances'])) {
        if ($inst) { [void]$notes.Add(('SQL Server instance {0} is not covered: give {1} the access of {2} there manually (D29)' -f $inst, $TargetName, $replacedText)) }
    }
    $p['Notes'] = $notes.ToArray()
    if (-not $sql['DefaultInstancePresent']) { return $p }
    # Only a replaced account that is still enabled can log on to run the tool.
    $hint = 'run the tool as an account that is sysadmin through its own Windows login'
    if ($enabledNames.Count -gt 0) {
        $hint = $hint + ', e.g. ' + (($enabledNames.ToArray()) -join ', ')
    } else {
        $verb = 'is'
        if ($replacedNames.Count -gt 1) { $verb = 'are' }
        $hint = $hint + ' (' + $replacedText + ' ' + $verb + ' disabled: enable one for the run, or create the login in SQL Server manually)'
    }
    $logins = ConvertTo-CrArray $sql['Logins']
    if ([string]$sql['ServiceState'] -ne 'Running') {
        $p['Unknown'] = $true
        $p['Reason'] = 'the default SQL Server instance is not running (state {0}), so the logins of {1} cannot be read; start it and re-run' -f $sql['ServiceState'], $replacedText
        return $p
    }
    if (-not $sql['Connected']) {
        $p['Unknown'] = $true
        $p['Reason'] = 'no connection to the default SQL Server instance ({0}); {1}' -f $sql['Error'], $hint
        # 18456: the running account has no login it can use (none, or a disabled one). The usual case is the target
        # itself, e.g. an existing SOP-Admin that the operator logged on with: it can't give itself a login.
        if ($sql['ConnectErrorNumber'] -eq 18456) {
            if ($RunningSid -and $TargetSid -and ($RunningSid -ieq $TargetSid)) {
                $p['Reason'] = '{0} is the running account and cannot log on to SQL Server ({1}): it has no login there, or a disabled one, so it cannot give itself the access of {2}; {3}' -f $TargetName, $sql['Error'], $replacedText, $hint
            } else {
                $p['Reason'] = 'the running account cannot log on to the default SQL Server instance ({0}): it has no login there, or a disabled one; {1}' -f $sql['Error'], $hint
            }
        }
        return $p
    }
    # A login that is not sysadmin sees only itself, the system logins and the fixed roles in sys.server_principals:
    # the logins of the replaced accounts would look absent.
    if ($sql['ConnectedAsSysadmin'] -ne $true) {
        $p['Unknown'] = $true
        $p['Reason'] = 'the running account ({0}) is not sysadmin, so it cannot see the SQL Server logins of {1}; {2}' -f $sql['ConnectedAs'], $replacedText, $hint
        return $p
    }
    if ($logins.Count -eq 0) {
        $p['Unknown'] = $true
        $p['Reason'] = 'the SQL Server logins could not be read ({0})' -f $sql['Error']
        return $p
    }

    $fixed = Get-CrSqlFixedServerRoles
    $roles = New-Object System.Collections.ArrayList
    $sources = New-Object System.Collections.ArrayList
    $sourceLogins = New-Object System.Collections.ArrayList
    $notCopied = New-Object System.Collections.ArrayList
    $rolesUnknown = New-Object System.Collections.ArrayList
    $anySysadmin = $false
    foreach ($r in $replaced) {
        foreach ($login in $logins) {
            if (-not ($login -is [hashtable]) -or [string]$login['Type'] -ne 'WINDOWS_LOGIN' -or ([string]$login['Sid'] -ine [string]$r['Sid'])) { continue }
            if ($login['IsDisabled']) {
                [void]$notes.Add(('The SQL Server login {0} of {1} is disabled; its access is not copied (D29)' -f $login['Name'], $r['Name']))
                continue
            }
            [void]$sources.Add(('{0} ({1})' -f $r['Name'], $login['Name']))
            [void]$sourceLogins.Add([string]$login['Name'])
            # Without the ServerRoles query only sysadmin is known; other fixed roles would be lost.
            if ($null -eq $login['ServerRoles'] -and -not $login['IsSysadmin']) { [void]$rolesUnknown.Add([string]$login['Name']) }
            $loginRoles = Get-CrSqlLoginRoles -Login $login
            if ($loginRoles -contains 'sysadmin') { $anySysadmin = $true }
            foreach ($role in $loginRoles) {
                if ($fixed -contains [string]$role) {
                    if ($roles -notcontains [string]$role) { [void]$roles.Add([string]$role) }
                } else {
                    [void]$notCopied.Add(('{0} ({1})' -f $role, $login['Name']))
                }
            }
        }
    }
    $p['Sources'] = $sources.ToArray()
    if ($rolesUnknown.Count -gt 0) {
        $p['Unknown'] = $true
        $p['Reason'] = 'the server roles of the SQL Server login {0} could not be read ({1})' -f (($rolesUnknown.ToArray()) -join ', '), $sql['Error']
        $p['Notes'] = $notes.ToArray()
        return $p
    }
    if ($notCopied.Count -gt 0) {
        [void]$notes.Add(('Server roles that are not fixed server roles are not copied to {0}: {1} (D29)' -f $TargetName, (($notCopied.ToArray()) -join ', ')))
    }
    if ($sources.Count -gt 0 -and -not $anySysadmin) {
        [void]$notes.Add(('The SQL Server logins of {0} are not sysadmin: {1} gets their server roles, but not their database permissions; check those manually (D29)' -f $replacedText, $TargetName))
    }
    foreach ($job in (ConvertTo-CrArray $sql['AgentJobs'])) {
        if (-not ($job -is [hashtable]) -or -not $job['Owner']) { continue }
        foreach ($ln in $sourceLogins) {
            if ([string]$job['Owner'] -ieq $ln) {
                [void]$notes.Add(('SQL Agent job ''{0}'' is owned by the login {1}; it may fail once that account is disabled: change its owner (D29)' -f $job['Name'], $ln))
            }
        }
    }
    $p['Notes'] = $notes.ToArray()
    if ($sources.Count -eq 0) { return $p }
    if ($roles -contains 'sysadmin') { $roles = New-Object System.Collections.ArrayList; [void]$roles.Add('sysadmin') }
    $p['Roles'] = $roles.ToArray()

    $target = $null
    if ($TargetSid) {
        foreach ($login in $logins) {
            if (($login -is [hashtable]) -and [string]$login['Type'] -eq 'WINDOWS_LOGIN' -and ([string]$login['Sid'] -ieq $TargetSid)) { $target = $login; break }
        }
    }
    $missing = New-Object System.Collections.ArrayList
    if ($target) {
        $p['Login'] = $target
        $p['LoginName'] = [string]$target['Name']
        $p['EnableLogin'] = [bool]$target['IsDisabled']
        $have = Get-CrSqlLoginRoles -Login $target
        if ($have -notcontains 'sysadmin') {
            foreach ($role in $roles) { if ($have -notcontains $role) { [void]$missing.Add($role) } }
        }
    } else {
        $p['CreateLogin'] = $true
        foreach ($role in $roles) { [void]$missing.Add($role) }
        # CREATE LOGIN fails when a login with this name exists for another SID (left over from a deleted account).
        foreach ($login in $logins) {
            if (($login -is [hashtable]) -and $p['LoginName'] -and ([string]$login['Name'] -ieq $p['LoginName'])) {
                $p['Blocked'] = $true
                $p['Reason'] = 'a SQL Server login named {0} already exists for another SID (left over from a deleted account); remove it in SQL Server, then re-run' -f $p['LoginName']
            }
        }
    }
    $p['MissingRoles'] = $missing.ToArray()
    $p['Needed'] = [bool]($p['CreateLogin'] -or $p['EnableLogin'] -or $missing.Count -gt 0)
    if ($p['Needed'] -and -not $p['Blocked'] -and $WriteBlocked) {
        $p['Blocked'] = $true
        $p['Reason'] = $WriteBlocked
    }
    return $p
}

#endregion
