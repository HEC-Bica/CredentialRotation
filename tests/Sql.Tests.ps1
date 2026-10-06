# Pester 3.4 tests for src\lib\Sql.ps1. Synthetic data only.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here '..\src\lib\Compat.ps1')
. (Join-Path $here '..\src\lib\Sql.ps1')

function Get-TestSqlSid {
    param([string]$Name)
    switch ($Name.ToLowerInvariant()) {
        '.\applicationuser'      { return 'S-1-5-21-1000-2000-3000-1005' }
        'nt service\mssqlserver' { return 'S-1-5-80-1000-2000-3000-4000-5000' }
    }
    return $null
}

function Get-TestSidBytes {
    param([string]$Sid)
    $s = New-Object System.Security.Principal.SecurityIdentifier($Sid)
    $b = New-Object byte[] ($s.BinaryLength)
    $s.GetBinaryForm($b, 0)
    return , $b
}

function New-TestLoginRow {
    param([string]$Name, [string]$Type, $Sid, [bool]$Disabled = $false, $PolicyChecked = $null, $ExpirationChecked = $null,
          $IsLocked = $null, $BadPasswordCount = $null, $PasswordLastSetTime = $null, $IsSysadmin = 1)
    return @{
        name                  = $Name
        type_desc             = $Type
        is_disabled           = $Disabled
        sid                   = $Sid
        is_policy_checked     = $PolicyChecked
        is_expiration_checked = $ExpirationChecked
        IsLocked              = $IsLocked
        BadPasswordCount      = $BadPasswordCount
        PasswordLastSetTime   = $PasswordLastSetTime
        IsSysadmin            = $IsSysadmin
    }
}

function Get-TestLoginRows {
    $sqlSid = [byte[]](0x1A, 0x2B, 0x3C, 0x4D, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B)
    return @(
        (New-TestLoginRow -Name 'BUILTIN\Users' -Type 'WINDOWS_GROUP' -Sid (Get-TestSidBytes 'S-1-5-32-545') -IsSysadmin 0),
        (New-TestLoginRow -Name 'sa' -Type 'SQL_LOGIN' -Sid ([byte[]](0x01)) -Disabled $true -PolicyChecked $true -ExpirationChecked $false -IsLocked 0 -BadPasswordCount 0),
        (New-TestLoginRow -Name 'SQLTestApp' -Type 'SQL_LOGIN' -Sid $sqlSid -PolicyChecked $true -ExpirationChecked $false -IsLocked 1 -BadPasswordCount 3 -PasswordLastSetTime ([datetime]'2020-01-02T03:04:05')),
        (New-TestLoginRow -Name 'WIN-0LDNAME01\TestAdmin' -Type 'WINDOWS_LOGIN' -Sid (Get-TestSidBytes 'S-1-5-21-1000-2000-3000-1001')),
        (New-TestLoginRow -Name 'DESKTOP-0LDNAME2\ApplicationUser' -Type 'WINDOWS_LOGIN' -Sid (Get-TestSidBytes 'S-1-5-21-1000-2000-3000-1005'))
    )
}

Describe 'Get-CrSqlQueryText' {
    It 'returns constant read-only SELECTs' {
        foreach ($n in @('Server', 'Logins', 'LoginsBasic', 'MasterFiles', 'AgentJobs', 'Credentials', 'Proxies', 'LinkedLogins')) {
            $q = Get-CrSqlQueryText -Name $n
            $q | Should Match '^SELECT '
            $q | Should Not Match ';'
            $q | Should Not Match '\b(ALTER|INSERT|UPDATE|DELETE|DROP|EXEC|EXECUTE|GRANT|CREATE|MERGE|TRUNCATE)\b'
            $q | Should Not Match '\bsp_'
        }
    }
    It 'reads master files of database_id 1' {
        Get-CrSqlQueryText -Name 'MasterFiles' | Should Match 'sys\.master_files WHERE database_id = 1'
    }
    It 'throws for an unknown query name' {
        { Get-CrSqlQueryText -Name 'SELECT 1' } | Should Throw
    }
}

Describe 'Get-CrSqlState' {
    Mock Resolve-CrNameToSid { Get-TestSqlSid -Name $Name }
    Mock Close-CrSqlConnection { }

    Context 'no default instance' {
        Mock Get-CrSqlInstanceNames {
            @{ View = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server'; Name = 'SQLEXPRESS'; InstanceId = 'MSSQL14.SQLEXPRESS' }
        }
        Mock Get-CrSqlServiceWmi { throw 'must not be called' }
        Mock Open-CrSqlConnection { throw 'must not be called' }
        $r = Get-CrSqlState

        It 'reports absence without an error and lists other instances' {
            $r['DefaultInstancePresent'] | Should Be $false
            $r['Error'] | Should BeNullOrEmpty
            $r['Connected'] | Should Be $false
            ($r['OtherInstances'] -join ',') | Should Be 'SQLEXPRESS'
            Assert-MockCalled Open-CrSqlConnection -Times 0 -Exactly
        }
    }

    Context 'default instance stopped' {
        Mock Get-CrSqlInstanceNames {
            @(
                @{ View = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server'; Name = 'MSSQLSERVER'; InstanceId = 'MSSQL14.MSSQLSERVER' },
                @{ View = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Microsoft SQL Server'; Name = 'MSSQLSERVER'; InstanceId = 'MSSQL14.MSSQLSERVER' }
            )
        }
        Mock Get-CrSqlServiceWmi { New-Object PSObject -Property @{ State = 'Stopped'; StartName = 'NT Service\MSSQLSERVER' } }
        Mock Open-CrSqlConnection { throw 'must not be called' }
        $r = Get-CrSqlState

        It 'reports the service without connecting' {
            $r['DefaultInstancePresent'] | Should Be $true
            $r['ServiceName'] | Should Be 'MSSQLSERVER'
            $r['ServiceState'] | Should Be 'Stopped'
            $r['ServiceAccountSid'] | Should Be 'S-1-5-80-1000-2000-3000-4000-5000'
            $r['Connected'] | Should Be $false
            $r['Error'] | Should BeNullOrEmpty
            @($r['OtherInstances']).Count | Should Be 0
            Assert-MockCalled Open-CrSqlConnection -Times 0 -Exactly
        }
    }

    Context 'SQL Server 2008 R2 Express running as ApplicationUser' {
        Mock Get-CrSqlInstanceNames {
            @{ View = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server'; Name = 'MSSQLSERVER'; InstanceId = 'MSSQL10_50.MSSQLSERVER' }
        }
        Mock Get-CrSqlServiceWmi { New-Object PSObject -Property @{ State = 'Running'; StartName = '.\ApplicationUser' } }
        Mock Open-CrSqlConnection { New-Object PSObject -Property @{ Fake = $true } }
        Mock Invoke-CrSqlQuery { throw ('unexpected query ' + $Name) }
        Mock Invoke-CrSqlQuery -ParameterFilter { $Name -eq 'Server' } {
            @{ ProductVersion = '10.50.6000.34'; Edition = 'Express Edition (64-bit)'; IsIntegratedSecurityOnly = 0; ConnectedAs = 'SM-TEST01\TestOperator'; ConnectedAsSysadmin = 1 }
        }
        Mock Invoke-CrSqlQuery -ParameterFilter { $Name -eq 'Logins' } { Get-TestLoginRows }
        Mock Invoke-CrSqlQuery -ParameterFilter { $Name -eq 'MasterFiles' } {
            @(
                @{ physical_name = 'C:\Program Files\Microsoft SQL Server\MSSQL10_50.MSSQLSERVER\MSSQL\DATA\master.mdf' },
                @{ physical_name = 'C:\Program Files\Microsoft SQL Server\MSSQL10_50.MSSQLSERVER\MSSQL\DATA\mastlog.ldf' }
            )
        }
        Mock Invoke-CrSqlQuery -ParameterFilter { $Name -eq 'AgentJobs' } { throw 'Invalid object name msdb.dbo.sysjobs.' }
        Mock Invoke-CrSqlQuery -ParameterFilter { $Name -eq 'Credentials' } { }
        Mock Invoke-CrSqlQuery -ParameterFilter { $Name -eq 'Proxies' } { }
        Mock Invoke-CrSqlQuery -ParameterFilter { $Name -eq 'LinkedLogins' } {
            @{ server_name = 'TESTLINK'; local_login = $null; uses_self_credential = $true; remote_name = $null }
        }
        $r = Get-CrSqlState

        It 'reports service, account SID and connection' {
            $r['DefaultInstancePresent'] | Should Be $true
            $r['ServiceState'] | Should Be 'Running'
            $r['ServiceAccount'] | Should Be '.\ApplicationUser'
            $r['ServiceAccountSid'] | Should Be 'S-1-5-21-1000-2000-3000-1005'
            $r['Connected'] | Should Be $true
        }
        It 'reads the server properties' {
            $r['ProductVersion'] | Should Be '10.50.6000.34'
            $r['MajorVersion'] | Should Be 10
            ($r['MajorVersion'] -is [int]) | Should Be $true
            $r['IsExpress'] | Should Be $true
            $r['IsIntegratedSecurityOnly'] | Should Be $false
            $r['ConnectedAs'] | Should Be 'SM-TEST01\TestOperator'
            $r['ConnectedAsSysadmin'] | Should Be $true
        }
        It 'converts Windows login SIDs to SID strings despite old computer names' {
            $admin = @($r['Logins'] | Where-Object { $_['Name'] -eq 'WIN-0LDNAME01\TestAdmin' })[0]
            $admin['Type'] | Should Be 'WINDOWS_LOGIN'
            $admin['Sid'] | Should Be 'S-1-5-21-1000-2000-3000-1001'
            $admin['IsSysadmin'] | Should Be $true
            $admin['IsPolicyChecked'] | Should BeNullOrEmpty
            $app = @($r['Logins'] | Where-Object { $_['Name'] -eq 'DESKTOP-0LDNAME2\ApplicationUser' })[0]
            $app['Sid'] | Should Be 'S-1-5-21-1000-2000-3000-1005'
            $users = @($r['Logins'] | Where-Object { $_['Name'] -eq 'BUILTIN\Users' })[0]
            $users['Sid'] | Should Be 'S-1-5-32-545'
            $users['IsSysadmin'] | Should Be $false
        }
        It 'keeps SQL login SIDs as hex and reads the password properties' {
            $l = @($r['Logins'] | Where-Object { $_['Name'] -eq 'SQLTestApp' })[0]
            $l['Type'] | Should Be 'SQL_LOGIN'
            $l['Sid'] | Should Be '0x1A2B3C4D000102030405060708090A0B'
            $l['IsLocked'] | Should Be $true
            $l['BadPasswordCount'] | Should Be 3
            $l['IsPolicyChecked'] | Should Be $true
            $l['IsExpirationChecked'] | Should Be $false
            $l['PasswordLastSetTime'] | Should Be ([datetime]'2020-01-02T03:04:05')
            $sa = @($r['Logins'] | Where-Object { $_['Name'] -eq 'sa' })[0]
            $sa['IsDisabled'] | Should Be $true
            $sa['IsLocked'] | Should Be $false
        }
        It 'has exactly the contract keys per login' {
            ((@($r['Logins'][0].Keys) | Sort-Object) -join ',') | Should Be 'BadPasswordCount,IsDisabled,IsExpirationChecked,IsLocked,IsPolicyChecked,IsSysadmin,Name,PasswordLastSetTime,Sid,Type'
        }
        It 'lists the master physical file names' {
            @($r['MasterFiles']).Count | Should Be 2
            $r['MasterFiles'][0] | Should Match 'master\.mdf$'
        }
        It 'records a failing query and still runs the others' {
            $r['Error'] | Should Match '^AgentJobs: Invalid object name'
            @($r['AgentJobs']).Count | Should Be 0
            @($r['Credentials']).Count | Should Be 0
            @($r['Proxies']).Count | Should Be 0
            @($r['LinkedLogins']).Count | Should Be 1
            $r['LinkedLogins'][0]['Server'] | Should Be 'TESTLINK'
            $r['LinkedLogins'][0]['UsesSelfCredential'] | Should Be $true
        }
        It 'closes the connection once' {
            Assert-MockCalled Close-CrSqlConnection -Times 1 -Exactly
        }
        It 'never runs the fallback login query when LOGINPROPERTY works' {
            Assert-MockCalled Invoke-CrSqlQuery -Times 0 -Exactly -ParameterFilter { $Name -eq 'LoginsBasic' }
        }
    }

    Context 'SQL Server 2017 Standard, LOGINPROPERTY query failing' {
        Mock Get-CrSqlInstanceNames {
            @(
                @{ View = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server'; Name = 'MSSQLSERVER'; InstanceId = 'MSSQL14.MSSQLSERVER' },
                @{ View = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server'; Name = 'TESTNAMED'; InstanceId = 'MSSQL14.TESTNAMED' }
            )
        }
        Mock Get-CrSqlServiceWmi { New-Object PSObject -Property @{ State = 'Running'; StartName = '.\ApplicationUser' } }
        Mock Open-CrSqlConnection { New-Object PSObject -Property @{ Fake = $true } }
        Mock Invoke-CrSqlQuery { }
        Mock Invoke-CrSqlQuery -ParameterFilter { $Name -eq 'Server' } {
            @{ ProductVersion = '14.0.3456.2'; Edition = 'Standard Edition (64-bit)'; IsIntegratedSecurityOnly = 0; ConnectedAs = 'SM-TEST01\TestOperator'; ConnectedAsSysadmin = 1 }
        }
        Mock Invoke-CrSqlQuery -ParameterFilter { $Name -eq 'Logins' } { throw 'LOGINPROPERTY failed' }
        Mock Invoke-CrSqlQuery -ParameterFilter { $Name -eq 'LoginsBasic' } {
            @{ name = 'SQLTestService'; type_desc = 'SQL_LOGIN'; is_disabled = $false; sid = [byte[]](0xAB, 0xCD); is_policy_checked = $true; is_expiration_checked = $false; IsSysadmin = 1 }
        }
        Mock Invoke-CrSqlQuery -ParameterFilter { $Name -eq 'AgentJobs' } {
            @(
                @{ name = 'Test Job 1'; owner_name = 'SQLTestService'; enabled = $true },
                @{ name = 'Test Job 2'; owner_name = 'SQLTestService'; enabled = $false }
            )
        }
        $r = Get-CrSqlState

        It 'reads version 14 Standard' {
            $r['MajorVersion'] | Should Be 14
            $r['IsExpress'] | Should Be $false
            $r['Edition'] | Should Be 'Standard Edition (64-bit)'
        }
        It 'lists other instances' {
            ($r['OtherInstances'] -join ',') | Should Be 'TESTNAMED'
        }
        It 'falls back to the basic login query and records the error' {
            $r['Error'] | Should Match '^Logins: LOGINPROPERTY failed'
            @($r['Logins']).Count | Should Be 1
            $r['Logins'][0]['Sid'] | Should Be '0xABCD'
            $r['Logins'][0]['IsLocked'] | Should BeNullOrEmpty
            $r['Logins'][0]['IsSysadmin'] | Should Be $true
        }
        It 'reads Agent job owners' {
            @($r['AgentJobs']).Count | Should Be 2
            $r['AgentJobs'][0]['Owner'] | Should Be 'SQLTestService'
            $r['AgentJobs'][1]['Enabled'] | Should Be $false
            ((@($r['AgentJobs'][0].Keys) | Sort-Object) -join ',') | Should Be 'Enabled,Name,Owner'
        }
    }

    Context 'connection fails' {
        Mock Get-CrSqlInstanceNames {
            @{ View = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server'; Name = 'MSSQLSERVER'; InstanceId = 'MSSQL14.MSSQLSERVER' }
        }
        Mock Get-CrSqlServiceWmi { New-Object PSObject -Property @{ State = 'Running'; StartName = '.\ApplicationUser' } }
        Mock Open-CrSqlConnection { throw 'Login failed for user.' }
        Mock Invoke-CrSqlQuery { throw 'must not be called' }
        $r = Get-CrSqlState

        It 'records the connection error and runs no query' {
            $r['Connected'] | Should Be $false
            $r['Error'] | Should Match '^Connect: Login failed'
            Assert-MockCalled Invoke-CrSqlQuery -Times 0 -Exactly
        }
        It 'still calls the close helper' {
            Assert-MockCalled Close-CrSqlConnection -Times 1 -Exactly
        }
        It 'has exactly the contract keys' {
            $expected = 'AgentJobs,Connected,ConnectedAs,ConnectedAsSysadmin,Credentials,DefaultInstancePresent,Edition,Error,IsExpress,IsIntegratedSecurityOnly,LinkedLogins,Logins,MajorVersion,MasterFiles,OtherInstances,ProductVersion,Proxies,ServiceAccount,ServiceAccountSid,ServiceName,ServiceState'
            ((@($r.Keys) | Sort-Object) -join ',') | Should Be $expected
        }
    }
}
