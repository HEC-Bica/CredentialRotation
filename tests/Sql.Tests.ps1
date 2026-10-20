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
        foreach ($n in @('Server', 'Logins', 'LoginsBasic', 'ServerRoles', 'MasterFiles', 'AgentJobs', 'Credentials', 'Proxies', 'LinkedLogins')) {
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
        Mock Invoke-CrSqlQuery -ParameterFilter { $Name -eq 'ServerRoles' } {
            @(
                @{ member_sid = (Get-TestSidBytes 'S-1-5-21-1000-2000-3000-1001'); member_type = 'WINDOWS_LOGIN'; role_name = 'dbcreator' },
                @{ member_sid = (Get-TestSidBytes 'S-1-5-21-1000-2000-3000-1001'); member_type = 'WINDOWS_LOGIN'; role_name = 'sysadmin' },
                @{ member_sid = [byte[]](0x01); member_type = 'SQL_LOGIN'; role_name = 'sysadmin' }
            )
        }
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
            ((@($r['Logins'][0].Keys) | Sort-Object) -join ',') | Should Be 'BadPasswordCount,IsDisabled,IsExpirationChecked,IsLocked,IsPolicyChecked,IsSysadmin,Name,PasswordLastSetTime,ServerRoles,Sid,Type'
        }
        It 'attaches the explicit server role memberships by SID (D29)' {
            $admin = @($r['Logins'] | Where-Object { $_['Name'] -eq 'WIN-0LDNAME01\TestAdmin' })[0]
            (@($admin['ServerRoles']) -join ',') | Should Be 'dbcreator,sysadmin'
            $sa = @($r['Logins'] | Where-Object { $_['Name'] -eq 'sa' })[0]
            (@($sa['ServerRoles']) -join ',') | Should Be 'sysadmin'
            $app = @($r['Logins'] | Where-Object { $_['Name'] -eq 'DESKTOP-0LDNAME2\ApplicationUser' })[0]
            ($null -ne $app['ServerRoles']) | Should Be $true
            @($app['ServerRoles']).Count | Should Be 0
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
        It 'reads the server roles after the fallback too' {
            Assert-MockCalled Invoke-CrSqlQuery -Times 1 -Exactly -ParameterFilter { $Name -eq 'ServerRoles' }
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

Describe 'Get-CrSqlWriteText (D29)' {
    It 'passes the names as parameters and quotes them with QUOTENAME' {
        foreach ($n in @('CreateWindowsLogin', 'EnableLogin', 'AddServerRole', 'LoginBySid')) {
            foreach ($v in @(10, 14)) {
                $t = Get-CrSqlWriteText -Name $n -MajorVersion $v
                $t | Should Not Match 'SOP-Admin'
                $t | Should Match '@(login|sid)'
            }
        }
        Get-CrSqlWriteText -Name 'CreateWindowsLogin' | Should Match "N'CREATE LOGIN ' \+ QUOTENAME\(@login\) \+ N' FROM WINDOWS'"
        Get-CrSqlWriteText -Name 'EnableLogin' | Should Match "N'ALTER LOGIN ' \+ QUOTENAME\(@login\) \+ N' ENABLE'"
        Get-CrSqlWriteText -Name 'LoginBySid' | Should Match '^SELECT .* WHERE p\.sid = @sid$'
    }
    It 'adds server roles with sp_addsrvrolemember up to 2008 R2 and ALTER SERVER ROLE from 2012 (PLAN 7.9)' {
        Get-CrSqlWriteText -Name 'AddServerRole' -MajorVersion 9 | Should Be 'EXEC sp_addsrvrolemember @loginame = @login, @rolename = @role;'
        Get-CrSqlWriteText -Name 'AddServerRole' -MajorVersion 10 | Should Match 'sp_addsrvrolemember'
        Get-CrSqlWriteText -Name 'AddServerRole' -MajorVersion 11 | Should Match "N'ALTER SERVER ROLE ' \+ QUOTENAME\(@role\) \+ N' ADD MEMBER ' \+ QUOTENAME\(@login\)"
        Get-CrSqlWriteText -Name 'AddServerRole' -MajorVersion 14 | Should Not Match 'sp_addsrvrolemember'
    }
    It 'throws for an unknown command name' {
        { Get-CrSqlWriteText -Name 'DropLogin' } | Should Throw
    }
}

Describe 'Grant-CrSqlLoginAccess (D29)' {
    Mock Close-CrSqlConnection { }

    Context 'create the login and add sysadmin on 2008 R2' {
        Mock Open-CrSqlConnection { New-Object PSObject -Property @{ Fake = $true } }
        Mock Invoke-CrSqlCommand { , @() }
        $r = Grant-CrSqlLoginAccess -LoginName 'SM-TEST01\SOP-Admin' -CreateLogin $true -EnableLogin $false -Roles @('sysadmin') -MajorVersion 10

        It 'runs CREATE LOGIN, then the role, with the names as parameters' {
            $r.Success | Should Be $true
            ($r.Steps -join ',') | Should Be 'CreateLogin,AddRole sysadmin'
            $r.FailedStep | Should BeNullOrEmpty
            Assert-MockCalled Invoke-CrSqlCommand -Times 2 -Exactly
            Assert-MockCalled Invoke-CrSqlCommand -Times 1 -Exactly -ParameterFilter {
                $Text -match 'CREATE LOGIN' -and @($Parameters).Count -eq 1 -and $Parameters[0].Name -eq 'login' -and $Parameters[0].Value -eq 'SM-TEST01\SOP-Admin' -and -not $Query
            }
            Assert-MockCalled Invoke-CrSqlCommand -Times 1 -Exactly -ParameterFilter {
                $Text -match 'sp_addsrvrolemember' -and @($Parameters).Count -eq 2 -and $Parameters[1].Name -eq 'role' -and $Parameters[1].Value -eq 'sysadmin'
            }
            Assert-MockCalled Close-CrSqlConnection -Times 1 -Exactly
        }
    }

    Context 'a failing role on 2017' {
        Mock Open-CrSqlConnection { New-Object PSObject -Property @{ Fake = $true } }
        Mock Invoke-CrSqlCommand { , @() }
        Mock Invoke-CrSqlCommand -ParameterFilter { $Text -match 'ALTER SERVER ROLE' } { throw 'Cannot alter the role' }
        $r = Grant-CrSqlLoginAccess -LoginName 'SM-TEST01\SOP-Admin' -CreateLogin $false -EnableLogin $true -Roles @('sysadmin', 'dbcreator') -MajorVersion 14

        It 'stops at the failing step and reports what is done' {
            $r.Success | Should Be $false
            ($r.Steps -join ',') | Should Be 'EnableLogin'
            $r.FailedStep | Should Be 'AddRole sysadmin'
            $r.Error | Should Match 'Cannot alter the role'
            Assert-MockCalled Invoke-CrSqlCommand -Times 2 -Exactly
            Assert-MockCalled Close-CrSqlConnection -Times 1 -Exactly
        }
    }

    Context 'the connection fails' {
        Mock Open-CrSqlConnection { throw 'Login failed for user.' }
        Mock Invoke-CrSqlCommand { throw 'must not be called' }
        $r = Grant-CrSqlLoginAccess -LoginName 'SM-TEST01\SOP-Admin' -CreateLogin $true -EnableLogin $false -Roles @('sysadmin') -MajorVersion 14

        It 'reports the Connect step and runs nothing' {
            $r.Success | Should Be $false
            $r.FailedStep | Should Be 'Connect'
            $r.Error | Should Match 'Login failed'
            @($r.Steps).Count | Should Be 0
            Assert-MockCalled Invoke-CrSqlCommand -Times 0 -Exactly
        }
    }

    It 'refuses a role that is not a fixed server role, before connecting' {
        Mock Open-CrSqlConnection { throw 'must not be called' }
        { Grant-CrSqlLoginAccess -LoginName 'SM-TEST01\SOP-Admin' -CreateLogin $true -EnableLogin $false -Roles @('db_owner') -MajorVersion 14 } | Should Throw 'not a fixed server role'
    }

    It 'requires a login name' {
        { Grant-CrSqlLoginAccess -LoginName '' -CreateLogin $true -EnableLogin $false -Roles @() -MajorVersion 14 } | Should Throw
    }
}

Describe 'Get-CrSqlLoginAccess (D29)' {
    Mock Close-CrSqlConnection { }

    Context 'a login with two roles' {
        Mock Open-CrSqlConnection { New-Object PSObject -Property @{ Fake = $true } }
        Mock Invoke-CrSqlCommand {
            , @(
                @{ name = 'SM-TEST01\SOP-Admin'; is_disabled = $false; role_name = 'sysadmin' },
                @{ name = 'SM-TEST01\SOP-Admin'; is_disabled = $false; role_name = 'dbcreator' }
            )
        }
        $r = Get-CrSqlLoginAccess -Sid 'S-1-5-21-1000-2000-3000-1040'

        It 'reads the login and its roles by the binary SID' {
            $r.Found | Should Be $true
            $r.Name | Should Be 'SM-TEST01\SOP-Admin'
            $r.IsDisabled | Should Be $false
            ($r.Roles -join ',') | Should Be 'sysadmin,dbcreator'
            $r.Error | Should BeNullOrEmpty
            Assert-MockCalled Invoke-CrSqlCommand -Times 1 -Exactly -ParameterFilter {
                $Query -and $Text -match 'WHERE p\.sid = @sid' -and $Parameters[0].Type -eq 'VarBinary' -and $Parameters[0].Value.Length -eq 28
            }
        }
    }

    Context 'a disabled login without roles' {
        Mock Open-CrSqlConnection { New-Object PSObject -Property @{ Fake = $true } }
        Mock Invoke-CrSqlCommand { , @(@{ name = 'SM-TEST01\SOP-Admin'; is_disabled = $true; role_name = $null }) }
        $r = Get-CrSqlLoginAccess -Sid 'S-1-5-21-1000-2000-3000-1040'

        It 'reports it disabled with no roles' {
            $r.Found | Should Be $true
            $r.IsDisabled | Should Be $true
            @($r.Roles).Count | Should Be 0
        }
    }

    Context 'no login' {
        Mock Open-CrSqlConnection { New-Object PSObject -Property @{ Fake = $true } }
        Mock Invoke-CrSqlCommand { , @() }
        $r = Get-CrSqlLoginAccess -Sid 'S-1-5-21-1000-2000-3000-1040'

        It 'reports Found = $false without an error' {
            $r.Found | Should Be $false
            $r.Error | Should BeNullOrEmpty
        }
    }

    Context 'the connection fails' {
        Mock Open-CrSqlConnection { throw 'Login failed for user.' }
        $r = Get-CrSqlLoginAccess -Sid 'S-1-5-21-1000-2000-3000-1040'

        It 'returns the error' {
            $r.Found | Should Be $false
            $r.Error | Should Match 'Login failed'
        }
    }
}

Describe 'Get-CrSqlAccessPlan (D29)' {
    $bicaAdmin = 'S-1-5-21-1000-2000-3000-1001'
    $bicaRemote = 'S-1-5-21-1000-2000-3000-1002'
    $sop = 'S-1-5-21-1000-2000-3000-1040'

    function New-TestWindowsLogin {
        param([string]$Name, [string]$Sid, $Roles, [bool]$Sysadmin = $false, [bool]$Disabled = $false)
        return @{ Name = $Name; Type = 'WINDOWS_LOGIN'; Sid = $Sid; IsDisabled = $Disabled; IsSysadmin = $Sysadmin; ServerRoles = $Roles }
    }
    function New-TestSqlAccessState {
        param($Logins, [string]$ServiceState = 'Running', [bool]$Connected = $true, $OtherInstances = @(), $AgentJobs = @(), [bool]$Present = $true, [string]$SqlError)
        return @{
            Computer = @{ Name = 'SM-TEST01' }
            Sql      = @{ DefaultInstancePresent = $Present; ServiceState = $ServiceState; Connected = $Connected; Error = $SqlError; MajorVersion = 10
                          Logins = @($Logins); OtherInstances = @($OtherInstances); AgentJobs = @($AgentJobs) }
        }
    }
    function New-TestSqlAccessEntry {
        return @{ Id = 'SOPAdmin'; SqlAccess = 'FromReplaced'
                  Replaced = @(@{ Name = 'BiCA Admin'; Sid = $bicaAdmin; Enabled = $true }, @{ Name = 'BiCA Remote'; Sid = $bicaRemote; Enabled = $false }) }
    }
    $sourceLogins = @(
        (New-TestWindowsLogin -Name 'OLD-NAME01\BiCA Admin' -Sid $bicaAdmin -Roles @('dbcreator', 'sysadmin') -Sysadmin $true),
        (New-TestWindowsLogin -Name 'OLD-NAME01\BiCA Remote' -Sid $bicaRemote -Roles $null -Sysadmin $true),
        @{ Name = 'sa'; Type = 'SQL_LOGIN'; Sid = '0x01'; IsDisabled = $true; IsSysadmin = $true; ServerRoles = @('sysadmin') }
    )

    It 'needs nothing when none of the replaced accounts exists' {
        $p = Get-CrSqlAccessPlan -State (New-TestSqlAccessState -Logins $sourceLogins) -Entry @{ Replaced = @() } -TargetSid $sop -TargetName 'SOP-Admin'
        $p.Needed | Should Be $false
        $p.Unknown | Should Be $false
        $p.LoginName | Should Be 'SM-TEST01\SOP-Admin'
    }

    It 'needs nothing without a default instance, and notes a named instance' {
        $p = Get-CrSqlAccessPlan -State (New-TestSqlAccessState -Logins @() -Present $false -OtherInstances @('SQLEXPRESS')) -Entry (New-TestSqlAccessEntry) -TargetSid $sop -TargetName 'SOP-Admin'
        $p.Needed | Should Be $false
        $p.Unknown | Should Be $false
        @($p.Notes).Count | Should Be 1
        $p.Notes[0] | Should Match 'instance SQLEXPRESS is not covered'
    }

    It 'is unknown while the default instance is stopped' {
        $p = Get-CrSqlAccessPlan -State (New-TestSqlAccessState -Logins @() -ServiceState 'Stopped' -Connected $false) -Entry (New-TestSqlAccessEntry) -TargetSid $sop -TargetName 'SOP-Admin'
        $p.Unknown | Should Be $true
        $p.Needed | Should Be $false
        $p.Reason | Should Match 'not running \(state Stopped\)'
    }

    It 'is unknown without a connection and tells which account to run as' {
        $p = Get-CrSqlAccessPlan -State (New-TestSqlAccessState -Logins @() -Connected $false -SqlError 'Connect: Login failed for user') -Entry (New-TestSqlAccessEntry) -TargetSid $sop -TargetName 'SOP-Admin'
        $p.Unknown | Should Be $true
        $p.Reason | Should Match 'no connection.*Login failed'
        $p.Reason | Should Match 'sysadmin through its own Windows login, e\.g\. BiCA Admin, BiCA Remote'
    }

    It 'is unknown when the logins could not be read' {
        $p = Get-CrSqlAccessPlan -State (New-TestSqlAccessState -Logins @() -SqlError 'Logins: denied; LoginsBasic: denied') -Entry (New-TestSqlAccessEntry) -TargetSid $sop -TargetName 'SOP-Admin'
        $p.Unknown | Should Be $true
        $p.Reason | Should Match 'could not be read'
    }

    It 'creates the login with sysadmin for an account still to be created (sysadmin covers the other roles)' {
        $p = Get-CrSqlAccessPlan -State (New-TestSqlAccessState -Logins $sourceLogins) -Entry (New-TestSqlAccessEntry) -TargetSid $null -TargetName 'SOP-Admin'
        $p.Unknown | Should Be $false
        $p.Blocked | Should Be $false
        $p.Needed | Should Be $true
        $p.CreateLogin | Should Be $true
        $p.EnableLogin | Should Be $false
        $p.LoginName | Should Be 'SM-TEST01\SOP-Admin'
        (@($p.Roles) -join ',') | Should Be 'sysadmin'
        (@($p.MissingRoles) -join ',') | Should Be 'sysadmin'
        (@($p.Sources) -join '; ') | Should Be 'BiCA Admin (OLD-NAME01\BiCA Admin); BiCA Remote (OLD-NAME01\BiCA Remote)'
        @($p.Notes).Count | Should Be 0
    }

    It 'needs nothing when the existing login of the account is sysadmin already (stale computer name)' {
        $logins = $sourceLogins + @(New-TestWindowsLogin -Name 'OLD-NAME01\SOP-Admin' -Sid $sop -Roles @('sysadmin') -Sysadmin $true)
        $p = Get-CrSqlAccessPlan -State (New-TestSqlAccessState -Logins $logins) -Entry (New-TestSqlAccessEntry) -TargetSid $sop -TargetName 'SOP-Admin'
        $p.Needed | Should Be $false
        $p.CreateLogin | Should Be $false
        $p.LoginName | Should Be 'OLD-NAME01\SOP-Admin'
        @($p.Sources).Count | Should Be 2
    }

    It 'enables a disabled login and adds the missing fixed roles; database permissions of non-sysadmin logins are noted' {
        $logins = @(
            (New-TestWindowsLogin -Name 'OLD-NAME01\BiCA Admin' -Sid $bicaAdmin -Roles @('dbcreator', 'MyServerRole')),
            (New-TestWindowsLogin -Name 'OLD-NAME01\BiCA Remote' -Sid $bicaRemote -Roles @('bulkadmin')),
            (New-TestWindowsLogin -Name 'SM-TEST01\SOP-Admin' -Sid $sop -Roles @('bulkadmin') -Disabled $true)
        )
        $p = Get-CrSqlAccessPlan -State (New-TestSqlAccessState -Logins $logins) -Entry (New-TestSqlAccessEntry) -TargetSid $sop -TargetName 'SOP-Admin'
        $p.Needed | Should Be $true
        $p.CreateLogin | Should Be $false
        $p.EnableLogin | Should Be $true
        (@($p.Roles) -join ',') | Should Be 'dbcreator,bulkadmin'
        (@($p.MissingRoles) -join ',') | Should Be 'dbcreator'
        $notes = @($p.Notes) -join ' | '
        $notes | Should Match 'not fixed server roles are not copied to SOP-Admin: MyServerRole \(OLD-NAME01\\BiCA Admin\)'
        $notes | Should Match 'not sysadmin: SOP-Admin gets their server roles, but not their database permissions'
    }

    It 'skips a disabled source login with a note' {
        $logins = @((New-TestWindowsLogin -Name 'OLD-NAME01\BiCA Admin' -Sid $bicaAdmin -Roles @('sysadmin') -Sysadmin $true -Disabled $true))
        $p = Get-CrSqlAccessPlan -State (New-TestSqlAccessState -Logins $logins) -Entry (New-TestSqlAccessEntry) -TargetSid $sop -TargetName 'SOP-Admin'
        $p.Needed | Should Be $false
        @($p.Sources).Count | Should Be 0
        (@($p.Notes) -join ' | ') | Should Match 'login OLD-NAME01\\BiCA Admin of BiCA Admin is disabled'
    }

    It 'is blocked by a login with the same name for another SID' {
        $logins = $sourceLogins + @(New-TestWindowsLogin -Name 'sm-test01\sop-admin' -Sid 'S-1-5-21-1000-2000-3000-1999' -Roles @())
        $p = Get-CrSqlAccessPlan -State (New-TestSqlAccessState -Logins $logins) -Entry (New-TestSqlAccessEntry) -TargetSid $sop -TargetName 'SOP-Admin'
        $p.Needed | Should Be $true
        $p.CreateLogin | Should Be $true
        $p.Blocked | Should Be $true
        $p.Reason | Should Match 'already exists for another SID'
    }

    It 'is blocked by the write conditions of the preflight only when something is needed' {
        $p = Get-CrSqlAccessPlan -State (New-TestSqlAccessState -Logins $sourceLogins) -Entry (New-TestSqlAccessEntry) -TargetSid $sop -TargetName 'SOP-Admin' -WriteBlocked 'the running account is not sysadmin'
        $p.Needed | Should Be $true
        $p.Blocked | Should Be $true
        $p.Reason | Should Be 'the running account is not sysadmin'
        $logins = $sourceLogins + @(New-TestWindowsLogin -Name 'SM-TEST01\SOP-Admin' -Sid $sop -Roles @('sysadmin') -Sysadmin $true)
        $q = Get-CrSqlAccessPlan -State (New-TestSqlAccessState -Logins $logins) -Entry (New-TestSqlAccessEntry) -TargetSid $sop -TargetName 'SOP-Admin' -WriteBlocked 'the running account is not sysadmin'
        $q.Needed | Should Be $false
        $q.Blocked | Should Be $false
    }

    It 'notes Agent jobs owned by a source login' {
        $jobs = @(@{ Name = 'Backup'; Owner = 'old-name01\bica admin'; Enabled = $true }, @{ Name = 'Cleanup'; Owner = 'SQLService'; Enabled = $true })
        $p = Get-CrSqlAccessPlan -State (New-TestSqlAccessState -Logins $sourceLogins -AgentJobs $jobs) -Entry (New-TestSqlAccessEntry) -TargetSid $sop -TargetName 'SOP-Admin'
        @($p.Notes).Count | Should Be 1
        $p.Notes[0] | Should Match "job 'Backup' is owned by the login OLD-NAME01\\BiCA Admin"
    }

    It 'uses IsSysadmin when the server roles are unknown' {
        $logins = @((New-TestWindowsLogin -Name 'OLD-NAME01\BiCA Remote' -Sid $bicaRemote -Roles $null -Sysadmin $true))
        $p = Get-CrSqlAccessPlan -State (New-TestSqlAccessState -Logins $logins) -Entry (New-TestSqlAccessEntry) -TargetSid $sop -TargetName 'SOP-Admin'
        (@($p.Roles) -join ',') | Should Be 'sysadmin'
        @($p.Notes).Count | Should Be 0
    }
}
