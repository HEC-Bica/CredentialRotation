# Pester 3.4 tests for src\lib\Services.ps1. Synthetic data only.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here '..\src\lib\Compat.ps1')
. (Join-Path $here '..\src\lib\Services.ps1')

# Stub for the Native.ps1 write wrapper (another module); mocked below.
function Set-CrServiceLogonPassword { param([string]$ServiceName, [string]$Account, $Secret) }

function Get-TestServiceSid {
    param([string]$Name)
    switch ($Name.ToLowerInvariant()) {
        '.\applicationuser'           { return 'S-1-5-21-1000-2000-3000-1005' }
        'localsystem'                 { return 'S-1-5-18' }
        'nt authority\localservice'   { return 'S-1-5-19' }
        'nt authority\networkservice' { return 'S-1-5-20' }
    }
    return $null
}

function New-TestWmiService {
    param([string]$Name, [string]$StartName, [string]$PathName, [string]$StartMode = 'Auto', [string]$State = 'Running')
    return (New-Object PSObject -Property @{
        Name        = $Name
        DisplayName = 'Display ' + $Name
        StartName   = $StartName
        PathName    = $PathName
        StartMode   = $StartMode
        State       = $State
    })
}

function New-TestController {
    param([string]$Name, [string[]]$Dependents = @(), [string[]]$DependsOn = @())
    $dep = @()
    foreach ($d in $Dependents) { $dep += (New-Object PSObject -Property @{ Name = $d }) }
    $on = @()
    foreach ($d in $DependsOn) { $on += (New-Object PSObject -Property @{ Name = $d }) }
    return (New-Object PSObject -Property @{ Name = $Name; DependentServices = $dep; ServicesDependedOn = $on })
}

Describe 'Get-CrExecutablePath' {
    It 'returns the quoted executable without arguments' {
        Get-CrExecutablePath -CommandLine '"C:\Program Files\Vendor\App Server.exe" -user x -pass y' | Should Be 'C:\Program Files\Vendor\App Server.exe'
    }
    It 'returns an unquoted executable with spaces up to the extension' {
        Get-CrExecutablePath -CommandLine 'C:\Program Files\Vendor\svc.exe /secret:abc' | Should Be 'C:\Program Files\Vendor\svc.exe'
    }
    It 'keeps environment variables in the path' {
        Get-CrExecutablePath -CommandLine '%SystemRoot%\System32\svchost.exe -k LocalService' | Should Be '%SystemRoot%\System32\svchost.exe'
    }
    It 'falls back to the first token without a known extension' {
        Get-CrExecutablePath -CommandLine 'C:\Tools\runner --token abc' | Should Be 'C:\Tools\runner'
    }
    It 'returns null for an empty command line' {
        Get-CrExecutablePath -CommandLine '' | Should BeNullOrEmpty
    }
}

Describe 'Get-CrServices' {
    Mock Resolve-CrNameToSid { Get-TestServiceSid -Name $Name }

    Context 'synthetic machine with ApplicationUser services' {
        Mock Get-CrServiceWmiObjects {
            @(
                (New-TestWmiService -Name 'MSSQLSERVER' -StartName '.\ApplicationUser' -PathName '"C:\Program Files\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\Binn\sqlservr.exe" -sMSSQLSERVER'),
                (New-TestWmiService -Name 'SQLSERVERAGENT' -StartName '.\ApplicationUser' -PathName '"C:\Program Files\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\Binn\SQLAGENT.EXE" -i MSSQLSERVER'),
                (New-TestWmiService -Name 'BootTest' -StartName '.\ApplicationUser' -PathName 'C:\Tools\srvany.exe -password=SyntheticSecret1'),
                (New-TestWmiService -Name 'Spooler' -StartName 'LocalSystem' -PathName 'C:\Windows\System32\spoolsv.exe'),
                (New-TestWmiService -Name 'TestLocalSvc' -StartName 'NT AUTHORITY\LocalService' -PathName '%SystemRoot%\System32\svchost.exe -k LocalService' -StartMode 'Manual' -State 'Stopped'),
                (New-TestWmiService -Name 'NoAccount' -StartName '' -PathName 'C:\Windows\System32\x.exe')
            )
        }
        Mock Get-CrServiceControllers {
            @(
                (New-TestController -Name 'MSSQLSERVER' -Dependents @('SQLSERVERAGENT', 'TestRetailService')),
                (New-TestController -Name 'SQLSERVERAGENT' -DependsOn @('MSSQLSERVER'))
            )
        }
        $r = Get-CrServices

        It 'returns an array of every service with a StartName' {
            ($r -is [array]) | Should Be $true
            @($r).Count | Should Be 5
        }
        It 'normalizes StartName to a SID' {
            $sql = @($r | Where-Object { $_['Name'] -eq 'MSSQLSERVER' })[0]
            $sql['StartName'] | Should Be '.\ApplicationUser'
            $sql['StartNameSid'] | Should Be 'S-1-5-21-1000-2000-3000-1005'
            $sys = @($r | Where-Object { $_['Name'] -eq 'Spooler' })[0]
            $sys['StartNameSid'] | Should Be 'S-1-5-18'
        }
        It 'keeps only the executable of PathName (D4)' {
            $boot = @($r | Where-Object { $_['Name'] -eq 'BootTest' })[0]
            $boot['PathExecutable'] | Should Be 'C:\Tools\srvany.exe'
            foreach ($s in $r) {
                foreach ($k in @($s.Keys)) {
                    ([string]$s[$k]) | Should Not Match 'SyntheticSecret1'
                }
            }
        }
        It 'has exactly the contract keys' {
            $expected = 'DependentServices,DependsOn,DisplayName,Name,PathExecutable,StartMode,StartName,StartNameSid,State'
            ((@($r[0].Keys) | Sort-Object) -join ',') | Should Be $expected
        }
        It 'fills dependency names' {
            $sql = @($r | Where-Object { $_['Name'] -eq 'MSSQLSERVER' })[0]
            ($sql['DependentServices'] -join ',') | Should Be 'SQLSERVERAGENT,TestRetailService'
            @($sql['DependsOn']).Count | Should Be 0
            $agent = @($r | Where-Object { $_['Name'] -eq 'SQLSERVERAGENT' })[0]
            ($agent['DependsOn'] -join ',') | Should Be 'MSSQLSERVER'
        }
        It 'keeps StartMode and State as strings' {
            $local = @($r | Where-Object { $_['Name'] -eq 'TestLocalSvc' })[0]
            $local['StartMode'] | Should Be 'Manual'
            $local['State'] | Should Be 'Stopped'
            $local['StartNameSid'] | Should Be 'S-1-5-19'
        }
        It 'resolves each distinct StartName once' {
            Assert-MockCalled Resolve-CrNameToSid -Times 1 -Exactly -ParameterFilter { $Name -eq '.\ApplicationUser' }
        }
    }

    Context 'single service' {
        Mock Get-CrServiceWmiObjects { New-TestWmiService -Name 'Only' -StartName 'LocalSystem' -PathName 'C:\x.exe' }
        Mock Get-CrServiceControllers { }
        $r = Get-CrServices

        It 'still returns an array' {
            ($r -is [array]) | Should Be $true
            @($r).Count | Should Be 1
            @($r[0]['DependentServices']).Count | Should Be 0
        }
    }

    Context 'no services' {
        Mock Get-CrServiceWmiObjects { }
        Mock Get-CrServiceControllers { }
        $r = Get-CrServices

        It 'returns an empty array' {
            ($r -is [array]) | Should Be $true
            @($r).Count | Should Be 0
        }
    }
}

function New-TestServiceState {
    return @{
        Services = @(
            @{ Name = 'MSSQLSERVER'; StartName = '.\ApplicationUser'; StartNameSid = 'S-1-5-21-1000-2000-3000-1005'; State = 'Running' },
            @{ Name = 'TestRetailService'; StartName = 'SM-TEST01\applicationuser'; StartNameSid = 'S-1-5-21-1000-2000-3000-1005'; State = 'Running' },
            @{ Name = 'Spooler'; StartName = 'LocalSystem'; StartNameSid = 'S-1-5-18'; State = 'Running' },
            @{ Name = 'OtherSvc'; StartName = '.\TestOperator'; StartNameSid = 'S-1-5-21-1000-2000-3000-1002'; State = 'Stopped' },
            @{ Name = 'Unresolved'; StartName = '.\Gone'; StartNameSid = $null; State = 'Stopped' }
        )
    }
}

Describe 'Update-CrServiceCredentials' {
    $secret = ConvertTo-SecureString 'Dummy-1a' -AsPlainText -Force

    Context 'two services of the account' {
        Mock Set-CrServiceLogonPassword { @{ Success = $true; Win32Error = 0 } }
        Mock Start-Service { }
        Mock Stop-Service { }
        Mock Restart-Service { }
        $r = Update-CrServiceCredentials -State (New-TestServiceState) -Sid 'S-1-5-21-1000-2000-3000-1005' -Secret $secret

        It 'returns one result per matching service' {
            ($r -is [array]) | Should Be $true
            (@($r | ForEach-Object { $_['Name'] }) -join ',') | Should Be 'MSSQLSERVER,TestRetailService'
            @($r | Where-Object { $_['Success'] }).Count | Should Be 2
        }
        It 'touches only the services of the SID' {
            Assert-MockCalled Set-CrServiceLogonPassword -Times 2 -Exactly
            Assert-MockCalled Set-CrServiceLogonPassword -Times 0 -Exactly -ParameterFilter { @('Spooler', 'OtherSvc', 'Unresolved') -contains $ServiceName }
        }
        It 'passes the existing StartName text unchanged' {
            Assert-MockCalled Set-CrServiceLogonPassword -Times 1 -Exactly -ParameterFilter { $ServiceName -eq 'MSSQLSERVER' -and $Account -ceq '.\ApplicationUser' }
            Assert-MockCalled Set-CrServiceLogonPassword -Times 1 -Exactly -ParameterFilter { $ServiceName -eq 'TestRetailService' -and $Account -ceq 'SM-TEST01\applicationuser' }
        }
        It 'passes the SecureString, not plaintext' {
            Assert-MockCalled Set-CrServiceLogonPassword -Times 2 -Exactly -ParameterFilter { $Secret -is [System.Security.SecureString] }
        }
        It 'never starts, stops or restarts a service (D17)' {
            Assert-MockCalled Start-Service -Times 0 -Exactly
            Assert-MockCalled Stop-Service -Times 0 -Exactly
            Assert-MockCalled Restart-Service -Times 0 -Exactly
        }
        It 'has the result keys' {
            ((@($r[0].Keys) | Sort-Object) -join ',') | Should Be 'Error,FromAccount,Name,Success,ToAccount,Win32Error'
        }
    }

    Context 'one service fails' {
        Mock Set-CrServiceLogonPassword { @{ Success = $true; Win32Error = 0 } }
        Mock Set-CrServiceLogonPassword -ParameterFilter { $ServiceName -eq 'MSSQLSERVER' } { @{ Success = $false; Win32Error = 5 } }
        $r = Update-CrServiceCredentials -State (New-TestServiceState) -Sid 'S-1-5-21-1000-2000-3000-1005' -Secret $secret

        It 'reports the failure per service and continues' {
            $sql = @($r | Where-Object { $_['Name'] -eq 'MSSQLSERVER' })[0]
            $sql['Success'] | Should Be $false
            $sql['Win32Error'] | Should Be 5
            $retail = @($r | Where-Object { $_['Name'] -eq 'TestRetailService' })[0]
            $retail['Success'] | Should Be $true
        }
    }

    Context 'wrapper throws' {
        Mock Set-CrServiceLogonPassword { throw 'Native helpers are not available: test' }
        $r = Update-CrServiceCredentials -State (New-TestServiceState) -Sid 'S-1-5-21-1000-2000-3000-1005' -Secret $secret

        It 'records the message for every service' {
            @($r).Count | Should Be 2
            foreach ($e in $r) {
                $e['Success'] | Should Be $false
                $e['Error'] | Should Match 'Native helpers are not available'
            }
        }
    }

    Context 'no service of the account' {
        Mock Set-CrServiceLogonPassword { @{ Success = $true; Win32Error = 0 } }
        $r = Update-CrServiceCredentials -State (New-TestServiceState) -Sid 'S-1-5-21-1000-2000-3000-1099' -Secret $secret

        It 'returns an empty array and calls nothing' {
            ($r -is [array]) | Should Be $true
            @($r).Count | Should Be 0
            Assert-MockCalled Set-CrServiceLogonPassword -Times 0 -Exactly
        }
    }

    Context 'services could not be read' {
        Mock Set-CrServiceLogonPassword { @{ Success = $true; Win32Error = 0 } }
        $r = Update-CrServiceCredentials -State @{ Services = @{ Error = 'WMI failed' } } -Sid 'S-1-5-21-1000-2000-3000-1005' -Secret $secret

        It 'returns a single failed entry' {
            @($r).Count | Should Be 1
            $r[0]['Success'] | Should Be $false
            $r[0]['Error'] | Should Match 'WMI failed'
            Assert-MockCalled Set-CrServiceLogonPassword -Times 0 -Exactly
        }
    }
}

Describe 'Move-CrServiceAccount' {
    $fromSid = 'S-1-5-21-1000-2000-3000-1005'
    $secret = ConvertTo-SecureString 'Dummy-2b' -AsPlainText -Force

    Context 'services of the old account' {
        Mock Set-CrServiceLogonPassword { @{ Success = $true; Win32Error = 0 } }
        Mock Start-Service { }
        Mock Stop-Service { }
        Mock Restart-Service { }
        $r = Move-CrServiceAccount -State (New-TestServiceState) -FromSid $fromSid -ToAccount '.\CrTestNewUser' -Secret $secret

        It 'returns one successful result per service of FromSid' {
            ($r -is [array]) | Should Be $true
            (@($r | ForEach-Object { $_['Name'] }) -join ',') | Should Be 'MSSQLSERVER,TestRetailService'
            @($r | Where-Object { $_['Success'] }).Count | Should Be 2
            ((@($r[0].Keys) | Sort-Object) -join ',') | Should Be 'Error,FromAccount,Name,Success,ToAccount,Win32Error'
        }
        It 'moves only the services of FromSid' {
            Assert-MockCalled Set-CrServiceLogonPassword -Times 2 -Exactly
            Assert-MockCalled Set-CrServiceLogonPassword -Times 0 -Exactly -ParameterFilter { @('Spooler', 'OtherSvc', 'Unresolved') -contains $ServiceName }
        }
        It 'passes the new account for every service' {
            Assert-MockCalled Set-CrServiceLogonPassword -Times 2 -Exactly -ParameterFilter { $Account -ceq '.\CrTestNewUser' }
            Assert-MockCalled Set-CrServiceLogonPassword -Times 1 -Exactly -ParameterFilter { $ServiceName -eq 'TestRetailService' -and $Account -ceq '.\CrTestNewUser' }
        }
        It 'passes the SecureString, not plaintext' {
            Assert-MockCalled Set-CrServiceLogonPassword -Times 2 -Exactly -ParameterFilter { $Secret -is [System.Security.SecureString] }
        }
        It 'reports the old and the new account' {
            $retail = @($r | Where-Object { $_['Name'] -eq 'TestRetailService' })[0]
            $retail['FromAccount'] | Should Be 'SM-TEST01\applicationuser'
            $retail['ToAccount'] | Should Be '.\CrTestNewUser'
        }
        It 'never starts, stops or restarts a service (D17)' {
            Assert-MockCalled Start-Service -Times 0 -Exactly
            Assert-MockCalled Stop-Service -Times 0 -Exactly
            Assert-MockCalled Restart-Service -Times 0 -Exactly
        }
    }

    Context 'one service fails' {
        Mock Set-CrServiceLogonPassword { @{ Success = $true; Win32Error = 0 } }
        Mock Set-CrServiceLogonPassword -ParameterFilter { $ServiceName -eq 'TestRetailService' } { @{ Success = $false; Win32Error = 1057 } }
        $r = Move-CrServiceAccount -State (New-TestServiceState) -FromSid $fromSid -ToAccount '.\CrTestNewUser' -Secret $secret

        It 'reports the failure per service and continues' {
            $retail = @($r | Where-Object { $_['Name'] -eq 'TestRetailService' })[0]
            $retail['Success'] | Should Be $false
            $retail['Win32Error'] | Should Be 1057
            (@($r | Where-Object { $_['Name'] -eq 'MSSQLSERVER' })[0])['Success'] | Should Be $true
        }
    }

    Context 'wrapper throws' {
        Mock Set-CrServiceLogonPassword { throw 'Native helpers are not available: test' }
        $r = Move-CrServiceAccount -State (New-TestServiceState) -FromSid $fromSid -ToAccount '.\CrTestNewUser' -Secret $secret

        It 'records the message for every service' {
            @($r).Count | Should Be 2
            foreach ($e in $r) {
                $e['Success'] | Should Be $false
                $e['Error'] | Should Match 'Native helpers are not available'
            }
        }
    }

    Context 'services could not be read' {
        Mock Set-CrServiceLogonPassword { @{ Success = $true; Win32Error = 0 } }
        $r = Move-CrServiceAccount -State @{ Services = @{ Error = 'WMI failed' } } -FromSid $fromSid -ToAccount '.\CrTestNewUser' -Secret $secret

        It 'returns a single failed entry' {
            @($r).Count | Should Be 1
            $r[0]['Success'] | Should Be $false
            $r[0]['Error'] | Should Match 'WMI failed'
            Assert-MockCalled Set-CrServiceLogonPassword -Times 0 -Exactly
        }
    }

    Context 'missing arguments' {
        Mock Set-CrServiceLogonPassword { @{ Success = $true; Win32Error = 0 } }

        It 'throws without a target account, FromSid or password and touches nothing' {
            { Move-CrServiceAccount -State (New-TestServiceState) -FromSid $fromSid -ToAccount '' -Secret $secret } | Should Throw
            { Move-CrServiceAccount -State (New-TestServiceState) -FromSid '' -ToAccount '.\CrTestNewUser' -Secret $secret } | Should Throw
            { Move-CrServiceAccount -State (New-TestServiceState) -FromSid $fromSid -ToAccount '.\CrTestNewUser' -Secret $null } | Should Throw
            Assert-MockCalled Set-CrServiceLogonPassword -Times 0 -Exactly
        }
    }
}

Describe 'Services.ps1 secret handling (D4)' {
    It 'never converts a secret to plaintext' {
        $text = [System.IO.File]::ReadAllText((Join-Path $here '..\src\lib\Services.ps1'))
        $text | Should Not Match '\$plain|PtrToStringBSTR|SecureStringToBSTR|ConvertFrom-SecureString|GetNetworkCredential'
    }
}
