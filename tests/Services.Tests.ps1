# Pester 3.4 tests for src\lib\Services.ps1. Synthetic data only.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here '..\src\lib\Compat.ps1')
. (Join-Path $here '..\src\lib\Services.ps1')

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
