# Pester 3.4 tests for src\lib\ComPlus.ps1. Synthetic data only.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here '..\src\lib\Compat.ps1')
. (Join-Path $here '..\src\lib\ComPlus.ps1')

function Get-TestComSid {
    param([string]$Name)
    switch ($Name.Trim().ToLowerInvariant()) {
        'applicationuser'          { return 'S-1-5-21-1000-2000-3000-1005' }
        'sm-test01\testoperator'   { return 'S-1-5-21-1000-2000-3000-1002' }
        'nt service\testsvc'       { return 'S-1-5-80-1000-2000-3000-4000-5000' }
        'nt authority\interactive' { return 'S-1-5-4' }
        'nt authority\localservice' { return 'S-1-5-19' }
    }
    return $null
}

function New-TestComApp {
    param([string]$Name, [string]$Key, $Activation, $Identity, [bool]$IsEnabled = $true, [bool]$IsSystem = $false)
    $a = New-Object PSObject -Property @{
        Name  = $Name
        Key   = $Key
        Props = @{ Activation = $Activation; Identity = $Identity; IsEnabled = $IsEnabled; IsSystem = $IsSystem }
    }
    Add-Member -InputObject $a -MemberType ScriptMethod -Name Value -Value { param($n) $this.Props[$n] }
    return $a
}

Describe 'Get-CrComPlusApplications' {
    Mock Resolve-CrNameToSid { Get-TestComSid -Name $Name }

    Context 'synthetic catalog' {
        Mock Get-CrComPlusCatalogApplications {
            @(
                (New-TestComApp -Name 'Test Manager +' -Key '{11111111-1111-1111-1111-111111111111}' -Activation 1 -Identity 'ApplicationUser'),
                (New-TestComApp -Name 'COM+ Utilities' -Key '{22222222-2222-2222-2222-222222222222}' -Activation 1 -Identity 'NT AUTHORITY\LocalService' -IsSystem $true),
                (New-TestComApp -Name 'Test Library' -Key '{33333333-3333-3333-3333-333333333333}' -Activation 0 -Identity 'Interactive User'),
                (New-TestComApp -Name 'Test Interactive' -Key '{44444444-4444-4444-4444-444444444444}' -Activation 1 -Identity 'nt authority\interactive' -IsEnabled $false)
            )
        }
        $r = Get-CrComPlusApplications

        It 'returns every application as an array' {
            ($r -is [array]) | Should Be $true
            @($r).Count | Should Be 4
        }
        It 'maps an account identity of a server application to its SID' {
            $app = @($r | Where-Object { $_['Name'] -eq 'Test Manager +' })[0]
            $app['Activation'] | Should Be 'Server'
            $app['Identity'] | Should Be 'ApplicationUser'
            $app['IdentitySid'] | Should Be 'S-1-5-21-1000-2000-3000-1005'
            $app['Id'] | Should Be '{11111111-1111-1111-1111-111111111111}'
            $app['IsEnabled'] | Should Be $true
            $app['IsSystem'] | Should Be $false
        }
        It 'maps Activation 0 to Library' {
            (@($r | Where-Object { $_['Name'] -eq 'Test Library' })[0])['Activation'] | Should Be 'Library'
        }
        It 'excludes built-in identity tokens by string' {
            foreach ($n in @('COM+ Utilities', 'Test Library', 'Test Interactive')) {
                (@($r | Where-Object { $_['Name'] -eq $n })[0])['IdentitySid'] | Should BeNullOrEmpty
            }
            Assert-MockCalled Resolve-CrNameToSid -Times 0 -Exactly -ParameterFilter { $Name -ne 'ApplicationUser' }
        }
        It 'has exactly the contract keys' {
            ((@($r[0].Keys) | Sort-Object) -join ',') | Should Be 'Activation,Id,Identity,IdentitySid,IsEnabled,IsSystem,Name'
        }
    }

    Context 'empty catalog' {
        Mock Get-CrComPlusCatalogApplications { }
        $r = Get-CrComPlusApplications

        It 'returns an empty array' {
            ($r -is [array]) | Should Be $true
            @($r).Count | Should Be 0
        }
    }
}

Describe 'Test-CrComBuiltinIdentity' {
    It 'recognizes built-in tokens' {
        foreach ($t in @('Interactive User', 'interactive user', 'nt authority\localservice', 'NT AUTHORITY\NetworkService', 'NT AUTHORITY\Network Service', 'NT AUTHORITY\SYSTEM', 'LocalSystem', '', $null)) {
            Test-CrComBuiltinIdentity -Identity $t | Should Be $true
        }
    }
    It 'does not treat accounts as built-in' {
        foreach ($t in @('ApplicationUser', '.\ApplicationUser', 'SM-TEST01\TestOperator')) {
            Test-CrComBuiltinIdentity -Identity $t | Should Be $false
        }
    }
}

Describe 'Get-CrDcomRunAs' {
    Mock Resolve-CrNameToSid { Get-TestComSid -Name $Name }
    Mock Get-CrDcomAppIdRoots { @('HKLM:\TestNative\AppID', 'HKLM:\TestWow\AppID') }
    Mock Get-CrDcomAppIdEntries { }
    Mock Get-CrDcomAppIdEntries -ParameterFilter { $Root -eq 'HKLM:\TestNative\AppID' } {
        @(
            @{ AppId = '{AAAAAAAA-0000-0000-0000-000000000001}'; Name = 'Test DCOM Server'; RunAs = 'SM-TEST01\TestOperator' },
            @{ AppId = '{AAAAAAAA-0000-0000-0000-000000000002}'; Name = 'Shell helper'; RunAs = 'Interactive User' },
            @{ AppId = '{AAAAAAAA-0000-0000-0000-000000000003}'; Name = 'Local service app'; RunAs = 'nt authority\localservice' },
            @{ AppId = '{AAAAAAAA-0000-0000-0000-000000000004}'; Name = 'Virtual account app'; RunAs = 'NT SERVICE\TestSvc' }
        )
    }
    Mock Get-CrDcomAppIdEntries -ParameterFilter { $Root -eq 'HKLM:\TestWow\AppID' } {
        @{ AppId = '{AAAAAAAA-0000-0000-0000-000000000005}'; Name = 'Test 32-bit Server'; RunAs = 'ApplicationUser' }
    }
    $r = Get-CrDcomRunAs

    It 'reads both views and excludes Interactive User and built-ins' {
        ($r -is [array]) | Should Be $true
        @($r).Count | Should Be 2
    }
    It 'reports the account entries with view and SID' {
        $native = @($r | Where-Object { $_['View'] -eq 'HKLM:\TestNative\AppID' })[0]
        $native['AppId'] | Should Be '{AAAAAAAA-0000-0000-0000-000000000001}'
        $native['Name'] | Should Be 'Test DCOM Server'
        $native['RunAs'] | Should Be 'SM-TEST01\TestOperator'
        $native['RunAsSid'] | Should Be 'S-1-5-21-1000-2000-3000-1002'
        $wow = @($r | Where-Object { $_['View'] -eq 'HKLM:\TestWow\AppID' })[0]
        $wow['RunAsSid'] | Should Be 'S-1-5-21-1000-2000-3000-1005'
    }
    It 'has exactly the contract keys' {
        ((@($r[0].Keys) | Sort-Object) -join ',') | Should Be 'AppId,Name,RunAs,RunAsSid,View'
    }
}
