# Pester 3.4 tests for src\lib\ComPlus.ps1. Synthetic data only.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here '..\src\lib\Compat.ps1')
. (Join-Path $here '..\src\lib\ComPlus.ps1')

# Stub for the Adapters.ps1 function (another module); mocked below.
function Set-CrComPlusPasswordAdapter { param($Application, $Secret, [string]$Identity) }

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

# --- write side ---

# Called by the fake collection's SaveChanges; mocked to count calls or to fail.
function Invoke-TestComSaveChanges { }

function New-TestComCollection {
    $c = New-Object PSObject -Property @{ Name = 'Applications' }
    Add-Member -InputObject $c -MemberType ScriptMethod -Name SaveChanges -Value { Invoke-TestComSaveChanges; return 1 }
    return $c
}

function New-TestComPlusState {
    $app = 'S-1-5-21-1000-2000-3000-1005'
    return @{
        ComPlus = @(
            @{ Name = 'Test Manager +'; Id = '{11111111-1111-1111-1111-111111111111}'; Activation = 'Server'; Identity = 'ApplicationUser'; IdentitySid = $app; IsEnabled = $true; IsSystem = $false },
            @{ Name = 'COM+ Utilities'; Id = '{22222222-2222-2222-2222-222222222222}'; Activation = 'Server'; Identity = 'NT AUTHORITY\LocalService'; IdentitySid = $null; IsEnabled = $true; IsSystem = $true },
            @{ Name = 'Test Library'; Id = '{33333333-3333-3333-3333-333333333333}'; Activation = 'Library'; Identity = 'ApplicationUser'; IdentitySid = $app; IsEnabled = $true; IsSystem = $false },
            @{ Name = 'Operator App'; Id = '{55555555-5555-5555-5555-555555555555}'; Activation = 'Server'; Identity = 'SM-TEST01\TestOperator'; IdentitySid = 'S-1-5-21-1000-2000-3000-1002'; IsEnabled = $true; IsSystem = $false },
            @{ Name = 'Second Server'; Id = '{6666aaaa-6666-6666-6666-666666666666}'; Activation = 'Server'; Identity = 'ApplicationUser'; IdentitySid = $app; IsEnabled = $false; IsSystem = $false }
        )
    }
}

# Live catalog objects matching New-TestComPlusState (GUID case differs on purpose).
function New-TestComLiveApps {
    param([switch]$ChangedIdentity, [switch]$MissingSecond)
    $secondIdentity = 'ApplicationUser'
    if ($ChangedIdentity) { $secondIdentity = 'SM-TEST01\TestOperator' }
    $list = New-Object System.Collections.ArrayList
    [void]$list.Add((New-TestComApp -Name 'Test Manager +' -Key '{11111111-1111-1111-1111-111111111111}' -Activation 1 -Identity 'ApplicationUser'))
    [void]$list.Add((New-TestComApp -Name 'COM+ Utilities' -Key '{22222222-2222-2222-2222-222222222222}' -Activation 1 -Identity 'NT AUTHORITY\LocalService' -IsSystem $true))
    [void]$list.Add((New-TestComApp -Name 'Test Library' -Key '{33333333-3333-3333-3333-333333333333}' -Activation 0 -Identity 'ApplicationUser'))
    [void]$list.Add((New-TestComApp -Name 'Operator App' -Key '{55555555-5555-5555-5555-555555555555}' -Activation 1 -Identity 'SM-TEST01\TestOperator'))
    if (-not $MissingSecond) {
        [void]$list.Add((New-TestComApp -Name 'Second Server' -Key '{6666AAAA-6666-6666-6666-666666666666}' -Activation 1 -Identity $secondIdentity -IsEnabled $false))
    }
    return , $list.ToArray()
}

Describe 'Update-CrComPlusCredentials' {
    $appSid = 'S-1-5-21-1000-2000-3000-1005'
    $secret = ConvertTo-SecureString 'Dummy-1a' -AsPlainText -Force
    Mock Resolve-CrNameToSid { Get-TestComSid -Name $Name }

    Context 'server applications of the account' {
        Mock Get-CrComPlusApplicationCollection { New-TestComCollection }
        Mock Get-CrComPlusCollectionItems { New-TestComLiveApps }
        Mock Set-CrComPlusPasswordAdapter { @{ Success = $true; Error = $null } }
        Mock Invoke-TestComSaveChanges { }
        $r = Update-CrComPlusCredentials -State (New-TestComPlusState) -Sid $appSid -Secret $secret

        It 'returns one successful result per server application of the SID' {
            ($r -is [array]) | Should Be $true
            (@($r | ForEach-Object { $_['Name'] }) -join ',') | Should Be 'Test Manager +,Second Server'
            @($r | Where-Object { $_['Success'] }).Count | Should Be 2
            ((@($r[0].Keys) | Sort-Object) -join ',') | Should Be 'Error,FromIdentity,Name,Success,ToIdentity'
        }
        It 'sets the password only on those applications' {
            Assert-MockCalled Set-CrComPlusPasswordAdapter -Times 2 -Exactly
            Assert-MockCalled Set-CrComPlusPasswordAdapter -Times 1 -Exactly -ParameterFilter { $Application.Key -eq '{11111111-1111-1111-1111-111111111111}' }
            Assert-MockCalled Set-CrComPlusPasswordAdapter -Times 1 -Exactly -ParameterFilter { $Application.Key -eq '{6666aaaa-6666-6666-6666-666666666666}' }
            Assert-MockCalled Set-CrComPlusPasswordAdapter -Times 2 -Exactly -ParameterFilter { $Secret -is [System.Security.SecureString] }
        }
        It 'calls SaveChanges once' {
            Assert-MockCalled Invoke-TestComSaveChanges -Times 1 -Exactly
        }
        It 'keeps the identity (no Identity passed to the adapter)' {
            Assert-MockCalled Set-CrComPlusPasswordAdapter -Times 2 -Exactly -ParameterFilter { -not $Identity }
            $a = @($r | Where-Object { $_['Name'] -eq 'Test Manager +' })[0]
            $a['FromIdentity'] | Should Be 'ApplicationUser'
            $a['ToIdentity'] | Should Be 'ApplicationUser'
        }
        It 'opens the catalog once' {
            Assert-MockCalled Get-CrComPlusApplicationCollection -Times 1 -Exactly
        }
    }

    Context 'the adapter fails for one application' {
        Mock Get-CrComPlusApplicationCollection { New-TestComCollection }
        Mock Get-CrComPlusCollectionItems { New-TestComLiveApps }
        Mock Set-CrComPlusPasswordAdapter { @{ Success = $true; Error = $null } }
        Mock Set-CrComPlusPasswordAdapter -ParameterFilter { $Application.Name -eq 'Test Manager +' } { @{ Success = $false; Error = 'Setting the COM+ password failed (COMException, 0x80070005)' } }
        Mock Invoke-TestComSaveChanges { }
        $r = Update-CrComPlusCredentials -State (New-TestComPlusState) -Sid $appSid -Secret $secret

        It 'reports that application and saves the other' {
            $a = @($r | Where-Object { $_['Name'] -eq 'Test Manager +' })[0]
            $a['Success'] | Should Be $false
            $a['Error'] | Should Match '80070005'
            (@($r | Where-Object { $_['Name'] -eq 'Second Server' })[0])['Success'] | Should Be $true
            Assert-MockCalled Invoke-TestComSaveChanges -Times 1 -Exactly
        }
    }

    Context 'SaveChanges fails' {
        Mock Get-CrComPlusApplicationCollection { New-TestComCollection }
        Mock Get-CrComPlusCollectionItems { New-TestComLiveApps }
        Mock Set-CrComPlusPasswordAdapter { @{ Success = $true; Error = $null } }
        Mock Invoke-TestComSaveChanges { throw 'The user name or password is not valid for this application.' }
        $r = Update-CrComPlusCredentials -State (New-TestComPlusState) -Sid $appSid -Secret $secret

        It 'fails every application whose password was set' {
            @($r).Count | Should Be 2
            foreach ($e in $r) {
                $e['Success'] | Should Be $false
                $e['Error'] | Should Match 'SaveChanges failed'
            }
        }
    }

    Context 'the adapter fails for every application' {
        Mock Get-CrComPlusApplicationCollection { New-TestComCollection }
        Mock Get-CrComPlusCollectionItems { New-TestComLiveApps }
        Mock Set-CrComPlusPasswordAdapter { @{ Success = $false; Error = 'Setting the COM+ password failed (COMException, 0x80070005)' } }
        Mock Invoke-TestComSaveChanges { }
        $r = Update-CrComPlusCredentials -State (New-TestComPlusState) -Sid $appSid -Secret $secret

        It 'does not call SaveChanges' {
            @($r | Where-Object { $_['Success'] }).Count | Should Be 0
            Assert-MockCalled Invoke-TestComSaveChanges -Times 0 -Exactly
        }
    }

    Context 'identity changed since the audit' {
        Mock Get-CrComPlusApplicationCollection { New-TestComCollection }
        Mock Get-CrComPlusCollectionItems { New-TestComLiveApps -ChangedIdentity }
        Mock Set-CrComPlusPasswordAdapter { @{ Success = $true; Error = $null } }
        Mock Invoke-TestComSaveChanges { }
        $r = Update-CrComPlusCredentials -State (New-TestComPlusState) -Sid $appSid -Secret $secret

        It 'does not touch that application and reports it' {
            $a = @($r | Where-Object { $_['Name'] -eq 'Second Server' })[0]
            $a['Success'] | Should Be $false
            $a['Error'] | Should Match 'changed since the audit'
            Assert-MockCalled Set-CrComPlusPasswordAdapter -Times 1 -Exactly
            (@($r | Where-Object { $_['Name'] -eq 'Test Manager +' })[0])['Success'] | Should Be $true
        }
    }

    Context 'application removed since the audit' {
        Mock Get-CrComPlusApplicationCollection { New-TestComCollection }
        Mock Get-CrComPlusCollectionItems { New-TestComLiveApps -MissingSecond }
        Mock Set-CrComPlusPasswordAdapter { @{ Success = $true; Error = $null } }
        Mock Invoke-TestComSaveChanges { }
        $r = Update-CrComPlusCredentials -State (New-TestComPlusState) -Sid $appSid -Secret $secret

        It 'reports it as not found' {
            $a = @($r | Where-Object { $_['Name'] -eq 'Second Server' })[0]
            $a['Success'] | Should Be $false
            $a['Error'] | Should Match 'not found'
        }
    }

    Context 'catalog not available' {
        Mock Get-CrComPlusApplicationCollection { throw 'Class not registered' }
        Mock Get-CrComPlusCollectionItems { New-TestComLiveApps }
        Mock Set-CrComPlusPasswordAdapter { @{ Success = $true; Error = $null } }
        $r = Update-CrComPlusCredentials -State (New-TestComPlusState) -Sid $appSid -Secret $secret

        It 'fails every application of the SID' {
            @($r).Count | Should Be 2
            foreach ($e in $r) {
                $e['Success'] | Should Be $false
                $e['Error'] | Should Match 'Class not registered'
            }
            Assert-MockCalled Set-CrComPlusPasswordAdapter -Times 0 -Exactly
        }
    }

    Context 'no application of the account' {
        Mock Get-CrComPlusApplicationCollection { New-TestComCollection }
        Mock Set-CrComPlusPasswordAdapter { @{ Success = $true; Error = $null } }
        $r = Update-CrComPlusCredentials -State (New-TestComPlusState) -Sid 'S-1-5-21-1000-2000-3000-1099' -Secret $secret

        It 'returns an empty array without opening the catalog' {
            ($r -is [array]) | Should Be $true
            @($r).Count | Should Be 0
            Assert-MockCalled Get-CrComPlusApplicationCollection -Times 0 -Exactly
        }
    }

    Context 'COM+ applications could not be read' {
        Mock Get-CrComPlusApplicationCollection { New-TestComCollection }
        Mock Set-CrComPlusPasswordAdapter { @{ Success = $true; Error = $null } }
        $r = Update-CrComPlusCredentials -State @{ ComPlus = @{ Error = 'COMAdmin failed' } } -Sid $appSid -Secret $secret

        It 'returns a single failed entry' {
            @($r).Count | Should Be 1
            $r[0]['Success'] | Should Be $false
            $r[0]['Error'] | Should Match 'COMAdmin failed'
            Assert-MockCalled Set-CrComPlusPasswordAdapter -Times 0 -Exactly
        }
    }

    Context 'no shutdown or start (D17)' {
        It 'never calls ShutdownApplication or StartApplication' {
            $text = [System.IO.File]::ReadAllText((Join-Path $here '..\src\lib\ComPlus.ps1'))
            $text | Should Not Match 'ShutdownApplication|StartApplication'
        }
    }
}

Describe 'Move-CrComPlusIdentity' {
    $appSid = 'S-1-5-21-1000-2000-3000-1005'
    $secret = ConvertTo-SecureString 'Dummy-2b' -AsPlainText -Force
    Mock Resolve-CrNameToSid { Get-TestComSid -Name $Name }

    Context 'server applications of the old account' {
        Mock Get-CrComPlusApplicationCollection { New-TestComCollection }
        Mock Get-CrComPlusCollectionItems { New-TestComLiveApps }
        Mock Set-CrComPlusPasswordAdapter { @{ Success = $true; Error = $null; IdentitySet = $true } }
        Mock Invoke-TestComSaveChanges { }
        $r = Move-CrComPlusIdentity -State (New-TestComPlusState) -FromSid $appSid -ToIdentity 'CrTestNewUser' -Secret $secret

        It 'returns one successful result per server application of FromSid' {
            ($r -is [array]) | Should Be $true
            (@($r | ForEach-Object { $_['Name'] }) -join ',') | Should Be 'Test Manager +,Second Server'
            @($r | Where-Object { $_['Success'] }).Count | Should Be 2
            ((@($r[0].Keys) | Sort-Object) -join ',') | Should Be 'Error,FromIdentity,Name,Success,ToIdentity'
        }
        It 'moves only those applications' {
            Assert-MockCalled Set-CrComPlusPasswordAdapter -Times 2 -Exactly
            Assert-MockCalled Set-CrComPlusPasswordAdapter -Times 1 -Exactly -ParameterFilter { $Application.Key -eq '{11111111-1111-1111-1111-111111111111}' }
            Assert-MockCalled Set-CrComPlusPasswordAdapter -Times 1 -Exactly -ParameterFilter { $Application.Key -eq '{6666AAAA-6666-6666-6666-666666666666}' }
        }
        It 'passes the new identity and the SecureString to the adapter' {
            Assert-MockCalled Set-CrComPlusPasswordAdapter -Times 2 -Exactly -ParameterFilter { $Identity -ceq 'CrTestNewUser' -and $Secret -is [System.Security.SecureString] }
        }
        It 'calls SaveChanges once' {
            Assert-MockCalled Invoke-TestComSaveChanges -Times 1 -Exactly
        }
        It 'reports the old and the new identity' {
            $a = @($r | Where-Object { $_['Name'] -eq 'Test Manager +' })[0]
            $a['FromIdentity'] | Should Be 'ApplicationUser'
            $a['ToIdentity'] | Should Be 'CrTestNewUser'
        }
    }

    Context 'the adapter fails after setting the identity' {
        Mock Get-CrComPlusApplicationCollection { New-TestComCollection }
        Mock Get-CrComPlusCollectionItems { New-TestComLiveApps }
        Mock Set-CrComPlusPasswordAdapter { @{ Success = $true; Error = $null; IdentitySet = $true } }
        Mock Set-CrComPlusPasswordAdapter -ParameterFilter { $Application.Name -eq 'Test Manager +' } { @{ Success = $false; Error = 'Setting the COM+ password failed (ArgumentException, 0x80070057)'; IdentitySet = $true } }
        Mock Invoke-TestComSaveChanges { }
        $r = Move-CrComPlusIdentity -State (New-TestComPlusState) -FromSid $appSid -ToIdentity 'CrTestNewUser' -Secret $secret

        It 'saves nothing' {
            Assert-MockCalled Invoke-TestComSaveChanges -Times 0 -Exactly
        }
        It 'reports the failed application and the unsaved other one' {
            $a = @($r | Where-Object { $_['Name'] -eq 'Test Manager +' })[0]
            $a['Success'] | Should Be $false
            $a['Error'] | Should Match '80070057'
            $b = @($r | Where-Object { $_['Name'] -eq 'Second Server' })[0]
            $b['Success'] | Should Be $false
            $b['Error'] | Should Match 'Not saved'
            $b['Error'] | Should Match 'Test Manager \+'
        }
    }

    Context 'the adapter fails before setting the identity' {
        Mock Get-CrComPlusApplicationCollection { New-TestComCollection }
        Mock Get-CrComPlusCollectionItems { New-TestComLiveApps }
        Mock Set-CrComPlusPasswordAdapter { @{ Success = $true; Error = $null; IdentitySet = $true } }
        Mock Set-CrComPlusPasswordAdapter -ParameterFilter { $Application.Name -eq 'Test Manager +' } { @{ Success = $false; Error = 'Setting the COM+ identity failed (COMException, 0x80070005)'; IdentitySet = $false } }
        Mock Invoke-TestComSaveChanges { }
        $r = Move-CrComPlusIdentity -State (New-TestComPlusState) -FromSid $appSid -ToIdentity 'CrTestNewUser' -Secret $secret

        It 'saves the other application' {
            Assert-MockCalled Invoke-TestComSaveChanges -Times 1 -Exactly
            (@($r | Where-Object { $_['Name'] -eq 'Second Server' })[0])['Success'] | Should Be $true
            $a = @($r | Where-Object { $_['Name'] -eq 'Test Manager +' })[0]
            $a['Success'] | Should Be $false
            $a['Error'] | Should Match '80070005'
        }
    }

    Context 'identity changed since the audit' {
        Mock Get-CrComPlusApplicationCollection { New-TestComCollection }
        Mock Get-CrComPlusCollectionItems { New-TestComLiveApps -ChangedIdentity }
        Mock Set-CrComPlusPasswordAdapter { @{ Success = $true; Error = $null; IdentitySet = $true } }
        Mock Invoke-TestComSaveChanges { }
        $r = Move-CrComPlusIdentity -State (New-TestComPlusState) -FromSid $appSid -ToIdentity 'CrTestNewUser' -Secret $secret

        It 'does not move that application and saves the other' {
            $a = @($r | Where-Object { $_['Name'] -eq 'Second Server' })[0]
            $a['Success'] | Should Be $false
            $a['Error'] | Should Match 'changed since the audit'
            Assert-MockCalled Set-CrComPlusPasswordAdapter -Times 1 -Exactly
            (@($r | Where-Object { $_['Name'] -eq 'Test Manager +' })[0])['Success'] | Should Be $true
            Assert-MockCalled Invoke-TestComSaveChanges -Times 1 -Exactly
        }
    }

    Context 'SaveChanges fails' {
        Mock Get-CrComPlusApplicationCollection { New-TestComCollection }
        Mock Get-CrComPlusCollectionItems { New-TestComLiveApps }
        Mock Set-CrComPlusPasswordAdapter { @{ Success = $true; Error = $null; IdentitySet = $true } }
        Mock Invoke-TestComSaveChanges { throw 'The user name or password is not valid for this application.' }
        $r = Move-CrComPlusIdentity -State (New-TestComPlusState) -FromSid $appSid -ToIdentity 'CrTestNewUser' -Secret $secret

        It 'fails every application' {
            @($r).Count | Should Be 2
            foreach ($e in $r) {
                $e['Success'] | Should Be $false
                $e['Error'] | Should Match 'SaveChanges failed'
            }
        }
    }

    Context 'catalog not available' {
        Mock Get-CrComPlusApplicationCollection { throw 'Class not registered' }
        Mock Set-CrComPlusPasswordAdapter { @{ Success = $true; Error = $null; IdentitySet = $true } }
        $r = Move-CrComPlusIdentity -State (New-TestComPlusState) -FromSid $appSid -ToIdentity 'CrTestNewUser' -Secret $secret

        It 'fails every application of FromSid' {
            @($r).Count | Should Be 2
            foreach ($e in $r) {
                $e['Success'] | Should Be $false
                $e['Error'] | Should Match 'Class not registered'
                $e['ToIdentity'] | Should Be 'CrTestNewUser'
            }
            Assert-MockCalled Set-CrComPlusPasswordAdapter -Times 0 -Exactly
        }
    }

    Context 'COM+ applications could not be read' {
        Mock Get-CrComPlusApplicationCollection { New-TestComCollection }
        Mock Set-CrComPlusPasswordAdapter { @{ Success = $true; Error = $null; IdentitySet = $true } }
        $r = Move-CrComPlusIdentity -State @{ ComPlus = @{ Error = 'COMAdmin failed' } } -FromSid $appSid -ToIdentity 'CrTestNewUser' -Secret $secret

        It 'returns a single failed entry' {
            @($r).Count | Should Be 1
            $r[0]['Success'] | Should Be $false
            $r[0]['Error'] | Should Match 'COMAdmin failed'
            Assert-MockCalled Set-CrComPlusPasswordAdapter -Times 0 -Exactly
        }
    }

    Context 'missing arguments' {
        Mock Get-CrComPlusApplicationCollection { New-TestComCollection }
        Mock Set-CrComPlusPasswordAdapter { @{ Success = $true; Error = $null; IdentitySet = $true } }

        It 'throws without a target identity, FromSid or password and touches nothing' {
            { Move-CrComPlusIdentity -State (New-TestComPlusState) -FromSid $appSid -ToIdentity '' -Secret $secret } | Should Throw
            { Move-CrComPlusIdentity -State (New-TestComPlusState) -FromSid '' -ToIdentity 'CrTestNewUser' -Secret $secret } | Should Throw
            { Move-CrComPlusIdentity -State (New-TestComPlusState) -FromSid $appSid -ToIdentity 'CrTestNewUser' -Secret $null } | Should Throw
            Assert-MockCalled Set-CrComPlusPasswordAdapter -Times 0 -Exactly
            Assert-MockCalled Get-CrComPlusApplicationCollection -Times 0 -Exactly
        }
    }
}

Describe 'ComPlus.ps1 secret handling (D4)' {
    It 'never converts a secret to plaintext' {
        $text = [System.IO.File]::ReadAllText((Join-Path $here '..\src\lib\ComPlus.ps1'))
        $text | Should Not Match '\$plain|PtrToStringBSTR|SecureStringToBSTR|ConvertFrom-SecureString|GetNetworkCredential'
    }
}
