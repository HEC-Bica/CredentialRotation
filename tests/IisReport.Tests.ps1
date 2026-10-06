# Pester 3.4 tests for src\lib\IisReport.ps1. Synthetic data only.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here '..\src\lib\Compat.ps1')
. (Join-Path $here '..\src\lib\IisReport.ps1')

function Get-TestIisSid {
    param([string]$Name)
    switch ($Name.ToLowerInvariant()) {
        'sm-test01\applicationuser' { return 'S-1-5-21-1000-2000-3000-1005' }
        'applicationuser'           { return 'S-1-5-21-1000-2000-3000-1005' }
        'testftpreader'             { return 'S-1-5-21-1000-2000-3000-1010' }
    }
    return $null
}

function New-TestPool {
    param([string]$Name, [string]$IdentityType, [string]$UserName = '')
    $pm = New-Object PSObject -Property @{ IdentityType = $IdentityType; UserName = $UserName }
    return (New-Object PSObject -Property @{ Name = $Name; ProcessModel = $pm })
}

function New-TestVdir {
    param([string]$Path, [string]$PhysicalPath, [string]$UserName = '')
    return (New-Object PSObject -Property @{ Path = $Path; PhysicalPath = $PhysicalPath; UserName = $UserName })
}

function New-TestSite {
    param([string]$Name, [string[]]$Protocols, [object[]]$Applications)
    $bindings = @()
    foreach ($p in $Protocols) { $bindings += (New-Object PSObject -Property @{ Protocol = $p; BindingInformation = '*:0:' }) }
    return (New-Object PSObject -Property @{ Name = $Name; Bindings = $bindings; Applications = $Applications })
}

function New-TestServerManager {
    $pools = @(
        (New-TestPool -Name 'DefaultAppPool' -IdentityType 'ApplicationPoolIdentity'),
        (New-TestPool -Name '.NET v4.5' -IdentityType 'ApplicationPoolIdentity'),
        (New-TestPool -Name 'LegacyPool' -IdentityType 'NetworkService' -UserName 'ApplicationUser'),
        (New-TestPool -Name 'TestAppPool' -IdentityType 'SpecificUser' -UserName 'SM-TEST01\ApplicationUser')
    )
    $web = New-TestSite -Name 'Default Web Site' -Protocols @('http', 'https') -Applications @(
        (New-Object PSObject -Property @{ Path = '/'; VirtualDirectories = @((New-TestVdir -Path '/' -PhysicalPath '%SystemDrive%\inetpub\wwwroot')) })
    )
    $ftp = New-TestSite -Name 'FTP_TestSite' -Protocols @('ftp') -Applications @(
        (New-Object PSObject -Property @{ Path = '/'; VirtualDirectories = @(
            (New-TestVdir -Path '/' -PhysicalPath 'D:\FTP'),
            (New-TestVdir -Path '/Reader' -PhysicalPath 'E:\FTP\Reader' -UserName 'TestFtpReader')
        ) })
    )
    $sm = New-Object PSObject -Property @{ ApplicationPools = $pools; Sites = @($web, $ftp) }
    Add-Member -InputObject $sm -MemberType ScriptMethod -Name CommitChanges -Value { throw 'CommitChanges must not be called' }
    return $sm
}

Describe 'Get-CrIisIdentities' {
    Mock Resolve-CrNameToSid { Get-TestIisSid -Name $Name }

    Context 'IIS not installed' {
        Mock Test-CrIisInstalled { $false }
        Mock Get-CrIisVersion { '10.0' }
        Mock Get-CrIisServerManager { throw 'must not be loaded' }
        $r = Get-CrIisIdentities

        It 'reports Installed = false without an error' {
            $r['Installed'] | Should Be $false
            $r['Error'] | Should BeNullOrEmpty
            @($r['AppPools']).Count | Should Be 0
            @($r['VirtualDirectories']).Count | Should Be 0
        }
        It 'does not load Microsoft.Web.Administration' {
            Assert-MockCalled Get-CrIisServerManager -Times 0 -Exactly
        }
    }

    Context 'IIS with built-in pools and an FTP site' {
        Mock Test-CrIisInstalled { $true }
        Mock Get-CrIisVersion { '10.0' }
        Mock Get-CrIisServerManager { New-TestServerManager }
        $r = Get-CrIisIdentities

        It 'reports installed, version and no error' {
            $r['Installed'] | Should Be $true
            $r['Version'] | Should Be '10.0'
            $r['Error'] | Should BeNullOrEmpty
        }
        It 'lists every application pool with its identity' {
            @($r['AppPools']).Count | Should Be 4
            $def = @($r['AppPools'] | Where-Object { $_['Name'] -eq 'DefaultAppPool' })[0]
            $def['IdentityType'] | Should Be 'ApplicationPoolIdentity'
            $def['UserSid'] | Should BeNullOrEmpty
        }
        It 'resolves SpecificUser pools only' {
            $specific = @($r['AppPools'] | Where-Object { $_['Name'] -eq 'TestAppPool' })[0]
            $specific['UserName'] | Should Be 'SM-TEST01\ApplicationUser'
            $specific['UserSid'] | Should Be 'S-1-5-21-1000-2000-3000-1005'
            $legacy = @($r['AppPools'] | Where-Object { $_['Name'] -eq 'LegacyPool' })[0]
            $legacy['UserSid'] | Should BeNullOrEmpty
        }
        It 'lists the virtual directories of every site with protocols' {
            @($r['VirtualDirectories']).Count | Should Be 3
            $root = @($r['VirtualDirectories'] | Where-Object { $_['Site'] -eq 'Default Web Site' })[0]
            ($root['Protocols'] -join ',') | Should Be 'http,https'
            $ftp = @($r['VirtualDirectories'] | Where-Object { $_['Site'] -eq 'FTP_TestSite' })
            $ftp.Count | Should Be 2
            ($ftp[0]['Protocols'] -join ',') | Should Be 'ftp'
        }
        It 'resolves the connect-as user of a virtual directory' {
            $reader = @($r['VirtualDirectories'] | Where-Object { $_['Path'] -eq '/Reader' })[0]
            $reader['Application'] | Should Be '/'
            $reader['PhysicalPath'] | Should Be 'E:\FTP\Reader'
            $reader['UserName'] | Should Be 'TestFtpReader'
            $reader['UserSid'] | Should Be 'S-1-5-21-1000-2000-3000-1010'
            $plain = @($r['VirtualDirectories'] | Where-Object { $_['PhysicalPath'] -eq 'D:\FTP' })[0]
            $plain['UserSid'] | Should BeNullOrEmpty
        }
        It 'has exactly the contract keys' {
            ((@($r.Keys) | Sort-Object) -join ',') | Should Be 'AppPools,Error,Installed,Version,VirtualDirectories'
            ((@($r['AppPools'][0].Keys) | Sort-Object) -join ',') | Should Be 'IdentityType,Name,UserName,UserSid'
            ((@($r['VirtualDirectories'][0].Keys) | Sort-Object) -join ',') | Should Be 'Application,Path,PhysicalPath,Protocols,Site,UserName,UserSid'
        }
    }

    Context 'Microsoft.Web.Administration fails to load' {
        Mock Test-CrIisInstalled { $true }
        Mock Get-CrIisVersion { '7.5' }
        Mock Get-CrIisServerManager { throw 'Could not load file or assembly Microsoft.Web.Administration' }
        $r = Get-CrIisIdentities

        It 'reports installed with the error' {
            $r['Installed'] | Should Be $true
            $r['Version'] | Should Be '7.5'
            $r['Error'] | Should Match 'Could not load'
            @($r['AppPools']).Count | Should Be 0
        }
    }
}
