# Pester 3.4 tests for src\lib\Accounts.ps1. ADSI is mocked: entries are hashtables of property values.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here '..\src\lib\Compat.ps1')
. (Join-Path $here '..\src\lib\Accounts.ps1')

function New-TestSidBytes {
    param([string]$Sid)
    $s = New-Object System.Security.Principal.SecurityIdentifier($Sid)
    $bytes = New-Object byte[] $s.BinaryLength
    $s.GetBinaryForm($bytes, 0)
    return , $bytes
}

# A fake ADSI user entry; a key 'Throw_<Property>' makes reading that property fail.
function New-TestUserEntry {
    param([string]$Name, [string]$Sid, [int]$Flags = 0x200, $Locked = $false, $Age = 3600, $Bad = 0, $FullName = '')
    return @{
        Name                = $Name
        objectSid           = (New-TestSidBytes $Sid)
        UserFlags           = $Flags
        IsAccountLocked     = $Locked
        PasswordAge         = $Age
        BadPasswordAttempts = $Bad
        FullName            = $FullName
    }
}

$crUserKeys = @('Name', 'Sid', 'Rid', 'FullName', 'Flags', 'Disabled', 'LockedOut', 'PasswordNeverExpires',
    'CannotChangePassword', 'PasswordNotRequired', 'PasswordAgeSeconds', 'BadPasswordCount', 'Error')

Describe 'Get-CrLocalUsers' {
    Mock Get-CrAdsiValue {
        if ($Entry.ContainsKey('Throw_' + $Name)) { throw $Entry['Throw_' + $Name] }
        if (-not $Entry.ContainsKey($Name)) { throw ('The property ' + $Name + ' was not found') }
        return $Entry[$Name]
    }

    Context 'maps properties and UserFlags bits per the contract' {
        It 'maps properties and UserFlags bits per the contract' {
            $tuEntry = New-TestUserEntry -Name 'TestUser1' -Sid 'S-1-5-21-1000-2000-3000-1001' -Flags 0x10262 `
                -Age 86400 -Bad 2 -FullName 'Test User One'
            Mock Get-CrAdsiUserEntries { return , @($tuEntry) }
            $users = Get-CrLocalUsers
            ($users -is [array]) | Should Be $true
            $users.Count | Should Be 1
            $u = $users[0]
            $u['Name'] | Should Be 'TestUser1'
            $u['Sid'] | Should Be 'S-1-5-21-1000-2000-3000-1001'
            $u['Rid'] | Should Be 1001
            ($u['Rid'] -is [int]) | Should Be $true
            $u['FullName'] | Should Be 'Test User One'
            $u['Flags'] | Should Be 0x10262
            $u['Disabled'] | Should Be $true
            $u['PasswordNotRequired'] | Should Be $true
            $u['CannotChangePassword'] | Should Be $true
            $u['PasswordNeverExpires'] | Should Be $true
            $u['LockedOut'] | Should Be $false
            $u['PasswordAgeSeconds'] | Should Be 86400
            $u['BadPasswordCount'] | Should Be 2
            $u['Error'] | Should BeNullOrEmpty
            foreach ($k in $crUserKeys) { $u.ContainsKey($k) | Should Be $true }
            $u.Count | Should Be $crUserKeys.Count
        }
    }

    Context 'reports a normal account with all flag booleans false' {
        It 'reports a normal account with all flag booleans false' {
            $tuEntry = New-TestUserEntry -Name 'TestUser2' -Sid 'S-1-5-21-1000-2000-3000-1002' -Flags 0x200
            Mock Get-CrAdsiUserEntries { return , @($tuEntry) }
            $u = (Get-CrLocalUsers)[0]
            $u['Disabled'] | Should Be $false
            $u['PasswordNotRequired'] | Should Be $false
            $u['CannotChangePassword'] | Should Be $false
            $u['PasswordNeverExpires'] | Should Be $false
            $u['LockedOut'] | Should Be $false
        }
    }

    Context 'uses IsAccountLocked when readable' {
        It 'uses IsAccountLocked when readable' {
            $tuEntry = New-TestUserEntry -Name 'TestUser3' -Sid 'S-1-5-21-1000-2000-3000-1003' -Flags 0x200 -Locked $true
            Mock Get-CrAdsiUserEntries { return , @($tuEntry) }
            (Get-CrLocalUsers)[0]['LockedOut'] | Should Be $true
        }
    }

    Context 'falls back to the UF_LOCKOUT bit when IsAccountLocked cannot be read' {
        It 'falls back to the UF_LOCKOUT bit when IsAccountLocked cannot be read' {
            $tuLocked = New-TestUserEntry -Name 'TestUser4' -Sid 'S-1-5-21-1000-2000-3000-1004' -Flags 0x210
            $tuLocked['Throw_IsAccountLocked'] = 'not supported'
            $tuUnlocked = New-TestUserEntry -Name 'TestUser5' -Sid 'S-1-5-21-1000-2000-3000-1005' -Flags 0x200
            $tuUnlocked['Throw_IsAccountLocked'] = 'not supported'
            Mock Get-CrAdsiUserEntries { return , @($tuLocked, $tuUnlocked) }
            $users = Get-CrLocalUsers
            $users[0]['LockedOut'] | Should Be $true
            $users[1]['LockedOut'] | Should Be $false
            $users[0]['Error'] | Should BeNullOrEmpty
        }
    }

    Context 'records a failing user with Error and still returns the others' {
        It 'records a failing user with Error and still returns the others' {
            $tuGood1 = New-TestUserEntry -Name 'TestUser6' -Sid 'S-1-5-21-1000-2000-3000-1006'
            $tuBad = New-TestUserEntry -Name 'TestUser7' -Sid 'S-1-5-21-1000-2000-3000-1007'
            $tuBad['Throw_UserFlags'] = 'Access is denied'
            $tuGood2 = New-TestUserEntry -Name 'TestUser8' -Sid 'S-1-5-21-1000-2000-3000-1008'
            Mock Get-CrAdsiUserEntries { return , @($tuGood1, $tuBad, $tuGood2) }
            $users = Get-CrLocalUsers
            $users.Count | Should Be 3
            $users[0]['Sid'] | Should Be 'S-1-5-21-1000-2000-3000-1006'
            $users[0]['Error'] | Should BeNullOrEmpty
            $users[1]['Name'] | Should Be 'TestUser7'
            $users[1]['Error'] | Should Match 'Access is denied'
            $users[1]['Sid'] | Should BeNullOrEmpty
            foreach ($k in $crUserKeys) { $users[1].ContainsKey($k) | Should Be $true }
            $users[2]['Sid'] | Should Be 'S-1-5-21-1000-2000-3000-1008'
            $users[2]['Error'] | Should BeNullOrEmpty
        }
    }

    Context 'records a user whose SID cannot be read' {
        It 'records a user whose SID cannot be read' {
            $tuBad = New-TestUserEntry -Name 'TestUser9' -Sid 'S-1-5-21-1000-2000-3000-1009'
            $tuBad['Throw_objectSid'] = 'no sid'
            Mock Get-CrAdsiUserEntries { return , @($tuBad) }
            $u = (Get-CrLocalUsers)[0]
            $u['Error'] | Should Match 'no sid'
            $u['Name'] | Should Be 'TestUser9'
        }
    }

    Context 'leaves optional properties $null when they cannot be read' {
        It 'leaves optional properties $null when they cannot be read' {
            $tuEntry = New-TestUserEntry -Name 'TestUser10' -Sid 'S-1-5-21-1000-2000-3000-1010'
            $tuEntry['Throw_PasswordAge'] = 'x'
            $tuEntry['Throw_BadPasswordAttempts'] = 'x'
            $tuEntry['Throw_FullName'] = 'x'
            Mock Get-CrAdsiUserEntries { return , @($tuEntry) }
            $u = (Get-CrLocalUsers)[0]
            $u['Error'] | Should BeNullOrEmpty
            ($null -eq $u['PasswordAgeSeconds']) | Should Be $true
            ($null -eq $u['BadPasswordCount']) | Should Be $true
            ($null -eq $u['FullName']) | Should Be $true
        }
    }

    Context 'returns an empty array when there are no users' {
        It 'returns an empty array when there are no users' {
            Mock Get-CrAdsiUserEntries { return , @() }
            $users = Get-CrLocalUsers
            ($null -eq $users) | Should Be $false
            ($users -is [array]) | Should Be $true
            $users.Count | Should Be 0
        }
    }

    Context 'reads RIDs above 1000 and well-known RIDs' {
        It 'reads RIDs above 1000 and well-known RIDs' {
            $tuAdm = New-TestUserEntry -Name 'TestAdmin' -Sid 'S-1-5-21-1000-2000-3000-500' -Flags 0x10200
            Mock Get-CrAdsiUserEntries { return , @($tuAdm) }
            $u = (Get-CrLocalUsers)[0]
            $u['Rid'] | Should Be 500
            $u['PasswordNeverExpires'] | Should Be $true
        }
    }
}
