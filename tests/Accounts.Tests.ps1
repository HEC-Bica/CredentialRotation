# Pester 3.4 tests for src\lib\Accounts.ps1. ADSI is mocked: entries are hashtables of property values.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here '..\src\lib\Compat.ps1')
. (Join-Path $here '..\src\lib\Accounts.ps1')

# Stubs for Native.ps1 / Journal.ps1 (other modules), mocked below; parameters as in CONTRACTS. They throw, so a
# missing mock can never reach a real account.
function Get-CrUserInfo { param([string]$UserName) throw 'Get-CrUserInfo is not mocked' }
function Set-CrUserFlags { param([string]$UserName, [int]$Flags) throw 'Set-CrUserFlags is not mocked' }
function Invoke-CrNetPasswordChange { param([string]$UserName, $OldSecret, $NewSecret) throw 'Invoke-CrNetPasswordChange is not mocked' }
function Invoke-CrNetPasswordReset { param([string]$UserName, $NewSecret) throw 'Invoke-CrNetPasswordReset is not mocked' }
function Add-CrJournalStep { param($Journal, [string]$RunId, [string]$Sid, [string]$Step) throw 'Add-CrJournalStep is not mocked' }
function New-CrLocalUser { param([string]$UserName, $Secret, [string]$Comment) throw 'New-CrLocalUser is not mocked' }

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

# ---------------------------------------------------------------------------------------------------------------
# Write side (M2). A fake account ($tcFake, set in each It) backs the Get-CrUserInfo / Set-CrUserFlags mocks and
# records every call in order. Secrets are dummy SecureStrings and are never converted.

function New-TestFakeAccount {
    param([int]$Flags)
    return @{ Flags = $Flags; Calls = (New-Object System.Collections.ArrayList); SetCount = 0 }
}

function New-TestSecret {
    param([string]$Text = 'Dummy-1a')
    return (ConvertTo-SecureString $Text -AsPlainText -Force)
}

$tcSid = 'S-1-5-21-1000-2000-3000-1001'

Describe 'Invoke-CrPasswordRotation' {
    Mock Get-CrUserInfo {
        [void]$tcFake.Calls.Add('GetInfo')
        return @{ Success = $true; Win32Error = 0; Flags = $tcFake.Flags; BadPasswordCount = 0; PasswordAgeSeconds = 0 }
    }
    Mock Set-CrUserFlags {
        [void]$tcFake.Calls.Add(('SetFlags:{0:X}' -f $Flags))
        $tcFake.Flags = $Flags
        return @{ Success = $true; Win32Error = 0 }
    }
    Mock Invoke-CrNetPasswordChange {
        [void]$tcFake.Calls.Add('Change')
        return @{ Success = $true; Win32Error = 0 }
    }
    Mock Invoke-CrNetPasswordReset {
        [void]$tcFake.Calls.Add('Reset')
        return @{ Success = $true; Win32Error = 0 }
    }
    Mock Add-CrJournalStep { [void]$tcFake.Calls.Add('Journal:' + $Step) }

    $tcJournal = @{ Runs = @() }

    Context 'change path for an unlocked account without CCP' {
        It 'changes the password and journals only Secret (the caller journals PreSteps)' {
            $tcFake = New-TestFakeAccount 0x10201
            $user = @{ Name = 'TestUser1'; Sid = $tcSid; LockedOut = $false }
            $r = Invoke-CrPasswordRotation -User $user -OldSecret (New-TestSecret 'Dummy-0a') -NewSecret (New-TestSecret) `
                -Path 'Change' -Journal $tcJournal -RunId 'run1'
            $r['Success'] | Should Be $true
            $r['Win32Error'] | Should Be 0
            $r['CcpRestoreFailed'] | Should Be $false
            ($tcFake.Calls -join ',') | Should Be 'GetInfo,Change,Journal:Secret'
            ($r['Steps'] -join ',') | Should Be 'Secret'
            Assert-MockCalled Invoke-CrNetPasswordReset -Times 0 -Exactly
            Assert-MockCalled Add-CrJournalStep -Times 1 -Exactly -ParameterFilter { $RunId -eq 'run1' -and $Sid -eq 'S-1-5-21-1000-2000-3000-1001' }
        }
    }

    Context 'passes the SecureStrings unchanged to the change wrapper' {
        It 'passes the SecureStrings unchanged to the change wrapper' {
            $tcFake = New-TestFakeAccount 0x10201
            $tcOld = New-TestSecret 'Dummy-0a'
            $tcNew = New-TestSecret
            $user = @{ Name = 'TestUser1'; Sid = $tcSid }
            $null = Invoke-CrPasswordRotation -User $user -OldSecret $tcOld -NewSecret $tcNew -Path 'Change' -Journal $tcJournal -RunId 'run1'
            Assert-MockCalled Invoke-CrNetPasswordChange -Times 1 -Exactly -ParameterFilter {
                $UserName -eq 'TestUser1' -and [object]::ReferenceEquals($OldSecret, $tcOld) -and [object]::ReferenceEquals($NewSecret, $tcNew)
            }
        }
    }

    Context 'reset path' {
        It 'resets without the old secret and does not clear CCP' {
            $tcFake = New-TestFakeAccount 0x10241
            $user = @{ Name = 'TestUser1'; Sid = $tcSid }
            $r = Invoke-CrPasswordRotation -User $user -OldSecret $null -NewSecret (New-TestSecret) -Path 'Reset' -Journal $tcJournal -RunId 'run1'
            $r['Success'] | Should Be $true
            ($tcFake.Calls -join ',') | Should Be 'GetInfo,Reset,Journal:Secret'
            $tcFake.Flags | Should Be 0x10241
            Assert-MockCalled Invoke-CrNetPasswordChange -Times 0 -Exactly
        }
    }

    Context 'CCP set on the change path' {
        It 'clears CCP before the change and restores it right after' {
            $tcFake = New-TestFakeAccount 0x10241
            $user = @{ Name = 'TestUser1'; Sid = $tcSid }
            $r = Invoke-CrPasswordRotation -User $user -OldSecret (New-TestSecret 'Dummy-0a') -NewSecret (New-TestSecret) `
                -Path 'Change' -Journal $tcJournal -RunId 'run1'
            $r['Success'] | Should Be $true
            ($tcFake.Calls -join ',') | Should Be ('GetInfo,SetFlags:10201,Journal:CcpCleared,Change,' +
                'GetInfo,SetFlags:10241,Journal:CcpRestored,Journal:Secret')
            ($r['Steps'] -join ',') | Should Be 'CcpCleared,CcpRestored,Secret'
            $tcFake.Flags | Should Be 0x10241
        }
    }

    Context 'CCP restored when the change fails' {
        It 'restores CCP, does not journal Secret and reports the error' {
            Mock Invoke-CrNetPasswordChange {
                [void]$tcFake.Calls.Add('Change')
                return @{ Success = $false; Win32Error = 86 }
            }
            $tcFake = New-TestFakeAccount 0x10241
            $user = @{ Name = 'TestUser1'; Sid = $tcSid }
            $r = Invoke-CrPasswordRotation -User $user -OldSecret (New-TestSecret 'Dummy-0a') -NewSecret (New-TestSecret) `
                -Path 'Change' -Journal $tcJournal -RunId 'run1'
            $r['Success'] | Should Be $false
            $r['Win32Error'] | Should Be 86
            $r['Message'] | Should Match 'old password is wrong'
            ($tcFake.Calls -join ',') | Should Be ('GetInfo,SetFlags:10201,Journal:CcpCleared,Change,' +
                'GetInfo,SetFlags:10241,Journal:CcpRestored')
            ($tcFake.Calls -contains 'Journal:Secret') | Should Be $false
            $tcFake.Flags | Should Be 0x10241
        }
    }

    Context 'CCP restored when the change wrapper throws' {
        It 'restores CCP and returns a failure instead of throwing' {
            Mock Invoke-CrNetPasswordChange {
                [void]$tcFake.Calls.Add('Change')
                throw 'The native helpers are not ready.'
            }
            $tcFake = New-TestFakeAccount 0x10241
            $user = @{ Name = 'TestUser1'; Sid = $tcSid }
            $r = Invoke-CrPasswordRotation -User $user -OldSecret (New-TestSecret 'Dummy-0a') -NewSecret (New-TestSecret) `
                -Path 'Change' -Journal $tcJournal -RunId 'run1'
            $r['Success'] | Should Be $false
            $r['Message'] | Should Match 'not ready'
            ($tcFake.Calls -contains 'Journal:CcpRestored') | Should Be $true
            ($tcFake.Calls -contains 'Journal:Secret') | Should Be $false
            $tcFake.Flags | Should Be 0x10241
        }
    }

    Context 'reports a policy rejection' {
        It 'maps error 2245 to the password policy' {
            Mock Invoke-CrNetPasswordReset {
                [void]$tcFake.Calls.Add('Reset')
                return @{ Success = $false; Win32Error = 2245 }
            }
            $tcFake = New-TestFakeAccount 0x10201
            $user = @{ Name = 'TestUser1'; Sid = $tcSid }
            $r = Invoke-CrPasswordRotation -User $user -NewSecret (New-TestSecret) -Path 'Reset' -Journal $tcJournal -RunId 'run1'
            $r['Success'] | Should Be $false
            $r['Win32Error'] | Should Be 2245
            $r['Message'] | Should Match 'policy'
        }
    }

    Context 'CCP restore fails after a successful change' {
        It 'reports success with CcpRestoreFailed and a warning' {
            Mock Set-CrUserFlags {
                $tcFake.SetCount = $tcFake.SetCount + 1
                [void]$tcFake.Calls.Add(('SetFlags:{0:X}' -f $Flags))
                if ($tcFake.SetCount -ge 2) { return @{ Success = $false; Win32Error = 5 } }
                $tcFake.Flags = $Flags
                return @{ Success = $true; Win32Error = 0 }
            }
            $tcFake = New-TestFakeAccount 0x10241
            $user = @{ Name = 'TestUser1'; Sid = $tcSid }
            $r = Invoke-CrPasswordRotation -User $user -OldSecret (New-TestSecret 'Dummy-0a') -NewSecret (New-TestSecret) `
                -Path 'Change' -Journal $tcJournal -RunId 'run1'
            $r['Success'] | Should Be $true
            $r['CcpRestoreFailed'] | Should Be $true
            @($r['Warnings']).Count | Should Be 1
            ($r['Steps'] -contains 'CcpRestored') | Should Be $false
            ($r['Steps'] -contains 'Secret') | Should Be $true
        }
    }

    Context 'locked account' {
        It 'unlocks first, journals Unlocked and re-checks the lock state' {
            $tcFake = New-TestFakeAccount 0x10211
            $user = @{ Name = 'TestUser1'; Sid = $tcSid; LockedOut = $true }
            $r = Invoke-CrPasswordRotation -User $user -OldSecret (New-TestSecret 'Dummy-0a') -NewSecret (New-TestSecret) `
                -Path 'Change' -Journal $tcJournal -RunId 'run1'
            $r['Success'] | Should Be $true
            ($tcFake.Calls -join ',') | Should Be 'GetInfo,GetInfo,SetFlags:10201,Journal:Unlocked,GetInfo,Change,Journal:Secret'
            ($r['Steps'] -join ',') | Should Be 'Unlocked,Secret'
        }
    }

    Context 'locked account with CCP' {
        It 'unlocks, then clears CCP, then changes, then restores CCP' {
            $tcFake = New-TestFakeAccount 0x10251
            $user = @{ Name = 'TestUser1'; Sid = $tcSid; LockedOut = $true }
            $r = Invoke-CrPasswordRotation -User $user -OldSecret (New-TestSecret 'Dummy-0a') -NewSecret (New-TestSecret) `
                -Path 'Change' -Journal $tcJournal -RunId 'run1'
            $r['Success'] | Should Be $true
            ($r['Steps'] -join ',') | Should Be 'Unlocked,CcpCleared,CcpRestored,Secret'
            $tcFake.Flags | Should Be 0x10241
        }
    }

    Context 'account relocks right after unlocking' {
        It 'stops before the password step' {
            Mock Set-CrUserFlags {
                [void]$tcFake.Calls.Add(('SetFlags:{0:X}' -f $Flags))
                $tcFake.Flags = $Flags -bor 0x10
                return @{ Success = $true; Win32Error = 0 }
            }
            $tcFake = New-TestFakeAccount 0x10211
            $user = @{ Name = 'TestUser1'; Sid = $tcSid; LockedOut = $true }
            $r = Invoke-CrPasswordRotation -User $user -OldSecret (New-TestSecret 'Dummy-0a') -NewSecret (New-TestSecret) `
                -Path 'Change' -Journal $tcJournal -RunId 'run1'
            $r['Success'] | Should Be $false
            $r['Win32Error'] | Should Be 1909
            $r['Message'] | Should Match 'locked out again'
            Assert-MockCalled Invoke-CrNetPasswordChange -Times 0 -Exactly
            ($tcFake.Calls -contains 'Journal:Secret') | Should Be $false
        }
    }

    Context 'unlock fails' {
        It 'stops before the password step' {
            Mock Set-CrUserFlags {
                [void]$tcFake.Calls.Add(('SetFlags:{0:X}' -f $Flags))
                return @{ Success = $false; Win32Error = 5 }
            }
            $tcFake = New-TestFakeAccount 0x10211
            $user = @{ Name = 'TestUser1'; Sid = $tcSid; LockedOut = $true }
            $r = Invoke-CrPasswordRotation -User $user -OldSecret (New-TestSecret 'Dummy-0a') -NewSecret (New-TestSecret) `
                -Path 'Change' -Journal $tcJournal -RunId 'run1'
            $r['Success'] | Should Be $false
            $r['Win32Error'] | Should Be 5
            $r['Message'] | Should Match 'could not be unlocked'
            Assert-MockCalled Invoke-CrNetPasswordChange -Times 0 -Exactly
            Assert-MockCalled Add-CrJournalStep -Times 0 -Exactly
        }
    }

    Context 'CCP cannot be cleared' {
        It 'stops before the password step without journaling CcpCleared' {
            Mock Set-CrUserFlags {
                [void]$tcFake.Calls.Add(('SetFlags:{0:X}' -f $Flags))
                return @{ Success = $false; Win32Error = 5 }
            }
            $tcFake = New-TestFakeAccount 0x10241
            $user = @{ Name = 'TestUser1'; Sid = $tcSid }
            $r = Invoke-CrPasswordRotation -User $user -OldSecret (New-TestSecret 'Dummy-0a') -NewSecret (New-TestSecret) `
                -Path 'Change' -Journal $tcJournal -RunId 'run1'
            $r['Success'] | Should Be $false
            $r['Message'] | Should Match 'could not be cleared'
            Assert-MockCalled Invoke-CrNetPasswordChange -Times 0 -Exactly
            Assert-MockCalled Add-CrJournalStep -Times 0 -Exactly
        }
    }

    Context 'account information cannot be read' {
        It 'stops without any write' {
            Mock Get-CrUserInfo { return @{ Success = $false; Win32Error = 2221; Flags = $null } }
            $tcFake = New-TestFakeAccount 0x10201
            $user = @{ Name = 'TestUser1'; Sid = $tcSid }
            $r = Invoke-CrPasswordRotation -User $user -OldSecret (New-TestSecret 'Dummy-0a') -NewSecret (New-TestSecret) `
                -Path 'Change' -Journal $tcJournal -RunId 'run1'
            $r['Success'] | Should Be $false
            $r['Win32Error'] | Should Be 2221
            Assert-MockCalled Set-CrUserFlags -Times 0 -Exactly
            Assert-MockCalled Invoke-CrNetPasswordChange -Times 0 -Exactly
        }
    }

    Context 'the journal cannot be written' {
        It 'still changes the password and reports a warning' {
            Mock Add-CrJournalStep { throw 'disk full' }
            $tcFake = New-TestFakeAccount 0x10201
            $user = @{ Name = 'TestUser1'; Sid = $tcSid }
            $r = Invoke-CrPasswordRotation -User $user -OldSecret (New-TestSecret 'Dummy-0a') -NewSecret (New-TestSecret) `
                -Path 'Change' -Journal $tcJournal -RunId 'run1'
            $r['Success'] | Should Be $true
            @($r['Warnings']).Count | Should Be 1
            @($r['Warnings'])[0] | Should Match 'disk full'
        }
    }

    Context 'no journal' {
        It 'does not call the journal' {
            $tcFake = New-TestFakeAccount 0x10241
            $user = @{ Name = 'TestUser1'; Sid = $tcSid }
            $r = Invoke-CrPasswordRotation -User $user -OldSecret (New-TestSecret 'Dummy-0a') -NewSecret (New-TestSecret) -Path 'Change'
            $r['Success'] | Should Be $true
            Assert-MockCalled Add-CrJournalStep -Times 0 -Exactly
            ($r['Steps'] -join ',') | Should Be 'CcpCleared,CcpRestored,Secret'
        }
    }

    Context 'argument checks' {
        It 'throws for the change path without the old secret, before any call' {
            $tcFake = New-TestFakeAccount 0x10201
            $user = @{ Name = 'TestUser1'; Sid = $tcSid }
            { Invoke-CrPasswordRotation -User $user -NewSecret (New-TestSecret) -Path 'Change' } | Should Throw 'old secret'
            { Invoke-CrPasswordRotation -User $user -Path 'Reset' } | Should Throw 'new secret'
            { Invoke-CrPasswordRotation -User @{ Name = 'TestUser1' } -NewSecret (New-TestSecret) -Path 'Reset' } | Should Throw
            { Invoke-CrPasswordRotation -User $user -NewSecret (New-TestSecret) -Path 'Other' } | Should Throw
            $tcFake.Calls.Count | Should Be 0
        }
    }
}

Describe 'Set-CrAccountFlags' {
    Mock Get-CrUserInfo {
        [void]$tcFake.Calls.Add('GetInfo')
        return @{ Success = $true; Win32Error = 0; Flags = $tcFake.Flags; BadPasswordCount = 0; PasswordAgeSeconds = 0 }
    }
    Mock Set-CrUserFlags {
        [void]$tcFake.Calls.Add(('SetFlags:{0:X}' -f $Flags))
        $tcFake.Flags = $Flags
        return @{ Success = $true; Win32Error = 0 }
    }
    $user = @{ Name = 'TestUser1'; Sid = $tcSid }
    $roleAdmin = @{ Groups = @('S-1-5-32-544'); ExclusiveGroups = $true; PasswordNeverExpires = $true; CannotChangePassword = $true; PasswordRequired = $true }
    $roleWinUser = @{ Groups = @('S-1-5-32-545'); ExclusiveGroups = $true; PasswordNeverExpires = $true; CannotChangePassword = $true }

    Context 'Admin role on an account with NOTREQD and without PNE/CCP' {
        It 'sets PNE and CCP and clears NOTREQD in one write' {
            $tcFake = New-TestFakeAccount 0x221
            $r = Set-CrAccountFlags -User $user -Role $roleAdmin
            $r['Changed'] | Should Be $true
            $r['Success'] | Should Be $true
            $tcFake.Flags | Should Be 0x10241
            Assert-MockCalled Set-CrUserFlags -Times 1 -Exactly -ParameterFilter { $UserName -eq 'TestUser1' -and $Flags -eq 0x10241 }
        }
    }

    Context 'already compliant' {
        It 'does not write' {
            $tcFake = New-TestFakeAccount 0x10241
            $r = Set-CrAccountFlags -User $user -Role $roleAdmin
            $r['Changed'] | Should Be $false
            $r['Success'] | Should Be $true
            Assert-MockCalled Set-CrUserFlags -Times 0 -Exactly
        }
    }

    Context 'role without PasswordRequired' {
        It 'keeps NOTREQD' {
            $tcFake = New-TestFakeAccount 0x221
            $r = Set-CrAccountFlags -User $user -Role $roleWinUser
            $r['Changed'] | Should Be $true
            $tcFake.Flags | Should Be 0x10261
        }
    }

    Context 'empty role' {
        It 'changes nothing' {
            $tcFake = New-TestFakeAccount 0x221
            $r = Set-CrAccountFlags -User $user -Role @{}
            $r['Changed'] | Should Be $false
            $r['Success'] | Should Be $true
            $tcFake.Flags | Should Be 0x221
            Assert-MockCalled Set-CrUserFlags -Times 0 -Exactly
        }
    }

    Context 'no role' {
        It 'changes nothing' {
            $tcFake = New-TestFakeAccount 0x221
            $r = Set-CrAccountFlags -User $user -Role $null
            $r['Changed'] | Should Be $false
            $r['Success'] | Should Be $true
            Assert-MockCalled Set-CrUserFlags -Times 0 -Exactly
        }
    }

    Context 'Operator role (v10) on a disabled account' {
        It 'sets PNE and CCP, clears NOTREQD and leaves UF_ACCOUNTDISABLE alone' {
            $roleOperator = @{ Groups = @('S-1-5-32-544', 'S-1-5-32-555', 'Name:Test Helpers?'); ExclusiveGroups = $true
                               PasswordNeverExpires = $true; CannotChangePassword = $true; PasswordRequired = $true }
            $tcFake = New-TestFakeAccount 0x223
            $r = Set-CrAccountFlags -User $user -Role $roleOperator
            $r['Changed'] | Should Be $true
            $r['Success'] | Should Be $true
            $tcFake.Flags | Should Be 0x10243
        }
    }

    Context 'the write fails' {
        It 'reports the Win32 error' {
            Mock Set-CrUserFlags { return @{ Success = $false; Win32Error = 5 } }
            $tcFake = New-TestFakeAccount 0x221
            $r = Set-CrAccountFlags -User $user -Role $roleAdmin
            $r['Changed'] | Should Be $false
            $r['Success'] | Should Be $false
            $r['Win32Error'] | Should Be 5
        }
    }

    Context 'the account cannot be read' {
        It 'reports the Win32 error without writing' {
            Mock Get-CrUserInfo { return @{ Success = $false; Win32Error = 2221 } }
            $tcFake = New-TestFakeAccount 0x221
            $r = Set-CrAccountFlags -User $user -Role $roleAdmin
            $r['Success'] | Should Be $false
            $r['Win32Error'] | Should Be 2221
            Assert-MockCalled Set-CrUserFlags -Times 0 -Exactly
        }
    }
}

Describe 'Unlock-CrAccount' {
    Mock Get-CrUserInfo {
        return @{ Success = $true; Win32Error = 0; Flags = $tcFake.Flags; BadPasswordCount = 0; PasswordAgeSeconds = 0 }
    }
    Mock Set-CrUserFlags {
        $tcFake.Flags = $Flags
        return @{ Success = $true; Win32Error = 0 }
    }

    Context 'locked account' {
        It 'clears only UF_LOCKOUT' {
            $tcFake = New-TestFakeAccount 0x10251
            $r = Unlock-CrAccount -UserName 'TestUser1'
            $r['Success'] | Should Be $true
            $r['Changed'] | Should Be $true
            $tcFake.Flags | Should Be 0x10241
            Assert-MockCalled Set-CrUserFlags -Times 1 -Exactly -ParameterFilter { $Flags -eq 0x10241 }
        }
    }

    Context 'account not locked' {
        It 'does not write' {
            $tcFake = New-TestFakeAccount 0x10241
            $r = Unlock-CrAccount -UserName 'TestUser1'
            $r['Success'] | Should Be $true
            $r['Changed'] | Should Be $false
            Assert-MockCalled Set-CrUserFlags -Times 0 -Exactly
        }
    }
}

# ---------------------------------------------------------------------------------------------------------------
# v10 account model (CONTRACTS "v10: account model"): create, set, disable, enable.

Describe 'New-CrManagedAccount' {
    $tcJournal = @{ Runs = @() }

    Context 'success' {
        Mock New-CrLocalUser { return @{ Success = $true; Win32Error = 0 } }
        Mock Resolve-CrNameToSid { return 'S-1-5-21-1000-2000-3000-1005' }
        Mock Add-CrJournalStep { }
        It 'creates the account, resolves its SID and journals Created for it' {
            $tcSecret = New-TestSecret
            $r = New-CrManagedAccount -Name 'TestManaged1' -Secret $tcSecret -Comment 'Test comment' -Journal $tcJournal -RunId 'run1'
            $r['Success'] | Should Be $true
            $r['Win32Error'] | Should Be 0
            $r['Sid'] | Should Be 'S-1-5-21-1000-2000-3000-1005'
            $r['Name'] | Should Be 'TestManaged1'
            ($r['Steps'] -join ',') | Should Be 'Created'
            @($r['Warnings']).Count | Should Be 0
            Assert-MockCalled New-CrLocalUser -Times 1 -Exactly -ParameterFilter {
                $UserName -eq 'TestManaged1' -and $Comment -eq 'Test comment' -and [object]::ReferenceEquals($Secret, $tcSecret)
            }
            Assert-MockCalled Add-CrJournalStep -Times 1 -Exactly -ParameterFilter {
                $Step -eq 'Created' -and $Sid -eq 'S-1-5-21-1000-2000-3000-1005' -and $RunId -eq 'run1'
            }
        }
    }

    Context 'the account already exists' {
        Mock New-CrLocalUser { return @{ Success = $false; Win32Error = 2224 } }
        Mock Resolve-CrNameToSid { return 'S-1-5-21-1000-2000-3000-1005' }
        Mock Add-CrJournalStep { }
        It 'reports 2224 as a failure and journals nothing' {
            $r = New-CrManagedAccount -Name 'TestManaged1' -Secret (New-TestSecret) -Journal $tcJournal -RunId 'run1'
            $r['Success'] | Should Be $false
            $r['Win32Error'] | Should Be 2224
            $r['Message'] | Should Match 'already exists'
            ($null -eq $r['Sid']) | Should Be $true
            @($r['Steps']).Count | Should Be 0
            Assert-MockCalled Add-CrJournalStep -Times 0 -Exactly
            Assert-MockCalled Resolve-CrNameToSid -Times 0 -Exactly
        }
    }

    Context 'password policy rejects the new password' {
        Mock New-CrLocalUser { return @{ Success = $false; Win32Error = 2245 } }
        Mock Add-CrJournalStep { }
        It 'reports the policy error' {
            $r = New-CrManagedAccount -Name 'TestManaged1' -Secret (New-TestSecret) -Journal $tcJournal -RunId 'run1'
            $r['Success'] | Should Be $false
            $r['Win32Error'] | Should Be 2245
            $r['Message'] | Should Match 'policy'
        }
    }

    Context 'the native wrapper throws' {
        Mock New-CrLocalUser { throw 'Native helpers are not available: x' }
        Mock Add-CrJournalStep { }
        It 'returns a failure instead of throwing' {
            $r = New-CrManagedAccount -Name 'TestManaged1' -Secret (New-TestSecret) -Journal $tcJournal -RunId 'run1'
            $r['Success'] | Should Be $false
            $r['Message'] | Should Match 'not available'
            Assert-MockCalled Add-CrJournalStep -Times 0 -Exactly
        }
    }

    Context 'the SID of the new account cannot be resolved' {
        Mock New-CrLocalUser { return @{ Success = $true; Win32Error = 0 } }
        Mock Resolve-CrNameToSid { return $null }
        Mock Add-CrJournalStep { }
        It 'reports success with a warning and no journal entry' {
            $r = New-CrManagedAccount -Name 'TestManaged1' -Secret (New-TestSecret) -Journal $tcJournal -RunId 'run1'
            $r['Success'] | Should Be $true
            ($null -eq $r['Sid']) | Should Be $true
            @($r['Warnings']).Count | Should Be 1
            @($r['Warnings'])[0] | Should Match 'SID could not be resolved'
            Assert-MockCalled Add-CrJournalStep -Times 0 -Exactly
        }
    }

    Context 'the journal cannot be written' {
        Mock New-CrLocalUser { return @{ Success = $true; Win32Error = 0 } }
        Mock Resolve-CrNameToSid { return 'S-1-5-21-1000-2000-3000-1005' }
        Mock Add-CrJournalStep { throw 'Add-CrJournalStep: unknown step Created' }
        It 'reports success with a warning' {
            $r = New-CrManagedAccount -Name 'TestManaged1' -Secret (New-TestSecret) -Journal $tcJournal -RunId 'run1'
            $r['Success'] | Should Be $true
            @($r['Warnings']).Count | Should Be 1
            @($r['Warnings'])[0] | Should Match 'unknown step'
        }
    }

    Context 'argument checks' {
        Mock New-CrLocalUser { return @{ Success = $true; Win32Error = 0 } }
        It 'throws without a name or a secret, before any call' {
            { New-CrManagedAccount -Name '' -Secret (New-TestSecret) } | Should Throw 'Name'
            { New-CrManagedAccount -Name 'TestManaged1' } | Should Throw 'secret'
            Assert-MockCalled New-CrLocalUser -Times 0 -Exactly
        }
    }
}

Describe 'Invoke-CrPasswordSet' {
    Mock Get-CrUserInfo {
        [void]$tcFake.Calls.Add('GetInfo')
        return @{ Success = $true; Win32Error = 0; Flags = $tcFake.Flags; BadPasswordCount = 0; PasswordAgeSeconds = 0 }
    }
    Mock Set-CrUserFlags {
        [void]$tcFake.Calls.Add(('SetFlags:{0:X}' -f $Flags))
        $tcFake.Flags = $Flags
        return @{ Success = $true; Win32Error = 0 }
    }
    Mock Invoke-CrNetPasswordReset {
        [void]$tcFake.Calls.Add('Reset')
        return @{ Success = $true; Win32Error = 0 }
    }
    Mock Invoke-CrNetPasswordChange { throw 'the set path must never change' }
    Mock Add-CrJournalStep { [void]$tcFake.Calls.Add('Journal:' + $Step) }

    $tcJournal = @{ Runs = @() }

    Context 'unlocked account with CCP' {
        It 'sets the password without touching CCP and journals Secret' {
            $tcFake = New-TestFakeAccount 0x10241
            $tcNew = New-TestSecret
            $user = @{ Name = 'TestUser1'; Sid = $tcSid; LockedOut = $false }
            $r = Invoke-CrPasswordSet -User $user -NewSecret $tcNew -Journal $tcJournal -RunId 'run1'
            $r['Success'] | Should Be $true
            $r['Win32Error'] | Should Be 0
            ($tcFake.Calls -join ',') | Should Be 'GetInfo,Reset,Journal:Secret'
            ($r['Steps'] -join ',') | Should Be 'Secret'
            $tcFake.Flags | Should Be 0x10241
            Assert-MockCalled Set-CrUserFlags -Times 0 -Exactly
            Assert-MockCalled Invoke-CrNetPasswordChange -Times 0 -Exactly
            Assert-MockCalled Invoke-CrNetPasswordReset -Times 1 -Exactly -ParameterFilter {
                $UserName -eq 'TestUser1' -and [object]::ReferenceEquals($NewSecret, $tcNew)
            }
            Assert-MockCalled Add-CrJournalStep -Times 1 -Exactly -ParameterFilter {
                $Step -eq 'Secret' -and $Sid -eq 'S-1-5-21-1000-2000-3000-1001' -and $RunId -eq 'run1'
            }
        }
    }

    Context 'locked account' {
        It 'unlocks first, journals Unlocked, re-checks the lock and then sets' {
            $tcFake = New-TestFakeAccount 0x10251
            $user = @{ Name = 'TestUser1'; Sid = $tcSid; LockedOut = $true }
            $r = Invoke-CrPasswordSet -User $user -NewSecret (New-TestSecret) -Journal $tcJournal -RunId 'run1'
            $r['Success'] | Should Be $true
            ($tcFake.Calls -join ',') | Should Be 'GetInfo,GetInfo,SetFlags:10241,Journal:Unlocked,GetInfo,Reset,Journal:Secret'
            ($r['Steps'] -join ',') | Should Be 'Unlocked,Secret'
            $tcFake.Flags | Should Be 0x10241
        }
    }

    Context 'account relocks right after unlocking' {
        It 'stops before the password step' {
            Mock Set-CrUserFlags {
                [void]$tcFake.Calls.Add(('SetFlags:{0:X}' -f $Flags))
                $tcFake.Flags = $Flags -bor 0x10
                return @{ Success = $true; Win32Error = 0 }
            }
            $tcFake = New-TestFakeAccount 0x10211
            $user = @{ Name = 'TestUser1'; Sid = $tcSid; LockedOut = $true }
            $r = Invoke-CrPasswordSet -User $user -NewSecret (New-TestSecret) -Journal $tcJournal -RunId 'run1'
            $r['Success'] | Should Be $false
            $r['Win32Error'] | Should Be 1909
            Assert-MockCalled Invoke-CrNetPasswordReset -Times 0 -Exactly
            ($tcFake.Calls -contains 'Journal:Secret') | Should Be $false
        }
    }

    Context 'unlock fails' {
        It 'stops before the password step without journaling' {
            Mock Set-CrUserFlags { return @{ Success = $false; Win32Error = 5 } }
            $tcFake = New-TestFakeAccount 0x10211
            $user = @{ Name = 'TestUser1'; Sid = $tcSid; LockedOut = $true }
            $r = Invoke-CrPasswordSet -User $user -NewSecret (New-TestSecret) -Journal $tcJournal -RunId 'run1'
            $r['Success'] | Should Be $false
            $r['Win32Error'] | Should Be 5
            $r['Message'] | Should Match 'could not be unlocked'
            Assert-MockCalled Invoke-CrNetPasswordReset -Times 0 -Exactly
            Assert-MockCalled Add-CrJournalStep -Times 0 -Exactly
        }
    }

    Context 'the set is rejected by the policy' {
        It 'reports 2245 and does not journal Secret' {
            Mock Invoke-CrNetPasswordReset {
                [void]$tcFake.Calls.Add('Reset')
                return @{ Success = $false; Win32Error = 2245 }
            }
            $tcFake = New-TestFakeAccount 0x10201
            $user = @{ Name = 'TestUser1'; Sid = $tcSid }
            $r = Invoke-CrPasswordSet -User $user -NewSecret (New-TestSecret) -Journal $tcJournal -RunId 'run1'
            $r['Success'] | Should Be $false
            $r['Win32Error'] | Should Be 2245
            $r['Message'] | Should Match 'password set was rejected by the password policy'
            ($tcFake.Calls -contains 'Journal:Secret') | Should Be $false
        }
    }

    Context 'the set wrapper throws' {
        It 'returns a failure instead of throwing' {
            Mock Invoke-CrNetPasswordReset { throw 'Native helpers are not available: x' }
            $tcFake = New-TestFakeAccount 0x10201
            $user = @{ Name = 'TestUser1'; Sid = $tcSid }
            $r = Invoke-CrPasswordSet -User $user -NewSecret (New-TestSecret) -Journal $tcJournal -RunId 'run1'
            $r['Success'] | Should Be $false
            $r['Message'] | Should Match 'not available'
            ($tcFake.Calls -contains 'Journal:Secret') | Should Be $false
        }
    }

    Context 'account information cannot be read' {
        It 'stops without any write' {
            Mock Get-CrUserInfo { return @{ Success = $false; Win32Error = 2221; Flags = $null } }
            $tcFake = New-TestFakeAccount 0x10201
            $user = @{ Name = 'TestUser1'; Sid = $tcSid }
            $r = Invoke-CrPasswordSet -User $user -NewSecret (New-TestSecret) -Journal $tcJournal -RunId 'run1'
            $r['Success'] | Should Be $false
            $r['Win32Error'] | Should Be 2221
            Assert-MockCalled Set-CrUserFlags -Times 0 -Exactly
            Assert-MockCalled Invoke-CrNetPasswordReset -Times 0 -Exactly
        }
    }

    Context 'no journal' {
        It 'does not call the journal' {
            $tcFake = New-TestFakeAccount 0x10201
            $user = @{ Name = 'TestUser1'; Sid = $tcSid }
            $r = Invoke-CrPasswordSet -User $user -NewSecret (New-TestSecret)
            $r['Success'] | Should Be $true
            ($r['Steps'] -join ',') | Should Be 'Secret'
            Assert-MockCalled Add-CrJournalStep -Times 0 -Exactly
        }
    }

    Context 'argument checks' {
        It 'throws without Sid or secret, before any call' {
            $tcFake = New-TestFakeAccount 0x10201
            { Invoke-CrPasswordSet -User @{ Name = 'TestUser1' } -NewSecret (New-TestSecret) } | Should Throw 'Name and Sid'
            { Invoke-CrPasswordSet -User @{ Name = 'TestUser1'; Sid = $tcSid } } | Should Throw 'new secret'
            $tcFake.Calls.Count | Should Be 0
        }
    }
}

Describe 'Disable-CrAccount / Enable-CrAccount' {
    Mock Get-CrUserInfo {
        return @{ Success = $true; Win32Error = 0; Flags = $tcFake.Flags; BadPasswordCount = 0; PasswordAgeSeconds = 0 }
    }
    Mock Set-CrUserFlags {
        $tcFake.Flags = $Flags
        return @{ Success = $true; Win32Error = 0 }
    }
    Mock Add-CrJournalStep { }
    $tcJournal = @{ Runs = @() }
    $user = @{ Name = 'TestUser1'; Sid = $tcSid }

    Context 'disable an enabled account' {
        It 'sets only UF_ACCOUNTDISABLE and journals Disabled' {
            $tcFake = New-TestFakeAccount 0x10261
            $r = Disable-CrAccount -User $user -Journal $tcJournal -RunId 'run1'
            $r['Success'] | Should Be $true
            $r['Changed'] | Should Be $true
            $r['Win32Error'] | Should Be 0
            $tcFake.Flags | Should Be 0x10263
            ($r['Steps'] -join ',') | Should Be 'Disabled'
            Assert-MockCalled Set-CrUserFlags -Times 1 -Exactly -ParameterFilter { $UserName -eq 'TestUser1' -and $Flags -eq 0x10263 }
            Assert-MockCalled Add-CrJournalStep -Times 1 -Exactly -ParameterFilter {
                $Step -eq 'Disabled' -and $Sid -eq 'S-1-5-21-1000-2000-3000-1001' -and $RunId -eq 'run1'
            }
        }
    }

    Context 'disable an already disabled account' {
        It 'does not write and does not journal' {
            $tcFake = New-TestFakeAccount 0x203
            $r = Disable-CrAccount -User $user -Journal $tcJournal -RunId 'run1'
            $r['Success'] | Should Be $true
            $r['Changed'] | Should Be $false
            @($r['Steps']).Count | Should Be 0
            Assert-MockCalled Set-CrUserFlags -Times 0 -Exactly
            Assert-MockCalled Add-CrJournalStep -Times 0 -Exactly
        }
    }

    Context 'disable fails' {
        It 'reports the error and does not journal' {
            Mock Set-CrUserFlags { return @{ Success = $false; Win32Error = 5 } }
            $tcFake = New-TestFakeAccount 0x201
            $r = Disable-CrAccount -User $user -Journal $tcJournal -RunId 'run1'
            $r['Success'] | Should Be $false
            $r['Changed'] | Should Be $false
            $r['Win32Error'] | Should Be 5
            $r['Message'] | Should Match 'could not be disabled'
            Assert-MockCalled Add-CrJournalStep -Times 0 -Exactly
        }
    }

    Context 'disable: the account cannot be read' {
        It 'reports the error without writing' {
            Mock Get-CrUserInfo { return @{ Success = $false; Win32Error = 2221 } }
            $tcFake = New-TestFakeAccount 0x201
            $r = Disable-CrAccount -User $user -Journal $tcJournal -RunId 'run1'
            $r['Success'] | Should Be $false
            $r['Win32Error'] | Should Be 2221
            Assert-MockCalled Set-CrUserFlags -Times 0 -Exactly
        }
    }

    Context 'disable without a journal' {
        It 'disables and records the step only in the result' {
            $tcFake = New-TestFakeAccount 0x201
            $r = Disable-CrAccount -User $user
            $r['Changed'] | Should Be $true
            ($r['Steps'] -join ',') | Should Be 'Disabled'
            Assert-MockCalled Add-CrJournalStep -Times 0 -Exactly
        }
    }

    Context 'enable a disabled account' {
        It 'clears only UF_ACCOUNTDISABLE' {
            $tcFake = New-TestFakeAccount 0x10243
            $r = Enable-CrAccount -User $user
            $r['Success'] | Should Be $true
            $r['Changed'] | Should Be $true
            $tcFake.Flags | Should Be 0x10241
            Assert-MockCalled Set-CrUserFlags -Times 1 -Exactly -ParameterFilter { $Flags -eq 0x10241 }
            Assert-MockCalled Add-CrJournalStep -Times 0 -Exactly
        }
    }

    Context 'enable an enabled account' {
        It 'does not write' {
            $tcFake = New-TestFakeAccount 0x10241
            $r = Enable-CrAccount -User $user
            $r['Success'] | Should Be $true
            $r['Changed'] | Should Be $false
            Assert-MockCalled Set-CrUserFlags -Times 0 -Exactly
        }
    }

    Context 'enable fails' {
        It 'reports the error' {
            Mock Set-CrUserFlags { return @{ Success = $false; Win32Error = 5 } }
            $tcFake = New-TestFakeAccount 0x203
            $r = Enable-CrAccount -User $user
            $r['Success'] | Should Be $false
            $r['Win32Error'] | Should Be 5
            $r['Message'] | Should Match 'could not be enabled'
        }
    }

    Context 'argument checks' {
        It 'throws for a user without Name (enable) or without Sid (disable)' {
            $tcFake = New-TestFakeAccount 0x201
            { Enable-CrAccount -User @{ Sid = $tcSid } } | Should Throw 'Name'
            { Disable-CrAccount -User @{ Name = 'TestUser1' } } | Should Throw 'Name and Sid'
            Assert-MockCalled Set-CrUserFlags -Times 0 -Exactly
        }
    }
}
