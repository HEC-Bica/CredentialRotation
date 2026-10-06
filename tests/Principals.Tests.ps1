$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here '..\src\lib\Compat.ps1')
. (Join-Path $here '..\src\lib\Principals.ps1')
. (Join-Path $here 'Fixtures.ps1')

# Resolve-CrAccounts and Find-CrSidOverlap return comma-wrapped arrays: assign directly, never wrap the call in @().

function Get-TestEntry {
    param($Resolved, [string]$Id)
    foreach ($r in $Resolved) { if ($r.Id -eq $Id) { return $r } }
    throw "no resolved entry $Id"
}

function Get-TestAccountNames {
    param($Entry)
    $names = @()
    foreach ($a in $Entry.Accounts) { $names += $a.Name }
    return , $names
}

function Add-TestAccount {
    param($Config, [hashtable]$Entry)
    $Config.Accounts = @($Config.Accounts) + @($Entry)
}

Describe 'Resolve-CrAccounts on an SM-like machine' {
    $config = New-CrTestConfig
    $state = New-CrTestState -Profile 'SM'
    $resolved = Resolve-CrAccounts -Config $config -State $state

    It 'returns one entry per config entry, in config order' {
        $resolved.Count | Should Be 9
        $resolved[0].Id | Should Be 'BiCAAdmin'
        $resolved[8].Id | Should Be 'SqlService'
    }

    It 'resolves a Name entry' {
        $e = Get-TestEntry $resolved 'BiCAAdmin'
        $e.Kind | Should Be 'Windows'
        $e.Mode | Should Be 'Rotate'
        $e.Slot | Should Be 'BiCAAdmin'
        $e.RoleName | Should Be 'Admin'
        $e.Role.ExclusiveGroups | Should Be $true
        $e.LoginsEntry | Should Be $true
        $e.NotApplicable | Should Be $false
        $e.Accounts.Count | Should Be 1
        $e.Accounts[0].Sid | Should Be (Get-CrTestUserSid $state 'BiCA Admin')
        $e.Accounts[0].User.Name | Should Be 'BiCA Admin'
        $e.Missing.Count | Should Be 0
        $e.Candidate | Should BeNullOrEmpty
        $e.AutoLogon | Should BeNullOrEmpty
        $e.AutoLogonUser | Should BeNullOrEmpty
    }

    It 'carries the original config entry in Config' {
        $e = Get-TestEntry $resolved 'AppUser'
        $e.Config.Services | Should Be 'Auto'
        $e.Config.ScheduledTasks | Should Be 'Auto'
        [object]::ReferenceEquals($e.Config, $config.Accounts[2]) | Should Be $true
        (Get-TestEntry $resolved 'SqlApp').Config.ServerRoles[0] | Should Be 'sysadmin'
    }

    It 'compares names case-insensitively' {
        $c = New-CrTestConfig
        $c.Accounts[0].Name = 'bica admin'
        $r = Resolve-CrAccounts -Config $c -State $state
        $r[0].Accounts[0].Name | Should Be 'BiCA Admin'
    }

    It 'chooses ApplicationUser as the first candidate' {
        $e = Get-TestEntry $resolved 'AppUser'
        $e.Candidate | Should Be 0
        $e.Slot | Should Be 'AppUserApplication'
        $e.RoleName | Should Be 'Admin'
        $e.Accounts.Count | Should Be 1
        $e.Accounts[0].Name | Should Be 'ApplicationUser'
    }

    It 'resolves Names to every existing account and reports the others as missing' {
        $e = Get-TestEntry $resolved 'AutoLogon'
        $e.Slot | Should Be 'AutoLogon'
        $e.Accounts.Count | Should Be 1
        $e.Accounts[0].Name | Should Be 'WinAutoUser'
        $e.Missing.Count | Should Be 1
        $e.Missing[0] | Should Be 'PUB-User'
        $e.NotApplicable | Should Be $false
        $e.AutoLogon.RestrictedComputerPattern | Should Be '^SM'
        $e.AutoLogonUser.Count | Should Be 2
        $e.AutoLogonUser[0].Name | Should Be 'PUB-User'
    }

    It 'marks Check entries' {
        $e = Get-TestEntry $resolved 'WinUsers'
        $e.Mode | Should Be 'Check'
        $e.Slot | Should BeNullOrEmpty
        $e.LoginsEntry | Should Be $false
        $e.Accounts.Count | Should Be 3
    }

    It 'matches NamePattern case-insensitively at the start or end only' {
        $e = Get-TestEntry $resolved 'FtpUsers'
        $names = Get-TestAccountNames $e
        $names.Count | Should Be 2
        ($names -contains 'TEST_FTP') | Should Be $true
        ($names -contains 'ftpClient') | Should Be $true
        ($names -contains 'myftpuser') | Should Be $false
        $e.Missing.Count | Should Be 0
        $e.RoleName | Should Be 'Ftp'
    }

    It 'resolves SQL logins by name among SQL_LOGIN entries, with the hex SID' {
        $e = Get-TestEntry $resolved 'SqlApp'
        $e.Kind | Should Be 'SqlLogin'
        $e.Slot | Should Be 'SQLApplication'
        $e.Accounts.Count | Should Be 1
        $e.Accounts[0].Sid | Should Be '0x1A2B3C4D5E6F708192A3B4C5D6E7F801'
        $e.Accounts[0].User.Type | Should Be 'SQL_LOGIN'
        $e.RoleName | Should BeNullOrEmpty
    }
}

Describe 'Resolve-CrAccounts candidate fallback' {
    It 'falls back to the built-in Administrator (RID 500, renamed) when ApplicationUser is missing' {
        $state = New-CrTestState -Profile 'SM' -OmitUsers 'ApplicationUser'
        $resolved = Resolve-CrAccounts -Config (New-CrTestConfig) -State $state
        $e = Get-TestEntry $resolved 'AppUser'
        $e.Candidate | Should Be 1
        $e.Slot | Should Be 'AppUserBuiltinAdmin'
        $e.RoleName | Should Be 'RotateOnly'
        $e.Role.Count | Should Be 0
        $e.Accounts[0].Sid | Should Be ($state.Computer.MachineSid + '-500')
        $e.Accounts[0].Name | Should Be 'LocalAdm'
        $e.NotApplicable | Should Be $false
    }

    It 'uses the user RID when the machine SID is unknown' {
        $state = New-CrTestState -Profile 'IPT01' -OmitUsers 'ApplicationUser'
        $state.Computer.MachineSid = $null
        $e = Get-TestEntry (Resolve-CrAccounts -Config (New-CrTestConfig) -State $state) 'AppUser'
        $e.Candidate | Should Be 1
        $e.Accounts[0].Name | Should Be 'Administrator'
    }

    It 'is not applicable when no candidate matches' {
        $state = New-CrTestState -Profile 'SM' -OmitUsers @('ApplicationUser', 'LocalAdm')
        $e = Get-TestEntry (Resolve-CrAccounts -Config (New-CrTestConfig) -State $state) 'AppUser'
        $e.NotApplicable | Should Be $true
        $e.Candidate | Should BeNullOrEmpty
        $e.Slot | Should BeNullOrEmpty
        $e.Accounts.Count | Should Be 0
        $e.Missing.Count | Should Be 2
        $e.Missing[1] | Should Be 'RID-500'
    }
}

Describe 'Resolve-CrAccounts on an IPT01-like machine' {
    $state = New-CrTestState -Profile 'IPT01'
    $resolved = Resolve-CrAccounts -Config (New-CrTestConfig) -State $state

    It 'rotates both auto-logon accounts' {
        $e = Get-TestEntry $resolved 'AutoLogon'
        $e.Accounts.Count | Should Be 2
        $e.Accounts[0].Name | Should Be 'PUB-User'
        $e.Accounts[1].Name | Should Be 'WinAutoUser'
        $e.Missing.Count | Should Be 0
    }

    It 'marks entries without accounts as not applicable' {
        $w = Get-TestEntry $resolved 'WinUsers'
        $w.NotApplicable | Should Be $true
        $w.Missing.Count | Should Be 3
        $f = Get-TestEntry $resolved 'FtpUsers'
        $f.NotApplicable | Should Be $true
        $f.Missing.Count | Should Be 0
    }

    It 'reports SQL logins as missing when SQL is not connected' {
        $s = New-CrTestState -Profile 'IPT01' -Customize { param($st) $st.Sql.Connected = $false; $st.Sql.Logins = @() }
        $e = Get-TestEntry (Resolve-CrAccounts -Config (New-CrTestConfig) -State $s) 'SqlScript'
        $e.NotApplicable | Should Be $true
        $e.Missing[0] | Should Be 'SQLScript'
        $e.Error | Should Match 'not connected'
    }

    It 'does not match a Windows login with a managed SQL login name' {
        $s = New-CrTestState -Profile 'IPT01' -Customize {
            param($st)
            $st.Sql.Logins = @(New-CrTestSqlLogin -Name 'SQLService' -Type 'WINDOWS_LOGIN' -Sid 'S-1-5-21-1000-2000-4000-1999')
        }
        $e = Get-TestEntry (Resolve-CrAccounts -Config (New-CrTestConfig) -State $s) 'SqlService'
        $e.NotApplicable | Should Be $true
    }

    It 'reports the Users error when the Users part failed' {
        $s = New-CrTestState -Profile 'IPT01' -Parts @{ Users = @{ Error = 'access denied' } }
        $e = Get-TestEntry (Resolve-CrAccounts -Config (New-CrTestConfig) -State $s) 'BiCAAdmin'
        $e.NotApplicable | Should Be $true
        $e.Missing[0] | Should Be 'BiCA Admin'
        $e.Error | Should Match 'access denied'
    }
}

Describe 'NamePattern exclusion and SID overlap' {
    It 'finds no overlap with the default config' {
        $resolved = Resolve-CrAccounts -Config (New-CrTestConfig) -State (New-CrTestState -Profile 'SM')
        $findings = Find-CrSidOverlap -Resolved $resolved
        $findings.Count | Should Be 0
    }

    It 'excludes accounts named by another entry from NamePattern' {
        $c = New-CrTestConfig
        Add-TestAccount $c @{ Id = 'NamedFtp'; Kind = 'Windows'; Name = 'TEST_FTP'; Role = 'User'; Mode = 'Check' }
        $resolved = Resolve-CrAccounts -Config $c -State (New-CrTestState -Profile 'SM')
        $names = Get-TestAccountNames (Get-TestEntry $resolved 'FtpUsers')
        $names.Count | Should Be 1
        $names[0] | Should Be 'ftpClient'
        (Get-TestEntry $resolved 'NamedFtp').Accounts[0].Name | Should Be 'TEST_FTP'
        (Find-CrSidOverlap -Resolved $resolved).Count | Should Be 0
    }

    It 'excludes a name named by another entry even if that account is missing there' {
        $c = New-CrTestConfig
        $c.Accounts[0].Name = 'ftpClient'
        $resolved = Resolve-CrAccounts -Config $c -State (New-CrTestState -Profile 'SM')
        $names = Get-TestAccountNames (Get-TestEntry $resolved 'FtpUsers')
        ($names -contains 'ftpClient') | Should Be $false
    }

    It 'reports a SID selected by two named entries as Ambiguous' {
        $c = New-CrTestConfig
        Add-TestAccount $c @{ Id = 'Dup'; Kind = 'Windows'; Name = 'BiCA Admin'; Role = 'RotateOnly'; Credential = 'BiCARemote' }
        $resolved = Resolve-CrAccounts -Config $c -State (New-CrTestState -Profile 'SM')
        $findings = Find-CrSidOverlap -Resolved $resolved
        $findings.Count | Should Be 1
        $findings[0].Severity | Should Be 'Ambiguous'
        $findings[0].Account | Should Be 'BiCA Admin'
        $findings[0].Message | Should Match 'BiCAAdmin, Dup'
    }

    It 'reports an overlap between two NamePattern entries' {
        $c = New-CrTestConfig
        Add-TestAccount $c @{ Id = 'Clients'; Kind = 'Windows'; NamePattern = 'client$'; Role = 'User'; Mode = 'Check' }
        $resolved = Resolve-CrAccounts -Config $c -State (New-CrTestState -Profile 'SM')
        $findings = Find-CrSidOverlap -Resolved $resolved
        $findings.Count | Should Be 1
        $findings[0].Account | Should Be 'ftpClient'
    }

    It 'reports a candidate RID-500 that another entry names explicitly' {
        $c = New-CrTestConfig
        Add-TestAccount $c @{ Id = 'Renamed'; Kind = 'Windows'; Name = 'LocalAdm'; Role = 'RotateOnly'; Credential = 'BiCARemote' }
        $resolved = Resolve-CrAccounts -Config $c -State (New-CrTestState -Profile 'SM' -OmitUsers 'ApplicationUser')
        $findings = Find-CrSidOverlap -Resolved $resolved
        $findings.Count | Should Be 1
        $findings[0].Message | Should Match 'AppUser, Renamed'
    }

    It 'does not report two names of one entry that resolve to one account' {
        $c = New-CrTestConfig
        foreach ($a in $c.Accounts) { if ($a.Id -eq 'WinUsers') { $a.Names = @('WinUser1', 'winuser1', 'WinUser2') } }
        $resolved = Resolve-CrAccounts -Config $c -State (New-CrTestState -Profile 'SM')
        (Get-TestEntry $resolved 'WinUsers').Accounts.Count | Should Be 2
        (Find-CrSidOverlap -Resolved $resolved).Count | Should Be 0
    }
}

Describe 'Resolve-CrGroupReference' {
    $sm = New-CrTestState -Profile 'SM'
    $ipt = New-CrTestState -Profile 'IPT01'

    It 'takes a SID as is' {
        $r = Resolve-CrGroupReference -Reference 'S-1-5-32-555' -State $ipt
        $r.Sids.Count | Should Be 1
        $r.Sids[0] | Should Be 'S-1-5-32-555'
        $r.Optional | Should Be $false
        $r.Missing | Should Be $false
    }

    It 'resolves RID-500 via the machine SID' {
        $r = Resolve-CrGroupReference -Reference 'RID-500' -State $sm
        $r.Sids[0] | Should Be 'S-1-5-21-1000-2000-3000-500'
    }

    It 'resolves Name: case-insensitively' {
        $r = Resolve-CrGroupReference -Reference 'Name:cardcenters' -State $sm
        $r.Sids.Count | Should Be 1
        $r.Sids[0] | Should Be (Get-CrTestGroup $sm 'CardCenters').Sid
        $r.Missing | Should Be $false
    }

    It 'reports a missing required Name: group' {
        $r = Resolve-CrGroupReference -Reference 'Name:CardCenters' -State $ipt
        $r.Sids.Count | Should Be 0
        $r.Missing | Should Be $true
        $r.Optional | Should Be $false
    }

    It 'treats Name:x? as optional: found on SM' {
        $r = Resolve-CrGroupReference -Reference 'Name:Offer Remote Assistance Helpers?' -State $sm
        $r.Optional | Should Be $true
        $r.Sids.Count | Should Be 1
        $r.Missing | Should Be $false
    }

    It 'treats Name:x? as optional: ignored on IPT01' {
        $r = Resolve-CrGroupReference -Reference 'Name:Offer Remote Assistance Helpers?' -State $ipt
        $r.Optional | Should Be $true
        $r.Sids.Count | Should Be 0
        $r.Missing | Should Be $false
    }

    It 'returns every group matching Pattern:, case-insensitively' {
        $r = Resolve-CrGroupReference -Reference 'Pattern:^HW_FN_' -State $sm
        $r.Sids.Count | Should Be 2
        $r.Missing | Should Be $false
        (Resolve-CrGroupReference -Reference 'Pattern:^hw_fn_' -State $ipt).Sids.Count | Should Be 0
    }

    It 'throws for an unknown form' {
        { Resolve-CrGroupReference -Reference 'CardCenters' -State $sm } | Should Throw
    }
}
