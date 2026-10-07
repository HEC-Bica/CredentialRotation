$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here '..\src\lib\Compat.ps1')
. (Join-Path $here '..\src\lib\Principals.ps1')
. (Join-Path $here 'Fixtures.ps1')

# Resolve-CrAccounts, Find-CrSidOverlap and Get-CrOtherEnabledAccounts return comma-wrapped arrays:
# assign directly, never wrap the call in @().

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

function Get-TestConfigEntry {
    param($Config, [string]$Id)
    foreach ($a in $Config.Accounts) { if ($a.Id -eq $Id) { return $a } }
    throw "no account $Id"
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
        $resolved.Count | Should Be 10
        $resolved[0].Id | Should Be 'BiCAAdmin'
        $resolved[1].Id | Should Be 'BiCARemote'
        $resolved[3].Id | Should Be 'AutoLogon'
        $resolved[4].Id | Should Be 'Retired'
        $resolved[9].Id | Should Be 'SqlService'
    }

    It 'resolves the existing BiCA Admin without creating it (no Replaces)' {
        $e = Get-TestEntry $resolved 'BiCAAdmin'
        $e.Kind | Should Be 'Windows'
        $e.Mode | Should Be 'Rotate'
        $e.Create | Should Be $false
        $e.NotApplicable | Should Be $false
        $e.Missing.Count | Should Be 0
        $e.Accounts.Count | Should Be 1
        $e.Accounts[0].Name | Should Be 'BiCA Admin'
        $e.Accounts[0].Sid | Should Be (Get-CrTestUserSid $state 'BiCA Admin')
        $e.Accounts[0].ToCreate | Should BeNullOrEmpty
        $e.Slot | Should Be 'BiCAAdmin'
        $e.RoleName | Should Be 'Admin'
        $e.PasswordMode | Should Be 'Set'
        $e.LoginsEntry | Should Be $true
        $e.Operator | Should Be $false
        $e.EnableIfDisabled | Should Be $false
        $e.Replaced.Count | Should Be 0
    }

    It 'resolves a missing BiCA Admin to a placeholder (Create, D21 v10.3)' {
        $s = New-CrTestState -Profile 'SM' -OmitUsers 'BiCA Admin'
        $e = Get-TestEntry (Resolve-CrAccounts -Config $config -State $s) 'BiCAAdmin'
        $e.Kind | Should Be 'Windows'
        $e.Mode | Should Be 'Rotate'
        $e.Create | Should Be $true
        $e.NotApplicable | Should Be $false
        $e.Missing.Count | Should Be 0
        $e.Accounts.Count | Should Be 1
        $e.Accounts[0].Name | Should Be 'BiCA Admin'
        $e.Accounts[0].Sid | Should BeNullOrEmpty
        $e.Accounts[0].User | Should BeNullOrEmpty
        $e.Accounts[0].ToCreate | Should Be $true
        $e.Slot | Should Be 'BiCAAdmin'
        $e.RoleName | Should Be 'Admin'
        $e.Role.ExclusiveGroups | Should Be $true
        $e.PasswordMode | Should Be 'Set'
        $e.LoginsEntry | Should Be $true
        $e.Operator | Should Be $false
        $e.Replaced.Count | Should Be 0
        $e.Candidate | Should BeNullOrEmpty
        $e.AutoLogon | Should BeNullOrEmpty
    }

    It 'resolves the operator account BiCA Remote (Operator, AdminRemote role)' {
        $e = Get-TestEntry $resolved 'BiCARemote'
        $e.Operator | Should Be $true
        $e.EnableIfDisabled | Should Be $false
        $e.Create | Should Be $false
        $e.Accounts[0].Name | Should Be 'BiCA Remote'
        $e.Slot | Should Be 'BiCARemote'
        $e.RoleName | Should Be 'AdminRemote'
        (@($e.Role.AllowedExtraGroups) -contains 'S-1-5-32-555') | Should Be $true
        $e.PasswordMode | Should Be 'Set'
        $e.Replaced.Count | Should Be 0
    }

    It 'resolves a missing BiCA Remote to a placeholder that keeps Operator' {
        $s = New-CrTestState -Profile 'SM' -OmitUsers 'BiCA Remote'
        $e = Get-TestEntry (Resolve-CrAccounts -Config $config -State $s) 'BiCARemote'
        $e.Create | Should Be $true
        $e.Operator | Should Be $true
        $e.Accounts.Count | Should Be 1
        $e.Accounts[0].Name | Should Be 'BiCA Remote'
        $e.Accounts[0].ToCreate | Should Be $true
    }

    It 'resolves an existing Change account and its replaced RID-500 (renamed, already disabled)' {
        $e = Get-TestEntry $resolved 'AppUser'
        $e.Create | Should Be $false
        $e.PasswordMode | Should Be 'Change'
        $e.EnableIfDisabled | Should Be $true
        $e.Operator | Should Be $false
        $e.Accounts.Count | Should Be 1
        $e.Accounts[0].Name | Should Be 'ApplicationUser'
        $e.Accounts[0].Sid | Should Be (Get-CrTestUserSid $state 'ApplicationUser')
        $e.Replaced.Count | Should Be 1
        $e.Replaced[0].Name | Should Be 'LocalAdm'
        $e.Replaced[0].Sid | Should Be ($state.Computer.MachineSid + '-500')
        $e.Replaced[0].Enabled | Should Be $false
    }

    It 'resolves a missing ApplicationUser to a placeholder and still lists the replaced RID-500' {
        $s = New-CrTestState -Profile 'SM' -OmitUsers 'ApplicationUser'
        $e = Get-TestEntry (Resolve-CrAccounts -Config $config -State $s) 'AppUser'
        $e.Create | Should Be $true
        $e.Accounts[0].Name | Should Be 'ApplicationUser'
        $e.Accounts[0].ToCreate | Should Be $true
        $e.Replaced.Count | Should Be 1
        $e.Replaced[0].Name | Should Be 'LocalAdm'
    }

    It 'carries the original config entry in Config' {
        $e = Get-TestEntry $resolved 'AppUser'
        $e.Config.Services | Should Be 'Auto'
        [object]::ReferenceEquals($e.Config, $config.Accounts[2]) | Should Be $true
        (Get-TestEntry $resolved 'SqlApp').Config.ServerRoles[0] | Should Be 'sysadmin'
    }

    It 'resolves the AutoLogon entry to WinAutoUser; the absent PUB-User is missing, not created' {
        $e = Get-TestEntry $resolved 'AutoLogon'
        $e.Mode | Should Be 'Rotate'
        $e.Create | Should Be $false
        $e.NotApplicable | Should Be $false
        $e.Accounts.Count | Should Be 1
        $e.Accounts[0].Name | Should Be 'WinAutoUser'
        $e.Accounts[0].Sid | Should Be (Get-CrTestUserSid $state 'WinAutoUser')
        $e.Accounts[0].ToCreate | Should BeNullOrEmpty
        $e.Missing.Count | Should Be 1
        $e.Missing[0] | Should Be 'PUB-User'
        $e.Replaced.Count | Should Be 0
        $e.Slot | Should Be 'AutoLogon'
        $e.RoleName | Should Be 'User'
        $e.PasswordMode | Should Be 'Set'
        $e.Operator | Should Be $false
        $e.EnableIfDisabled | Should Be $false
    }

    It 'keeps the auto-logon block and both AutoLogonUser names' {
        $e = Get-TestEntry $resolved 'AutoLogon'
        $e.AutoLogon.RestrictedComputerPattern | Should Be '^SM'
        $e.AutoLogonUser.Count | Should Be 2
        $e.AutoLogonUser[0].Name | Should Be 'PUB-User'
        $e.AutoLogonUser[1].Name | Should Be 'WinAutoUser'
    }

    It 'resolves a Disable entry to the existing accounts' {
        $e = Get-TestEntry $resolved 'Retired'
        $e.Mode | Should Be 'Disable'
        $e.Slot | Should BeNullOrEmpty
        $e.PasswordMode | Should BeNullOrEmpty
        $e.Create | Should Be $false
        $e.Operator | Should Be $false
        $e.EnableIfDisabled | Should Be $false
        $e.Replaced.Count | Should Be 0
        $e.Accounts.Count | Should Be 1
        $e.Accounts[0].Name | Should Be 'SP Admin'
        $e.Missing.Count | Should Be 2
        $e.Missing[0] | Should Be 'SYS Admin'
        $e.Missing[1] | Should Be 'SOP-Admin'
        $e.NotApplicable | Should Be $false
    }

    It 'compares names case-insensitively' {
        $c = New-CrTestConfig
        (Get-TestConfigEntry $c 'AppUser').Name = 'applicationuser'
        (Get-TestConfigEntry $c 'AutoLogon').Names = @('pub-user', 'winautouser')
        (Get-TestConfigEntry $c 'Retired').Names = @('sp admin')
        $r = Resolve-CrAccounts -Config $c -State $state
        (Get-TestEntry $r 'AppUser').Accounts[0].Name | Should Be 'ApplicationUser'
        $al = Get-TestEntry $r 'AutoLogon'
        $al.Accounts.Count | Should Be 1
        $al.Accounts[0].Name | Should Be 'WinAutoUser'
        $al.Missing[0] | Should Be 'pub-user'
        (Get-TestEntry $r 'Retired').Accounts[0].Name | Should Be 'SP Admin'
    }

    It 'marks Check entries' {
        $e = Get-TestEntry $resolved 'WinUsers'
        $e.Mode | Should Be 'Check'
        $e.Slot | Should BeNullOrEmpty
        $e.PasswordMode | Should BeNullOrEmpty
        $e.LoginsEntry | Should Be $false
        $e.Create | Should Be $false
        $e.Operator | Should Be $false
        $e.EnableIfDisabled | Should Be $false
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
        $e.PasswordMode | Should BeNullOrEmpty
        $e.Replaced.Count | Should Be 0
    }
}

Describe 'Resolve-CrAccounts on an IPT01-like machine' {
    $state = New-CrTestState -Profile 'IPT01'
    $resolved = Resolve-CrAccounts -Config (New-CrTestConfig) -State $state

    It 'resolves the existing BiCA accounts without creating them' {
        $a = Get-TestEntry $resolved 'BiCAAdmin'
        $a.Create | Should Be $false
        $a.Accounts.Count | Should Be 1
        $a.Accounts[0].Sid | Should Be (Get-CrTestUserSid $state 'BiCA Admin')
        $a.Accounts[0].ToCreate | Should BeNullOrEmpty
        $r = Get-TestEntry $resolved 'BiCARemote'
        $r.Create | Should Be $false
        $r.Operator | Should Be $true
        $r.Accounts[0].Sid | Should Be (Get-CrTestUserSid $state 'BiCA Remote')
    }

    It 'selects the existing SOP-Admin by the Retired entry (Mode Disable), never creates it' {
        $e = Get-TestEntry $resolved 'Retired'
        $e.Mode | Should Be 'Disable'
        $e.Create | Should Be $false
        $e.Slot | Should BeNullOrEmpty
        $e.Accounts.Count | Should Be 2
        $e.Accounts[1].Name | Should Be 'SOP-Admin'
        $e.Accounts[1].Sid | Should Be (Get-CrTestUserSid $state 'SOP-Admin')
        $e.Accounts[1].ToCreate | Should BeNullOrEmpty
        foreach ($r in $resolved) {
            if ($r.Id -eq 'Retired') { continue }
            (Get-TestAccountNames $r) -contains 'SOP-Admin' | Should Be $false
        }
    }

    It 'lists an enabled built-in Administrator as replaced by ApplicationUser' {
        $e = Get-TestEntry $resolved 'AppUser'
        $e.Replaced.Count | Should Be 1
        $e.Replaced[0].Name | Should Be 'Administrator'
        $e.Replaced[0].Enabled | Should Be $true
    }

    It 'finds RID-500 by the user RID when the machine SID is unknown' {
        $s = New-CrTestState -Profile 'IPT01'
        $s.Computer.MachineSid = $null
        $e = Get-TestEntry (Resolve-CrAccounts -Config (New-CrTestConfig) -State $s) 'AppUser'
        $e.Replaced.Count | Should Be 1
        $e.Replaced[0].Name | Should Be 'Administrator'
    }

    It 'skips replaced accounts that do not exist' {
        $s = New-CrTestState -Profile 'IPT01' -OmitUsers @('BiCA Admin', 'WinAutoUser')
        $r = Resolve-CrAccounts -Config (New-CrTestConfig) -State $s
        $sop = Get-TestEntry $r 'SOPAdmin'
        $sop.Replaced.Count | Should Be 1
        $sop.Replaced[0].Name | Should Be 'BiCA Remote'
        (Get-TestEntry $r 'PubUser').Replaced.Count | Should Be 0
    }

    It 'resolves the PUB-User entry to the existing account' {
        $e = Get-TestEntry $resolved 'PubUser'
        $e.Create | Should Be $false
        $e.Accounts.Count | Should Be 1
        $e.Accounts[0].Name | Should Be 'PUB-User'
    }

    It 'resolves the Disable entry to SYS Admin' {
        $e = Get-TestEntry $resolved 'Retired'
        (Get-TestAccountNames $e)[0] | Should Be 'SYS Admin'
        $e.Missing[0] | Should Be 'SP Admin'
    }

    It 'marks entries without accounts as not applicable' {
        $w = Get-TestEntry $resolved 'WinUsers'
        $w.NotApplicable | Should Be $true
        $w.Missing.Count | Should Be 3
        $f = Get-TestEntry $resolved 'FtpUsers'
        $f.NotApplicable | Should Be $true
        $f.Missing.Count | Should Be 0
    }

    It 'is not applicable when a managed account without Create is missing' {
        $c = New-CrTestConfig
        (Get-TestConfigEntry $c 'SOPAdmin').Remove('Create')
        $s = New-CrTestState -Profile 'IPT01' -OmitUsers 'SOP-Admin'
        $e = Get-TestEntry (Resolve-CrAccounts -Config $c -State $s) 'SOPAdmin'
        $e.Create | Should Be $false
        $e.NotApplicable | Should Be $true
        $e.Missing[0] | Should Be 'SOP-Admin'
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

    It 'never creates an account when the Users part failed' {
        $s = New-CrTestState -Profile 'SM' -Parts @{ Users = @{ Error = 'access denied' } }
        $r = Resolve-CrAccounts -Config (New-CrTestConfig) -State $s
        $e = Get-TestEntry $r 'SOPAdmin'
        $e.Create | Should Be $false
        $e.NotApplicable | Should Be $true
        $e.Missing[0] | Should Be 'SOP-Admin'
        $e.Error | Should Match 'access denied'
        $e.Replaced.Count | Should Be 0
    }
}

Describe 'Resolve-CrAccounts with Candidates (still supported)' {
    It 'falls back to the second candidate (RID-500)' {
        $c = New-CrTestConfig
        Add-TestAccount $c @{ Id = 'Cand'; Kind = 'Windows'
                              Candidates = @(@{ Name = 'Kiosk'; Role = 'User'; Credential = 'PubUser' }, @{ Sid = 'RID-500'; Role = 'Admin'; Credential = 'AppUser' }) }
        $state = New-CrTestState -Profile 'SM'
        $e = Get-TestEntry (Resolve-CrAccounts -Config $c -State $state) 'Cand'
        $e.Candidate | Should Be 1
        $e.Slot | Should Be 'AppUser'
        $e.Accounts[0].Name | Should Be 'LocalAdm'
        $e.PasswordMode | Should Be 'Set'
    }
}

Describe 'Get-CrOtherEnabledAccounts' {
    It 'lists the enabled accounts no entry selects (SM)' {
        $state = New-CrTestState -Profile 'SM'
        $resolved = Resolve-CrAccounts -Config (New-CrTestConfig) -State $state
        $others = Get-CrOtherEnabledAccounts -State $state -Resolved $resolved
        $others.Count | Should Be 2
        $names = @(); foreach ($u in $others) { $names += $u.Name }
        ($names -contains 'OtherAdmin') | Should Be $true
        ($names -contains 'myftpuser') | Should Be $true
    }

    It 'never lists disabled, replaced, retired, managed or checked accounts' {
        $state = New-CrTestState -Profile 'SM'
        $resolved = Resolve-CrAccounts -Config (New-CrTestConfig) -State $state
        $others = Get-CrOtherEnabledAccounts -State $state -Resolved $resolved
        $names = @(); foreach ($u in $others) { $names += $u.Name }
        foreach ($n in @('Guest', 'LocalAdm', 'BiCA Admin', 'BiCA Remote', 'WinAutoUser', 'SP Admin', 'ApplicationUser', 'WinUser1', 'TEST_FTP')) {
            ($names -contains $n) | Should Be $false
        }
    }

    It 'lists nothing on the IPT01-like machine' {
        $state = New-CrTestState -Profile 'IPT01'
        $resolved = Resolve-CrAccounts -Config (New-CrTestConfig) -State $state
        (Get-CrOtherEnabledAccounts -State $state -Resolved $resolved).Count | Should Be 0
    }

    It 'skips a disabled extra account' {
        $state = New-CrTestState -Profile 'IPT01' -Customize { param($st) [void](Add-CrTestUser -State $st -Name 'OldKiosk' -Disabled) }
        $resolved = Resolve-CrAccounts -Config (New-CrTestConfig) -State $state
        (Get-CrOtherEnabledAccounts -State $state -Resolved $resolved).Count | Should Be 0
    }

    It 'returns an empty list when the Users part failed' {
        $state = New-CrTestState -Profile 'SM' -Parts @{ Users = @{ Error = 'access denied' } }
        $resolved = Resolve-CrAccounts -Config (New-CrTestConfig) -State $state
        (Get-CrOtherEnabledAccounts -State $state -Resolved $resolved).Count | Should Be 0
    }
}

Describe 'NamePattern exclusion and SID overlap' {
    It 'finds no overlap with the default config (SM)' {
        $resolved = Resolve-CrAccounts -Config (New-CrTestConfig) -State (New-CrTestState -Profile 'SM')
        (Find-CrSidOverlap -Resolved $resolved).Count | Should Be 0
    }

    It 'finds no overlap with the default config (IPT01)' {
        $resolved = Resolve-CrAccounts -Config (New-CrTestConfig) -State (New-CrTestState -Profile 'IPT01')
        (Find-CrSidOverlap -Resolved $resolved).Count | Should Be 0
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

    It 'excludes a replaced account from NamePattern' {
        $c = New-CrTestConfig
        (Get-TestConfigEntry $c 'PubUser').Replaces = @('WinAutoUser', 'ftpClient')
        $resolved = Resolve-CrAccounts -Config $c -State (New-CrTestState -Profile 'SM')
        $names = Get-TestAccountNames (Get-TestEntry $resolved 'FtpUsers')
        ($names -contains 'ftpClient') | Should Be $false
        (Find-CrSidOverlap -Resolved $resolved).Count | Should Be 0
    }

    It 'excludes a name of a Disable entry from NamePattern' {
        $c = New-CrTestConfig
        (Get-TestConfigEntry $c 'Retired').Names = @('SP Admin', 'SYS Admin', 'ftpClient')
        $resolved = Resolve-CrAccounts -Config $c -State (New-CrTestState -Profile 'SM')
        $names = Get-TestAccountNames (Get-TestEntry $resolved 'FtpUsers')
        ($names -contains 'ftpClient') | Should Be $false
        (Find-CrSidOverlap -Resolved $resolved).Count | Should Be 0
    }

    It 'reports a SID selected by two named entries as Ambiguous' {
        $c = New-CrTestConfig
        Add-TestAccount $c @{ Id = 'Dup'; Kind = 'Windows'; Name = 'SOP-Admin'; Role = 'Admin'; Credential = 'SOPAdmin' }
        $resolved = Resolve-CrAccounts -Config $c -State (New-CrTestState -Profile 'IPT01')
        $findings = Find-CrSidOverlap -Resolved $resolved
        $findings.Count | Should Be 1
        $findings[0].Severity | Should Be 'Ambiguous'
        $findings[0].Account | Should Be 'SOP-Admin'
        $findings[0].Message | Should Match 'SOPAdmin, Dup'
    }

    It 'reports a replaced account that another entry selects' {
        $c = New-CrTestConfig
        Add-TestAccount $c @{ Id = 'Kiosk'; Kind = 'Windows'; Name = 'WinAutoUser'; Role = 'User'; Mode = 'Check' }
        $resolved = Resolve-CrAccounts -Config $c -State (New-CrTestState -Profile 'SM')
        $findings = Find-CrSidOverlap -Resolved $resolved
        $findings.Count | Should Be 1
        $findings[0].Account | Should Be 'WinAutoUser'
        $findings[0].Message | Should Match 'PubUser \(replaces\), Kiosk'
    }

    It 'reports a renamed RID-500 that another entry names explicitly' {
        $c = New-CrTestConfig
        Add-TestAccount $c @{ Id = 'Renamed'; Kind = 'Windows'; Name = 'LocalAdm'; Mode = 'Disable' }
        $resolved = Resolve-CrAccounts -Config $c -State (New-CrTestState -Profile 'SM')
        $findings = Find-CrSidOverlap -Resolved $resolved
        $findings.Count | Should Be 1
        $findings[0].Message | Should Match 'AppUser \(replaces\), Renamed'
    }

    It 'reports an entry that replaces its own account' {
        $c = New-CrTestConfig
        (Get-TestConfigEntry $c 'AppUser').Replaces = @('RID-500', 'ApplicationUser')
        $resolved = Resolve-CrAccounts -Config $c -State (New-CrTestState -Profile 'SM')
        $findings = Find-CrSidOverlap -Resolved $resolved
        $findings.Count | Should Be 1
        $findings[0].Account | Should Be 'ApplicationUser'
        $findings[0].Message | Should Match 'AppUser, AppUser \(replaces\)'
    }

    It 'reports a Disable account that is also replaced' {
        $c = New-CrTestConfig
        (Get-TestConfigEntry $c 'Retired').Names = @('SP Admin', 'SYS Admin', 'BiCA Admin')
        $resolved = Resolve-CrAccounts -Config $c -State (New-CrTestState -Profile 'SM')
        $findings = Find-CrSidOverlap -Resolved $resolved
        $findings.Count | Should Be 1
        $findings[0].Message | Should Match 'SOPAdmin \(replaces\), Retired'
    }

    It 'reports an overlap between two NamePattern entries' {
        $c = New-CrTestConfig
        Add-TestAccount $c @{ Id = 'Clients'; Kind = 'Windows'; NamePattern = 'client$'; Role = 'User'; Mode = 'Check' }
        $resolved = Resolve-CrAccounts -Config $c -State (New-CrTestState -Profile 'SM')
        $findings = Find-CrSidOverlap -Resolved $resolved
        $findings.Count | Should Be 1
        $findings[0].Account | Should Be 'ftpClient'
    }

    It 'does not report two names of one entry that resolve to one account' {
        $c = New-CrTestConfig
        (Get-TestConfigEntry $c 'WinUsers').Names = @('WinUser1', 'winuser1', 'WinUser2')
        $resolved = Resolve-CrAccounts -Config $c -State (New-CrTestState -Profile 'SM')
        (Get-TestEntry $resolved 'WinUsers').Accounts.Count | Should Be 2
        (Find-CrSidOverlap -Resolved $resolved).Count | Should Be 0
    }

    It 'ignores create placeholders (no SID yet)' {
        $c = New-CrTestConfig
        Add-TestAccount $c @{ Id = 'Twin'; Kind = 'Windows'; Name = 'SOP-Admin'; Role = 'Operator'; Credential = 'SOPAdmin'; Create = $true }
        $resolved = Resolve-CrAccounts -Config $c -State (New-CrTestState -Profile 'SM')
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
