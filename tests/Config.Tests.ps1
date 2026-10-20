$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here '..\src\lib\Compat.ps1')
. (Join-Path $here '..\src\lib\Config.ps1')
. (Join-Path $here 'Fixtures.ps1')

# $true if any error string matches the regex.
function Test-HasConfigError {
    param($Errors, [string]$Pattern)
    foreach ($e in $Errors) { if ($e -match $Pattern) { return $true } }
    return $false
}

function Get-TestAccount {
    param($Config, [string]$Id)
    foreach ($a in $Config.Accounts) { if ($a.Id -eq $Id) { return $a } }
    throw "no account $Id"
}

function Add-TestAccount {
    param($Config, [hashtable]$Entry)
    $Config.Accounts = @($Config.Accounts) + @($Entry)
}

# A Mode = 'Keep' entry (D26): the default config has none since v10.7, the mode stays supported.
function Add-TestKeepEntry {
    param($Config)
    $entry = @{ Id = 'Untouched'; Kind = 'Windows'; Names = @('Kept Admin'); Mode = 'Keep' }
    Add-TestAccount $Config $entry
    return $entry
}

Describe 'Import-CrConfig' {
    $defaultPath = Join-Path $here '..\config\CredentialRotation.psd1'

    It 'loads the default config' {
        $c = Import-CrConfig -Path $defaultPath
        ($c -is [hashtable]) | Should Be $true
        $c.SchemaVersion | Should Be 1
        @($c.Accounts).Count | Should Be 7
        @($c.Credentials).Count | Should Be 4
        $c.Roles.ContainsKey('AdminRemote') | Should Be $true
        $c.Roles.ContainsKey('Operator') | Should Be $false
        $c.Roles.ContainsKey('RotateOnly') | Should Be $false
        $c.OtherEnabledAccounts | Should Be 'Ask'
    }

    It 'has the slots in Order, SOPAdmin last (D25), no BiCA slots (v10.6) and no SQL slots (D27)' {
        $c = Import-CrConfig -Path $defaultPath
        $slots = @(); $orders = @()
        foreach ($cr in $c.Credentials) { $slots += $cr.Slot; $orders += $cr.Order }
        ($slots -join ',') | Should Be 'AppUser,AutoLogon,SPAdmin,SOPAdmin'
        ($orders -join ',') | Should Be '20,30,40,90'
    }

    It 'has SOP-Admin replacing BiCA Admin and BiCA Remote (created if missing, the operator, SQL access; D28, D29)' {
        $c = Import-CrConfig -Path $defaultPath
        $sop = Get-TestAccount $c 'SOPAdmin'
        $sop.Name | Should Be 'SOP-Admin'
        $sop.Role | Should Be 'AdminRemote'
        $sop.Credential | Should Be 'SOPAdmin'
        $sop.Create | Should Be $true
        $sop.EnableIfDisabled | Should Be $true
        $sop.Operator | Should Be $true
        $sop.ContainsKey('Application') | Should Be $false
        (@($sop.Replaces) -join ',') | Should Be 'BiCA Admin,BiCA Remote'
        $sop.SqlAccess | Should Be 'FromReplaced'
        $sop.LoginsEntry | Should Be $true
        $sop.Services | Should Be 'Auto'
        $sop.ScheduledTasks | Should Be 'Auto'
        $sop.ComPlus | Should Be 'Auto'
        $sop.ContainsKey('PasswordMode') | Should Be $false
    }

    It 'has ApplicationUser (Create, EnableIfDisabled, Change, the Application account, replaces RID-500)' {
        $c = Import-CrConfig -Path $defaultPath
        $app = Get-TestAccount $c 'AppUser'
        $app.Name | Should Be 'ApplicationUser'
        $app.Create | Should Be $true
        $app.EnableIfDisabled | Should Be $true
        $app.Application | Should Be $true
        $app.ContainsKey('SqlAccess') | Should Be $false
        $app.PasswordMode | Should Be 'Change'
        @($app.Replaces).Count | Should Be 1
        @($app.Replaces)[0] | Should Be 'RID-500'
    }

    It 'has the AutoLogon entry with both auto-logon accounts (never created, never replaced)' {
        $c = Import-CrConfig -Path $defaultPath
        $al = Get-TestAccount $c 'AutoLogon'
        (@($al.Names) -join ',') | Should Be 'PUB-User,WinAutoUser'
        $al.Role | Should Be 'User'
        $al.Credential | Should Be 'AutoLogon'
        $al.ContainsKey('Create') | Should Be $false
        $al.ContainsKey('Replaces') | Should Be $false
        $alu = @($al.AutoLogonUser)
        $alu.Count | Should Be 2
        $alu[0].Name | Should Be 'PUB-User'
        $alu[1].Name | Should Be 'WinAutoUser'
        @($alu[0].Keys).Count | Should Be 1
        @($alu[1].Keys).Count | Should Be 1
        $al.AutoLogon.RestrictedComputerPattern | Should Be '^SM'
    }

    It 'retires SYS Admin in both spellings (v10.5)' {
        $c = Import-CrConfig -Path $defaultPath
        $r = Get-TestAccount $c 'Retired'
        $r.Mode | Should Be 'Disable'
        (@($r.Names) -join ',') | Should Be 'SYS Admin,SYS-Admin'
    }

    It 'has SP Admin as a managed account: created if missing, Administrators only, its own slot, nothing else (D30, v10.7)' {
        $c = Import-CrConfig -Path $defaultPath
        $sp = Get-TestAccount $c 'SPAdmin'
        $sp.Kind | Should Be 'Windows'
        $sp.Name | Should Be 'SP Admin'
        $sp.Role | Should Be 'Admin'
        $sp.Credential | Should Be 'SPAdmin'
        $sp.Create | Should Be $true
        $sp.Services | Should Be 'Auto'
        $sp.ScheduledTasks | Should Be 'Auto'
        $sp.ComPlus | Should Be 'Auto'
        foreach ($k in @('Replaces', 'SqlAccess', 'Operator', 'Application', 'EnableIfDisabled', 'PasswordMode', 'LoginsEntry', 'Mode')) {
            $sp.ContainsKey($k) | Should Be $false
        }
        (@($c.Roles.Admin.Groups) -join ',') | Should Be 'S-1-5-32-544'
    }

    It 'keeps no account untouched any more (D26: SOP-Admin managed since v10.6, SP Admin since v10.7)' {
        $c = Import-CrConfig -Path $defaultPath
        foreach ($a in $c.Accounts) { [string]$a.Mode | Should Not Be 'Keep' }
    }

    It 'has no SQL login entries (D27, v10.5)' {
        $c = Import-CrConfig -Path $defaultPath
        foreach ($a in $c.Accounts) { $a.Kind | Should Be 'Windows' }
        foreach ($cr in $c.Credentials) { ($cr.Slot -like 'SQL*') | Should Be $false }
    }

    It 'has no SqlSysadminLogin key, no single-Name PUB-User entry and no entry that manages a BiCA account (v10.6)' {
        $c = Import-CrConfig -Path $defaultPath
        foreach ($a in $c.Accounts) {
            $a.ContainsKey('SqlSysadminLogin') | Should Be $false
            $a.Name | Should Not Be 'PUB-User'
            ([string]$a.Name -like 'BiCA*') | Should Be $false
            foreach ($n in @($a.Names)) { ([string]$n -like 'BiCA*') | Should Be $false }
        }
    }

    It 'throws for a missing file' {
        { Import-CrConfig -Path (Join-Path $TestDrive 'nope.psd1') } | Should Throw
    }

    It 'throws on a syntax error' {
        $bad = Join-Path $TestDrive 'Broken.psd1'
        Set-Content -LiteralPath $bad -Value "@{ SchemaVersion = 1; Roles = @{ " -Encoding UTF8
        { Import-CrConfig -Path $bad } | Should Throw
    }

    It 'throws on code that the data language forbids' {
        $bad = Join-Path $TestDrive 'Code.psd1'
        Set-Content -LiteralPath $bad -Value "@{ SchemaVersion = (Get-Date) }" -Encoding UTF8
        { Import-CrConfig -Path $bad } | Should Throw
    }
}

Describe 'Import-CrConfig: copy in a culture subfolder (PLAN 5, 9)' {
    # Import-LocalizedData -UICulture en-US would load en-US\<file> or en\<file> instead of the file whose hash is shown.
    # Every case gets its own folder under TestDrive.
    function New-TestConfigFolder {
        param([string]$Name, [string[]]$CopyCultures = @(), [string]$CopyName = 'Site.psd1')
        $dir = Join-Path $TestDrive $Name
        [void](New-Item -ItemType Directory -Path $dir -Force)
        $file = Join-Path $dir 'Site.psd1'
        Set-Content -LiteralPath $file -Value "@{ SchemaVersion = 1; OtherEnabledAccounts = 'Ask' }" -Encoding UTF8
        foreach ($culture in $CopyCultures) {
            $sub = Join-Path $dir $culture
            [void](New-Item -ItemType Directory -Path $sub -Force)
            Set-Content -LiteralPath (Join-Path $sub $CopyName) -Value "@{ SchemaVersion = 2; OtherEnabledAccounts = 'Ask' }" -Encoding UTF8
        }
        return $file
    }

    It 'loads a valid config without a culture subfolder' {
        $file = New-TestConfigFolder -Name 'Plain'
        $c = Import-CrConfig -Path $file
        ($c -is [hashtable]) | Should Be $true
        $c.SchemaVersion | Should Be 1
    }

    It 'throws when a copy exists in en-US' {
        $file = New-TestConfigFolder -Name 'EnUs' -CopyCultures @('en-US')
        { Import-CrConfig -Path $file } | Should Throw 'culture subfolder'
    }

    It 'throws when a copy exists in en' {
        $file = New-TestConfigFolder -Name 'En' -CopyCultures @('en')
        { Import-CrConfig -Path $file } | Should Throw 'culture subfolder'
    }

    It 'names the copy in the message' {
        $file = New-TestConfigFolder -Name 'Named' -CopyCultures @('en-US')
        $message = $null
        try { [void](Import-CrConfig -Path $file) } catch { $message = $_.Exception.Message }
        $message | Should Match ([regex]::Escape((Join-Path 'en-US' 'Site.psd1')))
    }

    It 'loads the config when the culture subfolders hold only other files' {
        $file = New-TestConfigFolder -Name 'OtherFile' -CopyCultures @('en-US', 'en') -CopyName 'Other.psd1'
        $c = Import-CrConfig -Path $file
        $c.SchemaVersion | Should Be 1
    }
}

Describe 'Get-CrRole' {
    $c = New-CrTestConfig

    It 'returns the role hashtable' {
        $role = Get-CrRole -Config $c -Name 'Ftp'
        $role.IfGroupMissing | Should Be 'ReportKeepGroups'
    }

    It 'returns the AdminRemote role of SOP-Admin: Administrators, Remote Desktop Users and Offer Remote Assistance Helpers (D28)' {
        $role = Get-CrRole -Config $c -Name 'AdminRemote'
        (@($role.Groups) -join ',') | Should Be 'S-1-5-32-544,S-1-5-32-555,Name:Offer Remote Assistance Helpers?'
        $role.ContainsKey('AllowedExtraGroups') | Should Be $false
        $role.ExclusiveGroups | Should Be $true
        $role.PasswordRequired | Should Be $true
    }

    It 'throws for an unknown role (RotateOnly is gone)' {
        { Get-CrRole -Config $c -Name 'RotateOnly' } | Should Throw
    }

    It 'throws for the Operator role (gone in v10.2)' {
        { Get-CrRole -Config $c -Name 'Operator' } | Should Throw
    }
}

Describe 'Test-CrConfig' {

    It 'accepts the default config' {
        $errors = @(Test-CrConfig -Config (New-CrTestConfig))
        $errors.Count | Should Be 0
    }

    It 'rejects a non-hashtable' {
        $errors = @(Test-CrConfig -Config 'x')
        $errors.Count | Should Be 1
    }

    Context 'unknown keys' {
        It 'at the top level' {
            $c = New-CrTestConfig; $c.Extra = 1
            Test-HasConfigError @(Test-CrConfig -Config $c) "unknown key 'Extra'" | Should Be $true
        }
        It 'in a role' {
            $c = New-CrTestConfig; $c.Roles.Admin.Exclusive = $true
            Test-HasConfigError @(Test-CrConfig -Config $c) "Role 'Admin': unknown key 'Exclusive'" | Should Be $true
        }
        It 'in a credential slot' {
            $c = New-CrTestConfig; $c.Credentials[0].Prompt = 'x'
            Test-HasConfigError @(Test-CrConfig -Config $c) "Slot 'AppUser': unknown key 'Prompt'" | Should Be $true
        }
        It 'in an account' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'AppUser').Group = 'x'
            Test-HasConfigError @(Test-CrConfig -Config $c) "Account 'AppUser': unknown key 'Group'" | Should Be $true
        }
        It 'SqlSysadminLogin (removed in v10.2)' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'SOPAdmin').SqlSysadminLogin = $true
            Test-HasConfigError @(Test-CrConfig -Config $c) "Account 'SOPAdmin': unknown key 'SqlSysadminLogin'" | Should Be $true
        }
        It 'in a candidate' {
            $c = New-CrTestConfig
            Add-TestAccount $c @{ Id = 'Cand'; Kind = 'Windows'; Candidates = @(@{ Name = 'Kiosk'; Role = 'User'; Credential = 'AutoLogon'; Rid = 1 }) }
            Test-HasConfigError @(Test-CrConfig -Config $c) "candidate 0: unknown key 'Rid'" | Should Be $true
        }
        It 'in SitePasswordRules' {
            $c = New-CrTestConfig; $c.SitePasswordRules.MaxLength = 5
            Test-HasConfigError @(Test-CrConfig -Config $c) "SitePasswordRules: unknown key 'MaxLength'" | Should Be $true
        }
        It 'in the AutoLogon block (only Mode and RestrictedComputerPattern)' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'AutoLogon').AutoLogon.Pattern = '^SM'
            Test-HasConfigError @(Test-CrConfig -Config $c) "AutoLogon: unknown key 'Pattern'" | Should Be $true
        }
        It 'in AutoLogonUser' {
            $c = New-CrTestConfig
            $item = @((Get-TestAccount $c 'AutoLogon').AutoLogonUser)[0]
            $item.Prefer = $true
            Test-HasConfigError @(Test-CrConfig -Config $c) "AutoLogonUser: unknown key 'Prefer'" | Should Be $true
        }
        It 'RequireEnabled in AutoLogonUser (removed in v10.1; only Name)' {
            $c = New-CrTestConfig
            $item = @((Get-TestAccount $c 'AutoLogon').AutoLogonUser)[1]
            $item.RequireEnabled = $true
            Test-HasConfigError @(Test-CrConfig -Config $c) "Account 'AutoLogon' AutoLogonUser: unknown key 'RequireEnabled'" | Should Be $true
        }
        It 'a key of the other Kind' {
            $c = New-CrTestSqlConfig; (Get-TestAccount $c 'SqlApp').Role = 'Admin'
            Test-HasConfigError @(Test-CrConfig -Config $c) "key 'Role' is not valid for Kind 'SqlLogin'" | Should Be $true
        }
        It 'a v10 Windows key on a SQL login' {
            $c = New-CrTestSqlConfig; (Get-TestAccount $c 'SqlApp').PasswordMode = 'Change'
            Test-HasConfigError @(Test-CrConfig -Config $c) "key 'PasswordMode' is not valid for Kind 'SqlLogin'" | Should Be $true
        }
        It 'reports a missing top-level key' {
            $c = New-CrTestConfig; $c.Remove('Credentials')
            Test-HasConfigError @(Test-CrConfig -Config $c) "missing key 'Credentials'" | Should Be $true
        }
    }

    Context 'OtherEnabledAccounts' {
        It 'is optional' {
            $c = New-CrTestConfig; $c.Remove('OtherEnabledAccounts')
            @(Test-CrConfig -Config $c).Count | Should Be 0
        }
        It 'accepts only Ask' {
            $c = New-CrTestConfig; $c.OtherEnabledAccounts = 'Disable'
            Test-HasConfigError @(Test-CrConfig -Config $c) "OtherEnabledAccounts 'Disable' is not valid" | Should Be $true
        }
    }

    Context 'roles and slots' {
        It 'an unknown role on an entry' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'AppUser').Role = 'Boss'
            Test-HasConfigError @(Test-CrConfig -Config $c) "unknown role 'Boss'" | Should Be $true
        }
        It 'the Operator role (gone in v10.2)' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'SOPAdmin').Role = 'Operator'
            Test-HasConfigError @(Test-CrConfig -Config $c) "Account 'SOPAdmin': unknown role 'Operator'" | Should Be $true
        }
        It 'an unknown role on a candidate' {
            $c = New-CrTestConfig
            Add-TestAccount $c @{ Id = 'Cand'; Kind = 'Windows'; Candidates = @(@{ Name = 'Kiosk'; Role = 'User'; Credential = 'AutoLogon' }, @{ Sid = 'RID-500'; Role = 'Nope'; Credential = 'AutoLogon' }) }
            Test-HasConfigError @(Test-CrConfig -Config $c) "candidate 1: unknown role 'Nope'" | Should Be $true
        }
        It 'a Windows entry without a role' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'SOPAdmin').Remove('Role')
            Test-HasConfigError @(Test-CrConfig -Config $c) "SOPAdmin': Role must be" | Should Be $true
        }
        It 'an unknown slot on an entry' {
            $c = New-CrTestSqlConfig; (Get-TestAccount $c 'SqlScript').Credential = 'SQLScripts'
            Test-HasConfigError @(Test-CrConfig -Config $c) "Credential 'SQLScripts' does not refer to an existing slot" | Should Be $true
        }
        It 'an unknown slot on a candidate' {
            $c = New-CrTestConfig
            Add-TestAccount $c @{ Id = 'Cand'; Kind = 'Windows'; Candidates = @(@{ Name = 'Kiosk'; Role = 'User'; Credential = 'AutoLogon' }, @{ Sid = 'RID-500'; Role = 'Admin'; Credential = 'AppUserBuiltin' }) }
            Test-HasConfigError @(Test-CrConfig -Config $c) "candidate 1: Credential 'AppUserBuiltin' does not refer" | Should Be $true
        }
        It 'a removed slot (BiCAAdmin and BiCARemote in v10.6, PubUser in v10.1)' {
            $c = New-CrTestConfig
            (Get-TestAccount $c 'SOPAdmin').Credential = 'BiCARemote'
            (Get-TestAccount $c 'AppUser').Credential = 'BiCAAdmin'
            (Get-TestAccount $c 'AutoLogon').Credential = 'PubUser'
            $errors = @(Test-CrConfig -Config $c)
            Test-HasConfigError $errors "SOPAdmin': Credential 'BiCARemote' does not refer to an existing slot" | Should Be $true
            Test-HasConfigError $errors "AppUser': Credential 'BiCAAdmin' does not refer to an existing slot" | Should Be $true
            Test-HasConfigError $errors "AutoLogon': Credential 'PubUser' does not refer to an existing slot" | Should Be $true
        }
        It 'a rotated entry without a Credential' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'SOPAdmin').Remove('Credential')
            Test-HasConfigError @(Test-CrConfig -Config $c) "SOPAdmin': Credential must be" | Should Be $true
        }
        It 'a Check entry with a Credential' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'WinUsers').Credential = 'AppUser'
            Test-HasConfigError @(Test-CrConfig -Config $c) "Mode 'Check' entries have no Credential" | Should Be $true
        }
        It 'Role/Credential on an entry with Candidates' {
            $c = New-CrTestConfig
            Add-TestAccount $c @{ Id = 'Cand'; Kind = 'Windows'; Credential = 'AutoLogon'; Candidates = @(@{ Name = 'Kiosk'; Role = 'User'; Credential = 'AutoLogon' }) }
            Test-HasConfigError @(Test-CrConfig -Config $c) 'Credential belongs on each candidate' | Should Be $true
        }
        It 'accepts an entry with Candidates (still supported)' {
            $c = New-CrTestConfig
            Add-TestAccount $c @{ Id = 'Cand'; Kind = 'Windows'; Candidates = @(@{ Name = 'Kiosk'; Role = 'User'; Credential = 'AutoLogon' }, @{ Sid = 'S-1-5-21-1000-2000-3000-1500'; Role = 'User'; Credential = 'AutoLogon' }) }
            @(Test-CrConfig -Config $c).Count | Should Be 0
        }
        It 'a duplicate Order' {
            $c = New-CrTestConfig; $c.Credentials[1].Order = 20
            Test-HasConfigError @(Test-CrConfig -Config $c) 'duplicate Order 20' | Should Be $true
        }
        It 'a non-integer Order' {
            $c = New-CrTestConfig; $c.Credentials[1].Order = 'first'
            Test-HasConfigError @(Test-CrConfig -Config $c) 'Order must be an integer' | Should Be $true
        }
        It 'a duplicate slot' {
            $c = New-CrTestConfig; $c.Credentials[1].Slot = 'AppUser'
            Test-HasConfigError @(Test-CrConfig -Config $c) "Slot 'AppUser': duplicate slot" | Should Be $true
        }
        It 'a duplicate Id' {
            $c = New-CrTestConfig
            Add-TestAccount $c @{ Id = 'SOPAdmin'; Kind = 'Windows'; Name = 'Someone'; Role = 'User'; Mode = 'Check' }
            Test-HasConfigError @(Test-CrConfig -Config $c) "Account 'SOPAdmin': duplicate Id" | Should Be $true
        }
        It 'a missing Id' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'WinUsers').Remove('Id')
            Test-HasConfigError @(Test-CrConfig -Config $c) 'Id must be a non-empty string' | Should Be $true
        }
        It 'a non-bool role flag' {
            $c = New-CrTestConfig; $c.Roles.User.PasswordNeverExpires = 'yes'
            Test-HasConfigError @(Test-CrConfig -Config $c) 'PasswordNeverExpires must be' | Should Be $true
        }
        It 'an unknown IfGroupMissing value' {
            $c = New-CrTestConfig; $c.Roles.Ftp.IfGroupMissing = 'Create'
            Test-HasConfigError @(Test-CrConfig -Config $c) "IfGroupMissing 'Create'" | Should Be $true
        }
        It 'an unsupported SchemaVersion' {
            $c = New-CrTestConfig; $c.SchemaVersion = 2
            Test-HasConfigError @(Test-CrConfig -Config $c) 'unsupported SchemaVersion' | Should Be $true
        }
    }

    Context 'SIDs and group references' {
        It 'an invalid SID in Groups' {
            $c = New-CrTestConfig; $c.Roles.Admin.Groups = @('S-1-5-32-x544')
            Test-HasConfigError @(Test-CrConfig -Config $c) "invalid SID 'S-1-5-32-x544'" | Should Be $true
        }
        It 'an invalid SID in AllowedExtraGroups' {
            $c = New-CrTestConfig; $c.Roles.WinUser.AllowedExtraGroups = @('S-1-')
            Test-HasConfigError @(Test-CrConfig -Config $c) "invalid SID 'S-1-'" | Should Be $true
        }
        It 'an invalid candidate Sid' {
            $c = New-CrTestConfig
            Add-TestAccount $c @{ Id = 'Cand'; Kind = 'Windows'; Candidates = @(@{ Sid = 'RID500'; Role = 'User'; Credential = 'AutoLogon' }) }
            Test-HasConfigError @(Test-CrConfig -Config $c) "invalid SID 'RID500'" | Should Be $true
        }
        It 'an unknown reference form' {
            $c = New-CrTestConfig; $c.Roles.Ftp.Groups = @('CardCenters')
            Test-HasConfigError @(Test-CrConfig -Config $c) "unknown reference form 'CardCenters'" | Should Be $true
        }
        It 'Pattern: outside AllowedExtraGroups' {
            $c = New-CrTestConfig; $c.Roles.WinUser.Groups = @('S-1-5-32-545', 'Pattern:^hw_fn_')
            Test-HasConfigError @(Test-CrConfig -Config $c) 'Pattern: is only valid in AllowedExtraGroups' | Should Be $true
        }
        It 'a Pattern: regex that does not compile' {
            $c = New-CrTestConfig; $c.Roles.WinUser.AllowedExtraGroups = @('S-1-5-32-555', 'Pattern:^hw_fn_(')
            Test-HasConfigError @(Test-CrConfig -Config $c) "regex '\^hw_fn_\(' does not compile" | Should Be $true
        }
        It 'accepts Name:x? and RID-500 references' {
            $c = New-CrTestConfig; $c.Roles.Admin.Groups = @('S-1-5-32-544', 'Name:Some Group?', 'RID-500')
            @(Test-CrConfig -Config $c).Count | Should Be 0
        }
    }

    Context 'selection rules' {
        It 'a NamePattern that does not compile' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'FtpUsers').NamePattern = '^ftp['
            Test-HasConfigError @(Test-CrConfig -Config $c) "NamePattern '\^ftp\[' does not compile" | Should Be $true
        }
        It 'two selection rules on one entry' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'WinUsers').Name = 'WinUser1'
            Test-HasConfigError @(Test-CrConfig -Config $c) 'needs exactly one of Name, Names, NamePattern, Candidates \(found 2\)' | Should Be $true
        }
        It 'no selection rule' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'WinUsers').Remove('Names')
            Test-HasConfigError @(Test-CrConfig -Config $c) '\(found 0\)' | Should Be $true
        }
        It 'a candidate with both Name and Sid' {
            $c = New-CrTestConfig
            Add-TestAccount $c @{ Id = 'Cand'; Kind = 'Windows'; Candidates = @(@{ Name = 'Kiosk'; Sid = 'RID-500'; Role = 'User'; Credential = 'AutoLogon' }) }
            Test-HasConfigError @(Test-CrConfig -Config $c) 'candidate 0: needs exactly one of Name or Sid' | Should Be $true
        }
        It 'an invalid Kind' {
            $c = New-CrTestSqlConfig; (Get-TestAccount $c 'SqlApp').Kind = 'Sql'
            Test-HasConfigError @(Test-CrConfig -Config $c) "SqlApp': Kind must be one of" | Should Be $true
        }
        It 'a Mode other than Check, Disable or Keep' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'AppUser').Mode = 'Rotate'
            Test-HasConfigError @(Test-CrConfig -Config $c) "Mode 'Rotate' is not valid \(only 'Check', 'Disable' or 'Keep'" | Should Be $true
        }
        It 'an unknown dependent value' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'AppUser').Services = 'Always'
            Test-HasConfigError @(Test-CrConfig -Config $c) 'Services must be one of' | Should Be $true
        }
    }

    Context 'managed-account keys (v10.3)' {
        It 'a non-bool Create' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'SOPAdmin').Create = 'yes'
            Test-HasConfigError @(Test-CrConfig -Config $c) "SOPAdmin': Create must be" | Should Be $true
        }
        It 'Create with Names' {
            $c = New-CrTestConfig
            Add-TestAccount $c @{ Id = 'Two'; Kind = 'Windows'; Names = @('Kiosk1', 'Kiosk2'); Role = 'User'; Credential = 'AutoLogon'; Create = $true }
            Test-HasConfigError @(Test-CrConfig -Config $c) "Two': Create requires a single Name" | Should Be $true
        }
        It 'a non-bool Operator' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'SOPAdmin').Operator = 1
            Test-HasConfigError @(Test-CrConfig -Config $c) "SOPAdmin': Operator must be" | Should Be $true
        }
        It 'a non-bool EnableIfDisabled' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'AppUser').EnableIfDisabled = 'yes'
            Test-HasConfigError @(Test-CrConfig -Config $c) "AppUser': EnableIfDisabled must be" | Should Be $true
        }
        It 'Operator with Names' {
            $c = New-CrTestConfig
            $r = Get-TestAccount $c 'SOPAdmin'; $r.Remove('Name'); $r.Remove('Create'); $r.Names = @('SOP-Admin', 'Kiosk')
            Test-HasConfigError @(Test-CrConfig -Config $c) "SOPAdmin': Operator requires a single Name" | Should Be $true
        }
        It 'two Operator entries' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'AppUser').Operator = $true
            Test-HasConfigError @(Test-CrConfig -Config $c) 'only one entry may be the Operator account' | Should Be $true
        }
        It 'accepts Operator = $false on another entry' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'AppUser').Operator = $false
            @(Test-CrConfig -Config $c).Count | Should Be 0
        }
        It 'accepts a config without an Operator entry (at most one)' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'SOPAdmin').Remove('Operator')
            @(Test-CrConfig -Config $c).Count | Should Be 0
        }
        It 'a non-bool Application' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'AppUser').Application = 'yes'
            Test-HasConfigError @(Test-CrConfig -Config $c) "AppUser': Application must be" | Should Be $true
        }
        It 'Application with Names' {
            $c = New-CrTestConfig
            Add-TestAccount $c @{ Id = 'Two'; Kind = 'Windows'; Names = @('Kiosk1', 'Kiosk2'); Role = 'User'; Credential = 'AutoLogon'; Application = $true }
            $errors = @(Test-CrConfig -Config $c)
            Test-HasConfigError $errors "Two': Application requires a single Name" | Should Be $true
            Test-HasConfigError $errors 'only one entry may be the Application account' | Should Be $true
        }
        It 'two Application entries (v10.6)' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'SOPAdmin').Application = $true
            Test-HasConfigError @(Test-CrConfig -Config $c) 'only one entry may be the Application account' | Should Be $true
        }
        It 'accepts a config without an Application entry' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'AppUser').Remove('Application')
            @(Test-CrConfig -Config $c).Count | Should Be 0
        }
        It 'an unknown SqlAccess value (D29)' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'SOPAdmin').SqlAccess = 'Sysadmin'
            Test-HasConfigError @(Test-CrConfig -Config $c) "SOPAdmin': SqlAccess must be one of: FromReplaced" | Should Be $true
        }
        It 'SqlAccess without Replaces' {
            $c = New-CrTestConfig
            $s = Get-TestAccount $c 'SOPAdmin'; $s.Remove('Replaces')
            Test-HasConfigError @(Test-CrConfig -Config $c) "SOPAdmin': SqlAccess requires Replaces" | Should Be $true
        }
        It 'accepts SqlAccess on another entry with Replaces' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'AppUser').SqlAccess = 'FromReplaced'
            @(Test-CrConfig -Config $c).Count | Should Be 0
        }
        It 'SqlAccess or Application on a SQL login' {
            $c = New-CrTestSqlConfig
            $s = Get-TestAccount $c 'SqlApp'; $s.SqlAccess = 'FromReplaced'; $s.Application = $true
            $errors = @(Test-CrConfig -Config $c)
            Test-HasConfigError $errors "SqlApp': key 'SqlAccess' is not valid for Kind 'SqlLogin'" | Should Be $true
            Test-HasConfigError $errors "SqlApp': key 'Application' is not valid for Kind 'SqlLogin'" | Should Be $true
        }
        It 'accepts EnableIfDisabled = $false' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'AppUser').EnableIfDisabled = $false
            @(Test-CrConfig -Config $c).Count | Should Be 0
        }
        It 'Operator or EnableIfDisabled on a SQL login' {
            $c = New-CrTestSqlConfig
            $s = Get-TestAccount $c 'SqlApp'; $s.Operator = $true; $s.EnableIfDisabled = $true
            $errors = @(Test-CrConfig -Config $c)
            Test-HasConfigError $errors "SqlApp': key 'Operator' is not valid for Kind 'SqlLogin'" | Should Be $true
            Test-HasConfigError $errors "SqlApp': key 'EnableIfDisabled' is not valid for Kind 'SqlLogin'" | Should Be $true
        }
        It 'an unknown PasswordMode' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'AppUser').PasswordMode = 'Reset'
            Test-HasConfigError @(Test-CrConfig -Config $c) 'PasswordMode must be one of: Set, Change' | Should Be $true
        }
        It 'accepts PasswordMode Set' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'SOPAdmin').PasswordMode = 'Set'
            @(Test-CrConfig -Config $c).Count | Should Be 0
        }
        It 'PasswordMode on an entry with Candidates (no entry Credential)' {
            $c = New-CrTestConfig
            Add-TestAccount $c @{ Id = 'Cand'; Kind = 'Windows'; PasswordMode = 'Change'; Candidates = @(@{ Name = 'Kiosk'; Role = 'User'; Credential = 'AutoLogon' }) }
            Test-HasConfigError @(Test-CrConfig -Config $c) "Cand': PasswordMode is only valid on Windows entries with a Credential" | Should Be $true
        }
        It 'managed keys on a Check entry' {
            $c = New-CrTestConfig
            $w = Get-TestAccount $c 'WinUsers'; $w.PasswordMode = 'Set'; $w.Create = $true; $w.Replaces = @('Kiosk')
            $w.Operator = $true; $w.EnableIfDisabled = $true; $w.Application = $true; $w.SqlAccess = 'FromReplaced'
            $errors = @(Test-CrConfig -Config $c)
            Test-HasConfigError $errors "WinUsers': key 'PasswordMode' is not valid for Mode 'Check'" | Should Be $true
            Test-HasConfigError $errors "WinUsers': key 'Create' is not valid for Mode 'Check'" | Should Be $true
            Test-HasConfigError $errors "WinUsers': key 'Replaces' is not valid for Mode 'Check'" | Should Be $true
            Test-HasConfigError $errors "WinUsers': key 'Operator' is not valid for Mode 'Check'" | Should Be $true
            Test-HasConfigError $errors "WinUsers': key 'EnableIfDisabled' is not valid for Mode 'Check'" | Should Be $true
            Test-HasConfigError $errors "WinUsers': key 'Application' is not valid for Mode 'Check'" | Should Be $true
            Test-HasConfigError $errors "WinUsers': key 'SqlAccess' is not valid for Mode 'Check'" | Should Be $true
        }
        It 'an empty Replaces' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'AppUser').Replaces = @()
            Test-HasConfigError @(Test-CrConfig -Config $c) "AppUser': Replaces is empty" | Should Be $true
        }
        It 'a RID other than RID-500 in Replaces' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'AppUser').Replaces = @('RID-501')
            Test-HasConfigError @(Test-CrConfig -Config $c) "Replaces 'RID-501': only RID-500" | Should Be $true
        }
        It 'a SID in Replaces' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'AppUser').Replaces = @('S-1-5-21-1000-2000-3000-500')
            Test-HasConfigError @(Test-CrConfig -Config $c) 'use an account name or RID-500' | Should Be $true
        }
        It 'an empty string in Replaces' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'AppUser').Replaces = @('RID-500', '')
            Test-HasConfigError @(Test-CrConfig -Config $c) 'every entry of Replaces must be a non-empty string' | Should Be $true
        }
        It 'a name replaced by two entries (case-insensitive)' {
            $c = New-CrTestConfig
            (Get-TestAccount $c 'AppUser').Replaces = @('RID-500', 'bica admin')
            Test-HasConfigError @(Test-CrConfig -Config $c) "AppUser': Replaces 'bica admin' is already replaced by Account 'SOPAdmin'" | Should Be $true
        }
        It 'RID-500 replaced by two entries' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'SOPAdmin').Replaces = @('BiCA Admin', 'BiCA Remote', 'RID-500')
            Test-HasConfigError @(Test-CrConfig -Config $c) "AppUser': Replaces 'RID-500' is already replaced by Account 'SOPAdmin'" | Should Be $true
        }
        It 'Replaces on an entry with Names' {
            $c = New-CrTestConfig
            Add-TestAccount $c @{ Id = 'Two'; Kind = 'Windows'; Names = @('Kiosk1', 'Kiosk2'); Role = 'User'; Credential = 'AutoLogon'; Replaces = @('OldKiosk') }
            Test-HasConfigError @(Test-CrConfig -Config $c) "Two': Replaces requires a single Name" | Should Be $true
        }
    }

    Context 'Disable entries' {
        It 'a Disable entry with a Role' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'Retired').Role = 'Admin'
            Test-HasConfigError @(Test-CrConfig -Config $c) "Retired': key 'Role' is not valid for Mode 'Disable'" | Should Be $true
        }
        It 'a Disable entry with a Credential' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'Retired').Credential = 'AppUser'
            Test-HasConfigError @(Test-CrConfig -Config $c) "Retired': key 'Credential' is not valid for Mode 'Disable'" | Should Be $true
        }
        It 'a Disable entry with Replaces or PasswordMode' {
            $c = New-CrTestConfig
            $r = Get-TestAccount $c 'Retired'; $r.Replaces = @('Kiosk'); $r.PasswordMode = 'Set'
            $errors = @(Test-CrConfig -Config $c)
            Test-HasConfigError $errors "Retired': key 'Replaces' is not valid for Mode 'Disable'" | Should Be $true
            Test-HasConfigError $errors "Retired': key 'PasswordMode' is not valid for Mode 'Disable'" | Should Be $true
        }
        It 'a Disable entry with Create, Operator or EnableIfDisabled' {
            $c = New-CrTestConfig
            $r = Get-TestAccount $c 'Retired'; $r.Create = $true; $r.Operator = $true; $r.EnableIfDisabled = $true
            $errors = @(Test-CrConfig -Config $c)
            Test-HasConfigError $errors "Retired': key 'Create' is not valid for Mode 'Disable'" | Should Be $true
            Test-HasConfigError $errors "Retired': key 'Operator' is not valid for Mode 'Disable'" | Should Be $true
            Test-HasConfigError $errors "Retired': key 'EnableIfDisabled' is not valid for Mode 'Disable'" | Should Be $true
        }
        It 'a Disable entry with a NamePattern' {
            $c = New-CrTestConfig
            Add-TestAccount $c @{ Id = 'Pat'; Kind = 'Windows'; NamePattern = '^old'; Mode = 'Disable' }
            Test-HasConfigError @(Test-CrConfig -Config $c) "Pat': key 'NamePattern' is not valid for Mode 'Disable'" | Should Be $true
        }
        It 'accepts a Disable entry with a single Name' {
            $c = New-CrTestConfig
            Add-TestAccount $c @{ Id = 'One'; Kind = 'Windows'; Name = 'Kiosk'; Mode = 'Disable' }
            @(Test-CrConfig -Config $c).Count | Should Be 0
        }
        It 'Mode Disable on a SQL login' {
            $c = New-CrTestSqlConfig; (Get-TestAccount $c 'SqlApp').Mode = 'Disable'
            Test-HasConfigError @(Test-CrConfig -Config $c) "key 'Mode' is not valid for Kind 'SqlLogin'" | Should Be $true
        }
    }

    Context 'Keep entries (v10.5)' {
        It 'a Keep entry with a Role or a Credential' {
            $c = New-CrTestConfig
            $k = Add-TestKeepEntry $c; $k.Role = 'Admin'; $k.Credential = 'AppUser'
            $errors = @(Test-CrConfig -Config $c)
            Test-HasConfigError $errors "Untouched': key 'Role' is not valid for Mode 'Keep'" | Should Be $true
            Test-HasConfigError $errors "Untouched': key 'Credential' is not valid for Mode 'Keep'" | Should Be $true
        }
        It 'a Keep entry with dependents or LoginsEntry' {
            $c = New-CrTestConfig
            $k = Add-TestKeepEntry $c; $k.Services = 'Auto'; $k.LoginsEntry = $true
            $errors = @(Test-CrConfig -Config $c)
            Test-HasConfigError $errors "Untouched': key 'Services' is not valid for Mode 'Keep'" | Should Be $true
            Test-HasConfigError $errors "Untouched': key 'LoginsEntry' is not valid for Mode 'Keep'" | Should Be $true
        }
        It 'a Keep entry with Create, Replaces or PasswordMode' {
            $c = New-CrTestConfig
            $k = Add-TestKeepEntry $c; $k.Create = $true; $k.Replaces = @('Kiosk'); $k.PasswordMode = 'Set'
            $errors = @(Test-CrConfig -Config $c)
            Test-HasConfigError $errors "Untouched': key 'Create' is not valid for Mode 'Keep'" | Should Be $true
            Test-HasConfigError $errors "Untouched': key 'Replaces' is not valid for Mode 'Keep'" | Should Be $true
            Test-HasConfigError $errors "Untouched': key 'PasswordMode' is not valid for Mode 'Keep'" | Should Be $true
        }
        It 'a Keep entry with a NamePattern' {
            $c = New-CrTestConfig
            Add-TestAccount $c @{ Id = 'PatKeep'; Kind = 'Windows'; NamePattern = '^sop'; Mode = 'Keep' }
            Test-HasConfigError @(Test-CrConfig -Config $c) "PatKeep': key 'NamePattern' is not valid for Mode 'Keep'" | Should Be $true
        }
        It 'accepts a Keep entry with a single Name' {
            $c = New-CrTestConfig
            Add-TestAccount $c @{ Id = 'OneKeep'; Kind = 'Windows'; Name = 'Kiosk'; Mode = 'Keep' }
            @(Test-CrConfig -Config $c).Count | Should Be 0
        }
        It 'an auto-logon account in a Keep entry (case-insensitive)' {
            $c = New-CrTestConfig; $k = Add-TestKeepEntry $c; $k.Names = @('Kept Admin', 'pub-user')
            Test-HasConfigError @(Test-CrConfig -Config $c) "the auto-logon account 'PUB-User' must not be in a Keep entry" | Should Be $true
        }
        It 'Mode Keep on a SQL login' {
            $c = New-CrTestSqlConfig; (Get-TestAccount $c 'SqlApp').Mode = 'Keep'
            Test-HasConfigError @(Test-CrConfig -Config $c) "key 'Mode' is not valid for Kind 'SqlLogin'" | Should Be $true
        }
    }

    Context 'auto-logon block' {
        It 'a Mode value other than IfAlreadyOn' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'AutoLogon').AutoLogon.Mode = 'Always'
            Test-HasConfigError @(Test-CrConfig -Config $c) 'AutoLogon Mode must be one of' | Should Be $true
        }
        It 'a RestrictedComputerPattern that does not compile' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'AutoLogon').AutoLogon.RestrictedComputerPattern = '^SM('
            Test-HasConfigError @(Test-CrConfig -Config $c) 'RestrictedComputerPattern .* does not compile' | Should Be $true
        }
        It 'AutoLogon without AutoLogonUser' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'AutoLogon').Remove('AutoLogonUser')
            Test-HasConfigError @(Test-CrConfig -Config $c) 'must be set together' | Should Be $true
        }
        It 'an AutoLogonUser that the entry does not select' {
            $c = New-CrTestConfig
            $item = @((Get-TestAccount $c 'AutoLogon').AutoLogonUser)[0]
            $item.Name = 'Kiosk'
            Test-HasConfigError @(Test-CrConfig -Config $c) "AutoLogonUser 'Kiosk' is not selected" | Should Be $true
        }
        It 'two entries with an AutoLogon block' {
            $c = New-CrTestConfig
            Add-TestAccount $c @{ Id = 'Second'; Kind = 'Windows'; Name = 'Kiosk'; Role = 'User'; Credential = 'AutoLogon'
                                  AutoLogonUser = @(@{ Name = 'Kiosk' }); AutoLogon = @{ Mode = 'IfAlreadyOn'; RestrictedComputerPattern = '^SM' } }
            Test-HasConfigError @(Test-CrConfig -Config $c) 'only one entry may have an AutoLogon block' | Should Be $true
        }
    }

    Context 'auto-logon accounts (D18, D21, D22)' {
        It 'an account of the entry missing from AutoLogonUser' {
            $c = New-CrTestConfig
            (Get-TestAccount $c 'AutoLogon').AutoLogonUser = @(@{ Name = 'PUB-User' })
            Test-HasConfigError @(Test-CrConfig -Config $c) "AutoLogon': 'WinAutoUser' is missing from AutoLogonUser" | Should Be $true
        }
        It 'accepts AutoLogonUser in another order, compared case-insensitively' {
            $c = New-CrTestConfig
            (Get-TestAccount $c 'AutoLogon').AutoLogonUser = @(@{ Name = 'winautouser' }, @{ Name = 'pub-user' })
            @(Test-CrConfig -Config $c).Count | Should Be 0
        }
        It 'Create on the AutoLogon entry (the auto-logon accounts are never created)' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'AutoLogon').Create = $true
            Test-HasConfigError @(Test-CrConfig -Config $c) "AutoLogon': the auto-logon accounts are never created; Create is not valid with AutoLogon" | Should Be $true
        }
        It 'Create with AutoLogon also on a single-Name entry' {
            $c = New-CrTestConfig
            $al = Get-TestAccount $c 'AutoLogon'
            $al.Remove('Names'); $al.Name = 'PUB-User'; $al.AutoLogonUser = @(@{ Name = 'PUB-User' }); $al.Create = $true
            $errors = @(Test-CrConfig -Config $c)
            Test-HasConfigError $errors 'Create is not valid with AutoLogon' | Should Be $true
            Test-HasConfigError $errors 'Create requires a single Name' | Should Be $false
        }
        It 'an auto-logon account in Replaces (case-insensitive)' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'AppUser').Replaces = @('RID-500', 'winautouser')
            Test-HasConfigError @(Test-CrConfig -Config $c) "the auto-logon account 'WinAutoUser' must not be replaced \(Account 'AppUser'\)" | Should Be $true
        }
        It 'an auto-logon account in a Disable entry with Names (case-insensitive)' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'Retired').Names = @('SYS Admin', 'SYS-Admin', 'pub-user')
            Test-HasConfigError @(Test-CrConfig -Config $c) "the auto-logon account 'PUB-User' must not be in a Disable entry" | Should Be $true
        }
        It 'an auto-logon account in a Disable entry with a single Name' {
            $c = New-CrTestConfig
            Add-TestAccount $c @{ Id = 'OldKiosk'; Kind = 'Windows'; Name = 'WinAutoUser'; Mode = 'Disable' }
            Test-HasConfigError @(Test-CrConfig -Config $c) "the auto-logon account 'WinAutoUser' must not be in a Disable entry" | Should Be $true
        }
    }
}

Describe 'Get-CrConfigSlotNames' {
    It 'returns the slot names in file order' {
        $names = Get-CrConfigSlotNames -Config (New-CrTestConfig)
        $names.Count | Should Be 4
        $names[0] | Should Be 'AppUser'
        $names[1] | Should Be 'AutoLogon'
        $names[2] | Should Be 'SPAdmin'
        $names[3] | Should Be 'SOPAdmin'
        ($names -contains 'SQLApplication') | Should Be $false
        ($names -contains 'BiCAAdmin') | Should Be $false
        ($names -contains 'BiCARemote') | Should Be $false
        ($names -contains 'PubUser') | Should Be $false
    }

    It 'returns a single slot as an array' {
        $c = New-CrTestConfig; $c.Credentials = @(@{ Slot = 'AppUser'; Order = 20 })
        $names = Get-CrConfigSlotNames -Config $c
        $names.Count | Should Be 1
        $names[0] | Should Be 'AppUser'
    }

    It 'returns an empty array without Credentials or for a non-hashtable' {
        $c = New-CrTestConfig; $c.Remove('Credentials')
        (Get-CrConfigSlotNames -Config $c).Count | Should Be 0
        (Get-CrConfigSlotNames -Config 'x').Count | Should Be 0
    }

    It 'skips slots without a name' {
        $c = New-CrTestConfig; $c.Credentials = @(@{ Order = 10 }, @{ Slot = 'AppUser'; Order = 20 }, 'x')
        $names = Get-CrConfigSlotNames -Config $c
        $names.Count | Should Be 1
        $names[0] | Should Be 'AppUser'
    }
}

Describe 'Get-CrUnknownOnlySlots' {
    $c = New-CrTestConfig

    It 'returns nothing for known slots' {
        (Get-CrUnknownOnlySlots -Config $c -Only @('AppUser', 'AutoLogon', 'SPAdmin', 'SOPAdmin')).Count | Should Be 0
    }

    It 'compares case-insensitively' {
        (Get-CrUnknownOnlySlots -Config $c -Only @('appuser', 'SOPADMIN', 'autologon')).Count | Should Be 0
    }

    It 'returns the removed BiCA slots as unknown (v10.6)' {
        $unknown = Get-CrUnknownOnlySlots -Config $c -Only @('BiCAAdmin', 'AppUser', 'BiCARemote')
        $unknown.Count | Should Be 2
        $unknown[0] | Should Be 'BiCAAdmin'
        $unknown[1] | Should Be 'BiCARemote'
    }

    It 'returns a removed SQL slot as unknown (D27)' {
        $unknown = Get-CrUnknownOnlySlots -Config $c -Only @('AppUser', 'SQLService')
        $unknown.Count | Should Be 1
        $unknown[0] | Should Be 'SQLService'
    }

    It 'returns the unknown names in the given order (a removed v10 slot)' {
        $unknown = Get-CrUnknownOnlySlots -Config $c -Only @('PubUser', 'AppUser', 'Operator')
        $unknown.Count | Should Be 2
        $unknown[0] | Should Be 'PubUser'
        $unknown[1] | Should Be 'Operator'
    }

    It 'returns a single unknown name as an array' {
        $unknown = Get-CrUnknownOnlySlots -Config $c -Only 'Operator'
        $unknown.Count | Should Be 1
        $unknown[0] | Should Be 'Operator'
    }

    It 'ignores empty names and an empty or missing -Only' {
        (Get-CrUnknownOnlySlots -Config $c -Only @('', 'AppUser')).Count | Should Be 0
        (Get-CrUnknownOnlySlots -Config $c -Only @()).Count | Should Be 0
        (Get-CrUnknownOnlySlots -Config $c).Count | Should Be 0
    }

    It 'treats every name as unknown when the config has no slots' {
        $empty = New-CrTestConfig; $empty.Remove('Credentials')
        (Get-CrUnknownOnlySlots -Config $empty -Only @('AppUser')).Count | Should Be 1
    }
}
