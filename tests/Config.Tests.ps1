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

Describe 'Import-CrConfig' {
    $defaultPath = Join-Path $here '..\config\CredentialRotation.psd1'

    It 'loads the default config' {
        $c = Import-CrConfig -Path $defaultPath
        ($c -is [hashtable]) | Should Be $true
        $c.SchemaVersion | Should Be 1
        @($c.Accounts).Count | Should Be 9
        @($c.Credentials).Count | Should Be 6
        $c.Roles.ContainsKey('Operator') | Should Be $true
        $c.Roles.ContainsKey('RotateOnly') | Should Be $false
        $c.OtherEnabledAccounts | Should Be 'Ask'
    }

    It 'has the v10 managed accounts' {
        $c = Import-CrConfig -Path $defaultPath
        $sop = Get-TestAccount $c 'SOPAdmin'
        $sop.Name | Should Be 'SOP-Admin'
        $sop.Create | Should Be $true
        $sop.SqlSysadminLogin | Should Be $true
        @($sop.Replaces).Count | Should Be 2
        $app = Get-TestAccount $c 'AppUser'
        $app.PasswordMode | Should Be 'Change'
        @($app.Replaces)[0] | Should Be 'RID-500'
        $pub = Get-TestAccount $c 'PubUser'
        $alu = @($pub.AutoLogonUser)
        $alu.Count | Should Be 1
        $alu[0].Name | Should Be 'PUB-User'
        $alu[0].RequireEnabled | Should Be $true
        $pub.AutoLogon.RestrictedComputerPattern | Should Be '^SM'
        (Get-TestAccount $c 'Retired').Mode | Should Be 'Disable'
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

Describe 'Get-CrRole' {
    $c = New-CrTestConfig

    It 'returns the role hashtable' {
        $role = Get-CrRole -Config $c -Name 'Ftp'
        $role.IfGroupMissing | Should Be 'ReportKeepGroups'
    }

    It 'returns the Operator role with Remote Desktop Users' {
        $role = Get-CrRole -Config $c -Name 'Operator'
        (@($role.Groups) -contains 'S-1-5-32-555') | Should Be $true
        $role.ExclusiveGroups | Should Be $true
    }

    It 'throws for an unknown role (RotateOnly is gone)' {
        { Get-CrRole -Config $c -Name 'RotateOnly' } | Should Throw
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
            Test-HasConfigError @(Test-CrConfig -Config $c) "Slot 'SOPAdmin': unknown key 'Prompt'" | Should Be $true
        }
        It 'in an account' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'SOPAdmin').Group = 'x'
            Test-HasConfigError @(Test-CrConfig -Config $c) "Account 'SOPAdmin': unknown key 'Group'" | Should Be $true
        }
        It 'in a candidate' {
            $c = New-CrTestConfig
            Add-TestAccount $c @{ Id = 'Cand'; Kind = 'Windows'; Candidates = @(@{ Name = 'Kiosk'; Role = 'User'; Credential = 'PubUser'; Rid = 1 }) }
            Test-HasConfigError @(Test-CrConfig -Config $c) "candidate 0: unknown key 'Rid'" | Should Be $true
        }
        It 'in SitePasswordRules' {
            $c = New-CrTestConfig; $c.SitePasswordRules.MaxLength = 5
            Test-HasConfigError @(Test-CrConfig -Config $c) "SitePasswordRules: unknown key 'MaxLength'" | Should Be $true
        }
        It 'in the AutoLogon block (only Mode and RestrictedComputerPattern)' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'PubUser').AutoLogon.Pattern = '^SM'
            Test-HasConfigError @(Test-CrConfig -Config $c) "AutoLogon: unknown key 'Pattern'" | Should Be $true
        }
        It 'in AutoLogonUser' {
            $c = New-CrTestConfig
            $item = @((Get-TestAccount $c 'PubUser').AutoLogonUser)[0]
            $item.Prefer = $true
            Test-HasConfigError @(Test-CrConfig -Config $c) "AutoLogonUser: unknown key 'Prefer'" | Should Be $true
        }
        It 'a key of the other Kind' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'SqlApp').Role = 'Admin'
            Test-HasConfigError @(Test-CrConfig -Config $c) "key 'Role' is not valid for Kind 'SqlLogin'" | Should Be $true
        }
        It 'a v10 Windows key on a SQL login' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'SqlApp').PasswordMode = 'Change'
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
            $c = New-CrTestConfig; (Get-TestAccount $c 'SOPAdmin').Role = 'Boss'
            Test-HasConfigError @(Test-CrConfig -Config $c) "unknown role 'Boss'" | Should Be $true
        }
        It 'an unknown role on a candidate' {
            $c = New-CrTestConfig
            Add-TestAccount $c @{ Id = 'Cand'; Kind = 'Windows'; Candidates = @(@{ Name = 'Kiosk'; Role = 'User'; Credential = 'PubUser' }, @{ Sid = 'RID-500'; Role = 'Nope'; Credential = 'PubUser' }) }
            Test-HasConfigError @(Test-CrConfig -Config $c) "candidate 1: unknown role 'Nope'" | Should Be $true
        }
        It 'a Windows entry without a role' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'SOPAdmin').Remove('Role')
            Test-HasConfigError @(Test-CrConfig -Config $c) "SOPAdmin': Role must be" | Should Be $true
        }
        It 'an unknown slot on an entry' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'SqlScript').Credential = 'SQLScripts'
            Test-HasConfigError @(Test-CrConfig -Config $c) "Credential 'SQLScripts' does not refer to an existing slot" | Should Be $true
        }
        It 'an unknown slot on a candidate' {
            $c = New-CrTestConfig
            Add-TestAccount $c @{ Id = 'Cand'; Kind = 'Windows'; Candidates = @(@{ Name = 'Kiosk'; Role = 'User'; Credential = 'PubUser' }, @{ Sid = 'RID-500'; Role = 'Admin'; Credential = 'AppUserBuiltin' }) }
            Test-HasConfigError @(Test-CrConfig -Config $c) "candidate 1: Credential 'AppUserBuiltin' does not refer" | Should Be $true
        }
        It 'a rotated entry without a Credential' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'SOPAdmin').Remove('Credential')
            Test-HasConfigError @(Test-CrConfig -Config $c) "SOPAdmin': Credential must be" | Should Be $true
        }
        It 'a Check entry with a Credential' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'WinUsers').Credential = 'SOPAdmin'
            Test-HasConfigError @(Test-CrConfig -Config $c) "Mode 'Check' entries have no Credential" | Should Be $true
        }
        It 'Role/Credential on an entry with Candidates' {
            $c = New-CrTestConfig
            Add-TestAccount $c @{ Id = 'Cand'; Kind = 'Windows'; Credential = 'PubUser'; Candidates = @(@{ Name = 'Kiosk'; Role = 'User'; Credential = 'PubUser' }) }
            Test-HasConfigError @(Test-CrConfig -Config $c) 'Credential belongs on each candidate' | Should Be $true
        }
        It 'accepts an entry with Candidates (still supported)' {
            $c = New-CrTestConfig
            Add-TestAccount $c @{ Id = 'Cand'; Kind = 'Windows'; Candidates = @(@{ Name = 'Kiosk'; Role = 'User'; Credential = 'PubUser' }, @{ Sid = 'S-1-5-21-1000-2000-3000-1500'; Role = 'User'; Credential = 'PubUser' }) }
            @(Test-CrConfig -Config $c).Count | Should Be 0
        }
        It 'a duplicate Order' {
            $c = New-CrTestConfig; $c.Credentials[1].Order = 10
            Test-HasConfigError @(Test-CrConfig -Config $c) 'duplicate Order 10' | Should Be $true
        }
        It 'a non-integer Order' {
            $c = New-CrTestConfig; $c.Credentials[1].Order = 'first'
            Test-HasConfigError @(Test-CrConfig -Config $c) 'Order must be an integer' | Should Be $true
        }
        It 'a duplicate slot' {
            $c = New-CrTestConfig; $c.Credentials[1].Slot = 'SOPAdmin'
            Test-HasConfigError @(Test-CrConfig -Config $c) "Slot 'SOPAdmin': duplicate slot" | Should Be $true
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
            Add-TestAccount $c @{ Id = 'Cand'; Kind = 'Windows'; Candidates = @(@{ Sid = 'RID500'; Role = 'User'; Credential = 'PubUser' }) }
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
            Add-TestAccount $c @{ Id = 'Cand'; Kind = 'Windows'; Candidates = @(@{ Name = 'Kiosk'; Sid = 'RID-500'; Role = 'User'; Credential = 'PubUser' }) }
            Test-HasConfigError @(Test-CrConfig -Config $c) 'candidate 0: needs exactly one of Name or Sid' | Should Be $true
        }
        It 'an invalid Kind' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'SqlApp').Kind = 'Sql'
            Test-HasConfigError @(Test-CrConfig -Config $c) "SqlApp': Kind must be one of" | Should Be $true
        }
        It 'a Mode other than Check or Disable' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'SOPAdmin').Mode = 'Rotate'
            Test-HasConfigError @(Test-CrConfig -Config $c) "Mode 'Rotate' is not valid \(only 'Check' or 'Disable'" | Should Be $true
        }
        It 'an unknown dependent value' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'AppUser').Services = 'Always'
            Test-HasConfigError @(Test-CrConfig -Config $c) 'Services must be one of' | Should Be $true
        }
    }

    Context 'v10 managed-account keys' {
        It 'a non-bool Create' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'SOPAdmin').Create = 'yes'
            Test-HasConfigError @(Test-CrConfig -Config $c) "SOPAdmin': Create must be" | Should Be $true
        }
        It 'Create with Names' {
            $c = New-CrTestConfig
            Add-TestAccount $c @{ Id = 'Two'; Kind = 'Windows'; Names = @('Kiosk1', 'Kiosk2'); Role = 'User'; Credential = 'PubUser'; Create = $true }
            Test-HasConfigError @(Test-CrConfig -Config $c) "Two': Create requires a single Name" | Should Be $true
        }
        It 'a non-bool SqlSysadminLogin' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'SOPAdmin').SqlSysadminLogin = 1
            Test-HasConfigError @(Test-CrConfig -Config $c) 'SqlSysadminLogin must be' | Should Be $true
        }
        It 'an unknown PasswordMode' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'AppUser').PasswordMode = 'Reset'
            Test-HasConfigError @(Test-CrConfig -Config $c) 'PasswordMode must be one of: Set, Change' | Should Be $true
        }
        It 'accepts PasswordMode Set' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'PubUser').PasswordMode = 'Set'
            @(Test-CrConfig -Config $c).Count | Should Be 0
        }
        It 'PasswordMode on an entry with Candidates (no entry Credential)' {
            $c = New-CrTestConfig
            Add-TestAccount $c @{ Id = 'Cand'; Kind = 'Windows'; PasswordMode = 'Change'; Candidates = @(@{ Name = 'Kiosk'; Role = 'User'; Credential = 'PubUser' }) }
            Test-HasConfigError @(Test-CrConfig -Config $c) "Cand': PasswordMode is only valid on Windows entries with a Credential" | Should Be $true
        }
        It 'v10 keys on a Check entry' {
            $c = New-CrTestConfig
            $w = Get-TestAccount $c 'WinUsers'; $w.PasswordMode = 'Set'; $w.Create = $true; $w.Replaces = @('Kiosk')
            $errors = @(Test-CrConfig -Config $c)
            Test-HasConfigError $errors "WinUsers': key 'PasswordMode' is not valid for Mode 'Check'" | Should Be $true
            Test-HasConfigError $errors "WinUsers': key 'Create' is not valid for Mode 'Check'" | Should Be $true
            Test-HasConfigError $errors "WinUsers': key 'Replaces' is not valid for Mode 'Check'" | Should Be $true
        }
        It 'an empty Replaces' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'PubUser').Replaces = @()
            Test-HasConfigError @(Test-CrConfig -Config $c) "PubUser': Replaces is empty" | Should Be $true
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
            $c = New-CrTestConfig; (Get-TestAccount $c 'PubUser').Replaces = @('WinAutoUser', '')
            Test-HasConfigError @(Test-CrConfig -Config $c) 'every entry of Replaces must be a non-empty string' | Should Be $true
        }
        It 'a name replaced by two entries (case-insensitive)' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'PubUser').Replaces = @('WinAutoUser', 'bica remote')
            Test-HasConfigError @(Test-CrConfig -Config $c) "PubUser': Replaces 'bica remote' is already replaced by Account 'SOPAdmin'" | Should Be $true
        }
        It 'RID-500 replaced by two entries' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'SOPAdmin').Replaces = @('BiCA Admin', 'BiCA Remote', 'RID-500')
            Test-HasConfigError @(Test-CrConfig -Config $c) "Replaces 'RID-500' is already replaced by" | Should Be $true
        }
        It 'Replaces on an entry with Names' {
            $c = New-CrTestConfig
            Add-TestAccount $c @{ Id = 'Two'; Kind = 'Windows'; Names = @('Kiosk1', 'Kiosk2'); Role = 'User'; Credential = 'PubUser'; Replaces = @('OldKiosk') }
            Test-HasConfigError @(Test-CrConfig -Config $c) "Two': Replaces requires a single Name" | Should Be $true
        }
    }

    Context 'Disable entries' {
        It 'a Disable entry with a Role' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'Retired').Role = 'Admin'
            Test-HasConfigError @(Test-CrConfig -Config $c) "Retired': key 'Role' is not valid for Mode 'Disable'" | Should Be $true
        }
        It 'a Disable entry with a Credential' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'Retired').Credential = 'SOPAdmin'
            Test-HasConfigError @(Test-CrConfig -Config $c) "Retired': key 'Credential' is not valid for Mode 'Disable'" | Should Be $true
        }
        It 'a Disable entry with Replaces or PasswordMode' {
            $c = New-CrTestConfig
            $r = Get-TestAccount $c 'Retired'; $r.Replaces = @('Kiosk'); $r.PasswordMode = 'Set'
            $errors = @(Test-CrConfig -Config $c)
            Test-HasConfigError $errors "Retired': key 'Replaces' is not valid for Mode 'Disable'" | Should Be $true
            Test-HasConfigError $errors "Retired': key 'PasswordMode' is not valid for Mode 'Disable'" | Should Be $true
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
            $c = New-CrTestConfig; (Get-TestAccount $c 'SqlApp').Mode = 'Disable'
            Test-HasConfigError @(Test-CrConfig -Config $c) "key 'Mode' is not valid for Kind 'SqlLogin'" | Should Be $true
        }
    }

    Context 'auto-logon block' {
        It 'a Mode value other than IfAlreadyOn' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'PubUser').AutoLogon.Mode = 'Always'
            Test-HasConfigError @(Test-CrConfig -Config $c) 'AutoLogon Mode must be one of' | Should Be $true
        }
        It 'a RestrictedComputerPattern that does not compile' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'PubUser').AutoLogon.RestrictedComputerPattern = '^SM('
            Test-HasConfigError @(Test-CrConfig -Config $c) 'RestrictedComputerPattern .* does not compile' | Should Be $true
        }
        It 'AutoLogon without AutoLogonUser' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'PubUser').Remove('AutoLogonUser')
            Test-HasConfigError @(Test-CrConfig -Config $c) 'must be set together' | Should Be $true
        }
        It 'an AutoLogonUser that the entry does not select' {
            $c = New-CrTestConfig
            $item = @((Get-TestAccount $c 'PubUser').AutoLogonUser)[0]
            $item.Name = 'WinAutoUser'
            Test-HasConfigError @(Test-CrConfig -Config $c) "AutoLogonUser 'WinAutoUser' is not selected" | Should Be $true
        }
        It 'two entries with an AutoLogon block' {
            $c = New-CrTestConfig
            Add-TestAccount $c @{ Id = 'Second'; Kind = 'Windows'; Name = 'Kiosk'; Role = 'User'; Credential = 'PubUser'
                                  AutoLogonUser = @(@{ Name = 'Kiosk' }); AutoLogon = @{ Mode = 'IfAlreadyOn'; RestrictedComputerPattern = '^SM' } }
            Test-HasConfigError @(Test-CrConfig -Config $c) 'only one entry may have an AutoLogon block' | Should Be $true
        }
    }
}
