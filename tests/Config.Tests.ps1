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
        @($c.Credentials).Count | Should Be 8
        $c.Roles.ContainsKey('AdminRemote') | Should Be $true
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

    It 'returns the empty RotateOnly role' {
        $role = Get-CrRole -Config $c -Name 'RotateOnly'
        ($role -is [hashtable]) | Should Be $true
        $role.Count | Should Be 0
    }

    It 'throws for an unknown role' {
        { Get-CrRole -Config $c -Name 'NoSuchRole' } | Should Throw
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
            Test-HasConfigError @(Test-CrConfig -Config $c) "Slot 'BiCAAdmin': unknown key 'Prompt'" | Should Be $true
        }
        It 'in an account' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'BiCAAdmin').Group = 'x'
            Test-HasConfigError @(Test-CrConfig -Config $c) "Account 'BiCAAdmin': unknown key 'Group'" | Should Be $true
        }
        It 'in a candidate' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'AppUser').Candidates[0].Rid = 1
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
            $c = New-CrTestConfig; (Get-TestAccount $c 'AutoLogon').AutoLogonUser[1].Prefer = $true
            Test-HasConfigError @(Test-CrConfig -Config $c) "AutoLogonUser: unknown key 'Prefer'" | Should Be $true
        }
        It 'a key of the other Kind' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'SqlApp').Role = 'Admin'
            Test-HasConfigError @(Test-CrConfig -Config $c) "key 'Role' is not valid for Kind 'SqlLogin'" | Should Be $true
        }
        It 'reports a missing top-level key' {
            $c = New-CrTestConfig; $c.Remove('Credentials')
            Test-HasConfigError @(Test-CrConfig -Config $c) "missing key 'Credentials'" | Should Be $true
        }
    }

    Context 'roles and slots' {
        It 'an unknown role on an entry' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'BiCAAdmin').Role = 'Boss'
            Test-HasConfigError @(Test-CrConfig -Config $c) "unknown role 'Boss'" | Should Be $true
        }
        It 'an unknown role on a candidate' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'AppUser').Candidates[1].Role = 'Nope'
            Test-HasConfigError @(Test-CrConfig -Config $c) "candidate 1: unknown role 'Nope'" | Should Be $true
        }
        It 'a Windows entry without a role' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'BiCAAdmin').Remove('Role')
            Test-HasConfigError @(Test-CrConfig -Config $c) "BiCAAdmin': Role must be" | Should Be $true
        }
        It 'an unknown slot on an entry' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'SqlScript').Credential = 'SQLScripts'
            Test-HasConfigError @(Test-CrConfig -Config $c) "Credential 'SQLScripts' does not refer to an existing slot" | Should Be $true
        }
        It 'an unknown slot on a candidate' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'AppUser').Candidates[1].Credential = 'AppUserBuiltin'
            Test-HasConfigError @(Test-CrConfig -Config $c) "candidate 1: Credential 'AppUserBuiltin' does not refer" | Should Be $true
        }
        It 'a rotated entry without a Credential' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'BiCARemote').Remove('Credential')
            Test-HasConfigError @(Test-CrConfig -Config $c) "BiCARemote': Credential must be" | Should Be $true
        }
        It 'a Check entry with a Credential' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'WinUsers').Credential = 'BiCAAdmin'
            Test-HasConfigError @(Test-CrConfig -Config $c) "Mode 'Check' entries have no Credential" | Should Be $true
        }
        It 'Role/Credential on an entry with Candidates' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'AppUser').Credential = 'AppUserApplication'
            Test-HasConfigError @(Test-CrConfig -Config $c) 'Credential belongs on each candidate' | Should Be $true
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
            $c = New-CrTestConfig; $c.Credentials[1].Slot = 'BiCAAdmin'
            Test-HasConfigError @(Test-CrConfig -Config $c) "Slot 'BiCAAdmin': duplicate slot" | Should Be $true
        }
        It 'a duplicate Id' {
            $c = New-CrTestConfig
            Add-TestAccount $c @{ Id = 'BiCAAdmin'; Kind = 'Windows'; Name = 'Someone'; Role = 'User'; Mode = 'Check' }
            Test-HasConfigError @(Test-CrConfig -Config $c) "Account 'BiCAAdmin': duplicate Id" | Should Be $true
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
            $c = New-CrTestConfig; $c.Roles.AdminRemote.AllowedExtraGroups = @('S-1-')
            Test-HasConfigError @(Test-CrConfig -Config $c) "invalid SID 'S-1-'" | Should Be $true
        }
        It 'an invalid candidate Sid' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'AppUser').Candidates[1].Sid = 'RID500'
            Test-HasConfigError @(Test-CrConfig -Config $c) "invalid SID 'RID500'" | Should Be $true
        }
        It 'accepts a full SID as candidate Sid' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'AppUser').Candidates[1].Sid = 'S-1-5-21-1000-2000-3000-500'
            @(Test-CrConfig -Config $c).Count | Should Be 0
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
            $c = New-CrTestConfig; (Get-TestAccount $c 'BiCAAdmin').Remove('Name')
            Test-HasConfigError @(Test-CrConfig -Config $c) '\(found 0\)' | Should Be $true
        }
        It 'a candidate with both Name and Sid' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'AppUser').Candidates[0].Sid = 'RID-500'
            Test-HasConfigError @(Test-CrConfig -Config $c) 'candidate 0: needs exactly one of Name or Sid' | Should Be $true
        }
        It 'an invalid Kind' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'SqlApp').Kind = 'Sql'
            Test-HasConfigError @(Test-CrConfig -Config $c) "SqlApp': Kind must be one of" | Should Be $true
        }
        It 'a Mode other than Check' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'BiCAAdmin').Mode = 'Rotate'
            Test-HasConfigError @(Test-CrConfig -Config $c) "Mode 'Rotate' is not valid" | Should Be $true
        }
        It 'an unknown dependent value' {
            $c = New-CrTestConfig; (Get-TestAccount $c 'AppUser').Services = 'Always'
            Test-HasConfigError @(Test-CrConfig -Config $c) 'Services must be one of' | Should Be $true
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
            $c = New-CrTestConfig; (Get-TestAccount $c 'AutoLogon').AutoLogonUser[1].Name = 'Kiosk'
            Test-HasConfigError @(Test-CrConfig -Config $c) "AutoLogonUser 'Kiosk' is not selected" | Should Be $true
        }
        It 'two entries with an AutoLogon block' {
            $c = New-CrTestConfig
            Add-TestAccount $c @{ Id = 'Second'; Kind = 'Windows'; Name = 'Kiosk'; Role = 'User'; Credential = 'AutoLogon'
                                  AutoLogonUser = @(@{ Name = 'Kiosk' }); AutoLogon = @{ Mode = 'IfAlreadyOn'; RestrictedComputerPattern = '^SM' } }
            Test-HasConfigError @(Test-CrConfig -Config $c) 'only one entry may have an AutoLogon block' | Should Be $true
        }
    }
}
