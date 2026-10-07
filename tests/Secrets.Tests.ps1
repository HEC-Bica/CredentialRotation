$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here '..\src\lib\Compat.ps1')
. (Join-Path $here '..\src\lib\Log.ps1')
. (Join-Path $here '..\src\lib\Rights.ps1')
. (Join-Path $here '..\src\lib\Journal.ps1')
. (Join-Path $here '..\src\lib\Secrets.ps1')
. (Join-Path $here 'Fixtures.ps1')

# Stubs for the Native.ps1 write wrappers (docs/dev/CONTRACTS.md); every test mocks the ones it needs.
function Test-CrSecretEqual { param($A, $B) throw 'stub: Test-CrSecretEqual' }
function Get-CrSecretLength { param($Secret) throw 'stub: Get-CrSecretLength' }
function Test-CrSecretComplexity { param($Secret, [int]$MinLength, [bool]$RequireComplexity, [string[]]$Tokens) throw 'stub: Test-CrSecretComplexity' }
function Test-CrLocalPasswordPolicy { param([string]$UserName, $Secret) throw 'stub: Test-CrLocalPasswordPolicy' }
function Invoke-CrLogonTest { param([string]$UserName, $Secret, [string]$LogonType) throw 'stub: Invoke-CrLogonTest' }
function Get-CrUserInfo { param([string]$UserName) throw 'stub: Get-CrUserInfo' }

# Obviously fake test values only. An empty text gives an empty SecureString.
function New-CrTestSecure {
    param([string]$Text)
    if (-not $Text) { return (New-Object System.Security.SecureString) }
    return (ConvertTo-SecureString $Text -AsPlainText -Force)
}

# Test-only SecureString comparison over the BSTRs (no managed string is created).
function Test-CrTestSecureEqual {
    param([System.Security.SecureString]$A, [System.Security.SecureString]$B)
    if (($null -eq $A) -or ($null -eq $B)) { return $false }
    if ($A.Length -ne $B.Length) { return $false }
    $pa = [IntPtr]::Zero
    $pb = [IntPtr]::Zero
    try {
        $pa = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($A)
        $pb = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($B)
        for ($i = 0; $i -lt $A.Length; $i++) {
            if ([Runtime.InteropServices.Marshal]::ReadInt16($pa, $i * 2) -ne [Runtime.InteropServices.Marshal]::ReadInt16($pb, $i * 2)) { return $false }
        }
        return $true
    } finally {
        if ($pa -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pa) }
        if ($pb -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pb) }
    }
}

# Console input queues for Read-CrSecureHost (texts become SecureStrings) and Read-CrHostLine.
function New-CrTestInput {
    param([string[]]$Secure = @(), [string[]]$Lines = @())
    $io = @{
        Secure        = (New-Object System.Collections.ArrayList)
        Lines         = (New-Object System.Collections.ArrayList)
        SecurePrompts = (New-Object System.Collections.ArrayList)
        LinePrompts   = (New-Object System.Collections.ArrayList)
    }
    if ($null -ne $Secure) { foreach ($s in $Secure) { [void]$io.Secure.Add((New-CrTestSecure $s)) } }
    if ($null -ne $Lines) { foreach ($l in $Lines) { [void]$io.Lines.Add($l) } }
    return $io
}

function Get-CrTestOkComplexity {
    return @{ Ok = $true; TooShort = $false; Categories = 4; MissingCategories = @(); ContainsNameToken = $false }
}

Describe 'Get-CrNameTokens' {
    It 'splits on the D15 separators and keeps tokens of 3+ characters' {
        $tokens = Get-CrNameTokens -Names @('PUB-User', 'Site_Ab#Kiosk.One,Two Three', "Tab`tSep")
        foreach ($t in @('PUB', 'User', 'Site', 'Kiosk', 'One', 'Two', 'Three', 'Tab', 'Sep')) { ($tokens -contains $t) | Should Be $true }
        ($tokens -contains 'Ab') | Should Be $false
    }

    It 'de-duplicates case-insensitively' {
        $tokens = Get-CrNameTokens -Names @('BiCA Remote', 'bica remote access')
        $tokens.Count | Should Be 3
    }

    It 'returns an empty array for no names' {
        $none = Get-CrNameTokens -Names $null
        $none.Count | Should Be 0
        $blank = Get-CrNameTokens -Names @('', 'ab')
        $blank.Count | Should Be 0
    }
}

Describe 'Test-CrSiteRules' {
    $config = @{ SitePasswordRules = @{ MinLength = 8; RequireComplexity = $true } }
    $secret = New-CrTestSecure 'Dummy-1a'

    Context 'passes rules and tokens to the complexity check' {
        Mock Test-CrSecretComplexity { Get-CrTestOkComplexity }
        It 'is Ok when the native check passes' {
            $r = Test-CrSiteRules -Secret $secret -Config $config -Names @('PUB-User', 'Kiosk Account')
            $r.Ok | Should Be $true
            @($r.Reasons).Count | Should Be 0
            Assert-MockCalled Test-CrSecretComplexity -Times 1 -ParameterFilter {
                ($MinLength -eq 8) -and ($RequireComplexity -eq $true) -and ($Tokens -contains 'PUB') -and ($Tokens -contains 'User') -and ($Tokens -contains 'Kiosk')
            }
        }
    }

    Context 'reports every failed rule without naming the token' {
        Mock Test-CrSecretComplexity { @{ Ok = $false; TooShort = $true; Categories = 2; MissingCategories = @('Digit'); ContainsNameToken = $true } }
        It 'lists length, categories and name token' {
            $r = Test-CrSiteRules -Secret $secret -Config $config -Names @('PUB-User')
            $r.Ok | Should Be $false
            @($r.Reasons).Count | Should Be 3
            (($r.Reasons -join ' ') -match 'PUB') | Should Be $false
        }
    }

    Context 'complexity not required' {
        Mock Test-CrSecretComplexity { @{ Ok = $true; TooShort = $false; Categories = 1; MissingCategories = @(); ContainsNameToken = $true } }
        It 'only checks the length' {
            $r = Test-CrSiteRules -Secret $secret -Config @{ SitePasswordRules = @{ MinLength = 8; RequireComplexity = $false } } -Names @('PUB-User')
            $r.Ok | Should Be $true
        }
    }
}

Describe 'Confirm-CrYes' {
    Context 'exact YES' {
        Mock Read-CrHostLine { 'YES' }
        It 'accepts YES' { (Confirm-CrYes -Prompt 'Type YES') | Should Be $true }
    }
    Context 'lower case' {
        Mock Read-CrHostLine { 'yes' }
        It 'rejects yes' { (Confirm-CrYes -Prompt 'Type YES') | Should Be $false }
    }
    Context 'other input' {
        Mock Read-CrHostLine { 'Y' }
        It 'rejects Y' { (Confirm-CrYes -Prompt 'Type YES') | Should Be $false }
    }
}

# --- v10 account model (CONTRACTS "v10: account model"): synthetic config and resolved entries ---------------------
# Built here instead of from config\CredentialRotation.psd1 + Resolve-CrAccounts, so these tests only depend on the
# resolved-entry contract (Create, PasswordMode, ToCreate placeholders).

$TcSidApp  = 'S-1-5-21-1000-2000-3000-1003'
$TcSidApp2 = 'S-1-5-21-1000-2000-3000-1006'
$TcSidPub  = 'S-1-5-21-1000-2000-3000-1005'
$TcSidSp   = 'S-1-5-21-1000-2000-3000-1007'
$TcSidWu1  = 'S-1-5-21-1000-2000-3000-1010'

function New-CrTestV10Config {
    # Listed out of Order on purpose: the prompts follow Order, not the list.
    return @{
        SitePasswordRules = @{ MinLength = 8; RequireComplexity = $true }
        Credentials = @(
            @{ Slot = 'PubUser';        Order = 30; Label = 'PUB-User (auto-logon)' },
            @{ Slot = 'SOPAdmin';       Order = 10; Label = 'SOP-Admin (operator account)' },
            @{ Slot = 'AppUser';        Order = 20; Label = 'ApplicationUser' },
            @{ Slot = 'SQLApplication'; Order = 40; Label = 'SQL login SQLApplication'; MaxLength = 128 }
        )
    }
}

function New-CrTestPlaceholder {
    param([string]$Name)
    return @{ Name = $Name; Sid = $null; User = $null; ToCreate = $true }
}

function New-CrTestAccount {
    param([string]$Name, [string]$Sid, [string]$FullName = '')
    return @{ Name = $Name; Sid = $Sid; User = @{ Name = $Name; Sid = $Sid; FullName = $FullName; Disabled = $false } }
}

# SOP-Admin is created (Set), ApplicationUser exists (Change), PUB-User exists (Set by default: no PasswordMode key).
function New-CrTestV10Resolved {
    param([switch]$AppCreate, [switch]$SecondChangeAccount)
    $app = @{ Id = 'AppUser'; Kind = 'Windows'; Mode = 'Rotate'; Slot = 'AppUser'; PasswordMode = 'Change'; Create = $false
              NotApplicable = $false; Accounts = @(New-CrTestAccount 'ApplicationUser' $TcSidApp 'Application Service') }
    if ($AppCreate) {
        $app.Create = $true
        $app.Accounts = @(New-CrTestPlaceholder 'ApplicationUser')
    }
    if ($SecondChangeAccount) {
        $app.Accounts = @((New-CrTestAccount 'ApplicationUser' $TcSidApp), (New-CrTestAccount 'AppHelper' $TcSidApp2))
    }
    return @(
        @{ Id = 'SOPAdmin'; Kind = 'Windows'; Mode = 'Rotate'; Slot = 'SOPAdmin'; PasswordMode = 'Set'; Create = $true
           NotApplicable = $false; Accounts = @(New-CrTestPlaceholder 'SOP-Admin') },
        $app,
        @{ Id = 'PubUser'; Kind = 'Windows'; Mode = 'Rotate'; Slot = 'PubUser'; Create = $false
           NotApplicable = $false; Accounts = @(New-CrTestAccount 'PUB-User' $TcSidPub 'Kiosk Account') },
        @{ Id = 'Retired'; Kind = 'Windows'; Mode = 'Disable'; Slot = $null; NotApplicable = $false
           Accounts = @(New-CrTestAccount 'SP Admin' $TcSidSp) },
        @{ Id = 'WinUsers'; Kind = 'Windows'; Mode = 'Check'; Slot = $null; NotApplicable = $false
           Accounts = @(New-CrTestAccount 'WinUser1' $TcSidWu1) },
        @{ Id = 'SqlApp'; Kind = 'SqlLogin'; Mode = 'Rotate'; Slot = 'SQLApplication'; NotApplicable = $false
           Accounts = @(@{ Name = 'SQLApplication'; Sid = '0x1A2B3C4D5E6F708192A3B4C5D6E7F801'; User = @{} }) }
    )
}

Describe 'Read-CrSlotSecrets (v10)' {
    $state = @{ Policy = @{ PasswordHistoryLength = 5; LockoutThreshold = 4 } }
    $config = New-CrTestV10Config
    $resolved = New-CrTestV10Resolved

    Mock Write-Host { }
    Mock Write-CrLog { }
    Mock Test-CrSecretEqual { Test-CrTestSecureEqual -A $A -B $B }
    Mock Test-CrSecretComplexity { Get-CrTestOkComplexity }
    Mock Test-CrLocalPasswordPolicy { @{ Ok = $true; Status = 0 } }
    Mock Get-CrSecretLength { $Secret.Length }

    Context 'created account (SOP-Admin)' {
        $io = New-CrTestInput -Secure @('Dummy-1a', 'Dummy-1a')
        Mock Read-CrSecureHost { [void]$io.SecurePrompts.Add($Prompt); $next = $io.Secure[0]; $io.Secure.RemoveAt(0); return $next }
        Mock Read-CrHostLine { [void]$io.LinePrompts.Add($Prompt); $next = $io.Lines[0]; $io.Lines.RemoveAt(0); return $next }
        It 'asks for the new password twice, no old password, and says the account will be created' {
            $r = Read-CrSlotSecrets -Config $config -Resolved $resolved -State $state -Only @('SOPAdmin')
            @($r.Keys).Count | Should Be 1
            $s = $r['SOPAdmin']
            $s.Skipped | Should Be $false
            (Test-CrTestSecureEqual -A $s.NewSecret -B (New-CrTestSecure 'Dummy-1a')) | Should Be $true
            @($s.Accounts).Count | Should Be 1
            $s.Accounts[0].Name | Should Be 'SOP-Admin'
            ($null -eq $s.Accounts[0].Sid) | Should Be $true
            $s.Accounts[0].Create | Should Be $true
            $s.Accounts[0].PasswordMode | Should Be 'Set'
            ($null -eq $s.Accounts[0].OldSecret) | Should Be $true
            $s.Accounts[0].Reapply | Should Be $false
            $io.SecurePrompts.Count | Should Be 2
            $io.LinePrompts.Count | Should Be 0
            ($io.SecurePrompts[0] -like '*SOP-Admin (will be created)*') | Should Be $true
            Assert-MockCalled Write-Host -ParameterFilter { $Object -like '*SOP-Admin*does not exist*created*' } -Times 1 -Exactly
        }
    }

    Context 'D15 tokens and local policy for an account that will be created' {
        $io = New-CrTestInput -Secure @('Dummy-1a', 'Dummy-1a')
        Mock Read-CrSecureHost { [void]$io.SecurePrompts.Add($Prompt); $next = $io.Secure[0]; $io.Secure.RemoveAt(0); return $next }
        Mock Read-CrHostLine { [void]$io.LinePrompts.Add($Prompt); $next = $io.Lines[0]; $io.Lines.RemoveAt(0); return $next }
        It 'includes the name of the account to be created' {
            [void](Read-CrSlotSecrets -Config $config -Resolved $resolved -State $state -Only @('SOPAdmin'))
            Assert-MockCalled Test-CrSecretComplexity -Times 1 -Exactly -ParameterFilter { ($Tokens -contains 'SOP') -and ($Tokens -contains 'Admin') }
            Assert-MockCalled Test-CrLocalPasswordPolicy -Times 1 -Exactly -ParameterFilter { $UserName -eq 'SOP-Admin' }
        }
    }

    Context 'set account (PUB-User) with a mismatch retry' {
        $io = New-CrTestInput -Secure @('Dummy-1a', 'Dummy-1b', 'Dummy-1a', 'Dummy-1a')
        Mock Read-CrSecureHost { [void]$io.SecurePrompts.Add($Prompt); $next = $io.Secure[0]; $io.Secure.RemoveAt(0); return $next }
        Mock Read-CrHostLine { [void]$io.LinePrompts.Add($Prompt); $next = $io.Lines[0]; $io.Lines.RemoveAt(0); return $next }
        It 'asks again after two different entries and never asks for the old password' {
            $r = Read-CrSlotSecrets -Config $config -Resolved $resolved -State $state -Only @('PubUser')
            $s = $r['PubUser']
            $s.Skipped | Should Be $false
            $s.Accounts[0].Name | Should Be 'PUB-User'
            $s.Accounts[0].Sid | Should Be $TcSidPub
            $s.Accounts[0].Create | Should Be $false
            $s.Accounts[0].PasswordMode | Should Be 'Set'
            ($null -eq $s.Accounts[0].OldSecret) | Should Be $true
            $s.Accounts[0].Reapply | Should Be $false
            $io.SecurePrompts.Count | Should Be 4
            (($io.SecurePrompts -join '|') -like '*old*') | Should Be $false
            ($io.SecurePrompts[0] -like '*PUB-User*') | Should Be $true
            ($io.SecurePrompts[0] -like '*will be created*') | Should Be $false
            $io.LinePrompts.Count | Should Be 0
            Assert-MockCalled Write-Host -ParameterFilter { $Object -like '*do not match*' } -Times 1 -Exactly
            Assert-MockCalled Test-CrSecretComplexity -ParameterFilter { $Tokens -contains 'Kiosk' } -Times 1 -Exactly
        }
    }

    Context 'change account (ApplicationUser)' {
        $io = New-CrTestInput -Secure @('Dummy-2a', 'Dummy-2a', 'Old-Dummy-9')
        Mock Read-CrSecureHost { [void]$io.SecurePrompts.Add($Prompt); $next = $io.Secure[0]; $io.Secure.RemoveAt(0); return $next }
        Mock Read-CrHostLine { [void]$io.LinePrompts.Add($Prompt); $next = $io.Lines[0]; $io.Lines.RemoveAt(0); return $next }
        It 'asks for the old password of the existing Change account' {
            $r = Read-CrSlotSecrets -Config $config -Resolved $resolved -State $state -Only @('AppUser')
            $a = $r['AppUser'].Accounts[0]
            $a.Name | Should Be 'ApplicationUser'
            $a.Sid | Should Be $TcSidApp
            $a.PasswordMode | Should Be 'Change'
            $a.Create | Should Be $false
            $a.Reapply | Should Be $false
            (Test-CrTestSecureEqual -A $a.OldSecret -B (New-CrTestSecure 'Old-Dummy-9')) | Should Be $true
            $io.SecurePrompts.Count | Should Be 3
            ($io.SecurePrompts[2] -like '*Current (old) password of ApplicationUser*') | Should Be $true
            $io.LinePrompts.Count | Should Be 0
        }
    }

    Context 're-apply (D20, Change account)' {
        $io = New-CrTestInput -Secure @('Dummy-3a', 'Dummy-3a', 'Dummy-3a')
        Mock Read-CrSecureHost { [void]$io.SecurePrompts.Add($Prompt); $next = $io.Secure[0]; $io.Secure.RemoveAt(0); return $next }
        Mock Read-CrHostLine { [void]$io.LinePrompts.Add($Prompt); $next = $io.Lines[0]; $io.Lines.RemoveAt(0); return $next }
        It 'marks the account whose new password equals its old one' {
            $r = Read-CrSlotSecrets -Config $config -Resolved $resolved -State $state -Only @('AppUser')
            $r['AppUser'].Accounts[0].Reapply | Should Be $true
        }
    }

    Context 'Change account that will be created' {
        $io = New-CrTestInput -Secure @('Dummy-3b', 'Dummy-3b')
        Mock Read-CrSecureHost { [void]$io.SecurePrompts.Add($Prompt); $next = $io.Secure[0]; $io.Secure.RemoveAt(0); return $next }
        Mock Read-CrHostLine { [void]$io.LinePrompts.Add($Prompt); $next = $io.Lines[0]; $io.Lines.RemoveAt(0); return $next }
        It 'asks no old password and never marks re-apply' {
            $r = Read-CrSlotSecrets -Config $config -Resolved (New-CrTestV10Resolved -AppCreate) -State $state -Only @('AppUser')
            $a = $r['AppUser'].Accounts[0]
            $a.Create | Should Be $true
            $a.PasswordMode | Should Be 'Change'
            ($null -eq $a.OldSecret) | Should Be $true
            $a.Reapply | Should Be $false
            $io.SecurePrompts.Count | Should Be 2
            ($io.SecurePrompts[0] -like '*ApplicationUser (will be created)*') | Should Be $true
            Assert-MockCalled Test-CrSecretEqual -Times 1 -Exactly
        }
    }

    Context 'same as previous (two Change accounts)' {
        $io = New-CrTestInput -Secure @('Dummy-2a', 'Dummy-2a', 'Old-Dummy-7') -Lines @('Y')
        Mock Read-CrSecureHost { [void]$io.SecurePrompts.Add($Prompt); $next = $io.Secure[0]; $io.Secure.RemoveAt(0); return $next }
        Mock Read-CrHostLine { [void]$io.LinePrompts.Add($Prompt); $next = $io.Lines[0]; $io.Lines.RemoveAt(0); return $next }
        It 'reuses a copy of the previous old password' {
            $r = Read-CrSlotSecrets -Config $config -Resolved (New-CrTestV10Resolved -SecondChangeAccount) -State $state -Only @('AppUser')
            $s = $r['AppUser']
            @($s.Accounts).Count | Should Be 2
            $s.Accounts[1].Name | Should Be 'AppHelper'
            (Test-CrTestSecureEqual -A $s.Accounts[1].OldSecret -B (New-CrTestSecure 'Old-Dummy-7')) | Should Be $true
            ([object]::ReferenceEquals($s.Accounts[0].OldSecret, $s.Accounts[1].OldSecret)) | Should Be $false
            ($io.LinePrompts[0] -like '*AppHelper*ApplicationUser*') | Should Be $true
            $io.SecurePrompts.Count | Should Be 3
        }
    }

    Context 'not the same as previous' {
        $io = New-CrTestInput -Secure @('Dummy-2a', 'Dummy-2a', 'Old-Dummy-7', 'Old-Dummy-8') -Lines @('N')
        Mock Read-CrSecureHost { [void]$io.SecurePrompts.Add($Prompt); $next = $io.Secure[0]; $io.Secure.RemoveAt(0); return $next }
        Mock Read-CrHostLine { [void]$io.LinePrompts.Add($Prompt); $next = $io.Lines[0]; $io.Lines.RemoveAt(0); return $next }
        It 'asks for the second account''s own old password' {
            $r = Read-CrSlotSecrets -Config $config -Resolved (New-CrTestV10Resolved -SecondChangeAccount) -State $state -Only @('AppUser')
            (Test-CrTestSecureEqual -A $r['AppUser'].Accounts[1].OldSecret -B (New-CrTestSecure 'Old-Dummy-8')) | Should Be $true
            ($io.SecurePrompts[3] -like '*AppHelper*') | Should Be $true
        }
    }

    Context 'skip after confirmation' {
        $io = New-CrTestInput -Secure @('') -Lines @('Y')
        Mock Read-CrSecureHost { [void]$io.SecurePrompts.Add($Prompt); $next = $io.Secure[0]; $io.Secure.RemoveAt(0); return $next }
        Mock Read-CrHostLine { [void]$io.LinePrompts.Add($Prompt); $next = $io.Lines[0]; $io.Lines.RemoveAt(0); return $next }
        It 'skips the slot on an empty entry confirmed with Y' {
            $r = Read-CrSlotSecrets -Config $config -Resolved $resolved -State $state -Only @('PubUser')
            $r['PubUser'].Skipped | Should Be $true
            $r['PubUser'].Reason | Should Be 'Skipped by the operator'
            $r['PubUser'].NewSecret | Should Be $null
            $io.SecurePrompts.Count | Should Be 1
            ($io.LinePrompts[0] -like '*skip*') | Should Be $true
        }
    }

    Context 'empty entry not confirmed' {
        $io = New-CrTestInput -Secure @('', 'Dummy-1a', 'Dummy-1a') -Lines @('N')
        Mock Read-CrSecureHost { [void]$io.SecurePrompts.Add($Prompt); $next = $io.Secure[0]; $io.Secure.RemoveAt(0); return $next }
        Mock Read-CrHostLine { [void]$io.LinePrompts.Add($Prompt); $next = $io.Lines[0]; $io.Lines.RemoveAt(0); return $next }
        It 'asks for the new password again' {
            $r = Read-CrSlotSecrets -Config $config -Resolved $resolved -State $state -Only @('PubUser')
            $r['PubUser'].Skipped | Should Be $false
            $io.SecurePrompts.Count | Should Be 3
        }
    }

    Context 'SQL slots' {
        $io = New-CrTestInput
        Mock Read-CrSecureHost { [void]$io.SecurePrompts.Add($Prompt); $next = $io.Secure[0]; $io.Secure.RemoveAt(0); return $next }
        Mock Read-CrHostLine { [void]$io.LinePrompts.Add($Prompt); $next = $io.Lines[0]; $io.Lines.RemoveAt(0); return $next }
        It 'returns SQL slots as skipped without a prompt' {
            $r = Read-CrSlotSecrets -Config $config -Resolved $resolved -State $state -Only @('SQLApplication')
            @($r.Keys).Count | Should Be 1
            $r['SQLApplication'].Skipped | Should Be $true
            $r['SQLApplication'].Reason | Should Be 'SQL rotation not available in this version'
            $io.SecurePrompts.Count | Should Be 0
        }
    }

    Context 'blocked slots' {
        $io = New-CrTestInput
        Mock Read-CrSecureHost { [void]$io.SecurePrompts.Add($Prompt); $next = $io.Secure[0]; $io.Secure.RemoveAt(0); return $next }
        Mock Read-CrHostLine { [void]$io.LinePrompts.Add($Prompt); $next = $io.Lines[0]; $io.Lines.RemoveAt(0); return $next }
        It 'does not prompt a blocked slot' {
            $r = Read-CrSlotSecrets -Config $config -Resolved $resolved -State $state -Only @('SOPAdmin') -BlockedSlots @{ SOPAdmin = 'write filter' }
            $r['SOPAdmin'].Skipped | Should Be $true
            $r['SOPAdmin'].Reason | Should Be 'Blocked: write filter'
            $io.SecurePrompts.Count | Should Be 0
        }
    }

    Context 'full run' {
        # SOPAdmin: new x2 | AppUser: new x2, old | PubUser: new x2 | SQLApplication: skipped
        $io = New-CrTestInput -Secure @('Dummy-4a', 'Dummy-4a', 'Dummy-4b', 'Dummy-4b', 'Old-Dummy-2', 'Dummy-4c', 'Dummy-4c')
        Mock Read-CrSecureHost { [void]$io.SecurePrompts.Add($Prompt); $next = $io.Secure[0]; $io.Secure.RemoveAt(0); return $next }
        Mock Read-CrHostLine { [void]$io.LinePrompts.Add($Prompt); $next = $io.Lines[0]; $io.Lines.RemoveAt(0); return $next }
        It 'prompts the Windows slots in Order, old password only for ApplicationUser, skips SQL, Disable and Check entries' {
            $r = Read-CrSlotSecrets -Config $config -Resolved $resolved -State $state
            $keys = @($r.Keys)
            $keys.Count | Should Be 4
            foreach ($k in @('SOPAdmin', 'AppUser', 'PubUser', 'SQLApplication')) { ($keys -contains $k) | Should Be $true }
            ($io.SecurePrompts[0] -like '*SOP-Admin*') | Should Be $true
            ($io.SecurePrompts[2] -like '*ApplicationUser*') | Should Be $true
            ($io.SecurePrompts[4] -like '*old*ApplicationUser*') | Should Be $true
            ($io.SecurePrompts[5] -like '*PUB-User*') | Should Be $true
            ($null -eq $r['SOPAdmin'].Accounts[0].OldSecret) | Should Be $true
            ($null -eq $r['PubUser'].Accounts[0].OldSecret) | Should Be $true
            (Test-CrTestSecureEqual -A $r['AppUser'].Accounts[0].OldSecret -B (New-CrTestSecure 'Old-Dummy-2')) | Should Be $true
            $io.Secure.Count | Should Be 0
            $io.LinePrompts.Count | Should Be 0
            Assert-MockCalled Write-Host -ParameterFilter { $Object -like '*never have been used before*' } -Times 1 -Exactly
        }
    }

    Context 'site rules fail three times' {
        $io = New-CrTestInput -Secure @('Dummy', 'Dummy', 'Dummy', 'Dummy', 'Dummy', 'Dummy')
        Mock Read-CrSecureHost { [void]$io.SecurePrompts.Add($Prompt); $next = $io.Secure[0]; $io.Secure.RemoveAt(0); return $next }
        Mock Read-CrHostLine { [void]$io.LinePrompts.Add($Prompt); $next = $io.Lines[0]; $io.Lines.RemoveAt(0); return $next }
        Mock Test-CrSecretComplexity { @{ Ok = $false; TooShort = $true; Categories = 2; MissingCategories = @(); ContainsNameToken = $false } }
        It 'skips the slot with a finding after three tries' {
            $r = Read-CrSlotSecrets -Config $config -Resolved $resolved -State $state -Only @('SOPAdmin')
            $s = $r['SOPAdmin']
            $s.Skipped | Should Be $true
            $s.Reason | Should Be 'No valid new password after 3 tries'
            @($s.Findings).Count | Should Be 1
            $s.Findings[0].Severity | Should Be 'HighImpact'
            $io.SecurePrompts.Count | Should Be 6
        }
    }

    Context 'local policy' {
        $io = New-CrTestInput -Secure @('Dummy-5a', 'Dummy-5a', 'Dummy-5a', 'Dummy-5a', 'Dummy-5a', 'Dummy-5a')
        Mock Read-CrSecureHost { [void]$io.SecurePrompts.Add($Prompt); $next = $io.Secure[0]; $io.Secure.RemoveAt(0); return $next }
        Mock Read-CrHostLine { [void]$io.LinePrompts.Add($Prompt); $next = $io.Lines[0]; $io.Lines.RemoveAt(0); return $next }
        Mock Test-CrLocalPasswordPolicy { @{ Ok = $false; Status = 2245 } }
        It 'checks the local policy per account and rejects on failure' {
            $r = Read-CrSlotSecrets -Config $config -Resolved $resolved -State $state -Only @('PubUser')
            $r['PubUser'].Skipped | Should Be $true
            Assert-MockCalled Test-CrLocalPasswordPolicy -ParameterFilter { $UserName -eq 'PUB-User' } -Times 3 -Exactly
        }
    }

    Context 'slot MaxLength' {
        $cfg = New-CrTestV10Config
        foreach ($c in $cfg.Credentials) { if ($c.Slot -eq 'PubUser') { $c.MaxLength = 6 } }
        $io = New-CrTestInput -Secure @('Dummy-6a', 'Dummy-6a', 'Dummy-6a', 'Dummy-6a', 'Dummy-6a', 'Dummy-6a')
        Mock Read-CrSecureHost { [void]$io.SecurePrompts.Add($Prompt); $next = $io.Secure[0]; $io.Secure.RemoveAt(0); return $next }
        Mock Read-CrHostLine { [void]$io.LinePrompts.Add($Prompt); $next = $io.Lines[0]; $io.Lines.RemoveAt(0); return $next }
        It 'rejects a password longer than MaxLength' {
            $r = Read-CrSlotSecrets -Config $cfg -Resolved $resolved -State $state -Only @('PubUser')
            $r['PubUser'].Skipped | Should Be $true
            Assert-MockCalled Write-Host -ParameterFilter { $Object -like '*longer than 6*' } -Times 3 -Exactly
        }
    }
}

Describe 'Read-CrOtherAccountDecisions (D23)' {
    $usb = @{ Name = 'USBTest'; Sid = 'S-1-5-21-1000-2000-3000-1040'; FullName = 'USB Service' }
    $legacy = @{ Name = 'LegacyUser'; Sid = 'S-1-5-21-1000-2000-3000-1041'; FullName = '' }

    Mock Write-Host { }
    Mock Write-CrLog { }

    Context 'one decision per account' {
        $io = New-CrTestInput -Lines @('Y', 'N')
        Mock Read-CrHostLine { [void]$io.LinePrompts.Add($Prompt); $next = $io.Lines[0]; $io.Lines.RemoveAt(0); return $next }
        It 'returns Disable or Keep per SID, asked in order' {
            $r = Read-CrOtherAccountDecisions -Accounts @($usb, $legacy)
            $r.Count | Should Be 2
            $r['S-1-5-21-1000-2000-3000-1040'] | Should Be 'Disable'
            $r['S-1-5-21-1000-2000-3000-1041'] | Should Be 'Keep'
            $io.LinePrompts.Count | Should Be 2
            ($io.LinePrompts[0] -like '*USBTest (USB Service)*') | Should Be $true
            ($io.LinePrompts[1] -like '*LegacyUser*') | Should Be $true
            Assert-MockCalled Write-CrLog -ParameterFilter { $Message -like '*USBTest*Disable*' } -Times 1 -Exactly
            Assert-MockCalled Write-CrLog -ParameterFilter { $Message -like '*LegacyUser*Keep*' } -Times 1 -Exactly
        }
    }

    Context 'unclear answers' {
        $io = New-CrTestInput -Lines @('maybe', 'disable', '?')
        Mock Read-CrHostLine { [void]$io.LinePrompts.Add($Prompt); $next = $io.Lines[0]; $io.Lines.RemoveAt(0); return $next }
        It 'keeps the account after three unclear answers' {
            $r = Read-CrOtherAccountDecisions -Accounts @($usb)
            $r['S-1-5-21-1000-2000-3000-1040'] | Should Be 'Keep'
            $io.LinePrompts.Count | Should Be 3
        }
    }

    Context 'no accounts' {
        $io = New-CrTestInput
        Mock Read-CrHostLine { [void]$io.LinePrompts.Add($Prompt); $next = $io.Lines[0]; $io.Lines.RemoveAt(0); return $next }
        It 'returns an empty hashtable without a prompt' {
            $r = Read-CrOtherAccountDecisions -Accounts $null
            ($r -is [hashtable]) | Should Be $true
            $r.Count | Should Be 0
            $r2 = Read-CrOtherAccountDecisions -Accounts @()
            $r2.Count | Should Be 0
            $io.LinePrompts.Count | Should Be 0
            Assert-MockCalled Write-Host -Times 0 -Exactly
        }
    }

    Context 'duplicates and accounts without a SID' {
        $io = New-CrTestInput -Lines @('Y')
        Mock Read-CrHostLine { [void]$io.LinePrompts.Add($Prompt); $next = $io.Lines[0]; $io.Lines.RemoveAt(0); return $next }
        It 'asks once per SID and ignores entries without a SID' {
            $r = Read-CrOtherAccountDecisions -Accounts @($usb, $usb, @{ Name = 'NoSid'; Sid = $null })
            $r.Count | Should Be 1
            $r['S-1-5-21-1000-2000-3000-1040'] | Should Be 'Disable'
            $io.LinePrompts.Count | Should Be 1
        }
    }

    Context 'resolved-account shape' {
        $io = New-CrTestInput -Lines @('n')
        Mock Read-CrHostLine { [void]$io.LinePrompts.Add($Prompt); $next = $io.Lines[0]; $io.Lines.RemoveAt(0); return $next }
        It 'takes the full name from User' {
            $acc = @{ Name = 'KioskTest'; Sid = 'S-1-5-21-1000-2000-3000-1042'; User = @{ FullName = 'Kiosk Test Account' } }
            $r = Read-CrOtherAccountDecisions -Accounts $acc
            $r['S-1-5-21-1000-2000-3000-1042'] | Should Be 'Keep'
            ($io.LinePrompts[0] -like '*KioskTest (Kiosk Test Account)*') | Should Be $true
        }
    }
}

Describe 'Invoke-CrCredentialProbe' {
    # Only the Change account (ApplicationUser) is probed in v10.
    $state = New-CrTestState -Profile 'IPT01'
    $user = Get-CrTestUser $state 'ApplicationUser'
    $userSid = $user.Sid
    $account = @{ Name = $user.Name; Sid = $userSid; User = $user }
    $oldSecret = New-CrTestSecure 'Old-Dummy-1'
    $newSecret = New-CrTestSecure 'Dummy-7a'
    $noJournal = @{ Runs = (New-Object System.Collections.ArrayList); Path = $null }

    Mock Write-CrLog { }
    Mock Test-CrSecretEqual { Test-CrTestSecureEqual -A $A -B $B }

    # $probe.Correct: the secret that logs on; $probe.Tried: 'Old'/'New' per attempt; $probe.Error: code on failure.
    function New-CrTestProbe {
        param($Correct, [int]$ErrorCode = 1326, [int[]]$BadCounts = @(0), [int]$Flags = 0x10201)
        return @{ Correct = $Correct; Tried = (New-Object System.Collections.ArrayList); Error = $ErrorCode; BadCounts = $BadCounts; Flags = $Flags; InfoCalls = 0; Locked = $false }
    }

    Context 'old password works' {
        $probe = New-CrTestProbe -Correct $oldSecret
        Mock Get-CrUserInfo { $i = [Math]::Min($probe.InfoCalls, $probe.BadCounts.Count - 1); $probe.InfoCalls = $probe.InfoCalls + 1; @{ Success = $true; Win32Error = 0; Flags = $probe.Flags; BadPasswordCount = $probe.BadCounts[$i]; PasswordAgeSeconds = 100 } }
        Mock Invoke-CrLogonTest {
            if (Test-CrTestSecureEqual -A $Secret -B $oldSecret) { [void]$probe.Tried.Add('Old') } else { [void]$probe.Tried.Add('New') }
            if (Test-CrTestSecureEqual -A $Secret -B $probe.Correct) { @{ Success = $true; Win32Error = 0 } } else { @{ Success = $false; Win32Error = $probe.Error } }
        }
        It 'tests the old password first and stops' {
            $r = Invoke-CrCredentialProbe -State $state -Account $account -OldSecret $oldSecret -NewSecret $newSecret -Journal $noJournal -RunId 'R2'
            $r.Outcome | Should Be 'Old'
            $r.Attempts | Should Be 1
            $r.LogonType | Should Be 'Network'
            $r.Fallback | Should Be $false
            $r.Sid | Should Be $user.Sid
            ($probe.Tried -join ',') | Should Be 'Old'
            Assert-MockCalled Invoke-CrLogonTest -ParameterFilter { $LogonType -eq 'Network' -and $UserName -eq 'ApplicationUser' } -Times 1 -Exactly
        }
    }

    Context 'new password works, no journal' {
        $probe = New-CrTestProbe -Correct $newSecret
        Mock Get-CrUserInfo { $i = [Math]::Min($probe.InfoCalls, $probe.BadCounts.Count - 1); $probe.InfoCalls = $probe.InfoCalls + 1; @{ Success = $true; Win32Error = 0; Flags = $probe.Flags; BadPasswordCount = $probe.BadCounts[$i]; PasswordAgeSeconds = 100 } }
        Mock Invoke-CrLogonTest {
            if (Test-CrTestSecureEqual -A $Secret -B $oldSecret) { [void]$probe.Tried.Add('Old') } else { [void]$probe.Tried.Add('New') }
            if (Test-CrTestSecureEqual -A $Secret -B $probe.Correct) { @{ Success = $true; Win32Error = 0 } } else { @{ Success = $false; Win32Error = $probe.Error } }
        }
        It 'tests old then new and re-reads the account before each attempt' {
            $r = Invoke-CrCredentialProbe -State $state -Account $account -OldSecret $oldSecret -NewSecret $newSecret -Journal $noJournal -RunId 'R2'
            $r.Outcome | Should Be 'New'
            $r.Attempts | Should Be 2
            ($probe.Tried -join ',') | Should Be 'Old,New'
            Assert-MockCalled Get-CrUserInfo -Times 2 -Exactly
        }
    }

    Context 'unfinished run recorded the Secret step' {
        $journal = @{ Runs = (New-Object System.Collections.ArrayList); Path = $null }
        [void]$journal.Runs.Add(@{ RunId = 'R1'; Started = (Get-Date); Finished = $false; Accounts = @{ $userSid = @('PreSteps', 'Secret') } })
        $probe = New-CrTestProbe -Correct $newSecret
        Mock Get-CrUserInfo { $i = [Math]::Min($probe.InfoCalls, $probe.BadCounts.Count - 1); $probe.InfoCalls = $probe.InfoCalls + 1; @{ Success = $true; Win32Error = 0; Flags = $probe.Flags; BadPasswordCount = $probe.BadCounts[$i]; PasswordAgeSeconds = 100 } }
        Mock Invoke-CrLogonTest {
            if (Test-CrTestSecureEqual -A $Secret -B $oldSecret) { [void]$probe.Tried.Add('Old') } else { [void]$probe.Tried.Add('New') }
            if (Test-CrTestSecureEqual -A $Secret -B $probe.Correct) { @{ Success = $true; Win32Error = 0 } } else { @{ Success = $false; Win32Error = $probe.Error } }
        }
        It 'tests the new password first' {
            $r = Invoke-CrCredentialProbe -State $state -Account $account -OldSecret $oldSecret -NewSecret $newSecret -Journal $journal -RunId 'R2'
            $r.Outcome | Should Be 'New'
            $r.Attempts | Should Be 1
            ($probe.Tried -join ',') | Should Be 'New'
        }
    }

    Context 'finished run or current run recorded the Secret step' {
        $journal = @{ Runs = (New-Object System.Collections.ArrayList); Path = $null }
        [void]$journal.Runs.Add(@{ RunId = 'R1'; Started = (Get-Date); Finished = $true; Accounts = @{ $userSid = @('Secret') } })
        [void]$journal.Runs.Add(@{ RunId = 'R2'; Started = (Get-Date); Finished = $false; Accounts = @{ $userSid = @('Secret') } })
        $probe = New-CrTestProbe -Correct $newSecret
        Mock Get-CrUserInfo { $i = [Math]::Min($probe.InfoCalls, $probe.BadCounts.Count - 1); $probe.InfoCalls = $probe.InfoCalls + 1; @{ Success = $true; Win32Error = 0; Flags = $probe.Flags; BadPasswordCount = $probe.BadCounts[$i]; PasswordAgeSeconds = 100 } }
        Mock Invoke-CrLogonTest {
            if (Test-CrTestSecureEqual -A $Secret -B $oldSecret) { [void]$probe.Tried.Add('Old') } else { [void]$probe.Tried.Add('New') }
            if (Test-CrTestSecureEqual -A $Secret -B $probe.Correct) { @{ Success = $true; Win32Error = 0 } } else { @{ Success = $false; Win32Error = $probe.Error } }
        }
        It 'keeps the default order (old first)' {
            $r = Invoke-CrCredentialProbe -State $state -Account $account -OldSecret $oldSecret -NewSecret $newSecret -Journal $journal -RunId 'R2'
            ($probe.Tried -join ',') | Should Be 'Old,New'
            $r.Outcome | Should Be 'New'
        }
    }

    Context 're-apply' {
        $sameSecret = New-CrTestSecure 'Old-Dummy-1'
        $probe = New-CrTestProbe -Correct $oldSecret
        Mock Get-CrUserInfo { $i = [Math]::Min($probe.InfoCalls, $probe.BadCounts.Count - 1); $probe.InfoCalls = $probe.InfoCalls + 1; @{ Success = $true; Win32Error = 0; Flags = $probe.Flags; BadPasswordCount = $probe.BadCounts[$i]; PasswordAgeSeconds = 100 } }
        Mock Invoke-CrLogonTest {
            if (Test-CrTestSecureEqual -A $Secret -B $oldSecret) { [void]$probe.Tried.Add('Old') } else { [void]$probe.Tried.Add('New') }
            if (Test-CrTestSecureEqual -A $Secret -B $probe.Correct) { @{ Success = $true; Win32Error = 0 } } else { @{ Success = $false; Win32Error = $probe.Error } }
        }
        It 'reports Reapply when the old password works and equals the new one' {
            $r = Invoke-CrCredentialProbe -State $state -Account $account -OldSecret $oldSecret -NewSecret $sameSecret -Journal $noJournal -RunId 'R2'
            $r.Outcome | Should Be 'Reapply'
            $r.Attempts | Should Be 1
        }
    }

    Context 'both fail' {
        $probe = New-CrTestProbe -Correct (New-CrTestSecure 'Other-Dummy-0')
        Mock Get-CrUserInfo { $i = [Math]::Min($probe.InfoCalls, $probe.BadCounts.Count - 1); $probe.InfoCalls = $probe.InfoCalls + 1; @{ Success = $true; Win32Error = 0; Flags = $probe.Flags; BadPasswordCount = $probe.BadCounts[$i]; PasswordAgeSeconds = 100 } }
        Mock Invoke-CrLogonTest {
            if (Test-CrTestSecureEqual -A $Secret -B $oldSecret) { [void]$probe.Tried.Add('Old') } else { [void]$probe.Tried.Add('New') }
            if (Test-CrTestSecureEqual -A $Secret -B $probe.Correct) { @{ Success = $true; Win32Error = 0 } } else { @{ Success = $false; Win32Error = $probe.Error } }
        }
        It 'makes at most two attempts and reports BothFailed' {
            $r = Invoke-CrCredentialProbe -State $state -Account $account -OldSecret $oldSecret -NewSecret $newSecret -Journal $noJournal -RunId 'R2'
            $r.Outcome | Should Be 'BothFailed'
            $r.Attempts | Should Be 2
            $r.Win32Error | Should Be 1326
            Assert-MockCalled Invoke-CrLogonTest -Times 2 -Exactly
        }
    }

    Context 'locked by flag' {
        $probe = New-CrTestProbe -Correct $oldSecret -Flags 0x10211
        Mock Get-CrUserInfo { @{ Success = $true; Win32Error = 0; Flags = $probe.Flags; BadPasswordCount = 0; PasswordAgeSeconds = 100 } }
        Mock Invoke-CrLogonTest { @{ Success = $true; Win32Error = 0 } }
        It 'reports Locked without an attempt' {
            $r = Invoke-CrCredentialProbe -State $state -Account $account -OldSecret $oldSecret -NewSecret $newSecret -Journal $noJournal -RunId 'R2'
            $r.Outcome | Should Be 'Locked'
            $r.Attempts | Should Be 0
            Assert-MockCalled Invoke-CrLogonTest -Times 0 -Exactly
        }
    }

    Context 'locked by IsAccountLocked' {
        Mock Get-CrUserInfo { @{ Success = $true; Win32Error = 0; Flags = 0x10201; BadPasswordCount = 0; PasswordAgeSeconds = 100; IsAccountLocked = $true } }
        Mock Invoke-CrLogonTest { @{ Success = $true; Win32Error = 0 } }
        It 'reports Locked without an attempt' {
            $r = Invoke-CrCredentialProbe -State $state -Account $account -OldSecret $oldSecret -NewSecret $newSecret -Journal $noJournal -RunId 'R2'
            $r.Outcome | Should Be 'Locked'
            Assert-MockCalled Invoke-CrLogonTest -Times 0 -Exactly
        }
    }

    Context 'disabled' {
        Mock Get-CrUserInfo { @{ Success = $true; Win32Error = 0; Flags = 0x10203; BadPasswordCount = 0; PasswordAgeSeconds = 100 } }
        Mock Invoke-CrLogonTest { @{ Success = $true; Win32Error = 0 } }
        It 'reports Disabled without an attempt' {
            $r = Invoke-CrCredentialProbe -State $state -Account $account -OldSecret $oldSecret -NewSecret $newSecret -Journal $noJournal -RunId 'R2'
            $r.Outcome | Should Be 'Disabled'
            $r.Attempts | Should Be 0
            Assert-MockCalled Invoke-CrLogonTest -Times 0 -Exactly
        }
    }

    Context 'budget: threshold 4 with 2 bad attempts' {
        Mock Get-CrUserInfo { @{ Success = $true; Win32Error = 0; Flags = 0x10201; BadPasswordCount = 2; PasswordAgeSeconds = 100 } }
        Mock Invoke-CrLogonTest { @{ Success = $true; Win32Error = 0 } }
        It 'reports BudgetExceeded without an attempt' {
            $state.Policy.LockoutThreshold | Should Be 4
            $r = Invoke-CrCredentialProbe -State $state -Account $account -OldSecret $oldSecret -NewSecret $newSecret -Journal $noJournal -RunId 'R2'
            $r.Outcome | Should Be 'BudgetExceeded'
            $r.Attempts | Should Be 0
            Assert-MockCalled Invoke-CrLogonTest -Times 0 -Exactly
        }
    }

    Context 'budget: threshold 4 with 1 bad attempt' {
        Mock Get-CrUserInfo { @{ Success = $true; Win32Error = 0; Flags = 0x10201; BadPasswordCount = 1; PasswordAgeSeconds = 100 } }
        Mock Invoke-CrLogonTest { @{ Success = $true; Win32Error = 0 } }
        It 'makes the attempt' {
            $r = Invoke-CrCredentialProbe -State $state -Account $account -OldSecret $oldSecret -NewSecret $newSecret -Journal $noJournal -RunId 'R2'
            $r.Outcome | Should Be 'Old'
            $r.Attempts | Should Be 1
        }
    }

    Context 'budget: re-read before the second attempt' {
        # Counter 1 before the first attempt, 2 after its failure: the second attempt is not allowed.
        $probe = New-CrTestProbe -Correct $newSecret -BadCounts @(1, 2)
        Mock Get-CrUserInfo { $i = [Math]::Min($probe.InfoCalls, $probe.BadCounts.Count - 1); $probe.InfoCalls = $probe.InfoCalls + 1; @{ Success = $true; Win32Error = 0; Flags = $probe.Flags; BadPasswordCount = $probe.BadCounts[$i]; PasswordAgeSeconds = 100 } }
        Mock Invoke-CrLogonTest {
            if (Test-CrTestSecureEqual -A $Secret -B $oldSecret) { [void]$probe.Tried.Add('Old') } else { [void]$probe.Tried.Add('New') }
            if (Test-CrTestSecureEqual -A $Secret -B $probe.Correct) { @{ Success = $true; Win32Error = 0 } } else { @{ Success = $false; Win32Error = $probe.Error } }
        }
        It 'stops with BudgetExceeded after one failure' {
            $r = Invoke-CrCredentialProbe -State $state -Account $account -OldSecret $oldSecret -NewSecret $newSecret -Journal $noJournal -RunId 'R2'
            $r.Outcome | Should Be 'BudgetExceeded'
            $r.Attempts | Should Be 1
            ($probe.Tried -join ',') | Should Be 'Old'
        }
    }

    Context 'no lockout policy' {
        $noLockout = New-CrTestState -Profile 'IPT01'
        $noLockout.Policy.LockoutThreshold = 0
        Mock Get-CrUserInfo { @{ Success = $true; Win32Error = 0; Flags = 0x10201; BadPasswordCount = 50; PasswordAgeSeconds = 100 } }
        Mock Invoke-CrLogonTest { @{ Success = $true; Win32Error = 0 } }
        It 'attempts regardless of the counter when the threshold is 0' {
            $r = Invoke-CrCredentialProbe -State $noLockout -Account $account -OldSecret $oldSecret -NewSecret $newSecret -Journal $noJournal -RunId 'R2'
            $r.Outcome | Should Be 'Old'
        }
    }

    Context 'logon type not granted (1385)' {
        Mock Get-CrUserInfo { @{ Success = $true; Win32Error = 0; Flags = 0x10201; BadPasswordCount = 0; PasswordAgeSeconds = 100 } }
        Mock Invoke-CrLogonTest { @{ Success = $false; Win32Error = 1385 } }
        It 'reports Unverifiable after one attempt' {
            $r = Invoke-CrCredentialProbe -State $state -Account $account -OldSecret $oldSecret -NewSecret $newSecret -Journal $noJournal -RunId 'R2'
            $r.Outcome | Should Be 'Unverifiable'
            $r.Win32Error | Should Be 1385
            $r.Attempts | Should Be 1
            Assert-MockCalled Invoke-CrLogonTest -Times 1 -Exactly
        }
    }

    Context 'ForceGuest: the next allowed logon type' {
        $fg = New-CrTestState -Profile 'IPT01'
        $fg.Policy.ForceGuest = $true
        Mock Get-CrUserInfo { @{ Success = $true; Win32Error = 0; Flags = 0x10201; BadPasswordCount = 0; PasswordAgeSeconds = 100 } }
        Mock Invoke-CrLogonTest { @{ Success = $true; Win32Error = 0 } }
        It 'never probes with a Network logon' {
            $r = Invoke-CrCredentialProbe -State $fg -Account $account -OldSecret $oldSecret -NewSecret $newSecret -Journal $noJournal -RunId 'R2'
            $r.Outcome | Should Be 'Old'
            $r.LogonType | Should Be 'Batch'
            Assert-MockCalled Invoke-CrLogonTest -ParameterFilter { $LogonType -eq 'Batch' } -Times 1 -Exactly
            Assert-MockCalled Invoke-CrLogonTest -ParameterFilter { $LogonType -eq 'Network' } -Times 0 -Exactly
        }
    }

    Context 'ForceGuest without another allowed logon type' {
        $fg = New-CrTestState -Profile 'IPT01'
        $fg.Policy.ForceGuest = $true
        Add-CrTestRight -State $fg -Right 'SeDenyBatchLogonRight' -Sids @($userSid)
        Add-CrTestRight -State $fg -Right 'SeDenyServiceLogonRight' -Sids @($userSid)
        Mock Get-CrUserInfo { @{ Success = $true; Win32Error = 0; Flags = 0x10201; BadPasswordCount = 0; PasswordAgeSeconds = 100 } }
        Mock Invoke-CrLogonTest { @{ Success = $true; Win32Error = 0 } }
        It 'reports Unverifiable without an attempt' {
            $r = Invoke-CrCredentialProbe -State $fg -Account $account -OldSecret $oldSecret -NewSecret $newSecret -Journal $noJournal -RunId 'R2'
            $r.Outcome | Should Be 'Unverifiable'
            ($null -eq $r.LogonType) | Should Be $true
            $r.Fallback | Should Be $true
            $r.Attempts | Should Be 0
            Assert-MockCalled Invoke-CrLogonTest -Times 0 -Exactly
            Assert-MockCalled Get-CrUserInfo -Times 0 -Exactly
        }
    }

    Context 'account that does not exist yet' {
        Mock Get-CrUserInfo { @{ Success = $true; Win32Error = 0; Flags = 0x10201; BadPasswordCount = 0; PasswordAgeSeconds = 100 } }
        Mock Invoke-CrLogonTest { @{ Success = $true; Win32Error = 0 } }
        It 'reports Unverifiable without an attempt' {
            $placeholder = @{ Name = 'ApplicationUser'; Sid = $null; User = $null; ToCreate = $true }
            $r = Invoke-CrCredentialProbe -State $state -Account $placeholder -OldSecret $oldSecret -NewSecret $newSecret -Journal $noJournal -RunId 'R2'
            $r.Outcome | Should Be 'Unverifiable'
            $r.Attempts | Should Be 0
            Assert-MockCalled Invoke-CrLogonTest -Times 0 -Exactly
        }
    }

    Context 'logging' {
        Mock Get-CrUserInfo { @{ Success = $true; Win32Error = 0; Flags = 0x10201; BadPasswordCount = 0; PasswordAgeSeconds = 100 } }
        Mock Invoke-CrLogonTest { @{ Success = $false; Win32Error = 1326 } }
        It 'logs the outcome once' {
            [void](Invoke-CrCredentialProbe -State $state -Account $account -OldSecret $oldSecret -NewSecret $newSecret -Journal $noJournal -RunId 'R2')
            Assert-MockCalled Write-CrLog -ParameterFilter { $Message -like '*ApplicationUser*BothFailed*1326*' } -Times 1 -Exactly
        }
    }
}
