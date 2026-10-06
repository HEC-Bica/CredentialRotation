# Pester 3.4 tests for src\lib\AutoLogon.ps1 (PLAN section 7.5, D18). Synthetic SIDs and machine names only.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here '..\src\lib\Compat.ps1')

# Stubs for Rights.ps1 (another module); mocked below. Parameters must match the contract for Mock.
function Get-CrEffectiveLogonRights { param($UserSid, $State) }
function Test-CrIsAdmin { param($UserSid, $State) }

. (Join-Path $here '..\src\lib\AutoLogon.ps1')

$SidBica     = 'S-1-5-21-1000-2000-3000-1001'
$SidRemote   = 'S-1-5-21-1000-2000-3000-1002'
$SidPub      = 'S-1-5-21-1000-2000-3000-1010'
$SidWinAuto  = 'S-1-5-21-1000-2000-3000-1011'
$SidWinUser1 = 'S-1-5-21-1000-2000-3000-1020'

function New-TestUser {
    param([string]$Name, [string]$Sid, [switch]$Disabled, [switch]$Locked)
    return @{
        Name = $Name; Sid = $Sid; Rid = [int]($Sid.Split('-')[-1]); FullName = ''; Flags = 0
        Disabled = [bool]$Disabled; LockedOut = [bool]$Locked; PasswordNeverExpires = $true; CannotChangePassword = $true
        PasswordNotRequired = $false; PasswordAgeSeconds = 0; BadPasswordCount = 0
    }
}

function New-TestUsers {
    param([switch]$NoPub, [switch]$PubDisabled, [switch]$PubLocked, [switch]$NoWinAuto)
    $list = New-Object System.Collections.ArrayList
    [void]$list.Add((New-TestUser 'BiCA Admin' $SidBica))
    [void]$list.Add((New-TestUser 'BiCA Remote' $SidRemote))
    if (-not $NoPub) { [void]$list.Add((New-TestUser 'PUB-User' $SidPub -Disabled:$PubDisabled -Locked:$PubLocked)) }
    if (-not $NoWinAuto) { [void]$list.Add((New-TestUser 'WinAutoUser' $SidWinAuto)) }
    [void]$list.Add((New-TestUser 'WinUser1' $SidWinUser1))
    return , $list.ToArray()
}

# DefaultDomainName '#computer' is replaced by the computer name in New-TestState.
function New-TestAutoLogon {
    param(
        $AutoAdminLogon = '1',
        $Kind = 'String',
        [string]$UserName,
        [string]$Domain = '#computer',
        [switch]$PlainPassword,
        [switch]$Count,
        [string[]]$Mechanisms = @(),
        [switch]$LegalText
    )
    if ($null -eq $AutoAdminLogon) { $Kind = $null }
    return @{
        AutoAdminLogon = $AutoAdminLogon; AutoAdminLogonKind = $Kind; DefaultUserName = $UserName; DefaultDomainName = $Domain
        DefaultPasswordPresent = [bool]$PlainPassword; AutoLogonCountPresent = [bool]$Count; ForceAutoLogon = $null
        AutoLogonSidValue = $null; OtherMechanisms = $Mechanisms; LegalNoticeCaptionSet = $false
        LegalNoticeTextSet = [bool]$LegalText; DevicePasswordLessBuildVersion = $null; Error = $null
    }
}

# FixtureAdmins / FixtureNoInteractive drive the Rights.ps1 mocks.
function New-TestState {
    param(
        [string]$Computer = 'IPT01-SITEA',
        $AutoLogon,
        $Users,
        [string[]]$Admins = @('S-1-5-21-1000-2000-3000-1001'),
        [string[]]$NoInteractive = @()
    )
    if (-not $Users) { $Users = New-TestUsers }
    if ($AutoLogon -and $AutoLogon['DefaultDomainName'] -eq '#computer') { $AutoLogon['DefaultDomainName'] = $Computer }
    return @{
        Computer = @{ Name = $Computer; IsSm = ($Computer -match '^SM') }
        Users = $Users; AutoLogon = $AutoLogon
        FixtureAdmins = $Admins; FixtureNoInteractive = $NoInteractive
    }
}

function New-TestResolved {
    param($State)
    $acc = New-Object System.Collections.ArrayList
    foreach ($n in @('PUB-User', 'WinAutoUser')) {
        foreach ($u in @($State['Users'])) {
            if ($u['Name'] -ieq $n) { [void]$acc.Add(@{ Name = $u['Name']; Sid = $u['Sid']; User = $u }) }
        }
    }
    $bica = @{ Id = 'BiCAAdmin'; Kind = 'Windows'; Mode = 'Rotate'; RoleName = 'Admin'; Slot = 'BiCAAdmin'
               Accounts = @(@{ Name = 'BiCA Admin'; Sid = $SidBica }); Missing = @(); AutoLogon = $null; AutoLogonUser = $null }
    $auto = @{ Id = 'AutoLogon'; Kind = 'Windows'; Mode = 'Rotate'; RoleName = 'User'; Slot = 'AutoLogon'
               Accounts = $acc.ToArray(); Missing = @(); AutoLogon = @{ Mode = 'IfAlreadyOn'; RestrictedComputerPattern = '^SM' }
               AutoLogonUser = @(@{ Name = 'PUB-User'; RequireEnabled = $true }, @{ Name = 'WinAutoUser' }) }
    return , @($bica, $auto)
}

$TestConfig = @{ Accounts = @() }
$AllVerified = @('S-1-5-21-1000-2000-3000-1001', 'S-1-5-21-1000-2000-3000-1010', 'S-1-5-21-1000-2000-3000-1011')
$AutoRemoved = @('S-1-5-21-1000-2000-3000-1010', 'S-1-5-21-1000-2000-3000-1011')

function Invoke-TestDecision {
    param($State, $Verified = $AllVerified, $Removed = $AutoRemoved)
    return Get-CrAutoLogonDecision -State $State -Resolved (New-TestResolved $State) -Config $TestConfig `
        -VerifiedSids $Verified -RemovedAdminSids $Removed
}

function Test-AnyMatch {
    param($Items, [string]$Pattern)
    if ($null -eq $Items) { return $false }
    foreach ($i in @($Items)) { if ([string]$i -match $Pattern) { return $true } }
    return $false
}

Describe 'Get-CrAutoLogonDecision' {
    Mock Test-CrIsAdmin { return (@($State['FixtureAdmins']) -contains $UserSid) }
    Mock Get-CrEffectiveLogonRights {
        return @{ Network = $true; Interactive = (@($State['FixtureNoInteractive']) -notcontains $UserSid)
                  RemoteInteractive = $false; Batch = $true; Service = $true }
    }

    Context 'Off' {
        It 'leaves off when AutoAdminLogon is missing (SM and other machine)' {
            foreach ($c in @('SM-SITEA', 'IPT01-SITEA')) {
                $s = New-TestState -Computer $c -AutoLogon (New-TestAutoLogon -AutoAdminLogon $null -UserName 'BiCA Admin')
                (Invoke-TestDecision $s)['Action'] | Should Be 'LeaveOff'
            }
        }
        It 'leaves off when AutoAdminLogon is REG_DWORD 0' {
            $s = New-TestState -AutoLogon (New-TestAutoLogon -AutoAdminLogon '0' -Kind 'DWord' -UserName 'PUB-User')
            $d = Invoke-TestDecision $s
            $d['Action'] | Should Be 'LeaveOff'
            @($d['HighImpact']).Count | Should Be 0
            @($d['OperatorOptions']).Count | Should Be 0
        }
        It 'reports a plain-text DefaultPassword while off without changing it' {
            $s = New-TestState -AutoLogon (New-TestAutoLogon -AutoAdminLogon '0' -UserName 'BiCA Admin' -PlainPassword)
            $d = Invoke-TestDecision $s
            $d['Action'] | Should Be 'LeaveOff'
            (Test-AnyMatch $d['Reasons'] 'plain-text DefaultPassword.*off') | Should Be $true
        }
        It 'is ambiguous when off but another mechanism exists' {
            $s = New-TestState -AutoLogon (New-TestAutoLogon -AutoAdminLogon '0' -UserName 'PUB-User' -Mechanisms @('Sysinternals Autologon settings in the profile hive of S-1-5-21-1000-2000-3000-1010'))
            $d = Invoke-TestDecision $s
            $d['Action'] | Should Be 'Ambiguous'
            ($d['OperatorOptions'] -join ',') | Should Be 'TurnOff,LeaveUnchanged'
        }
    }

    Context 'SM machine' {
        It 'keeps and standardizes PUB-User' {
            $s = New-TestState -Computer 'SM-SITEA' -AutoLogon (New-TestAutoLogon -UserName 'PUB-User')
            $d = Invoke-TestDecision $s
            $d['Action'] | Should Be 'Standardize'
            $d['TargetSid'] | Should Be $SidPub
            $d['CurrentSid'] | Should Be $SidPub
        }
        It 'keeps WinAutoUser even when PUB-User is usable (no switch on SM)' {
            $s = New-TestState -Computer 'SM-SITEA' -AutoLogon (New-TestAutoLogon -UserName 'WinAutoUser')
            $d = Invoke-TestDecision $s
            $d['Action'] | Should Be 'Standardize'
            $d['TargetSid'] | Should Be $SidWinAuto
        }
        It 'turns off an admin auto-logon' {
            $s = New-TestState -Computer 'SM-SITEA' -AutoLogon (New-TestAutoLogon -UserName 'BiCA Admin' -PlainPassword)
            $d = Invoke-TestDecision $s
            $d['Action'] | Should Be 'TurnOff'
            $d['TargetSid'] | Should BeNullOrEmpty
            (Test-AnyMatch $d['HighImpact'] 'waits at the logon screen') | Should Be $true
        }
        It 'turns off an auto-logon as any other account' {
            $s = New-TestState -Computer 'SM-SITEA' -AutoLogon (New-TestAutoLogon -UserName 'WinUser1')
            (Invoke-TestDecision $s)['Action'] | Should Be 'TurnOff'
        }
        It 'matches the SM pattern case-insensitively via Computer.IsSm' {
            $s = New-TestState -Computer 'IPT01-SITEA' -AutoLogon (New-TestAutoLogon -UserName 'WinUser1')
            $s['Computer']['IsSm'] = $true
            (Invoke-TestDecision $s)['Action'] | Should Be 'TurnOff'
        }
        It 'is ambiguous when the kept WinAutoUser is denied interactive logon' {
            $s = New-TestState -Computer 'SM-SITEA' -AutoLogon (New-TestAutoLogon -UserName 'WinAutoUser') -NoInteractive @($SidWinAuto)
            $d = Invoke-TestDecision $s
            $d['Action'] | Should Be 'Ambiguous'
            (Test-AnyMatch $d['Reasons'] 'kept auto-logon account WinAutoUser is not usable') | Should Be $true
            ($d['OperatorOptions'] -join ',') | Should Be 'TurnOff,LeaveUnchanged'
        }
        It 'is ambiguous when the kept PUB-User is an admin whose slot did not complete' {
            $s = New-TestState -Computer 'SM-SITEA' -AutoLogon (New-TestAutoLogon -UserName 'PUB-User') -Admins @($SidBica, $SidPub)
            $d = Invoke-TestDecision $s -Removed @()
            $d['Action'] | Should Be 'Ambiguous'
            (Test-AnyMatch $d['Reasons'] 'itself an admin') | Should Be $true
        }
        It 'standardizes an admin PUB-User whose admin membership this run removes' {
            $s = New-TestState -Computer 'SM-SITEA' -AutoLogon (New-TestAutoLogon -UserName 'PUB-User') -Admins @($SidBica, $SidPub)
            (Invoke-TestDecision $s -Removed @($SidPub))['Action'] | Should Be 'Standardize'
        }
        It 'turns off an admin auto-logon regardless of an admin PUB-User (no selection on SM)' {
            $s = New-TestState -Computer 'SM-SITEA' -AutoLogon (New-TestAutoLogon -UserName 'BiCA Admin') -Admins @($SidBica, $SidPub)
            (Invoke-TestDecision $s -Removed @())['Action'] | Should Be 'TurnOff'
        }
    }

    Context 'Other machine' {
        It 'standardizes the selected PUB-User' {
            $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'PUB-User')
            $d = Invoke-TestDecision $s
            $d['Action'] | Should Be 'Standardize'
            $d['TargetSid'] | Should Be $SidPub
            @($d['HighImpact']).Count | Should Be 0
        }
        It 'switches a WinAutoUser auto-logon to a usable PUB-User' {
            $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'WinAutoUser')
            $d = Invoke-TestDecision $s
            $d['Action'] | Should Be 'Switch'
            $d['TargetSid'] | Should Be $SidPub
            $d['CurrentSid'] | Should Be $SidWinAuto
        }
        It 'standardizes WinAutoUser when PUB-User does not exist' {
            $s = New-TestState -Users (New-TestUsers -NoPub) -AutoLogon (New-TestAutoLogon -UserName 'WinAutoUser')
            $d = Invoke-TestDecision $s
            $d['Action'] | Should Be 'Standardize'
            $d['TargetSid'] | Should Be $SidWinAuto
        }
        It 'standardizes WinAutoUser when PUB-User is disabled (RequireEnabled)' {
            $s = New-TestState -Users (New-TestUsers -PubDisabled) -AutoLogon (New-TestAutoLogon -UserName 'WinAutoUser')
            (Invoke-TestDecision $s)['TargetSid'] | Should Be $SidWinAuto
        }
        It 'standardizes WinAutoUser when PUB-User is locked out' {
            $s = New-TestState -Users (New-TestUsers -PubLocked) -AutoLogon (New-TestAutoLogon -UserName 'WinAutoUser')
            $d = Invoke-TestDecision $s
            $d['Action'] | Should Be 'Standardize'
            (Test-AnyMatch $d['Reasons'] 'PUB-User is not a usable.*locked') | Should Be $true
        }
        It 'standardizes WinAutoUser when PUB-User is denied interactive logon' {
            $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'WinAutoUser') -NoInteractive @($SidPub)
            (Invoke-TestDecision $s)['Action'] | Should Be 'Standardize'
        }
        It 'switches an admin auto-logon to the selected user with the standard-user high-impact text' {
            $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'BiCA Admin' -PlainPassword)
            $d = Invoke-TestDecision $s
            $d['Action'] | Should Be 'Switch'
            $d['TargetSid'] | Should Be $SidPub
            (Test-AnyMatch $d['HighImpact'] 'standard user') | Should Be $true
            (Test-AnyMatch $d['Reasons'] '\(an admin\)') | Should Be $true
        }
        It 'switches an auto-logon as any other account' {
            $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'WinUser1')
            $d = Invoke-TestDecision $s
            $d['Action'] | Should Be 'Switch'
            $d['TargetName'] | Should Be 'PUB-User'
        }
        It 'is ambiguous when no usable target exists for a switch' {
            $s = New-TestState -Users (New-TestUsers -NoPub) -AutoLogon (New-TestAutoLogon -UserName 'BiCA Admin') -NoInteractive @($SidWinAuto)
            $d = Invoke-TestDecision $s
            $d['Action'] | Should Be 'Ambiguous'
            (Test-AnyMatch $d['Reasons'] 'No usable auto-logon target') | Should Be $true
        }
        It 'is ambiguous when the standardized WinAutoUser is not usable and PUB-User is missing' {
            $s = New-TestState -Users (New-TestUsers -NoPub) -AutoLogon (New-TestAutoLogon -UserName 'WinAutoUser') -NoInteractive @($SidWinAuto)
            $d = Invoke-TestDecision $s
            $d['Action'] | Should Be 'Ambiguous'
            (Test-AnyMatch $d['Reasons'] 'standardized auto-logon account WinAutoUser is not usable') | Should Be $true
        }
        It 'is ambiguous when a preferred PUB-User is an admin whose slot did not complete' {
            $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'BiCA Admin') -Admins @($SidBica, $SidPub)
            $d = Invoke-TestDecision $s -Removed @()
            $d['Action'] | Should Be 'Ambiguous'
            (Test-AnyMatch $d['Reasons'] 'PUB-User is itself an admin') | Should Be $true
        }
        It 'is ambiguous when the current PUB-User is an admin whose slot did not complete' {
            $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'PUB-User') -Admins @($SidBica, $SidPub)
            (Invoke-TestDecision $s -Removed @())['Action'] | Should Be 'Ambiguous'
        }
        It 'standardizes an admin PUB-User whose admin membership this run removes' {
            $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'PUB-User') -Admins @($SidBica, $SidPub)
            (Invoke-TestDecision $s -Removed @($SidPub))['Action'] | Should Be 'Standardize'
        }
    }

    Context 'Ambiguous detections' {
        It 'is ambiguous with AutoLogonCount present' {
            $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'PUB-User' -Count)
            $d = Invoke-TestDecision $s
            $d['Action'] | Should Be 'Ambiguous'
            (Test-AnyMatch $d['Reasons'] 'AutoLogonCount') | Should Be $true
        }
        It 'is ambiguous when the account cannot be resolved' {
            $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'NoSuchUser')
            $d = Invoke-TestDecision $s
            $d['Action'] | Should Be 'Ambiguous'
            $d['CurrentSid'] | Should BeNullOrEmpty
            $d['CurrentName'] | Should Be 'NoSuchUser'
        }
        It 'is ambiguous when auto-logon is on with an empty DefaultUserName' {
            $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName '')
            (Invoke-TestDecision $s)['Action'] | Should Be 'Ambiguous'
        }
        It 'is ambiguous with a non-Winlogon mechanism while on' {
            $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'PUB-User' -Mechanisms @('Winlogon Shell is not explorer.exe: C:\POS\shell.exe'))
            $d = Invoke-TestDecision $s
            $d['Action'] | Should Be 'Ambiguous'
            (Test-AnyMatch $d['Reasons'] 'Non-Winlogon') | Should Be $true
        }
        It 'is ambiguous with an unexpected AutoAdminLogon value' {
            $s = New-TestState -AutoLogon (New-TestAutoLogon -AutoAdminLogon '2' -UserName 'PUB-User')
            (Invoke-TestDecision $s)['Action'] | Should Be 'Ambiguous'
        }
        It 'is ambiguous on an SM machine too (same rule)' {
            $s = New-TestState -Computer 'SM-SITEA' -AutoLogon (New-TestAutoLogon -UserName 'BiCA Admin' -Count)
            (Invoke-TestDecision $s)['Action'] | Should Be 'Ambiguous'
        }
    }

    Context 'Detection details' {
        It 'accepts AutoAdminLogon as REG_DWORD 1' {
            $s = New-TestState -AutoLogon (New-TestAutoLogon -AutoAdminLogon '1' -Kind 'DWord' -UserName 'PUB-User')
            $d = Invoke-TestDecision $s
            $d['Action'] | Should Be 'Standardize'
            (Test-AnyMatch $d['Reasons'] 'REG_DWORD') | Should Be $true
        }
        It 'resolves DefaultUserName case-insensitively against local users' {
            $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'Bica Admin')
            $d = Invoke-TestDecision $s
            $d['CurrentSid'] | Should Be $SidBica
            $d['CurrentName'] | Should Be 'BiCA Admin'
        }
        It 'resolves a domain-qualified DefaultUserName against local users' {
            $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'SM-OLDNAME\PUB-User')
            (Invoke-TestDecision $s)['CurrentSid'] | Should Be $SidPub
        }
        It 'reports a DefaultDomainName mismatch while on' {
            $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'PUB-User' -Domain 'IPT01-OLDNAME')
            $d = Invoke-TestDecision $s
            $d['Action'] | Should Be 'Standardize'
            (Test-AnyMatch $d['Reasons'] 'DefaultDomainName "IPT01-OLDNAME" differs') | Should Be $true
        }
        It 'does not report a mismatch for an empty DefaultDomainName or different case' {
            $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'PUB-User' -Domain '')
            (Test-AnyMatch (Invoke-TestDecision $s)['Reasons'] 'mismatch') | Should Be $false
            $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'PUB-User' -Domain 'ipt01-sitea')
            (Test-AnyMatch (Invoke-TestDecision $s)['Reasons'] 'mismatch') | Should Be $false
        }
        It 'reports a legal-notice text without caption' {
            $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'PUB-User' -LegalText)
            (Test-AnyMatch (Invoke-TestDecision $s)['Reasons'] 'legal-notice text without a caption') | Should Be $true
        }
        It 'returns NoChange without an AutoLogon entry in Resolved' {
            $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'BiCA Admin')
            $d = Get-CrAutoLogonDecision -State $s -Resolved @(@{ Id = 'X'; AutoLogon = $null }) -Config $TestConfig -VerifiedSids $AllVerified -RemovedAdminSids @()
            $d['Action'] | Should Be 'NoChange'
        }
        It 'returns NoChange when the auto-logon state has an error' {
            $s = New-TestState -AutoLogon @{ Error = 'access denied' }
            $d = Invoke-TestDecision $s
            $d['Action'] | Should Be 'NoChange'
            (Test-AnyMatch $d['Reasons'] 'access denied') | Should Be $true
        }
    }

    Context 'Password source per target account' {
        It 'changes nothing when the standardized account is not changed in this run' {
            $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'PUB-User' -PlainPassword)
            $d = Invoke-TestDecision $s -Verified @($SidBica)
            $d['Action'] | Should Be 'NoChange'
            (Test-AnyMatch $d['Reasons'] 'standardize changes nothing') | Should Be $true
            (Test-AnyMatch $d['Reasons'] 'plain-text DefaultPassword') | Should Be $true
        }
        It 'asks the operator when the switch target is not on the new secret (auto-logon slot skipped)' {
            $s = New-TestState -Users (New-TestUsers -NoPub) -AutoLogon (New-TestAutoLogon -UserName 'BiCA Admin' -PlainPassword)
            $d = Invoke-TestDecision $s -Verified @($SidBica)
            $d['Action'] | Should Be 'Ambiguous'
            $d['TargetSid'] | Should Be $SidWinAuto
            ($d['OperatorOptions'] -join ',') | Should Be 'TurnOff,LeaveUnchanged'
            (Test-AnyMatch $d['HighImpact'] 'broken until re-run') | Should Be $true
        }
        It 'does not report a broken auto-logon when the current account is not rotated' {
            $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'WinUser1')
            $d = Invoke-TestDecision $s -Verified @()
            $d['Action'] | Should Be 'Ambiguous'
            (Test-AnyMatch $d['HighImpact'] 'broken') | Should Be $false
        }
        It 'offers StandardizeCurrent when PUB-User failed and the current WinAutoUser succeeded' {
            $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'WinAutoUser')
            $d = Invoke-TestDecision $s -Verified @($SidBica, $SidWinAuto)
            $d['Action'] | Should Be 'Ambiguous'
            $d['TargetSid'] | Should Be $SidPub
            ($d['OperatorOptions'] -join ',') | Should Be 'TurnOff,LeaveUnchanged,StandardizeCurrent'
            (Test-AnyMatch $d['HighImpact'] 'broken until re-run') | Should Be $true
        }
        It 'does not offer StandardizeCurrent when the current WinAutoUser is not verified' {
            $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'WinAutoUser')
            $d = Invoke-TestDecision $s -Verified @($SidBica)
            ($d['OperatorOptions'] -join ',') | Should Be 'TurnOff,LeaveUnchanged'
        }
        It 'does not offer StandardizeCurrent when the current WinAutoUser is not usable' {
            $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'WinAutoUser') -NoInteractive @($SidWinAuto)
            $d = Invoke-TestDecision $s -Verified @($SidWinAuto)
            ($d['OperatorOptions'] -join ',') | Should Be 'TurnOff,LeaveUnchanged'
        }
        It 'switches when only the target of a two-account slot is verified' {
            $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'WinAutoUser')
            (Invoke-TestDecision $s -Verified @($SidPub))['Action'] | Should Be 'Switch'
        }
        It 'turns off without needing a verified account' {
            $s = New-TestState -Computer 'SM-SITEA' -AutoLogon (New-TestAutoLogon -UserName 'BiCA Admin')
            (Invoke-TestDecision $s -Verified @())['Action'] | Should Be 'TurnOff'
        }
        It 'reports a broken auto-logon for any ambiguity when the current account is rotated' {
            $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'BiCA Admin' -Count)
            $d = Invoke-TestDecision $s
            $d['Action'] | Should Be 'Ambiguous'
            (Test-AnyMatch $d['HighImpact'] 'broken until re-run') | Should Be $true
        }
    }

    Context 'Test-site examples (PLAN 7.5, synthetic names)' {
        It 'IPT01 with PUB-User and LSA secret: standardize' {
            $al = New-TestAutoLogon -UserName 'PUB-User'
            $al['AutoLogonSidValue'] = 'S-1-5-21-1000-2000-3000-1010'
            $s = New-TestState -Computer 'IPT01-SITEA' -Users (New-TestUsers -NoWinAuto) -AutoLogon $al
            $d = Invoke-TestDecision $s -Verified @($SidBica, $SidPub)
            $d['Action'] | Should Be 'Standardize'
            $d['TargetSid'] | Should Be $SidPub
        }
        It 'SM off with stale DefaultUserName and old computer name: leave off, mismatch reported' {
            $s = New-TestState -Computer 'SM-SITEA' -AutoLogon (New-TestAutoLogon -AutoAdminLogon '0' -UserName 'WinUser1' -Domain 'SM-OLDNAME') -NoInteractive @($SidWinAuto)
            $d = Invoke-TestDecision $s
            $d['Action'] | Should Be 'LeaveOff'
            (Test-AnyMatch $d['Reasons'] 'SM-OLDNAME.*mismatch') | Should Be $true
        }
        It 'SM on as BiCA Admin with plain-text password: turn off' {
            $s = New-TestState -Computer 'SM-SITEB' -Users (New-TestUsers -NoPub) -AutoLogon (New-TestAutoLogon -UserName 'BiCA Admin' -PlainPassword) -NoInteractive @($SidWinAuto)
            $d = Invoke-TestDecision $s -Verified @($SidBica, $SidWinAuto)
            $d['Action'] | Should Be 'TurnOff'
            (Test-AnyMatch $d['HighImpact'] 'logon screen') | Should Be $true
        }
        It 'IPT01 on as "Bica Admin" with plain-text password, no PUB-User: switch to WinAutoUser' {
            $s = New-TestState -Computer 'IPT01-SITEB' -Users (New-TestUsers -NoPub) -AutoLogon (New-TestAutoLogon -UserName 'Bica Admin' -PlainPassword)
            $d = Invoke-TestDecision $s -Verified @($SidBica, $SidWinAuto)
            $d['Action'] | Should Be 'Switch'
            $d['CurrentSid'] | Should Be $SidBica
            $d['TargetSid'] | Should Be $SidWinAuto
            (Test-AnyMatch $d['HighImpact'] 'standard user') | Should Be $true
        }
    }
}

Describe 'Test-CrAutoLogonStandardized' {
    It 'is true when all readable values match' {
        $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'PUB-User')
        Test-CrAutoLogonStandardized -State $s -TargetSid $SidPub | Should Be $true
    }
    It 'is false for REG_DWORD AutoAdminLogon' {
        $s = New-TestState -AutoLogon (New-TestAutoLogon -Kind 'DWord' -UserName 'PUB-User')
        Test-CrAutoLogonStandardized -State $s -TargetSid $SidPub | Should Be $false
    }
    It 'is false when auto-logon is off' {
        $s = New-TestState -AutoLogon (New-TestAutoLogon -AutoAdminLogon '0' -UserName 'PUB-User')
        Test-CrAutoLogonStandardized -State $s -TargetSid $SidPub | Should Be $false
    }
    It 'is false for another user' {
        $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'WinAutoUser')
        Test-CrAutoLogonStandardized -State $s -TargetSid $SidPub | Should Be $false
    }
    It 'is false for a domain-qualified DefaultUserName' {
        $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'IPT01-SITEA\PUB-User')
        Test-CrAutoLogonStandardized -State $s -TargetSid $SidPub | Should Be $false
    }
    It 'is false for a stale DefaultDomainName' {
        $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'PUB-User' -Domain 'IPT01-OLDNAME')
        Test-CrAutoLogonStandardized -State $s -TargetSid $SidPub | Should Be $false
    }
    It 'is false with a plain-text DefaultPassword' {
        $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'PUB-User' -PlainPassword)
        Test-CrAutoLogonStandardized -State $s -TargetSid $SidPub | Should Be $false
    }
    It 'is false with AutoLogonCount' {
        $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'PUB-User' -Count)
        Test-CrAutoLogonStandardized -State $s -TargetSid $SidPub | Should Be $false
    }
    It 'is false without a target or with a state error' {
        $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'PUB-User')
        Test-CrAutoLogonStandardized -State $s -TargetSid '' | Should Be $false
        $s = New-TestState -AutoLogon @{ Error = 'x' }
        Test-CrAutoLogonStandardized -State $s -TargetSid $SidPub | Should Be $false
    }
}

# Builds the Get-CrAutoLogonKeyValues result: [int] values are REG_DWORD, everything else REG_SZ.
function New-TestKeyValues {
    param([hashtable]$Values)
    $r = @{}
    foreach ($k in $Values.Keys) {
        $v = $Values[$k]
        $kind = 'String'
        if ($v -is [int]) { $kind = 'DWord' }
        $r[$k] = @{ Value = $v; Kind = $kind }
    }
    return $r
}

Describe 'Get-CrAutoLogonState' {
    Mock Get-CrAutoLogonKeyValues { return $null }
    Mock Get-CrSysinternalsAutologonSids { return , @() }

    It 'reads a REG_SZ auto-logon and the value presence flags' {
        Mock Get-CrAutoLogonKeyValues -ParameterFilter { $Path -like '*\Winlogon' } {
            New-TestKeyValues @{ AutoAdminLogon = '1'; DefaultUserName = 'PUB-User'; DefaultDomainName = 'IPT01-SITEA'
                                 AutoLogonSID = 'S-1-5-21-1000-2000-3000-1010'; Shell = 'explorer.exe'
                                 Userinit = 'C:\Windows\system32\userinit.exe,' }
        }
        $st = Get-CrAutoLogonState
        $st['Error'] | Should BeNullOrEmpty
        $st['AutoAdminLogon'] | Should Be '1'
        $st['AutoAdminLogonKind'] | Should Be 'String'
        $st['DefaultUserName'] | Should Be 'PUB-User'
        $st['DefaultPasswordPresent'] | Should Be $false
        $st['AutoLogonCountPresent'] | Should Be $false
        $st['AutoLogonSidValue'] | Should Be 'S-1-5-21-1000-2000-3000-1010'
        @($st['OtherMechanisms']).Count | Should Be 0
    }
    It 'reads a REG_DWORD AutoAdminLogon with its kind' {
        Mock Get-CrAutoLogonKeyValues -ParameterFilter { $Path -like '*\Winlogon' } { New-TestKeyValues @{ AutoAdminLogon = 1 } }
        $st = Get-CrAutoLogonState
        $st['AutoAdminLogon'] | Should Be '1'
        $st['AutoAdminLogonKind'] | Should Be 'DWord'
    }
    It 'records only the presence of DefaultPassword and AutoLogonCount' {
        Mock Get-CrAutoLogonKeyValues -ParameterFilter { $Path -like '*\Winlogon' } {
            New-TestKeyValues @{ AutoAdminLogon = '1'; DefaultPassword = 'not-a-real-secret'; AutoLogonCount = 3 }
        }
        $st = Get-CrAutoLogonState
        $st['DefaultPasswordPresent'] | Should Be $true
        $st['AutoLogonCountPresent'] | Should Be $true
        $st.ContainsKey('DefaultPassword') | Should Be $false
        foreach ($k in @($st.Keys)) { ([string]$st[$k]) -match 'not-a-real-secret' | Should Be $false }
    }
    It 'reports a shell replacement without its arguments' {
        Mock Get-CrAutoLogonKeyValues -ParameterFilter { $Path -like '*\Winlogon' } {
            New-TestKeyValues @{ AutoAdminLogon = '1'; Shell = 'C:\POS\possh.exe /token:abc' }
        }
        $st = Get-CrAutoLogonState
        @($st['OtherMechanisms']).Count | Should Be 1
        @($st['OtherMechanisms'])[0] | Should Match 'possh\.exe'
        @($st['OtherMechanisms'])[0] -match 'token' | Should Be $false
    }
    It 'reports additional Userinit programs' {
        Mock Get-CrAutoLogonKeyValues -ParameterFilter { $Path -like '*\Winlogon' } {
            New-TestKeyValues @{ AutoAdminLogon = '1'; Userinit = 'C:\Windows\system32\userinit.exe,"C:\Tools\logon helper.exe" -x,' }
        }
        $st = Get-CrAutoLogonState
        @($st['OtherMechanisms']).Count | Should Be 1
        @($st['OtherMechanisms'])[0] | Should Match 'logon helper\.exe'
    }
    It 'reports Sysinternals Autologon traces' {
        Mock Get-CrAutoLogonKeyValues -ParameterFilter { $Path -like '*\Winlogon' } { New-TestKeyValues @{ AutoAdminLogon = '0' } }
        Mock Get-CrSysinternalsAutologonSids { return , @('S-1-5-21-1000-2000-3000-1001') }
        $st = Get-CrAutoLogonState
        @($st['OtherMechanisms']).Count | Should Be 1
        @($st['OtherMechanisms'])[0] | Should Match 'Sysinternals'
    }
    It 'reads legal-notice settings from the policy key' {
        Mock Get-CrAutoLogonKeyValues -ParameterFilter { $Path -like '*\Winlogon' } {
            New-TestKeyValues @{ AutoAdminLogon = '1'; LegalNoticeCaption = ''; LegalNoticeText = '' }
        }
        Mock Get-CrAutoLogonKeyValues -ParameterFilter { $Path -like '*\Policies\System' } {
            New-TestKeyValues @{ legalnoticecaption = ''; legalnoticetext = 'Authorized use only' }
        }
        $st = Get-CrAutoLogonState
        $st['LegalNoticeTextSet'] | Should Be $true
        $st['LegalNoticeCaptionSet'] | Should Be $false
    }
    It 'returns an Error when the Winlogon key cannot be opened' {
        $st = Get-CrAutoLogonState
        $st['Error'] | Should Not BeNullOrEmpty
    }
}
