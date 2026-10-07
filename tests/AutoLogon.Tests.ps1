# Pester 3.4 tests for src\lib\AutoLogon.ps1 (PLAN section 7.5, D18). Synthetic SIDs and machine names only.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here '..\src\lib\Compat.ps1')

# Stubs for Rights.ps1 (another module); mocked below. Parameters must match the contract for Mock.
function Get-CrEffectiveLogonRights { param($UserSid, $State) }
function Test-CrIsAdmin { param($UserSid, $State) }

. (Join-Path $here '..\src\lib\AutoLogon.ps1')

# Write side: the real registry writers are kept aside (only their argument checks are tested, which run before any
# registry access) and replaced by throwing stubs, so a missing mock can never write HKLM. The LSA wrappers are
# Native.ps1 stubs (CONTRACTS).
$tcRealSetWinlogonValue = ${function:Set-CrWinlogonValue}
function Set-CrWinlogonValue { param([string]$Name, [string]$Value, [string]$Kind) throw 'Set-CrWinlogonValue is not mocked' }
function Remove-CrWinlogonValue { param([string]$Name) throw 'Remove-CrWinlogonValue is not mocked' }
function Set-CrLsaSecret { param([string]$Name, $Secret) throw 'Set-CrLsaSecret is not mocked' }
function Remove-CrLsaSecret { param([string]$Name) throw 'Remove-CrLsaSecret is not mocked' }

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

$SidSop    = 'S-1-5-21-1000-2000-3000-1030'
$SidNewPub = 'S-1-5-21-1000-2000-3000-1050'

# v10 resolved entries (CONTRACTS "v10"): SOP-Admin, and PUB-User with the AutoLogon block and AutoLogonUser = PUB-User
# only; WinAutoUser is a replaced account, not an auto-logon target. -CreatePub: PUB-User doesn't exist and is created
# in this run (placeholder with ToCreate; -CreatedPubSid = the SID the caller filled in after creating it).
function New-TestResolved {
    param($State, [switch]$CreatePub, [string]$CreatedPubSid)
    $acc = New-Object System.Collections.ArrayList
    foreach ($u in @($State['Users'])) {
        if ($u['Name'] -ieq 'PUB-User') { [void]$acc.Add(@{ Name = $u['Name']; Sid = $u['Sid']; User = $u }) }
    }
    $create = $false
    if (($acc.Count -eq 0) -and $CreatePub) {
        $create = $true
        $placeholderSid = $null
        if ($CreatedPubSid) { $placeholderSid = $CreatedPubSid }
        [void]$acc.Add(@{ Name = 'PUB-User'; Sid = $placeholderSid; User = $null; ToCreate = $true })
    }
    $sop = @{ Id = 'SOPAdmin'; Kind = 'Windows'; Mode = 'Rotate'; RoleName = 'Operator'; Slot = 'SOPAdmin'; Create = $false
              Accounts = @(@{ Name = 'SOP-Admin'; Sid = $SidSop }); Missing = @(); AutoLogon = $null; AutoLogonUser = $null
              Replaced = @(@{ Name = 'BiCA Admin'; Sid = $SidBica; Enabled = $true }) }
    $pub = @{ Id = 'PubUser'; Kind = 'Windows'; Mode = 'Rotate'; RoleName = 'User'; Slot = 'PubUser'; Create = $create
              Accounts = $acc.ToArray(); Missing = @(); NotApplicable = ($acc.Count -eq 0)
              AutoLogon = @{ Mode = 'IfAlreadyOn'; RestrictedComputerPattern = '^SM' }
              AutoLogonUser = @(@{ Name = 'PUB-User'; RequireEnabled = $true })
              Replaced = @(@{ Name = 'WinAutoUser'; Sid = $SidWinAuto; Enabled = $true }) }
    return , @($sop, $pub)
}

$TestConfig = @{ Accounts = @() }
$AllVerified = @('S-1-5-21-1000-2000-3000-1001', 'S-1-5-21-1000-2000-3000-1010', 'S-1-5-21-1000-2000-3000-1011')
$AutoRemoved = @('S-1-5-21-1000-2000-3000-1010', 'S-1-5-21-1000-2000-3000-1011')

function Invoke-TestDecision {
    param($State, $Verified = $AllVerified, $Removed = $AutoRemoved, [string[]]$Created = @(), [switch]$CreatePub, [string]$CreatedPubSid)
    return Get-CrAutoLogonDecision -State $State -Resolved (New-TestResolved $State -CreatePub:$CreatePub -CreatedPubSid $CreatedPubSid) `
        -Config $TestConfig -VerifiedSids $Verified -RemovedAdminSids $Removed -CreatedTargetNames $Created
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
        It 'leaves off even when PUB-User is created in this run' {
            $s = New-TestState -Users (New-TestUsers -NoPub) -AutoLogon (New-TestAutoLogon -AutoAdminLogon '0' -UserName 'WinAutoUser')
            (Invoke-TestDecision $s -CreatePub -Created @('PUB-User'))['Action'] | Should Be 'LeaveOff'
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
            $d['TargetCreated'] | Should Be $false
        }
        It 'turns off a WinAutoUser auto-logon (WinAutoUser is any other account, D22)' {
            $s = New-TestState -Computer 'SM-SITEA' -AutoLogon (New-TestAutoLogon -UserName 'WinAutoUser')
            $d = Invoke-TestDecision $s
            $d['Action'] | Should Be 'TurnOff'
            $d['CurrentSid'] | Should Be $SidWinAuto
            $d['TargetSid'] | Should BeNullOrEmpty
            (Test-AnyMatch $d['Reasons'] 'SM machine: auto-logon as any account other than PUB-User is turned off') | Should Be $true
            (Test-AnyMatch $d['HighImpact'] 'WinAutoUser is turned off') | Should Be $true
        }
        It 'turns off a WinAutoUser auto-logon also when WinAutoUser is not usable' {
            $s = New-TestState -Computer 'SM-SITEA' -AutoLogon (New-TestAutoLogon -UserName 'WinAutoUser') -NoInteractive @($SidWinAuto)
            (Invoke-TestDecision $s)['Action'] | Should Be 'TurnOff'
        }
        It 'turns off a WinAutoUser auto-logon when PUB-User is missing or created in this run' {
            $s = New-TestState -Computer 'SM-SITEA' -Users (New-TestUsers -NoPub) -AutoLogon (New-TestAutoLogon -UserName 'WinAutoUser')
            (Invoke-TestDecision $s)['Action'] | Should Be 'TurnOff'
            (Invoke-TestDecision $s -CreatePub -Created @('PUB-User'))['Action'] | Should Be 'TurnOff'
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
        It 'is ambiguous when the kept PUB-User is denied interactive logon' {
            $s = New-TestState -Computer 'SM-SITEA' -AutoLogon (New-TestAutoLogon -UserName 'PUB-User') -NoInteractive @($SidPub)
            $d = Invoke-TestDecision $s
            $d['Action'] | Should Be 'Ambiguous'
            (Test-AnyMatch $d['Reasons'] 'kept auto-logon account PUB-User is not usable') | Should Be $true
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
        It 'standardizes a disabled PUB-User that this run enables and verifies' {
            $s = New-TestState -Computer 'SM-SITEA' -Users (New-TestUsers -PubDisabled) -AutoLogon (New-TestAutoLogon -UserName 'PUB-User')
            (Invoke-TestDecision $s -Verified @($SidPub))['Action'] | Should Be 'Standardize'
        }
        It 'is ambiguous for a disabled PUB-User that is not verified in this run' {
            $s = New-TestState -Computer 'SM-SITEA' -Users (New-TestUsers -PubDisabled) -AutoLogon (New-TestAutoLogon -UserName 'PUB-User')
            $d = Invoke-TestDecision $s -Verified @($SidBica)
            $d['Action'] | Should Be 'Ambiguous'
            (Test-AnyMatch $d['Reasons'] 'PUB-User is not usable: is disabled') | Should Be $true
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
            (Test-AnyMatch $d['Reasons'] 'on as WinAutoUser \(another account\)') | Should Be $true
        }
        It 'never standardizes WinAutoUser: ambiguous when PUB-User neither exists nor is created' {
            $s = New-TestState -Users (New-TestUsers -NoPub) -AutoLogon (New-TestAutoLogon -UserName 'WinAutoUser')
            $d = Invoke-TestDecision $s
            $d['Action'] | Should Be 'Ambiguous'
            $d['TargetSid'] | Should BeNullOrEmpty
            (Test-AnyMatch $d['Reasons'] 'No usable auto-logon target \(PUB-User\)') | Should Be $true
            ($d['OperatorOptions'] -join ',') | Should Be 'TurnOff,LeaveUnchanged'
        }
        It 'is ambiguous when PUB-User is disabled and not enabled by this run' {
            $s = New-TestState -Users (New-TestUsers -PubDisabled) -AutoLogon (New-TestAutoLogon -UserName 'WinAutoUser')
            $d = Invoke-TestDecision $s -Verified @($SidBica)
            $d['Action'] | Should Be 'Ambiguous'
            (Test-AnyMatch $d['Reasons'] 'PUB-User is not a usable.*disabled') | Should Be $true
        }
        It 'switches to a disabled PUB-User that this run enables and verifies' {
            $s = New-TestState -Users (New-TestUsers -PubDisabled) -AutoLogon (New-TestAutoLogon -UserName 'WinAutoUser')
            $d = Invoke-TestDecision $s
            $d['Action'] | Should Be 'Switch'
            $d['TargetSid'] | Should Be $SidPub
        }
        It 'is ambiguous when PUB-User is locked out' {
            $s = New-TestState -Users (New-TestUsers -PubLocked) -AutoLogon (New-TestAutoLogon -UserName 'WinAutoUser')
            $d = Invoke-TestDecision $s
            $d['Action'] | Should Be 'Ambiguous'
            (Test-AnyMatch $d['Reasons'] 'PUB-User is not a usable.*locked') | Should Be $true
        }
        It 'is ambiguous when PUB-User is denied interactive logon' {
            $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'WinAutoUser') -NoInteractive @($SidPub)
            (Invoke-TestDecision $s)['Action'] | Should Be 'Ambiguous'
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
            $s = New-TestState -Users (New-TestUsers -NoPub) -AutoLogon (New-TestAutoLogon -UserName 'BiCA Admin')
            $d = Invoke-TestDecision $s
            $d['Action'] | Should Be 'Ambiguous'
            (Test-AnyMatch $d['Reasons'] 'No usable auto-logon target') | Should Be $true
        }
        It 'is ambiguous when the standardized PUB-User is not usable' {
            $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'PUB-User') -NoInteractive @($SidPub)
            $d = Invoke-TestDecision $s
            $d['Action'] | Should Be 'Ambiguous'
            (Test-AnyMatch $d['Reasons'] 'standardized auto-logon account PUB-User is not usable') | Should Be $true
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

    Context 'PUB-User created in this run (D21)' {
        It 'switches a WinAutoUser auto-logon to the created PUB-User listed in -CreatedTargetNames' {
            $s = New-TestState -Users (New-TestUsers -NoPub) -AutoLogon (New-TestAutoLogon -UserName 'WinAutoUser')
            $d = Invoke-TestDecision $s -Verified @() -CreatePub -Created @('PUB-User')
            $d['Action'] | Should Be 'Switch'
            $d['CurrentSid'] | Should Be $SidWinAuto
            $d['TargetName'] | Should Be 'PUB-User'
            $d['TargetSid'] | Should BeNullOrEmpty
            $d['TargetCreated'] | Should Be $true
            (Test-AnyMatch $d['Reasons'] 'PUB-User does not exist yet; it is created in this run') | Should Be $true
            (Test-AnyMatch $d['HighImpact'] 'from WinAutoUser to PUB-User') | Should Be $true
        }
        It 'switches an admin auto-logon to the created PUB-User whose SID is verified' {
            $s = New-TestState -Users (New-TestUsers -NoPub) -AutoLogon (New-TestAutoLogon -UserName 'BiCA Admin' -PlainPassword)
            $d = Invoke-TestDecision $s -Verified @($SidNewPub) -CreatePub -CreatedPubSid $SidNewPub
            $d['Action'] | Should Be 'Switch'
            $d['TargetSid'] | Should Be $SidNewPub
            $d['TargetName'] | Should Be 'PUB-User'
            $d['TargetCreated'] | Should Be $true
        }
        It 'accepts -CreatedTargetNames without a placeholder in Resolved' {
            $s = New-TestState -Users (New-TestUsers -NoPub) -AutoLogon (New-TestAutoLogon -UserName 'WinUser1')
            $d = Invoke-TestDecision $s -Verified @() -Created @('pub-user')
            $d['Action'] | Should Be 'Switch'
            $d['TargetName'] | Should Be 'PUB-User'
        }
        It 'asks the operator when the created PUB-User is not verified (slot skipped or failed)' {
            $s = New-TestState -Users (New-TestUsers -NoPub) -AutoLogon (New-TestAutoLogon -UserName 'BiCA Admin')
            $d = Invoke-TestDecision $s -Verified @($SidBica) -CreatePub
            $d['Action'] | Should Be 'Ambiguous'
            $d['TargetName'] | Should Be 'PUB-User'
            $d['TargetCreated'] | Should Be $true
            (Test-AnyMatch $d['Reasons'] 'switch to PUB-User impossible') | Should Be $true
            ($d['OperatorOptions'] -join ',') | Should Be 'TurnOff,LeaveUnchanged'
            (Test-AnyMatch $d['HighImpact'] 'broken until re-run') | Should Be $true
        }
        It 'ignores created names outside the AutoLogonUser list' {
            $s = New-TestState -Users (New-TestUsers -NoPub) -AutoLogon (New-TestAutoLogon -UserName 'WinAutoUser')
            $d = Invoke-TestDecision $s -Created @('SOP-Admin', 'WinAutoUser')
            $d['Action'] | Should Be 'Ambiguous'
            (Test-AnyMatch $d['Reasons'] 'No usable auto-logon target') | Should Be $true
        }
        It 'does not change the state while evaluating the created account' {
            $s = New-TestState -Users (New-TestUsers -NoPub) -AutoLogon (New-TestAutoLogon -UserName 'WinAutoUser')
            $s['Groups'] = @(@{ Name = 'Users'; Sid = 'S-1-5-32-545'; MemberSids = @('S-1-5-11', $SidWinAuto); Error = $null })
            $before = @($s['Users']).Count
            [void](Invoke-TestDecision $s -CreatePub -Created @('PUB-User'))
            @($s['Groups'][0]['MemberSids']).Count | Should Be 2
            @($s['Users']).Count | Should Be $before
        }
    }

    Context 'created PUB-User that would be denied interactive logon' {
        It 'is not a usable target' {
            Mock Get-CrEffectiveLogonRights { return @{ Network = $true; Interactive = $false; RemoteInteractive = $false; Batch = $true; Service = $true } }
            $s = New-TestState -Users (New-TestUsers -NoPub) -AutoLogon (New-TestAutoLogon -UserName 'WinAutoUser')
            $d = Invoke-TestDecision $s -CreatePub -Created @('PUB-User')
            $d['Action'] | Should Be 'Ambiguous'
            (Test-AnyMatch $d['Reasons'] 'PUB-User \(created in this run\) is not a usable.*interactive') | Should Be $true
            (Test-AnyMatch $d['Reasons'] 'No usable auto-logon target') | Should Be $true
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
        It 'asks the operator when the switch target is not on the new secret (PUB-User slot skipped)' {
            $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'BiCA Admin' -PlainPassword)
            $d = Invoke-TestDecision $s -Verified @($SidBica)
            $d['Action'] | Should Be 'Ambiguous'
            $d['TargetSid'] | Should Be $SidPub
            ($d['OperatorOptions'] -join ',') | Should Be 'TurnOff,LeaveUnchanged'
            (Test-AnyMatch $d['HighImpact'] 'broken until re-run') | Should Be $true
        }
        It 'does not report a broken auto-logon when the current account is not rotated' {
            $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'WinUser1')
            $d = Invoke-TestDecision $s -Verified @()
            $d['Action'] | Should Be 'Ambiguous'
            (Test-AnyMatch $d['HighImpact'] 'broken') | Should Be $false
        }
        It 'does not offer StandardizeCurrent for a WinAutoUser auto-logon (not an auto-logon target, D22)' {
            $s = New-TestState -AutoLogon (New-TestAutoLogon -UserName 'WinAutoUser')
            $d = Invoke-TestDecision $s -Verified @($SidBica, $SidWinAuto)
            $d['Action'] | Should Be 'Ambiguous'
            $d['TargetSid'] | Should Be $SidPub
            ($d['OperatorOptions'] -join ',') | Should Be 'TurnOff,LeaveUnchanged'
        }
        It 'switches when the target is verified' {
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
            $d = Invoke-TestDecision $s -Verified @() -CreatePub -Created @('PUB-User')
            $d['Action'] | Should Be 'TurnOff'
            (Test-AnyMatch $d['HighImpact'] 'logon screen') | Should Be $true
        }
        It 'IPT01 on as "Bica Admin" with plain-text password, no PUB-User: switch to the PUB-User created in this run' {
            $s = New-TestState -Computer 'IPT01-SITEB' -Users (New-TestUsers -NoPub) -AutoLogon (New-TestAutoLogon -UserName 'Bica Admin' -PlainPassword)
            $d = Invoke-TestDecision $s -Verified @() -CreatePub -Created @('PUB-User')
            $d['Action'] | Should Be 'Switch'
            $d['CurrentSid'] | Should Be $SidBica
            $d['TargetName'] | Should Be 'PUB-User'
            $d['TargetCreated'] | Should Be $true
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

    Context 'reads a REG_SZ auto-logon and the value presence flags' {
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
    }
    Context 'reads a REG_DWORD AutoAdminLogon with its kind' {
        It 'reads a REG_DWORD AutoAdminLogon with its kind' {
            Mock Get-CrAutoLogonKeyValues -ParameterFilter { $Path -like '*\Winlogon' } { New-TestKeyValues @{ AutoAdminLogon = 1 } }
            $st = Get-CrAutoLogonState
            $st['AutoAdminLogon'] | Should Be '1'
            $st['AutoAdminLogonKind'] | Should Be 'DWord'
        }
    }
    Context 'records only the presence of DefaultPassword and AutoLogonCount' {
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
    }
    Context 'reports a shell replacement without its arguments' {
        It 'reports a shell replacement without its arguments' {
            Mock Get-CrAutoLogonKeyValues -ParameterFilter { $Path -like '*\Winlogon' } {
                New-TestKeyValues @{ AutoAdminLogon = '1'; Shell = 'C:\POS\possh.exe /token:abc' }
            }
            $st = Get-CrAutoLogonState
            @($st['OtherMechanisms']).Count | Should Be 1
            @($st['OtherMechanisms'])[0] | Should Match 'possh\.exe'
            @($st['OtherMechanisms'])[0] -match 'token' | Should Be $false
        }
    }
    Context 'reports additional Userinit programs' {
        It 'reports additional Userinit programs' {
            Mock Get-CrAutoLogonKeyValues -ParameterFilter { $Path -like '*\Winlogon' } {
                New-TestKeyValues @{ AutoAdminLogon = '1'; Userinit = 'C:\Windows\system32\userinit.exe,"C:\Tools\logon helper.exe" -x,' }
            }
            $st = Get-CrAutoLogonState
            @($st['OtherMechanisms']).Count | Should Be 1
            @($st['OtherMechanisms'])[0] | Should Match 'logon helper\.exe'
        }
    }
    Context 'reports Sysinternals Autologon traces' {
        It 'reports Sysinternals Autologon traces' {
            Mock Get-CrAutoLogonKeyValues -ParameterFilter { $Path -like '*\Winlogon' } { New-TestKeyValues @{ AutoAdminLogon = '0' } }
            Mock Get-CrSysinternalsAutologonSids { return , @('S-1-5-21-1000-2000-3000-1001') }
            $st = Get-CrAutoLogonState
            @($st['OtherMechanisms']).Count | Should Be 1
            @($st['OtherMechanisms'])[0] | Should Match 'Sysinternals'
        }
    }
    Context 'reads legal-notice settings from the policy key' {
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
    }
    It 'returns an Error when the Winlogon key cannot be opened' {
        $st = Get-CrAutoLogonState
        $st['Error'] | Should Not BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------------------------------------------
# Write side (M2): PLAN section 7.5 "Actions". Every registry / LSA call is recorded in $tcCalls (set in each It),
# so the exact order can be asserted. Dummy SecureStrings only.

function New-TestActionDecision {
    param([string]$Action, [string]$TargetSid, [string]$TargetName, [string]$CurrentSid, [string]$CurrentName)
    return @{
        Action = $Action; TargetSid = $TargetSid; TargetName = $TargetName; CurrentSid = $CurrentSid; CurrentName = $CurrentName
        Reasons = @(); OperatorOptions = @(); HighImpact = @()
    }
}

Describe 'Invoke-CrAutoLogonAction' {
    Mock Set-CrWinlogonValue { [void]$tcCalls.Add(('Set:{0}={1}:{2}' -f $Name, $Value, $Kind)) }
    Mock Remove-CrWinlogonValue { [void]$tcCalls.Add('Remove:' + $Name) }
    Mock Set-CrLsaSecret {
        [void]$tcCalls.Add('LsaSet:' + $Name)
        return @{ Success = $true; Win32Error = 0 }
    }
    Mock Remove-CrLsaSecret {
        [void]$tcCalls.Add('LsaRemove:' + $Name)
        return @{ Success = $true; Win32Error = 0 }
    }

    $tcState = New-TestState -Computer 'IPT01-SITEA' -AutoLogon (New-TestAutoLogon -UserName 'BiCA Admin' -PlainPassword)
    $tcSecret = ConvertTo-SecureString 'Dummy-1a' -AsPlainText -Force

    Context 'Standardize' {
        It 'writes the LSA secret, deletes the plain-text values, sets user and domain, then AutoAdminLogon "1"' {
            $tcCalls = New-Object System.Collections.ArrayList
            $d = New-TestActionDecision 'Standardize' $SidPub 'PUB-User' $SidPub 'PUB-User'
            $r = Invoke-CrAutoLogonAction -Decision $d -State $tcState -Secret $tcSecret
            $r['Success'] | Should Be $true
            $r['Written'] | Should Be $true
            ($tcCalls -join '|') | Should Be ('LsaSet:DefaultPassword|Remove:DefaultPassword|Remove:AutoLogonCount|' +
                'Set:DefaultUserName=PUB-User:String|Set:DefaultDomainName=IPT01-SITEA:String|Set:AutoAdminLogon=1:String')
            ($r['Steps'] -join ',') | Should Be 'StoreLsaSecret,RemovePlainDefaultPassword,RemoveAutoLogonCount,DefaultUserName,DefaultDomainName,AutoAdminLogonOn'
            @($r['Pending']).Count | Should Be 0
            ($null -eq $r['FailedStep']) | Should Be $true
            ($tcCalls -contains 'Remove:AutoLogonSID') | Should Be $false
        }
    }

    Context 'passes the secret unchanged to Set-CrLsaSecret' {
        It 'passes the same SecureString object' {
            $tcCalls = New-Object System.Collections.ArrayList
            $d = New-TestActionDecision 'Standardize' $SidPub 'PUB-User' $SidPub 'PUB-User'
            $null = Invoke-CrAutoLogonAction -Decision $d -State $tcState -Secret $tcSecret
            Assert-MockCalled Set-CrLsaSecret -Times 1 -Exactly -ParameterFilter { $Name -eq 'DefaultPassword' -and [object]::ReferenceEquals($Secret, $tcSecret) }
            Assert-MockCalled Set-CrWinlogonValue -Times 0 -Exactly -ParameterFilter { $Name -eq 'DefaultPassword' }
        }
    }

    Context 'Switch' {
        It 'also deletes AutoLogonSID (spike 11 open) before AutoAdminLogon "1"' {
            $tcCalls = New-Object System.Collections.ArrayList
            $d = New-TestActionDecision 'Switch' $SidPub 'PUB-User' $SidBica 'BiCA Admin'
            $r = Invoke-CrAutoLogonAction -Decision $d -State $tcState -Secret $tcSecret
            $r['Success'] | Should Be $true
            ($tcCalls -join '|') | Should Be ('LsaSet:DefaultPassword|Remove:DefaultPassword|Remove:AutoLogonCount|' +
                'Set:DefaultUserName=PUB-User:String|Set:DefaultDomainName=IPT01-SITEA:String|Remove:AutoLogonSID|Set:AutoAdminLogon=1:String')
            @($r['Steps'])[5] | Should Be 'RemoveAutoLogonSID'
        }
    }

    Context 'Switch with a differently written target name' {
        It 'writes the account name from $State.Users (by SID)' {
            $tcCalls = New-Object System.Collections.ArrayList
            $d = New-TestActionDecision 'Switch' $SidPub 'pub-user' $SidBica 'BiCA Admin'
            $null = Invoke-CrAutoLogonAction -Decision $d -State $tcState -Secret $tcSecret
            ($tcCalls -contains 'Set:DefaultUserName=PUB-User:String') | Should Be $true
        }
    }

    Context 'Switch to a PUB-User created in this run (not yet in $State.Users)' {
        It 'writes the decision''s target name' {
            $tcCalls = New-Object System.Collections.ArrayList
            $d = New-TestActionDecision 'Switch' $null 'PUB-User' $SidBica 'BiCA Admin'
            $d['TargetCreated'] = $true
            $noPubState = New-TestState -Computer 'IPT01-SITEA' -Users (New-TestUsers -NoPub) -AutoLogon (New-TestAutoLogon -UserName 'BiCA Admin')
            $r = Invoke-CrAutoLogonAction -Decision $d -State $noPubState -Secret $tcSecret
            $r['Success'] | Should Be $true
            ($tcCalls -contains 'Set:DefaultUserName=PUB-User:String') | Should Be $true
            @($tcCalls)[$tcCalls.Count - 1] | Should Be 'Set:AutoAdminLogon=1:String'
        }
    }

    Context 'StandardizeCurrent (operator option)' {
        It 'standardizes the current account, not the switch target' {
            $tcCalls = New-Object System.Collections.ArrayList
            $d = New-TestActionDecision 'StandardizeCurrent' $SidPub 'PUB-User' $SidWinAuto 'WinAutoUser'
            $r = Invoke-CrAutoLogonAction -Decision $d -State $tcState -Secret $tcSecret
            $r['Success'] | Should Be $true
            ($tcCalls -contains 'Set:DefaultUserName=WinAutoUser:String') | Should Be $true
            ($tcCalls -contains 'Remove:AutoLogonSID') | Should Be $false
            @($tcCalls)[$tcCalls.Count - 1] | Should Be 'Set:AutoAdminLogon=1:String'
        }
    }

    Context 'TurnOff' {
        It 'sets AutoAdminLogon "0" first, then deletes the plain-text password, the LSA secret and the count, without a secret' {
            $tcCalls = New-Object System.Collections.ArrayList
            $d = New-TestActionDecision 'TurnOff' $null $null $SidBica 'BiCA Admin'
            $r = Invoke-CrAutoLogonAction -Decision $d -State $tcState -Secret $null
            $r['Success'] | Should Be $true
            ($tcCalls -join '|') | Should Be 'Set:AutoAdminLogon=0:String|Remove:DefaultPassword|LsaRemove:DefaultPassword|Remove:AutoLogonCount'
            ($r['Steps'] -join ',') | Should Be 'AutoAdminLogonOff,RemovePlainDefaultPassword,RemoveLsaSecret,RemoveAutoLogonCount'
            Assert-MockCalled Set-CrLsaSecret -Times 0 -Exactly
            Assert-MockCalled Set-CrWinlogonValue -Times 0 -Exactly -ParameterFilter { $Name -eq 'DefaultUserName' }
        }
    }

    Context 'TurnOff when the LSA secret does not exist' {
        It 'counts the missing secret (error 2) as deleted' {
            Mock Remove-CrLsaSecret {
                [void]$tcCalls.Add('LsaRemove:' + $Name)
                return @{ Success = $false; Win32Error = 2 }
            }
            $tcCalls = New-Object System.Collections.ArrayList
            $d = New-TestActionDecision 'TurnOff' $null $null $SidBica 'BiCA Admin'
            $r = Invoke-CrAutoLogonAction -Decision $d -State $tcState
            $r['Success'] | Should Be $true
            $tcCalls.Count | Should Be 4
        }
    }

    Context 'actions without a write' {
        It 'writes nothing for LeaveOff, NoChange, Ambiguous and LeaveUnchanged' {
            $tcCalls = New-Object System.Collections.ArrayList
            foreach ($a in @('LeaveOff', 'NoChange', 'Ambiguous', 'LeaveUnchanged')) {
                $d = New-TestActionDecision $a $SidPub 'PUB-User' $SidBica 'BiCA Admin'
                $r = Invoke-CrAutoLogonAction -Decision $d -State $tcState -Secret $tcSecret
                $r['Success'] | Should Be $true
                $r['Written'] | Should Be $false
                $r['Action'] | Should Be $a
                @($r['Steps']).Count | Should Be 0
            }
            $tcCalls.Count | Should Be 0
        }
    }

    Context 'failure mid-way (Standardize)' {
        It 'stops at the failing step and reports done and pending steps' {
            Mock Remove-CrWinlogonValue {
                [void]$tcCalls.Add('Remove:' + $Name)
                if ($Name -eq 'AutoLogonCount') { throw 'Access is denied' }
            }
            $tcCalls = New-Object System.Collections.ArrayList
            $d = New-TestActionDecision 'Standardize' $SidPub 'PUB-User' $SidPub 'PUB-User'
            $r = Invoke-CrAutoLogonAction -Decision $d -State $tcState -Secret $tcSecret
            $r['Success'] | Should Be $false
            $r['Written'] | Should Be $true
            $r['FailedStep'] | Should Be 'RemoveAutoLogonCount'
            $r['Error'] | Should Match 'Access is denied'
            ($r['Steps'] -join ',') | Should Be 'StoreLsaSecret,RemovePlainDefaultPassword'
            ($r['Pending'] -join ',') | Should Be 'RemoveAutoLogonCount,DefaultUserName,DefaultDomainName,AutoAdminLogonOn'
            ($tcCalls -join '|') | Should Be 'LsaSet:DefaultPassword|Remove:DefaultPassword|Remove:AutoLogonCount'
            Assert-MockCalled Set-CrWinlogonValue -Times 0 -Exactly
        }
    }

    Context 'the LSA secret cannot be stored' {
        It 'writes nothing else' {
            Mock Set-CrLsaSecret {
                [void]$tcCalls.Add('LsaSet:' + $Name)
                return @{ Success = $false; Win32Error = 5 }
            }
            $tcCalls = New-Object System.Collections.ArrayList
            $d = New-TestActionDecision 'Switch' $SidPub 'PUB-User' $SidBica 'BiCA Admin'
            $r = Invoke-CrAutoLogonAction -Decision $d -State $tcState -Secret $tcSecret
            $r['Success'] | Should Be $false
            $r['Written'] | Should Be $false
            $r['FailedStep'] | Should Be 'StoreLsaSecret'
            $r['Error'] | Should Match 'error 5'
            @($r['Steps']).Count | Should Be 0
            @($r['Pending']).Count | Should Be 7
            ($tcCalls -join '|') | Should Be 'LsaSet:DefaultPassword'
        }
    }

    Context 'TurnOff fails at the first step' {
        It 'deletes nothing' {
            Mock Set-CrWinlogonValue {
                [void]$tcCalls.Add(('Set:{0}={1}:{2}' -f $Name, $Value, $Kind))
                throw 'Access is denied'
            }
            $tcCalls = New-Object System.Collections.ArrayList
            $d = New-TestActionDecision 'TurnOff' $null $null $SidBica 'BiCA Admin'
            $r = Invoke-CrAutoLogonAction -Decision $d -State $tcState
            $r['Success'] | Should Be $false
            $r['FailedStep'] | Should Be 'AutoAdminLogonOff'
            ($r['Pending'] -join ',') | Should Be 'AutoAdminLogonOff,RemovePlainDefaultPassword,RemoveLsaSecret,RemoveAutoLogonCount'
            $tcCalls.Count | Should Be 1
            Assert-MockCalled Remove-CrLsaSecret -Times 0 -Exactly
            Assert-MockCalled Remove-CrWinlogonValue -Times 0 -Exactly
        }
    }

    Context 'TurnOff when the LSA secret cannot be deleted' {
        It 'stops before deleting AutoLogonCount' {
            Mock Remove-CrLsaSecret {
                [void]$tcCalls.Add('LsaRemove:' + $Name)
                return @{ Success = $false; Win32Error = 5 }
            }
            $tcCalls = New-Object System.Collections.ArrayList
            $d = New-TestActionDecision 'TurnOff' $null $null $SidBica 'BiCA Admin'
            $r = Invoke-CrAutoLogonAction -Decision $d -State $tcState
            $r['Success'] | Should Be $false
            $r['FailedStep'] | Should Be 'RemoveLsaSecret'
            ($r['Steps'] -join ',') | Should Be 'AutoAdminLogonOff,RemovePlainDefaultPassword'
            ($r['Pending'] -join ',') | Should Be 'RemoveLsaSecret,RemoveAutoLogonCount'
            ($tcCalls -contains 'Remove:AutoLogonCount') | Should Be $false
        }
    }

    Context 'Standardize or Switch without a secret' {
        It 'writes nothing and fails' {
            $tcCalls = New-Object System.Collections.ArrayList
            foreach ($a in @('Standardize', 'Switch', 'StandardizeCurrent')) {
                $d = New-TestActionDecision $a $SidPub 'PUB-User' $SidPub 'PUB-User'
                $r = Invoke-CrAutoLogonAction -Decision $d -State $tcState -Secret $null
                $r['Success'] | Should Be $false
                $r['Error'] | Should Match 'secret'
            }
            $tcCalls.Count | Should Be 0
        }
    }

    Context 'unknown action or missing decision' {
        It 'writes nothing and fails' {
            $tcCalls = New-Object System.Collections.ArrayList
            $r = Invoke-CrAutoLogonAction -Decision (New-TestActionDecision 'Enable' $SidPub 'PUB-User' $null $null) -State $tcState -Secret $tcSecret
            $r['Success'] | Should Be $false
            $r['Error'] | Should Match 'Unknown'
            $r2 = Invoke-CrAutoLogonAction -Decision $null -State $tcState -Secret $tcSecret
            $r2['Success'] | Should Be $false
            $tcCalls.Count | Should Be 0
        }
    }

    Context 'target unknown' {
        It 'writes nothing when neither the SID nor the name gives an account' {
            $tcCalls = New-Object System.Collections.ArrayList
            $d = New-TestActionDecision 'Switch' 'S-1-5-21-1000-2000-3000-1999' '' $SidBica 'BiCA Admin'
            $r = Invoke-CrAutoLogonAction -Decision $d -State $tcState -Secret $tcSecret
            $r['Success'] | Should Be $false
            $tcCalls.Count | Should Be 0
        }
    }
}

Describe 'Set-CrWinlogonValue (argument checks only, no registry access)' {
    It 'refuses to write DefaultPassword before opening the key' {
        { & $tcRealSetWinlogonValue -Name 'DefaultPassword' -Value 'x' -Kind 'String' } | Should Throw 'never written'
    }
    It 'refuses an empty name' {
        { & $tcRealSetWinlogonValue -Name '' -Value '1' -Kind 'String' } | Should Throw
    }
}
