$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here '..\src\lib\Compat.ps1')
. (Join-Path $here '..\src\lib\Rights.ps1')
. (Join-Path $here 'Fixtures.ps1')

# Get-CrTokenSids returns a comma-wrapped array: assign directly, never wrap the call in @().

Describe 'Get-CrTokenSids' {
    $ipt = New-CrTestState -Profile 'IPT01'
    $pub = Get-CrTestUserSid $ipt 'PUB-User'
    $bicaAdmin = Get-CrTestUserSid $ipt 'BiCA Admin'

    It 'contains the account, Everyone, Authenticated Users, Local account and Users (via Authenticated Users)' {
        $token = Get-CrTokenSids -UserSid $pub -State $ipt -LogonType 'Network'
        foreach ($sid in @($pub, 'S-1-1-0', 'S-1-5-11', 'S-1-5-113', 'S-1-5-32-545', 'S-1-5-2')) {
            ($token -contains $sid) | Should Be $true
        }
        ($token -contains 'S-1-5-32-544') | Should Be $false
        ($token -contains 'S-1-5-114') | Should Be $false
    }

    It 'adds Administrators and S-1-5-114 for an admin' {
        $token = Get-CrTokenSids -UserSid $bicaAdmin -State $ipt -LogonType 'Network'
        ($token -contains 'S-1-5-32-544') | Should Be $true
        ($token -contains 'S-1-5-114') | Should Be $true
    }

    It 'puts LOCAL (S-1-2-0) only into interactive-type tokens' {
        (Get-CrTokenSids -UserSid $pub -State $ipt -LogonType 'Network') -contains 'S-1-2-0' | Should Be $false
        (Get-CrTokenSids -UserSid $pub -State $ipt -LogonType 'Batch') -contains 'S-1-2-0' | Should Be $false
        (Get-CrTokenSids -UserSid $pub -State $ipt -LogonType 'Service') -contains 'S-1-2-0' | Should Be $false
        $interactive = Get-CrTokenSids -UserSid $pub -State $ipt -LogonType 'Interactive'
        ($interactive -contains 'S-1-2-0') | Should Be $true
        ($interactive -contains 'S-1-2-1') | Should Be $true
        ($interactive -contains 'S-1-5-4') | Should Be $true
        $remote = Get-CrTokenSids -UserSid $pub -State $ipt -LogonType 'RemoteInteractive'
        ($remote -contains 'S-1-2-0') | Should Be $true
        ($remote -contains 'S-1-5-14') | Should Be $true
    }

    It 'uses the logon-type SID of the evaluated type only' {
        $batch = Get-CrTokenSids -UserSid $pub -State $ipt -LogonType 'Batch'
        ($batch -contains 'S-1-5-3') | Should Be $true
        ($batch -contains 'S-1-5-2') | Should Be $false
        ($batch -contains 'S-1-5-4') | Should Be $false
        (Get-CrTokenSids -UserSid $pub -State $ipt -LogonType 'Service') -contains 'S-1-5-6' | Should Be $true
    }

    It 'adds a group that contains a well-known SID of this logon type only' {
        $s = New-CrTestState -Profile 'IPT01'
        [void](Add-CrTestGroup -State $s -Name 'Kiosk' -Sid 'S-1-5-21-1000-2000-4000-1200' -MemberSids @('S-1-5-4'))
        (Get-CrTokenSids -UserSid $pub -State $s -LogonType 'Interactive') -contains 'S-1-5-21-1000-2000-4000-1200' | Should Be $true
        (Get-CrTokenSids -UserSid $pub -State $s -LogonType 'Network') -contains 'S-1-5-21-1000-2000-4000-1200' | Should Be $false
    }

    It 'iterates until no new group is added' {
        $s = New-CrTestState -Profile 'IPT01'
        # declared in reverse order so a single pass would miss the chain
        [void](Add-CrTestGroup -State $s -Name 'Outer' -Sid 'S-1-5-21-1000-2000-4000-1202' -MemberSids @('S-1-5-21-1000-2000-4000-1201'))
        [void](Add-CrTestGroup -State $s -Name 'Inner' -Sid 'S-1-5-21-1000-2000-4000-1201' -MemberSids @('S-1-5-11'))
        $token = Get-CrTokenSids -UserSid $pub -State $s -LogonType 'Network'
        ($token -contains 'S-1-5-21-1000-2000-4000-1201') | Should Be $true
        ($token -contains 'S-1-5-21-1000-2000-4000-1202') | Should Be $true
    }

    It 'throws for an unknown logon type' {
        { Get-CrTokenSids -UserSid $pub -State $ipt -LogonType 'Unlock' } | Should Throw
    }
}

Describe 'Get-CrEffectiveLogonRights with the SM deny rights' {
    $sm = New-CrTestState -Profile 'SM'

    It 'BiCA Remote: denied local logon and service, RDP allowed' {
        $r = Get-CrEffectiveLogonRights -UserSid (Get-CrTestUserSid $sm 'BiCA Remote') -State $sm
        $r.Network | Should Be $true
        $r.Interactive | Should Be $false
        $r.RemoteInteractive | Should Be $true
        $r.Batch | Should Be $true
        $r.Service | Should Be $false
    }

    It 'ApplicationUser: denied local logon and RDP, holds batch and service' {
        $r = Get-CrEffectiveLogonRights -UserSid (Get-CrTestUserSid $sm 'ApplicationUser') -State $sm
        $r.Network | Should Be $true
        $r.Interactive | Should Be $false
        $r.RemoteInteractive | Should Be $false
        $r.Batch | Should Be $true
        $r.Service | Should Be $true
    }

    It 'BiCA Admin: denied RDP only' {
        $r = Get-CrEffectiveLogonRights -UserSid (Get-CrTestUserSid $sm 'BiCA Admin') -State $sm
        $r.Interactive | Should Be $true
        $r.RemoteInteractive | Should Be $false
    }

    It 'WinUser1: RDP through Remote Desktop Users' {
        $r = Get-CrEffectiveLogonRights -UserSid (Get-CrTestUserSid $sm 'WinUser1') -State $sm
        $r.RemoteInteractive | Should Be $true
        (Get-CrEffectiveLogonRights -UserSid (Get-CrTestUserSid $sm 'WinUser2') -State $sm).RemoteInteractive | Should Be $false
    }

    It 'a deny on a group wins over a grant to the account' {
        $s = New-CrTestState -Profile 'SM'
        $sid = Get-CrTestUserSid $s 'WinUser2'
        Add-CrTestRight -State $s -Right 'SeBatchLogonRight' -Sids @($sid)
        Add-CrTestRight -State $s -Right 'SeDenyBatchLogonRight' -Sids @('S-1-5-32-547')
        (Get-CrEffectiveLogonRights -UserSid $sid -State $s).Batch | Should Be $false
    }

    It 'returns all five keys' {
        $r = Get-CrEffectiveLogonRights -UserSid (Get-CrTestUserSid $sm 'WinAutoUser') -State $sm
        $r.Count | Should Be 5
    }
}

Describe 'Select-CrProbeLogonType (D16)' {

    It 'BiCA Remote (denied local logon): Network' {
        $sm = New-CrTestState -Profile 'SM'
        $p = Select-CrProbeLogonType -UserSid (Get-CrTestUserSid $sm 'BiCA Remote') -State $sm
        $p.LogonType | Should Be 'Network'
        $p.Fallback | Should Be $false
    }

    It 'BiCA Remote on IPT01 (denied local, batch and service): Network' {
        $ipt = New-CrTestState -Profile 'IPT01'
        $p = Select-CrProbeLogonType -UserSid (Get-CrTestUserSid $ipt 'BiCA Remote') -State $ipt
        $p.LogonType | Should Be 'Network'
        $p.Fallback | Should Be $false
    }

    It 'PUB-User on an IPT01 where network logon is only granted to Administrators and Remote Desktop Users: Interactive' {
        $ipt = New-CrTestState -Profile 'IPT01'
        Set-CrTestRight -State $ipt -Right 'SeNetworkLogonRight' -Sids @('S-1-5-32-544', 'S-1-5-32-555')
        $p = Select-CrProbeLogonType -UserSid (Get-CrTestUserSid $ipt 'PUB-User') -State $ipt
        $p.LogonType | Should Be 'Interactive'
        $p.Fallback | Should Be $false
    }

    It 'the same, but Authenticated Users in Remote Desktop Users: Network' {
        $ipt = New-CrTestState -Profile 'IPT01'
        Set-CrTestRight -State $ipt -Right 'SeNetworkLogonRight' -Sids @('S-1-5-32-544', 'S-1-5-32-555')
        Add-CrTestGroupMember -State $ipt -Group 'Remote Desktop Users' -MemberSids @('S-1-5-11')
        $p = Select-CrProbeLogonType -UserSid (Get-CrTestUserSid $ipt 'PUB-User') -State $ipt
        $p.LogonType | Should Be 'Network'
    }

    It 'ApplicationUser denied network, local and batch logon (batch is granted via Administrators): Service' {
        $ipt = New-CrTestState -Profile 'IPT01'
        $sid = Get-CrTestUserSid $ipt 'ApplicationUser'
        Add-CrTestRight -State $ipt -Right 'SeDenyNetworkLogonRight' -Sids @($sid)
        (Select-CrProbeLogonType -UserSid $sid -State $ipt).LogonType | Should Be 'Batch'
        Add-CrTestRight -State $ipt -Right 'SeDenyBatchLogonRight' -Sids @($sid)
        $p = Select-CrProbeLogonType -UserSid $sid -State $ipt
        $p.LogonType | Should Be 'Service'
        $p.Fallback | Should Be $false
    }

    It 'WinAutoUser denied network and local logon, no batch or service right: fallback to Network' {
        $sm = New-CrTestState -Profile 'SM'
        $sid = Get-CrTestUserSid $sm 'WinAutoUser'
        Add-CrTestRight -State $sm -Right 'SeDenyNetworkLogonRight' -Sids @($sid)
        $p = Select-CrProbeLogonType -UserSid $sid -State $sm
        $p.LogonType | Should Be 'Network'
        $p.Fallback | Should Be $true
    }

    It 'never probes RemoteInteractive' {
        $ipt = New-CrTestState -Profile 'IPT01'
        $sid = Get-CrTestUserSid $ipt 'BiCA Remote'
        Add-CrTestRight -State $ipt -Right 'SeDenyNetworkLogonRight' -Sids @($sid)
        (Get-CrEffectiveLogonRights -UserSid $sid -State $ipt).RemoteInteractive | Should Be $true
        $p = Select-CrProbeLogonType -UserSid $sid -State $ipt
        $p.LogonType | Should Be 'Network'
        $p.Fallback | Should Be $true
    }

    It 'falls back when the Rights part failed' {
        $s = New-CrTestState -Profile 'SM' -Parts @{ Rights = @{ Error = 'LSA unavailable' } }
        $p = Select-CrProbeLogonType -UserSid (Get-CrTestUserSid $s 'BiCA Admin') -State $s
        $p.LogonType | Should Be 'Network'
        $p.Fallback | Should Be $true
    }

    It 'follows the order Network, Interactive, Batch, Service' {
        Mock Get-CrEffectiveLogonRights { @{ Network = $false; Interactive = $false; RemoteInteractive = $true; Batch = $true; Service = $true } }
        $p = Select-CrProbeLogonType -UserSid 'S-1-5-21-1000-2000-3000-1999' -State @{}
        $p.LogonType | Should Be 'Batch'
        Assert-MockCalled Get-CrEffectiveLogonRights -Times 1 -Exactly
    }
}

Describe 'Test-CrIsAdmin' {
    $sm = New-CrTestState -Profile 'SM'

    It 'is true for members of Administrators' {
        Test-CrIsAdmin -UserSid (Get-CrTestUserSid $sm 'BiCA Admin') -State $sm | Should Be $true
        Test-CrIsAdmin -UserSid (Get-CrTestUserSid $sm 'OtherAdmin') -State $sm | Should Be $true
    }

    It 'counts the (disabled, renamed) built-in Administrator' {
        Test-CrIsAdmin -UserSid ($sm.Computer.MachineSid + '-500') -State $sm | Should Be $true
    }

    It 'is false for standard users' {
        Test-CrIsAdmin -UserSid (Get-CrTestUserSid $sm 'WinAutoUser') -State $sm | Should Be $false
        Test-CrIsAdmin -UserSid (Get-CrTestUserSid $sm 'WinUser1') -State $sm | Should Be $false
    }

    It 'detects an admin PUB-User' {
        $ipt = New-CrTestState -Profile 'IPT01'
        $sid = Get-CrTestUserSid $ipt 'PUB-User'
        Add-CrTestGroupMember -State $ipt -Group 'S-1-5-32-544' -MemberSids @($sid)
        Test-CrIsAdmin -UserSid $sid -State $ipt | Should Be $true
    }

    It 'is false when the Groups part failed' {
        $s = New-CrTestState -Profile 'SM' -Parts @{ Groups = @{ Error = 'netapi32 failed' } }
        Test-CrIsAdmin -UserSid (Get-CrTestUserSid $s 'BiCA Admin') -State $s | Should Be $false
    }
}
