# Pester 3.4 tests for src\lib\Native.ps1. Unit tests mock the native layer; 'Integration' tests only read.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here '..\src\lib\Compat.ps1')
. (Join-Path $here '..\src\lib\Native.ps1')

$crExpectedRights = @(
    'SeNetworkLogonRight', 'SeInteractiveLogonRight', 'SeRemoteInteractiveLogonRight',
    'SeBatchLogonRight', 'SeServiceLogonRight',
    'SeDenyNetworkLogonRight', 'SeDenyInteractiveLogonRight', 'SeDenyRemoteInteractiveLogonRight',
    'SeDenyBatchLogonRight', 'SeDenyServiceLogonRight'
)

Describe 'Get-CrNativeSource' {
    $src = Get-CrNativeSource

    It 'defines the Cr-prefixed static classes without a namespace' {
        $src | Should Match 'public static class CrNativeLsa'
        $src | Should Match 'public static class CrNativeNet'
        $src | Should Not Match '(?m)^\s*namespace\s'
    }

    It 'uses no C# 3+ constructs (var, lambdas, auto-properties)' {
        $src | Should Not Match '\bvar\s+\w+\s*='
        $src | Should Not Match '=>'
        $src | Should Not Match '\{\s*get;\s*set;\s*\}'
        $src | Should Not Match 'using System\.Linq'
    }

    It 'has no write API in M1' {
        $src | Should Not Match 'NetLocalGroupAddMembers|NetLocalGroupDelMembers|LsaAddAccountRights|LsaRemoveAccountRights'
    }
}

Describe 'Initialize-CrNative' {
    Context 'never throws and records the compile error' {
        It 'never throws and records the compile error' {
            Mock Test-CrNativeTypeLoaded { $false }
            Mock Add-Type { throw 'compile failed' }
            $script:CrNativeReady = $null
            $script:CrNativeError = $null
            { Initialize-CrNative } | Should Not Throw
            Test-CrNativeReady | Should Be $false
            $script:CrNativeError | Should Be 'compile failed'
        }
    }

    Context 'makes the wrappers throw with the compile error when not ready' {
        It 'makes the wrappers throw with the compile error when not ready' {
            Mock Test-CrNativeTypeLoaded { $false }
            Mock Add-Type { throw 'compile failed' }
            $script:CrNativeReady = $null
            { Get-CrMachineSid } | Should Throw 'compile failed'
        }
    }

    It 'compiles the real source and is idempotent' {
        $script:CrNativeReady = $null
        Initialize-CrNative
        Test-CrNativeReady | Should Be $true
        $script:CrNativeError | Should BeNullOrEmpty
        Initialize-CrNative
        Test-CrNativeReady | Should Be $true
        ('CrNativeLsa' -as [type]) | Should Not BeNullOrEmpty
        ('CrNativeNet' -as [type]) | Should Not BeNullOrEmpty
    }
}

Describe 'Get-CrLsaRightNames' {
    It 'lists exactly the ten contract rights' {
        $names = Get-CrLsaRightNames
        $names.Count | Should Be 10
        (@($names | Sort-Object) -join ',') | Should Be (@($crExpectedRights | Sort-Object) -join ',')
    }
}

Describe 'Get-CrLsaRightsMap' {
    Mock Assert-CrNativeReady { }

    Context 'returns all ten rights with SID arrays, empty when nobody holds a right' {
        It 'returns all ten rights with SID arrays, empty when nobody holds a right' {
            Mock Get-CrLsaAccountsWithRight {
                if ($Right -eq 'SeServiceLogonRight') { return , @('S-1-5-21-1000-2000-3000-1001', 'S-1-5-80-0') }
                if ($Right -eq 'SeDenyInteractiveLogonRight') { return 'S-1-5-21-1000-2000-3000-1002' }
                return , @()
            }
            $map = Get-CrLsaRightsMap
            $map.Count | Should Be 10
            foreach ($r in $crExpectedRights) {
                $map.ContainsKey($r) | Should Be $true
                ($map[$r] -is [array]) | Should Be $true
            }
            $map['SeServiceLogonRight'].Count | Should Be 2
            $map['SeServiceLogonRight'][0] | Should Be 'S-1-5-21-1000-2000-3000-1001'
            $map['SeDenyInteractiveLogonRight'].Count | Should Be 1
            $map['SeDenyInteractiveLogonRight'][0] | Should Be 'S-1-5-21-1000-2000-3000-1002'
            $map['SeNetworkLogonRight'].Count | Should Be 0
            Assert-MockCalled Get-CrLsaAccountsWithRight -Times 10 -Exactly
        }
    }

    Context 'throws when a right cannot be read' {
        It 'throws when a right cannot be read' {
            Mock Get-CrLsaAccountsWithRight {
                if ($Right -eq 'SeBatchLogonRight') { throw 'Access is denied' }
                return , @()
            }
            { Get-CrLsaRightsMap } | Should Throw 'Access is denied'
        }
    }
}

Describe 'Get-CrUserModals' {
    Context 'maps the raw values to the contract keys' {
        It 'maps the raw values to the contract keys' {
            Mock Get-CrUserModalsRaw { return , @([long]8, [long]7776000, [long]86400, [long]24, [long]900, [long]1800, [long]10) }
            $m = Get-CrUserModals
            $m['MinPasswordLength'] | Should Be 8
            $m['MaxPasswordAgeSeconds'] | Should Be 7776000
            $m['MinPasswordAgeSeconds'] | Should Be 86400
            $m['PasswordHistoryLength'] | Should Be 24
            $m['LockoutDurationSeconds'] | Should Be 900
            $m['LockoutObservationSeconds'] | Should Be 1800
            $m['LockoutThreshold'] | Should Be 10
            $m.Count | Should Be 7
            ($m['MinPasswordLength'] -is [int]) | Should Be $true
            ($m['MaxPasswordAgeSeconds'] -is [long]) | Should Be $true
        }
    }

    Context 'maps TIMEQ_FOREVER to -1' {
        It 'maps TIMEQ_FOREVER to -1' {
            Mock Get-CrUserModalsRaw { return , @([long]0, [long]4294967295, [long]0, [long]0, [long]4294967295, [long]0, [long]0) }
            $m = Get-CrUserModals
            $m['MaxPasswordAgeSeconds'] | Should Be -1
            $m['LockoutDurationSeconds'] | Should Be -1
            $m['LockoutThreshold'] | Should Be 0
        }
    }

    Context 'throws on an unexpected number of values' {
        It 'throws on an unexpected number of values' {
            Mock Get-CrUserModalsRaw { return , @([long]1, [long]2) }
            { Get-CrUserModals } | Should Throw
        }
    }
}

Describe 'Native (integration, read-only)' -Tags 'Integration' {
    Initialize-CrNative
    $principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
    $isElevated = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

    It 'compiles on this host' {
        Test-CrNativeReady | Should Be $true
    }

    It 'reads the machine SID' {
        Get-CrMachineSid | Should Match '^S-1-5-21-\d+-\d+-\d+$'
    }

    It 'reads the user modals' {
        $m = Get-CrUserModals
        $m.Count | Should Be 7
        ($m['MinPasswordLength'] -ge 0) | Should Be $true
        ($m['MaxPasswordAgeSeconds'] -ge -1) | Should Be $true
    }

    It 'enumerates local groups and the Administrators members by SID' {
        $names = Get-CrLocalGroupNames
        ($names -is [array]) | Should Be $true
        ($names.Count -gt 0) | Should Be $true
        $admName = (Resolve-CrSidToName 'S-1-5-32-544').Split('\')[1]
        ($names -contains $admName) | Should Be $true
        $sids = Get-CrLocalGroupMemberSids -GroupName $admName
        ($sids -is [array]) | Should Be $true
        foreach ($s in $sids) { $s | Should Match '^S-1-\d+(-\d+)+$' }
    }

    It 'throws for a missing group' {
        { Get-CrLocalGroupMemberSids -GroupName 'CrNoSuchGroup-7f3a' } | Should Throw '2220'
    }

    It 'reads all ten rights (elevated only)' -Skip:(-not $isElevated) {
        $map = Get-CrLsaRightsMap
        $map.Count | Should Be 10
        foreach ($r in $crExpectedRights) {
            ($map[$r] -is [array]) | Should Be $true
            foreach ($s in $map[$r]) { $s | Should Match '^S-1-\d+(-\d+)+$' }
        }
    }
}
