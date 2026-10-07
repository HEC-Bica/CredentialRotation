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

    # M1 had "no write API at all"; since M2 only these two limits remain (PLAN 7.3, CONTRACTS D4).
    It 'never removes rights and never reads LSA secrets' {
        $src | Should Not Match 'LsaRemoveAccountRights|LsaRetrievePrivateData|LsaOpenSecret|LsaQuerySecret'
    }

    It 'defines the M2 write classes' {
        $src | Should Match 'public static class CrNativeSecret'
        $src | Should Match 'public static class CrNativeAcct'
        $src | Should Match 'public static class CrNativeSvc'
    }

    It 'creates users only through NetUserAdd level 1 and never deletes accounts' {
        $src | Should Match 'NetUserAdd\(null, 1, ref info'
        $src | Should Match 'info\.usri1_password = bstr;'
        $src | Should Match 'info\.usri1_password = IntPtr\.Zero;'
        $src | Should Not Match 'NetUserDel'
    }

    It 'uses no C# 3 object or collection initializers' {
        $src | Should Not Match 'new\s+\w+\s*(\(\s*\))?\s*\{\s*\w+\s*='
    }

    It 'never turns a secret into a managed string' {
        $src | Should Not Match 'PtrToStringBSTR|PtrToStringAuto|SecureStringToGlobalAlloc|PtrToStringUni\(\s*(bstr|oldBstr|newBstr|password)'
        # secrets reach C# as IntPtr only
        $src | Should Not Match 'string\s+(password|oldPassword|newPassword|secret|bstr|oldBstr|newBstr)\s*[,)]'
    }
}

Describe 'Native.ps1 BSTR boundary' {
    $crNativeText = [System.IO.File]::ReadAllText((Join-Path $here '..\src\lib\Native.ps1'))

    It 'converts SecureStrings to BSTRs and zero-frees them in exactly one place each' {
        ([regex]::Matches($crNativeText, 'SecureStringToBSTR')).Count | Should Be 1
        ([regex]::Matches($crNativeText, 'ZeroFreeBSTR')).Count | Should Be 1
        $crNativeText | Should Not Match 'PtrToStringBSTR|PtrToStringAuto|SecureStringToGlobalAlloc'
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

# ---------------------------------------------------------------------------------------------------------------------
# M2/M3 write side. Unit tests mock Assert-CrNativeReady, ConvertTo-CrBstr / Clear-CrBstr and the call layer
# (Invoke-CrNative* etc.), so nothing touches the system. Fake BSTR pointers are 1000 + the secret's length.
# ---------------------------------------------------------------------------------------------------------------------

# Synthetic SecureString from a dummy literal (never a real password).
function New-CrTestSecureString {
    param([string]$Text)
    $s = New-Object System.Security.SecureString
    foreach ($c in $Text.ToCharArray()) { $s.AppendChar($c) }
    $s.MakeReadOnly()
    return $s
}

$crOld = New-CrTestSecureString 'Old-Dummy1'      # 10 chars -> fake pointer 1010
$crNew = New-CrTestSecureString 'New-Dummy-22'    # 12 chars -> fake pointer 1012
$crTestSid = 'S-1-5-21-1000-2000-3000-1001'

# Every public write wrapper, called with valid arguments.
$crWrapperCalls = @(
    @{ Name = 'Test-CrSecretEqual'; Call = { Test-CrSecretEqual -A $crOld -B $crNew } },
    @{ Name = 'Get-CrSecretLength'; Call = { Get-CrSecretLength -Secret $crNew } },
    @{ Name = 'Test-CrSecretComplexity'; Call = { Test-CrSecretComplexity -Secret $crNew -MinLength 8 -RequireComplexity $true -Tokens @('crtest') } },
    @{ Name = 'Test-CrLocalPasswordPolicy'; Call = { Test-CrLocalPasswordPolicy -UserName 'CrTestUser' -Secret $crNew } },
    @{ Name = 'Invoke-CrLogonTest'; Call = { Invoke-CrLogonTest -UserName 'CrTestUser' -Secret $crNew -LogonType 'Network' } },
    @{ Name = 'Get-CrUserInfo'; Call = { Get-CrUserInfo -UserName 'CrTestUser' } },
    @{ Name = 'Set-CrUserFlags'; Call = { Set-CrUserFlags -UserName 'CrTestUser' -Flags 0x10201 } },
    @{ Name = 'Invoke-CrNetPasswordChange'; Call = { Invoke-CrNetPasswordChange -UserName 'CrTestUser' -OldSecret $crOld -NewSecret $crNew } },
    @{ Name = 'Invoke-CrNetPasswordReset'; Call = { Invoke-CrNetPasswordReset -UserName 'CrTestUser' -NewSecret $crNew } },
    @{ Name = 'New-CrLocalUser'; Call = { New-CrLocalUser -UserName 'CrTestUser' -Secret $crNew -Comment 'Test comment' } },
    @{ Name = 'Add-CrLocalGroupMemberSid'; Call = { Add-CrLocalGroupMemberSid -GroupName 'CrTestGroup' -MemberSid $crTestSid } },
    @{ Name = 'Remove-CrLocalGroupMemberSid'; Call = { Remove-CrLocalGroupMemberSid -GroupName 'CrTestGroup' -MemberSid $crTestSid } },
    @{ Name = 'Grant-CrAccountRight'; Call = { Grant-CrAccountRight -Sid $crTestSid -Right 'SeBatchLogonRight' } },
    @{ Name = 'Set-CrLsaSecret'; Call = { Set-CrLsaSecret -Name 'CrTestKey' -Secret $crNew } },
    @{ Name = 'Remove-CrLsaSecret'; Call = { Remove-CrLsaSecret -Name 'CrTestKey' } },
    @{ Name = 'Set-CrServiceLogonPassword'; Call = { Set-CrServiceLogonPassword -ServiceName 'CrTestSvc' -Account '.\CrTestUser' -Secret $crNew } }
)

Describe 'Write wrappers refuse when the native helpers are not ready' {
    foreach ($crCase in $crWrapperCalls) {
        Context ($crCase.Name) {
            Mock Test-CrNativeTypeLoaded { $false }
            Mock Add-Type { throw 'compile failed' }
            Mock ConvertTo-CrBstr { [IntPtr]1 }
            It ('{0} throws with the compile error and allocates no BSTR' -f $crCase.Name) {
                $script:CrNativeReady = $null
                $call = $crCase.Call
                { & $call } | Should Throw 'compile failed'
                Assert-MockCalled ConvertTo-CrBstr -Times 0 -Exactly
            }
        }
    }
}

# Wrappers that take secrets: layer = the mocked call-layer function, Freed = one filter per expected BSTR.
$crBstrCases = @(
    @{ Name = 'Test-CrSecretEqual'; Layer = 'Invoke-CrNativeSecretEqual'; Result = { $true }
       Call = { Test-CrSecretEqual -A $crOld -B $crNew }
       Passed = { ($PointerA -eq [IntPtr]1010) -and ($PointerB -eq [IntPtr]1012) }
       Freed = @({ $Pointer -eq [IntPtr]1010 }, { $Pointer -eq [IntPtr]1012 }) },
    @{ Name = 'Get-CrSecretLength'; Layer = 'Get-CrNativeSecretLength'; Result = { 12 }
       Call = { Get-CrSecretLength -Secret $crNew }
       Passed = { $Pointer -eq [IntPtr]1012 }
       Freed = @({ $Pointer -eq [IntPtr]1012 }) },
    @{ Name = 'Test-CrSecretComplexity'; Layer = 'Invoke-CrNativeSecretComplexity'; Result = { return , @(12, 15, 0) }
       Call = { Test-CrSecretComplexity -Secret $crNew -MinLength 8 -RequireComplexity $true -Tokens @('crtest') }
       Passed = { $Pointer -eq [IntPtr]1012 }
       Freed = @({ $Pointer -eq [IntPtr]1012 }) },
    @{ Name = 'Test-CrLocalPasswordPolicy'; Layer = 'Invoke-CrNativeValidatePassword'; Result = { return , @(0, 0) }
       Call = { Test-CrLocalPasswordPolicy -UserName 'CrTestUser' -Secret $crNew }
       Passed = { ($Pointer -eq [IntPtr]1012) -and ($UserName -eq 'CrTestUser') }
       Freed = @({ $Pointer -eq [IntPtr]1012 }) },
    @{ Name = 'Invoke-CrLogonTest'; Layer = 'Invoke-CrNativeLogonUser'; Result = { 0 }
       Call = { Invoke-CrLogonTest -UserName 'CrTestUser' -Secret $crNew -LogonType 'Network' }
       Passed = { ($Pointer -eq [IntPtr]1012) -and ($UserName -eq 'CrTestUser') -and ($LogonType -eq 3) }
       Freed = @({ $Pointer -eq [IntPtr]1012 }) },
    @{ Name = 'Invoke-CrNetPasswordChange'; Layer = 'Invoke-CrNativeChangePassword'; Result = { 0 }
       Call = { Invoke-CrNetPasswordChange -UserName 'CrTestUser' -OldSecret $crOld -NewSecret $crNew }
       Passed = { ($OldPointer -eq [IntPtr]1010) -and ($NewPointer -eq [IntPtr]1012) -and ($UserName -eq 'CrTestUser') }
       Freed = @({ $Pointer -eq [IntPtr]1010 }, { $Pointer -eq [IntPtr]1012 }) },
    @{ Name = 'Invoke-CrNetPasswordReset'; Layer = 'Invoke-CrNativeResetPassword'; Result = { 0 }
       Call = { Invoke-CrNetPasswordReset -UserName 'CrTestUser' -NewSecret $crNew }
       Passed = { ($Pointer -eq [IntPtr]1012) -and ($UserName -eq 'CrTestUser') }
       Freed = @({ $Pointer -eq [IntPtr]1012 }) },
    @{ Name = 'New-CrLocalUser'; Layer = 'Add-CrNativeUser'; Result = { 0 }
       Call = { New-CrLocalUser -UserName 'CrTestUser' -Secret $crNew -Comment 'Test comment' }
       Passed = { ($Pointer -eq [IntPtr]1012) -and ($UserName -eq 'CrTestUser') -and ($Comment -eq 'Test comment') }
       Freed = @({ $Pointer -eq [IntPtr]1012 }) },
    @{ Name = 'Set-CrLsaSecret'; Layer = 'Set-CrNativeLsaPrivateData'; Result = { 0 }
       Call = { Set-CrLsaSecret -Name 'CrTestKey' -Secret $crNew }
       Passed = { ($Pointer -eq [IntPtr]1012) -and ($Name -eq 'CrTestKey') }
       Freed = @({ $Pointer -eq [IntPtr]1012 }) },
    @{ Name = 'Set-CrServiceLogonPassword'; Layer = 'Set-CrNativeServiceLogon'; Result = { 0 }
       Call = { Set-CrServiceLogonPassword -ServiceName 'CrTestSvc' -Account '.\CrTestUser' -Secret $crNew }
       Passed = { ($Pointer -eq [IntPtr]1012) -and ($ServiceName -eq 'CrTestSvc') -and ($Account -eq '.\CrTestUser') }
       Freed = @({ $Pointer -eq [IntPtr]1012 }) }
)

Describe 'Write wrappers always zero-free their BSTRs' {
    foreach ($crCase in $crBstrCases) {
        Context ('{0} on success' -f $crCase.Name) {
            Mock Assert-CrNativeReady { }
            Mock ConvertTo-CrBstr { [IntPtr](1000 + $Secret.Length) }
            Mock Clear-CrBstr { }
            Mock -CommandName $crCase.Layer -MockWith $crCase.Result
            It ('{0} passes the BSTR to the native layer and frees each one once' -f $crCase.Name) {
                $call = $crCase.Call
                $null = & $call
                Assert-MockCalled -CommandName $crCase.Layer -Times 1 -Exactly -ParameterFilter $crCase.Passed
                foreach ($filter in $crCase.Freed) {
                    Assert-MockCalled Clear-CrBstr -Times 1 -Exactly -ParameterFilter $filter
                }
                Assert-MockCalled Clear-CrBstr -Times $crCase.Freed.Count -Exactly
                Assert-MockCalled ConvertTo-CrBstr -Times $crCase.Freed.Count -Exactly
            }
        }

        Context ('{0} when the native layer throws' -f $crCase.Name) {
            Mock Assert-CrNativeReady { }
            Mock ConvertTo-CrBstr { [IntPtr](1000 + $Secret.Length) }
            Mock Clear-CrBstr { }
            Mock -CommandName $crCase.Layer -MockWith { throw 'native boom' }
            It ('{0} rethrows and still frees every BSTR' -f $crCase.Name) {
                $call = $crCase.Call
                { & $call } | Should Throw 'native boom'
                foreach ($filter in $crCase.Freed) {
                    Assert-MockCalled Clear-CrBstr -Times 1 -Exactly -ParameterFilter $filter
                }
            }
        }
    }

    Context 'Invoke-CrNetPasswordChange when the second conversion fails' {
        Mock Assert-CrNativeReady { }
        Mock ConvertTo-CrBstr {
            if ($Secret.Length -eq 12) { throw 'alloc failed' }
            [IntPtr](1000 + $Secret.Length)
        }
        Mock Clear-CrBstr { }
        Mock Invoke-CrNativeChangePassword { 0 }
        It 'frees the first BSTR and never calls the native layer' {
            { Invoke-CrNetPasswordChange -UserName 'CrTestUser' -OldSecret $crOld -NewSecret $crNew } | Should Throw 'alloc failed'
            Assert-MockCalled Clear-CrBstr -Times 1 -Exactly -ParameterFilter { $Pointer -eq [IntPtr]1010 }
            Assert-MockCalled Invoke-CrNativeChangePassword -Times 0 -Exactly
        }
    }

    Context 'Test-CrSecretEqual when the second conversion fails' {
        Mock Assert-CrNativeReady { }
        Mock ConvertTo-CrBstr {
            if ($Secret.Length -eq 12) { throw 'alloc failed' }
            [IntPtr](1000 + $Secret.Length)
        }
        Mock Clear-CrBstr { }
        Mock Invoke-CrNativeSecretEqual { $true }
        It 'frees the first BSTR and never compares' {
            { Test-CrSecretEqual -A $crOld -B $crNew } | Should Throw 'alloc failed'
            Assert-MockCalled Clear-CrBstr -Times 1 -Exactly -ParameterFilter { $Pointer -eq [IntPtr]1010 }
            Assert-MockCalled Invoke-CrNativeSecretEqual -Times 0 -Exactly
        }
    }
}

Describe 'Write wrappers validate their arguments' {
    Mock Assert-CrNativeReady { }
    Mock ConvertTo-CrBstr { [IntPtr]1 }
    Mock Clear-CrBstr { }

    It 'refuses a missing SecureString before allocating anything' {
        { Invoke-CrNetPasswordChange -UserName 'CrTestUser' -OldSecret $null -NewSecret $crNew } | Should Throw 'OldSecret'
        { Test-CrSecretEqual -A $crOld -B $null } | Should Throw 'must be a SecureString'
        { Set-CrLsaSecret -Name 'CrTestKey' -Secret $null } | Should Throw 'must be a SecureString'
        { New-CrLocalUser -UserName 'CrTestUser' -Secret $null } | Should Throw 'must be a SecureString'
        Assert-MockCalled ConvertTo-CrBstr -Times 0 -Exactly
    }

    It 'refuses empty names' {
        { Invoke-CrLogonTest -UserName '' -Secret $crNew } | Should Throw 'UserName'
        { Add-CrLocalGroupMemberSid -GroupName '' -MemberSid $crTestSid } | Should Throw 'GroupName'
        { Remove-CrLsaSecret -Name '' } | Should Throw 'Name'
        { Set-CrServiceLogonPassword -ServiceName 'CrTestSvc' -Account '' -Secret $crNew } | Should Throw 'Account'
        { New-CrLocalUser -UserName '' -Secret $crNew } | Should Throw 'UserName'
    }

    It 'refuses an unknown logon type' {
        { Invoke-CrLogonTest -UserName 'CrTestUser' -Secret $crNew -LogonType 'RemoteInteractive' } | Should Throw
    }
}

Describe 'Write wrapper results' {
    Mock Assert-CrNativeReady { }
    Mock ConvertTo-CrBstr { [IntPtr](1000 + $Secret.Length) }
    Mock Clear-CrBstr { }

    Context 'success shape' {
        Mock Invoke-CrNativeChangePassword { 0 }
        It 'returns exactly Success and Win32Error' {
            $r = Invoke-CrNetPasswordChange -UserName 'CrTestUser' -OldSecret $crOld -NewSecret $crNew
            ($r -is [hashtable]) | Should Be $true
            $r.Count | Should Be 2
            $r['Success'] | Should Be $true
            $r['Win32Error'] | Should Be 0
        }
    }

    Context 'wrong old password' {
        Mock Invoke-CrNativeChangePassword { 86 }
        It 'reports failure with the code' {
            $r = Invoke-CrNetPasswordChange -UserName 'CrTestUser' -OldSecret $crOld -NewSecret $crNew
            $r['Success'] | Should Be $false
            $r['Win32Error'] | Should Be 86
        }
    }

    Context 'logon type mapping' {
        Mock Invoke-CrNativeLogonUser { 0 }
        It 'maps Network/Interactive/Batch/Service to 3/2/4/5' {
            $null = Invoke-CrLogonTest -UserName 'CrTestUser' -Secret $crNew -LogonType 'Network'
            $null = Invoke-CrLogonTest -UserName 'CrTestUser' -Secret $crNew -LogonType 'Interactive'
            $null = Invoke-CrLogonTest -UserName 'CrTestUser' -Secret $crNew -LogonType 'Batch'
            $null = Invoke-CrLogonTest -UserName 'CrTestUser' -Secret $crNew -LogonType 'Service'
            Assert-MockCalled Invoke-CrNativeLogonUser -Times 1 -Exactly -ParameterFilter { $LogonType -eq 3 }
            Assert-MockCalled Invoke-CrNativeLogonUser -Times 1 -Exactly -ParameterFilter { $LogonType -eq 2 }
            Assert-MockCalled Invoke-CrNativeLogonUser -Times 1 -Exactly -ParameterFilter { $LogonType -eq 4 }
            Assert-MockCalled Invoke-CrNativeLogonUser -Times 1 -Exactly -ParameterFilter { $LogonType -eq 5 }
        }
    }

    Context 'logon type not granted' {
        Mock Invoke-CrNativeLogonUser { 1385 }
        It 'reports 1385 as a failure' {
            $r = Invoke-CrLogonTest -UserName 'CrTestUser' -Secret $crNew -LogonType 'Batch'
            $r['Success'] | Should Be $false
            $r['Win32Error'] | Should Be 1385
        }
    }

    Context 'add member: already a member' {
        Mock Add-CrNativeGroupMember { 1378 }
        It 'counts 1378 as success and keeps the code' {
            $r = Add-CrLocalGroupMemberSid -GroupName 'CrTestGroup' -MemberSid $crTestSid
            $r['Success'] | Should Be $true
            $r['Win32Error'] | Should Be 1378
            Assert-MockCalled Add-CrNativeGroupMember -Times 1 -Exactly -ParameterFilter {
                ($GroupName -eq 'CrTestGroup') -and ($MemberSid -eq 'S-1-5-21-1000-2000-3000-1001')
            }
        }
    }

    Context 'add member: 1377 is not a success for add' {
        Mock Add-CrNativeGroupMember { 1377 }
        It 'reports failure' {
            (Add-CrLocalGroupMemberSid -GroupName 'CrTestGroup' -MemberSid $crTestSid)['Success'] | Should Be $false
        }
    }

    Context 'remove member: not a member' {
        Mock Remove-CrNativeGroupMember { 1377 }
        It 'counts 1377 as success' {
            $r = Remove-CrLocalGroupMemberSid -GroupName 'CrTestGroup' -MemberSid $crTestSid
            $r['Success'] | Should Be $true
            $r['Win32Error'] | Should Be 1377
        }
    }

    Context 'remove member: 1378 is not a success for remove' {
        Mock Remove-CrNativeGroupMember { 1378 }
        It 'reports failure' {
            (Remove-CrLocalGroupMemberSid -GroupName 'CrTestGroup' -MemberSid $crTestSid)['Success'] | Should Be $false
        }
    }

    Context 'remove member: group not found' {
        Mock Remove-CrNativeGroupMember { 2220 }
        It 'reports failure' {
            $r = Remove-CrLocalGroupMemberSid -GroupName 'CrTestGroup' -MemberSid $crTestSid
            $r['Success'] | Should Be $false
            $r['Win32Error'] | Should Be 2220
        }
    }

    Context 'grant right' {
        Mock Add-CrNativeAccountRight { 0 }
        It 'passes SID and right' {
            $r = Grant-CrAccountRight -Sid $crTestSid -Right 'SeServiceLogonRight'
            $r['Success'] | Should Be $true
            Assert-MockCalled Add-CrNativeAccountRight -Times 1 -Exactly -ParameterFilter {
                ($Sid -eq 'S-1-5-21-1000-2000-3000-1001') -and ($Right -eq 'SeServiceLogonRight')
            }
        }
    }

    Context 'LSA secret delete: missing secret' {
        Mock Remove-CrNativeLsaPrivateData { 2 }
        It 'counts STATUS_OBJECT_NAME_NOT_FOUND (2) as success' {
            (Remove-CrLsaSecret -Name 'CrTestKey')['Success'] | Should Be $true
        }
    }

    Context 'LSA secret store: error 2 is a failure' {
        Mock Set-CrNativeLsaPrivateData { 2 }
        It 'reports failure' {
            (Set-CrLsaSecret -Name 'CrTestKey' -Secret $crNew)['Success'] | Should Be $false
        }
    }

    Context 'user flags' {
        Mock Set-CrNativeUserFlags { 0 }
        It 'passes the flags word' {
            (Set-CrUserFlags -UserName 'CrTestUser' -Flags 0x10241)['Success'] | Should Be $true
            Assert-MockCalled Set-CrNativeUserFlags -Times 1 -Exactly -ParameterFilter { $Flags -eq 0x10241 }
        }
    }

    Context 'create user: success' {
        Mock Add-CrNativeUser { 0 }
        It 'returns exactly Success and Win32Error' {
            $r = New-CrLocalUser -UserName 'CrTestUser' -Secret $crNew -Comment 'Test comment'
            ($r -is [hashtable]) | Should Be $true
            $r.Count | Should Be 2
            $r['Success'] | Should Be $true
            $r['Win32Error'] | Should Be 0
        }
    }

    Context 'create user: the account already exists' {
        Mock Add-CrNativeUser { 2224 }
        It 'reports 2224 as a failure with the code' {
            $r = New-CrLocalUser -UserName 'CrTestUser' -Secret $crNew
            $r['Success'] | Should Be $false
            $r['Win32Error'] | Should Be 2224
        }
    }

    Context 'create user: password policy' {
        Mock Add-CrNativeUser { 2245 }
        It 'reports 2245 as a failure' {
            $r = New-CrLocalUser -UserName 'CrTestUser' -Secret $crNew
            $r['Success'] | Should Be $false
            $r['Win32Error'] | Should Be 2245
        }
    }

    Context 'create user: no comment' {
        Mock Add-CrNativeUser { 0 }
        It 'passes an empty comment' {
            $null = New-CrLocalUser -UserName 'CrTestUser' -Secret $crNew
            Assert-MockCalled Add-CrNativeUser -Times 1 -Exactly -ParameterFilter { [string]::IsNullOrEmpty($Comment) }
        }
    }

    Context 'user info' {
        Mock Get-CrNativeUserInfo { return , @([long]0, [long]0x10211, [long]2, [long]86400) }
        It 'maps the raw values' {
            $r = Get-CrUserInfo -UserName 'CrTestUser'
            $r['Success'] | Should Be $true
            $r['Win32Error'] | Should Be 0
            $r['Flags'] | Should Be 0x10211
            $r['BadPasswordCount'] | Should Be 2
            $r['PasswordAgeSeconds'] | Should Be 86400
            ($r['Flags'] -is [int]) | Should Be $true
            ($r['PasswordAgeSeconds'] -is [long]) | Should Be $true
            $r.Count | Should Be 5
        }
    }

    Context 'user info: user not found' {
        Mock Get-CrNativeUserInfo { return , @([long]2221, [long]0, [long]0, [long]0) }
        It 'reports failure with null values' {
            $r = Get-CrUserInfo -UserName 'CrTestUser'
            $r['Success'] | Should Be $false
            $r['Win32Error'] | Should Be 2221
            $r['Flags'] | Should BeNullOrEmpty
            $r['BadPasswordCount'] | Should BeNullOrEmpty
        }
    }

    Context 'local policy: accepted' {
        Mock Invoke-CrNativeValidatePassword { return , @(0, 0) }
        It 'is Ok' {
            $r = Test-CrLocalPasswordPolicy -UserName 'CrTestUser' -Secret $crNew
            $r['Ok'] | Should Be $true
            $r['Status'] | Should Be 0
            $r['Win32Error'] | Should Be 0
        }
    }

    Context 'local policy: too short' {
        Mock Invoke-CrNativeValidatePassword { return , @(0, 2245) }
        It 'is not Ok and reports the validation status' {
            $r = Test-CrLocalPasswordPolicy -UserName 'CrTestUser' -Secret $crNew
            $r['Ok'] | Should Be $false
            $r['Status'] | Should Be 2245
        }
    }

    Context 'local policy: API failure' {
        Mock Invoke-CrNativeValidatePassword { return , @(5, -1) }
        It 'is not Ok, Status is null, Win32Error is the API code' {
            $r = Test-CrLocalPasswordPolicy -UserName 'CrTestUser' -Secret $crNew
            $r['Ok'] | Should Be $false
            $r['Status'] | Should BeNullOrEmpty
            $r['Win32Error'] | Should Be 5
        }
    }

    Context 'secret equal / length' {
        Mock Invoke-CrNativeSecretEqual { $false }
        Mock Get-CrNativeSecretLength { 12 }
        It 'returns a bool and an int' {
            $eq = Test-CrSecretEqual -A $crOld -B $crNew
            ($eq -is [bool]) | Should Be $true
            $eq | Should Be $false
            $len = Get-CrSecretLength -Secret $crNew
            ($len -is [int]) | Should Be $true
            $len | Should Be 12
        }
    }
}

Describe 'Test-CrSecretComplexity' {
    Mock Assert-CrNativeReady { }
    Mock ConvertTo-CrBstr { [IntPtr](1000 + $Secret.Length) }
    Mock Clear-CrBstr { }

    Context 'four categories, long enough, no token' {
        Mock Invoke-CrNativeSecretComplexity { return , @(12, 15, 0) }
        It 'is Ok and lists OtherLetter as missing' {
            $r = Test-CrSecretComplexity -Secret $crNew -MinLength 8 -RequireComplexity $true -Tokens @('crtest')
            $r['Ok'] | Should Be $true
            $r['TooShort'] | Should Be $false
            $r['Categories'] | Should Be 4
            @($r['MissingCategories']).Count | Should Be 1
            $r['MissingCategories'][0] | Should Be 'OtherLetter'
            $r['ContainsNameToken'] | Should Be $false
            $r.Count | Should Be 5
            Assert-MockCalled Invoke-CrNativeSecretComplexity -Times 1 -Exactly -ParameterFilter {
                (@($Tokens).Count -eq 1) -and ($Tokens[0] -eq 'crtest')
            }
        }
    }

    Context 'too short' {
        Mock Invoke-CrNativeSecretComplexity { return , @(6, 15, 0) }
        It 'is not Ok' {
            $r = Test-CrSecretComplexity -Secret $crNew -MinLength 8 -RequireComplexity $true
            $r['Ok'] | Should Be $false
            $r['TooShort'] | Should Be $true
        }
    }

    Context 'two categories' {
        Mock Invoke-CrNativeSecretComplexity { return , @(12, 6, 0) }
        It 'is not Ok when complexity is required, Ok otherwise' {
            $r = Test-CrSecretComplexity -Secret $crNew -MinLength 8 -RequireComplexity $true
            $r['Ok'] | Should Be $false
            $r['Categories'] | Should Be 2
            ($r['MissingCategories'] -join ',') | Should Be 'Uppercase,NonAlphanumeric,OtherLetter'
            (Test-CrSecretComplexity -Secret $crNew -MinLength 8 -RequireComplexity $false)['Ok'] | Should Be $true
        }
    }

    Context 'name token found' {
        Mock Invoke-CrNativeSecretComplexity { return , @(12, 15, 1) }
        It 'is not Ok and says only that a token was found' {
            $r = Test-CrSecretComplexity -Secret $crNew -MinLength 8 -RequireComplexity $true -Tokens @('crtest', 'dummy')
            $r['Ok'] | Should Be $false
            $r['ContainsNameToken'] | Should Be $true
            $text = ($r.Values | ForEach-Object { $_ } | Out-String)
            $text | Should Not Match 'crtest|dummy'
        }
    }

    Context 'all five categories' {
        Mock Invoke-CrNativeSecretComplexity { return , @(12, 31, 0) }
        It 'has an empty MissingCategories array' {
            $r = Test-CrSecretComplexity -Secret $crNew -MinLength 8 -RequireComplexity $true
            $r['Categories'] | Should Be 5
            ($r['MissingCategories'] -is [array]) | Should Be $true
            @($r['MissingCategories']).Count | Should Be 0
        }
    }
}

Describe 'Native write side (integration, read-only)' -Tags 'Integration' {
    Initialize-CrNative
    $crCanary = 'CrCanary-7Q!x'

    It 'compiles the full source including the write classes' {
        Test-CrNativeReady | Should Be $true
        ('CrNativeSecret' -as [type]) | Should Not BeNullOrEmpty
        ('CrNativeAcct' -as [type]) | Should Not BeNullOrEmpty
        ('CrNativeSvc' -as [type]) | Should Not BeNullOrEmpty
    }

    It 'compares secrets on BSTRs' {
        $a = New-CrTestSecureString 'Dummy-Abc1'
        $b = New-CrTestSecureString 'Dummy-Abc1'
        $c = New-CrTestSecureString 'Dummy-Abc2'
        $d = New-CrTestSecureString 'Dummy'
        $empty = New-Object System.Security.SecureString
        Test-CrSecretEqual -A $a -B $b | Should Be $true
        Test-CrSecretEqual -A $a -B $c | Should Be $false
        Test-CrSecretEqual -A $a -B $d | Should Be $false
        Test-CrSecretEqual -A $empty -B $empty | Should Be $true
        Get-CrSecretLength -Secret $a | Should Be 10
        Get-CrSecretLength -Secret $empty | Should Be 0
    }

    It 'emulates the complexity categories and name tokens (D15)' {
        $r = Test-CrSecretComplexity -Secret (New-CrTestSecureString 'Dummy-Abc1') -MinLength 8 -RequireComplexity $true -Tokens @('zzz')
        $r['Categories'] | Should Be 4
        $r['Ok'] | Should Be $true
        $r = Test-CrSecretComplexity -Secret (New-CrTestSecureString 'xxCRTESTuser1!') -MinLength 8 -RequireComplexity $true -Tokens @('crtest')
        $r['ContainsNameToken'] | Should Be $true
        $r['Ok'] | Should Be $false
        # tokens shorter than 3 characters are ignored
        (Test-CrSecretComplexity -Secret (New-CrTestSecureString 'Dummy-Abc1') -Tokens @('du'))['ContainsNameToken'] | Should Be $false
        # a letter without case (CJK) counts as OtherLetter
        $other = New-CrTestSecureString ('ab' + [char]0x4E00 + '1')
        $r = Test-CrSecretComplexity -Secret $other -MinLength 0 -RequireComplexity $true
        $r['Categories'] | Should Be 3
        ($r['MissingCategories'] -join ',') | Should Be 'Uppercase,NonAlphanumeric'
    }

    It 'never returns the secret or the token' {
        $r = Test-CrSecretComplexity -Secret (New-CrTestSecureString $crCanary) -MinLength 8 -RequireComplexity $true -Tokens @('canary')
        $r['ContainsNameToken'] | Should Be $true
        $text = ($r.Values | ForEach-Object { $_ } | Out-String)
        $text | Should Not Match ([regex]::Escape($crCanary))
        $text | Should Not Match 'canary'
    }

    It 'reads user info of the built-in Administrator (RID 500) without a password' {
        $name = (Resolve-CrSidToName ((Get-CrMachineSid) + '-500')).Split('\')[1]
        $r = Get-CrUserInfo -UserName $name
        $r['Success'] | Should Be $true
        ($r['Flags'] -is [int]) | Should Be $true
        (($r['Flags'] -band 0x200) -ne 0) | Should Be $true   # UF_NORMAL_ACCOUNT
        ($r['BadPasswordCount'] -ge 0) | Should Be $true
        ($r['PasswordAgeSeconds'] -ge 0) | Should Be $true
    }

    It 'lays out USER_INFO_1 like lmaccess.h on this architecture' {
        $t = [CrNativeAcct].GetNestedType('USER_INFO_1', [System.Reflection.BindingFlags]::NonPublic)
        ($null -eq $t) | Should Be $false
        $p = [IntPtr]::Size
        $flagsOffset = [System.Runtime.InteropServices.Marshal]::OffsetOf($t, 'usri1_flags').ToInt32()
        $scriptOffset = [System.Runtime.InteropServices.Marshal]::OffsetOf($t, 'usri1_script_path').ToInt32()
        if ($p -eq 8) {
            [System.Runtime.InteropServices.Marshal]::SizeOf([System.Activator]::CreateInstance($t)) | Should Be 56
            $flagsOffset | Should Be 40
            $scriptOffset | Should Be 48
        } else {
            [System.Runtime.InteropServices.Marshal]::SizeOf([System.Activator]::CreateInstance($t)) | Should Be 32
            $flagsOffset | Should Be 24
            $scriptOffset | Should Be 28
        }
        [System.Runtime.InteropServices.Marshal]::OffsetOf($t, 'usri1_priv').ToInt32() | Should Be (2 * $p + 4)
    }

    It 'reports 2221 for a missing user' {
        $r = Get-CrUserInfo -UserName 'CrNoSuchUser-7f3a'
        $r['Success'] | Should Be $false
        $r['Win32Error'] | Should Be 2221
    }

    It 'checks a dummy value against the local policy' {
        $r = Test-CrLocalPasswordPolicy -UserName 'CrNoSuchUser-7f3a' -Secret (New-CrTestSecureString 'Dummy-Abc1')
        $r['Win32Error'] | Should Be 0
        ($r['Status'] -is [int]) | Should Be $true
        $r = Test-CrLocalPasswordPolicy -UserName 'CrNoSuchUser-7f3a' -Secret (New-Object System.Security.SecureString)
        $r['Win32Error'] | Should Be 0
    }
}
