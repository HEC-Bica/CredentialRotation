# Pester 3.4 tests for src\lib\Adapters.ps1 (D4 plaintext boundary). Fake values and fake COM objects only.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here '..\src\lib\Compat.ps1')
. (Join-Path $here '..\src\lib\Adapters.ps1')

# Catalog object with a parameterized Value property like COMAdmin's ICatalogObject, so that
# "$obj.Value('Password') = x" works. SetLog records the names in the order they were set.
# FailMode: 0 = store, 1 = COMException (access denied), 2 = an exception whose message quotes the
# value (like a PowerShell conversion error). FailOnName limits the failure to one value name.
if (-not ('CrTestCatalogObject2' -as [type])) {
    Add-Type -Language VisualBasic -TypeDefinition @'
Public Class CrTestCatalogObject2
    Private _values As New System.Collections.Hashtable()
    Public SetCount As Integer = 0
    Public FailMode As Integer = 0
    Public FailOnName As String = Nothing
    Public SetLog As New System.Collections.ArrayList()
    Public Property Value(ByVal name As String) As Object
        Get
            Return _values(name)
        End Get
        Set(ByVal v As Object)
            SetCount = SetCount + 1
            SetLog.Add(name)
            If FailMode <> 0 AndAlso (FailOnName Is Nothing OrElse FailOnName = name) Then
                If FailMode = 1 Then
                    Throw New System.Runtime.InteropServices.COMException("Access is denied.", &H80070005)
                End If
                If FailMode = 2 Then
                    Throw New System.ArgumentException("Cannot use value " & CStr(v))
                End If
            End If
            _values(name) = v
        End Set
    End Property
End Class
'@
}

# Fake ITaskFolder: records RegisterTaskDefinition calls; Fail = 'com' throws a COMException whose
# message contains the password, as a worst case.
function New-TestTaskFolder {
    param([string]$Fail = '')
    $f = New-Object PSObject -Property @{ Calls = (New-Object System.Collections.ArrayList); Fail = $Fail }
    Add-Member -InputObject $f -MemberType ScriptMethod -Name RegisterTaskDefinition -Value {
        param($Path, $Definition, $Flags, $UserId, $Password, $LogonType, $Sddl)
        [void]$this.Calls.Add(@{ Path = $Path; Definition = $Definition; Flags = $Flags; UserId = $UserId; Password = $Password; LogonType = $LogonType; Sddl = $Sddl })
        if ($this.Fail -eq 'com') {
            throw (New-Object System.Runtime.InteropServices.COMException(('The user name or password is incorrect: ' + $Password), -2147023570))
        }
        return 'registered-task'
    }
    return $f
}

function New-TestSecret {
    return (ConvertTo-SecureString 'Dummy-1a' -AsPlainText -Force)
}

function Get-TestResultText {
    param($Result)
    $parts = @()
    foreach ($k in @($Result.Keys)) { $parts += ([string]$k + '=' + [string]$Result[$k]) }
    return ($parts -join '|')
}

Describe 'Invoke-CrTaskRegistrationAdapter' {

    Context 'successful registration' {
        Mock Clear-CrSecretBstr { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr) }
        $folder = New-TestTaskFolder
        $definition = New-Object PSObject -Property @{ Marker = 'definition-1' }
        $r = Invoke-CrTaskRegistrationAdapter -Folder $folder -TaskName 'CrTestTask' -Definition $definition -UserId 'CRTEST01\CrTestUser' -Secret (New-TestSecret) -LogonType 6 -Sddl 'O:BAG:SYD:(A;;FA;;;BA)'

        It 'returns Success and no error' {
            $r['Success'] | Should Be $true
            $r['Error'] | Should BeNullOrEmpty
            $r['HResult'] | Should BeNullOrEmpty
            ((@($r.Keys) | Sort-Object) -join ',') | Should Be 'Error,HResult,Success'
        }
        It 'calls RegisterTaskDefinition once with TASK_UPDATE (4)' {
            $folder.Calls.Count | Should Be 1
            $folder.Calls[0]['Flags'] | Should Be 4
        }
        It 'passes task name, definition, UserId, LogonType and SDDL unchanged' {
            $c = $folder.Calls[0]
            $c['Path'] | Should Be 'CrTestTask'
            [object]::ReferenceEquals($c['Definition'], $definition) | Should Be $true
            $c['UserId'] | Should Be 'CRTEST01\CrTestUser'
            $c['LogonType'] | Should Be 6
            $c['Sddl'] | Should Be 'O:BAG:SYD:(A;;FA;;;BA)'
        }
        It 'hands the converted password to the COM call' {
            $folder.Calls[0]['Password'] | Should Be 'Dummy-1a'
        }
        It 'returns no secret material' {
            (Get-TestResultText $r) | Should Not Match 'Dummy-1a'
        }
        It 'frees the BSTR with ZeroFreeBSTR once' {
            Assert-MockCalled Clear-CrSecretBstr -Times 1 -Exactly -ParameterFilter { $Bstr -ne [IntPtr]::Zero }
        }
    }

    Context 'COM error' {
        Mock Clear-CrSecretBstr { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr) }
        $folder = New-TestTaskFolder -Fail 'com'
        try { throw 'adapter-test-marker' } catch { }
        $r = Invoke-CrTaskRegistrationAdapter -Folder $folder -TaskName 'Job' -Definition (New-Object PSObject) -UserId 'CrTestUser' -Secret (New-TestSecret) -LogonType 1 -Sddl 'D:(A;;FA;;;BA)'

        It 'reports the failure with type and HRESULT' {
            $r['Success'] | Should Be $false
            $r['Error'] | Should Match 'RegisterTaskDefinition failed'
            $r['Error'] | Should Match '8007052E'
            $r['Error'] | Should Match 'COMException'
            $r['HResult'] | Should Be -2147023570
        }
        It 'never returns the exception message (it may quote the password)' {
            (Get-TestResultText $r) | Should Not Match 'Dummy-1a'
        }
        It 'removes the error records it caught from $Error and keeps older ones' {
            @($Error | Where-Object { [string]$_ -match 'Dummy-1a' }).Count | Should Be 0
            @($Error | Where-Object { [string]$_ -match 'adapter-test-marker' }).Count | Should BeGreaterThan 0
        }
        It 'still frees the BSTR' {
            Assert-MockCalled Clear-CrSecretBstr -Times 1 -Exactly
        }
    }

    Context 'BSTR conversion fails' {
        Mock ConvertTo-CrSecretBstr { throw 'conversion failed' }
        Mock Clear-CrSecretBstr { }
        $folder = New-TestTaskFolder
        $r = Invoke-CrTaskRegistrationAdapter -Folder $folder -TaskName 'Job' -Definition (New-Object PSObject) -UserId 'CrTestUser' -Secret (New-TestSecret) -LogonType 1 -Sddl 'D:'

        It 'fails without calling COM or freeing a null pointer' {
            $r['Success'] | Should Be $false
            $folder.Calls.Count | Should Be 0
            Assert-MockCalled Clear-CrSecretBstr -Times 0 -Exactly
        }
    }

    Context 'no secret' {
        Mock ConvertTo-CrSecretBstr { [IntPtr]::Zero }
        $folder = New-TestTaskFolder
        $r = Invoke-CrTaskRegistrationAdapter -Folder $folder -TaskName 'Job' -Definition (New-Object PSObject) -UserId 'CrTestUser' -Secret $null -LogonType 1 -Sddl 'D:'

        It 'fails before converting anything' {
            $r['Success'] | Should Be $false
            $folder.Calls.Count | Should Be 0
            Assert-MockCalled ConvertTo-CrSecretBstr -Times 0 -Exactly
        }
    }
}

Describe 'Set-CrComPlusPasswordAdapter' {

    Context 'successful set' {
        Mock Clear-CrSecretBstr { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr) }
        $app = New-Object CrTestCatalogObject2
        $r = Set-CrComPlusPasswordAdapter -Application $app -Secret (New-TestSecret)

        It 'sets Value(Password) once and returns Success' {
            $r['Success'] | Should Be $true
            $r['Error'] | Should BeNullOrEmpty
            $app.SetCount | Should Be 1
            $app.Value('Password') | Should Be 'Dummy-1a'
            $r['IdentitySet'] | Should Be $false
            ($app.SetLog.ToArray() -join ',') | Should Be 'Password'
            ((@($r.Keys) | Sort-Object) -join ',') | Should Be 'Error,IdentitySet,Success'
        }
        It 'does not touch other catalog values' {
            $app.Value('Identity') | Should BeNullOrEmpty
        }
        It 'returns no secret material' {
            (Get-TestResultText $r) | Should Not Match 'Dummy-1a'
        }
        It 'frees the BSTR with ZeroFreeBSTR once' {
            Assert-MockCalled Clear-CrSecretBstr -Times 1 -Exactly -ParameterFilter { $Bstr -ne [IntPtr]::Zero }
        }
    }

    Context 'COM error' {
        Mock Clear-CrSecretBstr { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr) }
        $app = New-Object CrTestCatalogObject2
        $app.FailMode = 1
        $r = Set-CrComPlusPasswordAdapter -Application $app -Secret (New-TestSecret)

        It 'reports the HRESULT and the Win32 text' {
            $r['Success'] | Should Be $false
            $r['Error'] | Should Match '80070005'
            $r['Error'] | Should Match 'COMException'
        }
        It 'still frees the BSTR' {
            Assert-MockCalled Clear-CrSecretBstr -Times 1 -Exactly
        }
    }

    Context 'error message quoting the value' {
        Mock Clear-CrSecretBstr { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr) }
        $app = New-Object CrTestCatalogObject2
        $app.FailMode = 2
        $r = Set-CrComPlusPasswordAdapter -Application $app -Secret (New-TestSecret)

        It 'returns only the exception type and HRESULT' {
            $r['Success'] | Should Be $false
            $r['Error'] | Should Match 'ArgumentException'
            (Get-TestResultText $r) | Should Not Match 'Dummy-1a'
        }
        It 'still frees the BSTR' {
            Assert-MockCalled Clear-CrSecretBstr -Times 1 -Exactly
        }
    }

    Context 'no secret' {
        Mock ConvertTo-CrSecretBstr { [IntPtr]::Zero }
        $app = New-Object CrTestCatalogObject2
        $r = Set-CrComPlusPasswordAdapter -Application $app -Secret $null

        It 'fails without setting anything' {
            $r['Success'] | Should Be $false
            $app.SetCount | Should Be 0
            Assert-MockCalled ConvertTo-CrSecretBstr -Times 0 -Exactly
        }
    }
    Context 'with Identity (move, D24)' {
        Mock Clear-CrSecretBstr { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr) }
        $app = New-Object CrTestCatalogObject2
        $r = Set-CrComPlusPasswordAdapter -Application $app -Secret (New-TestSecret) -Identity 'CrTestNewUser'

        It 'sets Identity before Password and returns Success' {
            $r['Success'] | Should Be $true
            $r['IdentitySet'] | Should Be $true
            ($app.SetLog.ToArray() -join ',') | Should Be 'Identity,Password'
        }
        It 'stores the new identity and the password' {
            $app.Value('Identity') | Should Be 'CrTestNewUser'
            $app.Value('Password') | Should Be 'Dummy-1a'
        }
        It 'returns no secret material' {
            (Get-TestResultText $r) | Should Not Match 'Dummy-1a'
        }
        It 'frees the BSTR once' {
            Assert-MockCalled Clear-CrSecretBstr -Times 1 -Exactly -ParameterFilter { $Bstr -ne [IntPtr]::Zero }
        }
    }

    Context 'setting the Identity fails' {
        Mock ConvertTo-CrSecretBstr { [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret) }
        Mock Clear-CrSecretBstr { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr) }
        $app = New-Object CrTestCatalogObject2
        $app.FailMode = 1
        $app.FailOnName = 'Identity'
        $r = Set-CrComPlusPasswordAdapter -Application $app -Secret (New-TestSecret) -Identity 'CrTestNewUser'

        It 'fails without touching the password' {
            $r['Success'] | Should Be $false
            $r['IdentitySet'] | Should Be $false
            $r['Error'] | Should Match 'COM\+ identity'
            $r['Error'] | Should Match '80070005'
            ($app.SetLog.ToArray() -join ',') | Should Be 'Identity'
        }
        It 'never converts the secret' {
            Assert-MockCalled ConvertTo-CrSecretBstr -Times 0 -Exactly
            Assert-MockCalled Clear-CrSecretBstr -Times 0 -Exactly
        }
    }

    Context 'setting the Password fails after the Identity' {
        Mock Clear-CrSecretBstr { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr) }
        $app = New-Object CrTestCatalogObject2
        $app.FailMode = 2
        $app.FailOnName = 'Password'
        $r = Set-CrComPlusPasswordAdapter -Application $app -Secret (New-TestSecret) -Identity 'CrTestNewUser'

        It 'reports the failure with IdentitySet so the caller does not save' {
            $r['Success'] | Should Be $false
            $r['IdentitySet'] | Should Be $true
            $r['Error'] | Should Match 'COM\+ password'
            ($app.SetLog.ToArray() -join ',') | Should Be 'Identity,Password'
        }
        It 'returns no secret material' {
            (Get-TestResultText $r) | Should Not Match 'Dummy-1a'
        }
        It 'still frees the BSTR' {
            Assert-MockCalled Clear-CrSecretBstr -Times 1 -Exactly
        }
    }

    Context 'Identity without a secret' {
        Mock ConvertTo-CrSecretBstr { [IntPtr]::Zero }
        $app = New-Object CrTestCatalogObject2
        $r = Set-CrComPlusPasswordAdapter -Application $app -Secret $null -Identity 'CrTestNewUser'

        It 'sets nothing, not even the identity' {
            $r['Success'] | Should Be $false
            $r['IdentitySet'] | Should Be $false
            $app.SetCount | Should Be 0
            Assert-MockCalled ConvertTo-CrSecretBstr -Times 0 -Exactly
        }
    }
}

Describe 'Get-CrAdapterErrorText' {
    It 'adds the Win32 message for FACILITY_WIN32 HRESULTs' {
        $t = Get-CrAdapterErrorText -Operation 'Op' -TypeName 'COMException' -HResult (-2147024891)
        $t | Should Match '^Op failed \(COMException, 0x80070005\): .+'
    }
    It 'keeps other HRESULTs as a number only' {
        Get-CrAdapterErrorText -Operation 'Op' -TypeName 'COMException' -HResult (-2146368508) | Should Be 'Op failed (COMException, 0x80110404)'
    }
}
