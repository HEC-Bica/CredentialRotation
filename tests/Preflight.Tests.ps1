# Pester 3.4 tests for src\lib\Preflight.ps1 (PLAN section 6 step 2, D19). Synthetic data only.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here '..\src\lib\Compat.ps1')

# Stubs for Native.ps1 (another module); mocked below.
function Get-CrMachineSid { }
function Get-CrUserModals { }
function Test-CrNativeReady { }

. (Join-Path $here '..\src\lib\Preflight.ps1')

# The account entries of the v10.4 config (CONTRACTS 4.2), reduced to the keys Preflight reads.
$TestConfig = @{
    Accounts = @(
        @{ Id = 'BiCAAdmin'; Kind = 'Windows'; Name = 'BiCA Admin'; Role = 'Admin'; Credential = 'BiCAAdmin'; Create = $true }
        @{ Id = 'BiCARemote'; Kind = 'Windows'; Name = 'BiCA Remote'; Role = 'AdminRemote'; Credential = 'BiCARemote'; Create = $true; Operator = $true }
        @{ Id = 'AppUser'; Kind = 'Windows'; Name = 'ApplicationUser'; Role = 'Admin'; Credential = 'AppUser'; Create = $true
           EnableIfDisabled = $true; PasswordMode = 'Change'; Replaces = @('RID-500') }
        @{ Id = 'AutoLogon'; Kind = 'Windows'; Names = @('PUB-User', 'WinAutoUser'); Role = 'User'; Credential = 'AutoLogon'
           AutoLogonUser = @(@{ Name = 'PUB-User' }, @{ Name = 'WinAutoUser' })
           AutoLogon = @{ Mode = 'IfAlreadyOn'; RestrictedComputerPattern = '^SM' } }
        @{ Id = 'Retired'; Kind = 'Windows'; Names = @('SP Admin', 'SYS Admin', 'SOP-Admin'); Mode = 'Disable' }
        @{ Id = 'WinUsers'; Kind = 'Windows'; Names = @('WinUser1'); Role = 'WinUser'; Mode = 'Check' }
        @{ Id = 'SqlApp'; Kind = 'SqlLogin'; Name = 'SQLApplication'; Credential = 'SQLApplication' }
        @{ Id = 'SqlScript'; Kind = 'SqlLogin'; Name = 'SQLScript'; Credential = 'SQLScript' }
        @{ Id = 'SqlService'; Kind = 'SqlLogin'; Name = 'SQLService'; Credential = 'SQLService' }
    )
}

function Get-TestEwfLines {
    param([string]$State = 'ENABLED', [string]$BootCommand = 'NO_CMD')
    return @(
        'Protected Volume Configuration',
        '  Type            RAM (REG)',
        ('  State           {0}' -f $State),
        ('  Boot Command    {0}' -f $BootCommand),
        '    Param1        0',
        '    Param2        0',
        '  Volume ID       00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF',
        '  Device Name     "\Device\HarddiskVolume1" [C:]',
        '  Max Levels      1',
        '  Clump Size      512',
        '  Current Level   1',
        'Memory used for data 0 bytes',
        'Memory used for mapping 0 bytes'
    )
}

function Get-TestFbwfLines {
    param([string]$Current = 'enabled', [string]$Next = 'enabled', [string]$Volume = 'C:')
    return @(
        'File-based write filter configuration for the current session:',
        ('    filter state: {0}.' -f $Current),
        '    overlay cache data compression state: disabled.',
        '    overlay cache threshold: 64 MB.',
        '    size display: actual mode.',
        '    protected volume list:',
        ('      {0}' -f $Volume),
        '    write through list of each protected volume:',
        '      D:',
        '        \pagefile.sys',
        'File-based write filter configuration for the next session:',
        ('    filter state: {0}.' -f $Next),
        '    protected volume list:',
        ('      {0}' -f $Volume)
    )
}

function New-TestFilter {
    param([string]$Type = 'EWF', [bool]$Installed = $true, [bool]$Known = $true, $Current = $true, $Next = $true,
          [bool]$Commit = $false, [string[]]$Volumes = @('C:'))
    return @{ Type = $Type; DriverInstalled = $Installed; StateKnown = $Known; CurrentEnabled = $Current; NextEnabled = $Next
              CommitPending = $Commit; ProtectedVolumes = $Volumes; Detail = 'test' }
}

function New-TestPreflightState {
    return @{
        Computer = @{ Name = 'IPT01-SITEA'; IsSm = $false; OsVersion = '10.0.17763'; OsCaption = 'Windows 10 Enterprise LTSC'
                      Is64BitOs = $true; Is64BitProcess = $true; PSVersion = '2.0'; ClrVersion = '2.0.50727'
                      LanguageMode = 'FullLanguage'; IsElevated = $true; PartOfDomain = $false
                      MachineSid = 'S-1-5-21-1000-2000-3000'; SystemDrive = 'C:'; Error = $null }
        Policy = @{ MinPasswordLength = 8; MaxPasswordAgeSeconds = 5184000; MinPasswordAgeSeconds = 86400; PasswordHistoryLength = 24
                    LockoutThreshold = 10; LockoutDurationSeconds = 900; LockoutObservationSeconds = 900
                    ComplexityEnabled = $true; ForceGuest = $false; Error = $null }
        WriteFilter = @{ Filters = @((New-TestFilter -Type 'EWF' -Installed $false -Current $false -Next $false -Volumes @())); Error = $null }
        Sql = @{ DefaultInstancePresent = $true; ServiceName = 'MSSQLSERVER'; ServiceState = 'Running'; Connected = $true
                 Error = $null; MajorVersion = 14; ProductVersion = '14.0.1000.169'; ConnectedAs = 'IPT01-SITEA\BiCA Remote'
                 ConnectedAsSysadmin = $true; IsIntegratedSecurityOnly = $false; OtherInstances = @()
                 MasterFiles = @('C:\Program Files\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\DATA\master.mdf',
                                 'C:\Program Files\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\DATA\mastlog.ldf') }
    }
}

function Test-AnyFinding {
    param($Result, [string]$Severity, [string]$Pattern)
    foreach ($f in @($Result['Findings'])) {
        if ($f -and $f['Severity'] -eq $Severity -and ([string]$f['Message'] -match $Pattern)) { return $true }
    }
    return $false
}

# Matching findings, written to the pipeline one by one: wrap the call in @().
function Get-TestFindings {
    param($Result, [string]$Severity, [string]$Pattern)
    foreach ($f in @($Result['Findings'])) {
        if ($f -and $f['Severity'] -eq $Severity -and ([string]$f['Message'] -match $Pattern)) { $f }
    }
}

$SqlSlotNames = @('SQLApplication', 'SQLScript', 'SQLService')
$WindowsSlotNames = @('BiCAAdmin', 'BiCARemote', 'AppUser', 'AutoLogon')

Describe 'Get-CrComputerInfo' {
    Mock Get-CrProcessEnvironment {
        return @{ Is64BitProcess = $true; Wow64 = $false; PSVersion = '2.0'; ClrVersion = '2.0.50727.8806'
                  LanguageMode = 'FullLanguage'; IsElevated = $true; SystemDrive = 'C:' }
    }
    Mock Get-CrPreflightWmi -ParameterFilter { $Class -eq 'Win32_OperatingSystem' } {
        return New-Object PSObject -Property @{ Version = '6.1.7601'; Caption = 'Windows Embedded Standard'; OSArchitecture = '64-bit'; SystemDrive = 'C:' }
    }
    Mock Get-CrPreflightWmi -ParameterFilter { $Class -eq 'Win32_ComputerSystem' } {
        return New-Object PSObject -Property @{ Name = 'SM-SITEA'; PartOfDomain = $false }
    }
    Mock Get-CrMachineSid { return 'S-1-5-21-1000-2000-3000' }

    It 'collects OS, process and machine data' {
        $c = Get-CrComputerInfo -Config $TestConfig
        $c['Error'] | Should BeNullOrEmpty
        $c['Name'] | Should Be 'SM-SITEA'
        $c['OsVersion'] | Should Be '6.1.7601'
        $c['Is64BitOs'] | Should Be $true
        $c['Is64BitProcess'] | Should Be $true
        $c['PSVersion'] | Should Be '2.0'
        $c['LanguageMode'] | Should Be 'FullLanguage'
        $c['IsElevated'] | Should Be $true
        $c['PartOfDomain'] | Should Be $false
        $c['MachineSid'] | Should Be 'S-1-5-21-1000-2000-3000'
        $c['SystemDrive'] | Should Be 'C:'
        $c['IsSm'] | Should Be $true
    }
    Context 'matches the SM pattern case-insensitively' {
        It 'matches the SM pattern case-insensitively' {
            Mock Get-CrPreflightWmi -ParameterFilter { $Class -eq 'Win32_ComputerSystem' } {
                return New-Object PSObject -Property @{ Name = 'sm-sitea'; PartOfDomain = $false }
            }
            (Get-CrComputerInfo -Config $TestConfig)['IsSm'] | Should Be $true
        }
    }
    Context 'is not SM for other names' {
        It 'is not SM for other names' {
            Mock Get-CrPreflightWmi -ParameterFilter { $Class -eq 'Win32_ComputerSystem' } {
                return New-Object PSObject -Property @{ Name = 'IPT01-SITEA'; PartOfDomain = $true }
            }
            $c = Get-CrComputerInfo -Config $TestConfig
            $c['IsSm'] | Should Be $false
            $c['PartOfDomain'] | Should Be $true
        }
    }
    It 'uses the configured RestrictedComputerPattern' {
        $cfg = @{ Accounts = @(@{ Id = 'AutoLogon'; Kind = 'Windows'; AutoLogon = @{ RestrictedComputerPattern = 'SITEA$' } }) }
        (Get-CrComputerInfo -Config $cfg)['IsSm'] | Should Be $true
    }
    Context 'reads a 32-bit OS' {
        It 'reads a 32-bit OS' {
            Mock Get-CrPreflightWmi -ParameterFilter { $Class -eq 'Win32_OperatingSystem' } {
                return New-Object PSObject -Property @{ Version = '10.0.17763'; Caption = 'Windows 10'; OSArchitecture = '32-Bit'; SystemDrive = 'C:' }
            }
            (Get-CrComputerInfo -Config $TestConfig)['Is64BitOs'] | Should Be $false
        }
    }
    Context 'keeps going when the machine SID is not available' {
        It 'keeps going when the machine SID is not available' {
            Mock Get-CrMachineSid { throw 'native not ready' }
            $c = Get-CrComputerInfo -Config $TestConfig
            $c['MachineSid'] | Should BeNullOrEmpty
            $c['Error'] | Should BeNullOrEmpty
        }
    }
    Context 'sets Error when WMI fails' {
        It 'sets Error when WMI fails' {
            Mock Get-CrPreflightWmi -ParameterFilter { $Class -eq 'Win32_OperatingSystem' } { throw 'WMI broken' }
            (Get-CrComputerInfo -Config $TestConfig)['Error'] | Should Match 'WMI broken'
        }
    }
}

Describe 'Get-CrPasswordPolicy' {
    Mock Get-CrUserModals {
        return @{ MinPasswordLength = 8; MaxPasswordAgeSeconds = 5184000; MinPasswordAgeSeconds = 86400; PasswordHistoryLength = 24
                  LockoutDurationSeconds = 900; LockoutObservationSeconds = 900; LockoutThreshold = 10 }
    }
    Mock Get-CrSeceditSystemAccess { return @{ MinimumPasswordLength = '8'; PasswordComplexity = '1' } }
    Mock Get-CrRegistryValue -ParameterFilter { $Name -eq 'forceguest' } { return @{ Exists = $true; Value = 0; Kind = 'DWord' } }

    It 'combines NetUserModalsGet, secedit complexity and ForceGuest' {
        $p = Get-CrPasswordPolicy
        $p['Error'] | Should BeNullOrEmpty
        $p['MinPasswordLength'] | Should Be 8
        $p['PasswordHistoryLength'] | Should Be 24
        $p['LockoutThreshold'] | Should Be 10
        $p['LockoutDurationSeconds'] | Should Be 900
        $p['MaxPasswordAgeSeconds'] | Should Be 5184000
        $p['ComplexityEnabled'] | Should Be $true
        $p['ForceGuest'] | Should Be $false
    }
    Context 'reads complexity off' {
        It 'reads complexity off' {
            Mock Get-CrSeceditSystemAccess { return @{ PasswordComplexity = '0' } }
            (Get-CrPasswordPolicy)['ComplexityEnabled'] | Should Be $false
        }
    }
    Context 'leaves complexity unknown when secedit has no value or fails' {
        It 'leaves complexity unknown when secedit has no value or fails' {
            Mock Get-CrSeceditSystemAccess { return @{ } }
            $p = Get-CrPasswordPolicy
            $p['ComplexityEnabled'] | Should BeNullOrEmpty
            $p['ComplexityError'] | Should Not BeNullOrEmpty
            Mock Get-CrSeceditSystemAccess { throw 'secedit failed' }
            $p = Get-CrPasswordPolicy
            $p['ComplexityEnabled'] | Should BeNullOrEmpty
            $p['ComplexityError'] | Should Match 'secedit failed'
        }
    }
    Context 'maps an unlimited maximum age to -1' {
        It 'maps an unlimited maximum age to -1' {
            Mock Get-CrUserModals { return @{ MinPasswordLength = 0; MaxPasswordAgeSeconds = [uint32]4294967295; MinPasswordAgeSeconds = 0
                                              PasswordHistoryLength = 0; LockoutDurationSeconds = 1800; LockoutObservationSeconds = 1800; LockoutThreshold = 0 } }
            (Get-CrPasswordPolicy)['MaxPasswordAgeSeconds'] | Should Be -1
        }
    }
    Context 'reports ForceGuest = 1 and a missing value as off' {
        It 'reports ForceGuest = 1 and a missing value as off' {
            Mock Get-CrRegistryValue -ParameterFilter { $Name -eq 'forceguest' } { return @{ Exists = $true; Value = 1; Kind = 'DWord' } }
            (Get-CrPasswordPolicy)['ForceGuest'] | Should Be $true
            Mock Get-CrRegistryValue -ParameterFilter { $Name -eq 'forceguest' } { return @{ Exists = $false; Value = $null; Kind = $null } }
            (Get-CrPasswordPolicy)['ForceGuest'] | Should Be $false
        }
    }
    Context 'sets Error when NetUserModalsGet fails' {
        It 'sets Error when NetUserModalsGet fails' {
            Mock Get-CrUserModals { throw 'access denied' }
            $p = Get-CrPasswordPolicy
            $p['Error'] | Should Match 'access denied'
            $p['ComplexityEnabled'] | Should Be $true
        }
    }
}

Describe 'Get-CrSeceditSystemAccess' {
    Context 'parses [System Access] and deletes the temporary file' {
        It 'parses [System Access] and deletes the temporary file' {
            Mock Invoke-CrSeceditExport {
                Set-Content -LiteralPath $Path -Value @('[Unicode]', 'Unicode=yes', '[System Access]', 'MinimumPasswordLength = 8',
                                                       'PasswordComplexity = 1', '[Event Audit]', 'AuditSystemEvents = 0')
                return 0
            }
            $sa = Get-CrSeceditSystemAccess
            $sa['PasswordComplexity'] | Should Be '1'
            $sa['MinimumPasswordLength'] | Should Be '8'
            $sa.ContainsKey('AuditSystemEvents') | Should Be $false
            $sa.ContainsKey('Unicode') | Should Be $false
            Assert-MockCalled Invoke-CrSeceditExport -Times 1 -Exactly -Scope It -ParameterFilter { -not (Test-Path -LiteralPath $Path) }
        }
    }
    Context 'deletes the temporary file when the export fails' {
        It 'deletes the temporary file when the export fails' {
            Mock Invoke-CrSeceditExport {
                Set-Content -LiteralPath $Path -Value @('[System Access]')
                throw 'secedit crashed'
            }
            { Get-CrSeceditSystemAccess } | Should Throw
            Assert-MockCalled Invoke-CrSeceditExport -Times 1 -Exactly -Scope It -ParameterFilter { -not (Test-Path -LiteralPath $Path) }
        }
    }
    Context 'throws when secedit writes no file' {
        It 'throws when secedit writes no file' {
            Mock Invoke-CrSeceditExport { return 5 }
            { Get-CrSeceditSystemAccess } | Should Throw
        }
    }
}

Describe 'ConvertFrom-CrEwfMgrOutput' {
    It 'parses an enabled volume without boot command' {
        $r = ConvertFrom-CrEwfMgrOutput -Lines (Get-TestEwfLines)
        $r['Parsed'] | Should Be $true
        $r['CurrentEnabled'] | Should Be $true
        $r['NextEnabled'] | Should Be $true
        $r['CommitPending'] | Should Be $false
    }
    It 'detects a pending commit' {
        $r = ConvertFrom-CrEwfMgrOutput -Lines (Get-TestEwfLines -BootCommand 'COMMIT')
        $r['CommitPending'] | Should Be $true
        $r['NextEnabled'] | Should Be $true
    }
    It 'detects disable at the next boot' {
        $r = ConvertFrom-CrEwfMgrOutput -Lines (Get-TestEwfLines -BootCommand 'DISABLE')
        $r['NextEnabled'] | Should Be $false
        $r['CommitPending'] | Should Be $false
    }
    It 'detects enable at the next boot' {
        $r = ConvertFrom-CrEwfMgrOutput -Lines (Get-TestEwfLines -State 'DISABLED' -BootCommand 'ENABLE')
        $r['CurrentEnabled'] | Should Be $false
        $r['NextEnabled'] | Should Be $true
    }
    It 'reports unparsable output' {
        $r = ConvertFrom-CrEwfMgrOutput -Lines @('Failed getting protected volume configuration with error 1.')
        $r['Parsed'] | Should Be $false
    }
}

Describe 'ConvertFrom-CrFbwfMgrOutput' {
    It 'parses current and next session' {
        $r = ConvertFrom-CrFbwfMgrOutput -Lines (Get-TestFbwfLines -Next 'disabled')
        $r['Parsed'] | Should Be $true
        $r['CurrentEnabled'] | Should Be $true
        $r['NextEnabled'] | Should Be $false
        ($r['CurrentVolumes'] -join ',') | Should Be 'C:'
        @($r['Unmapped']).Count | Should Be 0
    }
    It 'keeps device paths as unmapped volumes' {
        $r = ConvertFrom-CrFbwfMgrOutput -Lines (Get-TestFbwfLines -Volume '\Device\HarddiskVolume1')
        @($r['CurrentVolumes']).Count | Should Be 0
        ($r['Unmapped'] -join ',') | Should Be '\Device\HarddiskVolume1'
    }
    It 'reports unparsable output' {
        (ConvertFrom-CrFbwfMgrOutput -Lines @('something else'))['Parsed'] | Should Be $false
    }
}

Describe 'Get-CrWriteFilterState' {
    Mock Get-CrFilterDriverInfo { return @{ Installed = $false; Start = $null } }
    Mock Invoke-CrSystemTool { return @{ Present = $false; Output = @(); ExitCode = $null } }
    Mock Get-CrPreflightWmi { throw 'not available' }
    Mock Get-CrEwfProtectedVolumeKeys { 'Volume0' }

    Context 'treats an EWF driver without a configured protected volume as not protecting' {
        It 'treats an EWF driver without a configured protected volume as not protecting' {
            Mock Get-CrFilterDriverInfo -ParameterFilter { $Service -eq 'ewf' } { return @{ Installed = $true; Start = 0 } }
            Mock Get-CrEwfProtectedVolumeKeys { }
            $ewf = @(@((Get-CrWriteFilterState)['Filters']) | Where-Object { $_['Type'] -eq 'EWF' })
            $ewf.Count | Should Be 1
            $ewf[0]['StateKnown'] | Should Be $true
            $ewf[0]['CurrentEnabled'] | Should Be $false
            Assert-MockCalled Invoke-CrSystemTool -ParameterFilter { $Name -eq 'ewfmgr.exe' } -Times 0 -Exactly -Scope It
        }
    }
    It 'reports all three filters as not installed' {
        $wf = Get-CrWriteFilterState
        $wf['Error'] | Should BeNullOrEmpty
        @($wf['Filters']).Count | Should Be 3
        foreach ($f in @($wf['Filters'])) { $f['DriverInstalled'] | Should Be $false }
        Assert-MockCalled Invoke-CrSystemTool -Times 0 -Exactly -Scope It
    }
    Context 'parses EWF per volume and skips volumes without configuration' {
        It 'parses EWF per volume and skips volumes without configuration' {
            Mock Get-CrFilterDriverInfo -ParameterFilter { $Service -eq 'ewf' } { return @{ Installed = $true; Start = 0 } }
            Mock Get-CrPreflightWmi -ParameterFilter { $Class -eq 'Win32_LogicalDisk' } {
                return @((New-Object PSObject -Property @{ DeviceID = 'C:' }), (New-Object PSObject -Property @{ DeviceID = 'Z:' }))
            }
            Mock Invoke-CrSystemTool -ParameterFilter { $Name -eq 'ewfmgr.exe' } {
                return @{ Present = $true; Output = @('Failed getting protected volume configuration with error 1.'); ExitCode = 1 }
            }
            Mock Invoke-CrSystemTool -ParameterFilter { $Name -eq 'ewfmgr.exe' -and $Arguments[0] -eq 'C:' } {
                return @{ Present = $true; Output = (Get-TestEwfLines -BootCommand 'COMMIT'); ExitCode = 0 }
            }
            $ewf = @(@((Get-CrWriteFilterState)['Filters']) | Where-Object { $_['Type'] -eq 'EWF' })
            $ewf.Count | Should Be 1
            $ewf[0]['StateKnown'] | Should Be $true
            $ewf[0]['CurrentEnabled'] | Should Be $true
            $ewf[0]['CommitPending'] | Should Be $true
            ($ewf[0]['ProtectedVolumes'] -join ',') | Should Be 'C:'
        }
    }
    Context 'marks EWF unknown when ewfmgr is missing' {
        It 'marks EWF unknown when ewfmgr is missing' {
            Mock Get-CrFilterDriverInfo -ParameterFilter { $Service -eq 'ewf' } { return @{ Installed = $true; Start = 0 } }
            $ewf = @(@((Get-CrWriteFilterState)['Filters']) | Where-Object { $_['Type'] -eq 'EWF' })
            $ewf.Count | Should Be 1
            $ewf[0]['DriverInstalled'] | Should Be $true
            $ewf[0]['StateKnown'] | Should Be $false
        }
    }
    Context 'marks EWF unknown when no output can be parsed' {
        It 'marks EWF unknown when no output can be parsed' {
            Mock Get-CrFilterDriverInfo -ParameterFilter { $Service -eq 'ewf' } { return @{ Installed = $true; Start = 0 } }
            Mock Invoke-CrSystemTool -ParameterFilter { $Name -eq 'ewfmgr.exe' } { return @{ Present = $true; Output = @('unexpected'); ExitCode = 0 } }
            $ewf = @(@((Get-CrWriteFilterState)['Filters']) | Where-Object { $_['Type'] -eq 'EWF' })
            $ewf[0]['StateKnown'] | Should Be $false
        }
    }
    Context 'parses FBWF and marks unmappable device paths unknown' {
        It 'parses FBWF and marks unmappable device paths unknown' {
            Mock Get-CrFilterDriverInfo -ParameterFilter { $Service -eq 'fbwf' } { return @{ Installed = $true; Start = 1 } }
            Mock Invoke-CrSystemTool -ParameterFilter { $Name -eq 'fbwfmgr.exe' } { return @{ Present = $true; Output = (Get-TestFbwfLines); ExitCode = 0 } }
            $fb = @(@((Get-CrWriteFilterState)['Filters']) | Where-Object { $_['Type'] -eq 'FBWF' })[0]
            $fb['StateKnown'] | Should Be $true
            $fb['CurrentEnabled'] | Should Be $true
            ($fb['ProtectedVolumes'] -join ',') | Should Be 'C:'
            Mock Invoke-CrSystemTool -ParameterFilter { $Name -eq 'fbwfmgr.exe' } {
                return @{ Present = $true; Output = (Get-TestFbwfLines -Volume '\Device\HarddiskVolume2'); ExitCode = 0 }
            }
            $fb = @(@((Get-CrWriteFilterState)['Filters']) | Where-Object { $_['Type'] -eq 'FBWF' })[0]
            $fb['StateKnown'] | Should Be $false
        }
    }
    Context 'reads UWF from WMI (current-session protected volumes only)' {
        It 'reads UWF from WMI (current-session protected volumes only)' {
            Mock Get-CrFilterDriverInfo -ParameterFilter { $Service -eq 'uwfvol' } { return @{ Installed = $true; Start = 0 } }
            Mock Get-CrPreflightWmi -ParameterFilter { $Class -eq 'UWF_Filter' } {
                return New-Object PSObject -Property @{ CurrentEnabled = $true; NextEnabled = $false }
            }
            Mock Get-CrPreflightWmi -ParameterFilter { $Class -eq 'UWF_Volume' } {
                return @((New-Object PSObject -Property @{ CurrentSession = $true; DriveLetter = 'C:'; Protected = $true }),
                         (New-Object PSObject -Property @{ CurrentSession = $false; DriveLetter = 'D:'; Protected = $true }),
                         (New-Object PSObject -Property @{ CurrentSession = $true; DriveLetter = 'E:'; Protected = $false }))
            }
            $uwf = @(@((Get-CrWriteFilterState)['Filters']) | Where-Object { $_['Type'] -eq 'UWF' })[0]
            $uwf['StateKnown'] | Should Be $true
            $uwf['CurrentEnabled'] | Should Be $true
            $uwf['NextEnabled'] | Should Be $false
            ($uwf['ProtectedVolumes'] -join ',') | Should Be 'C:'
        }
    }
    Context 'marks UWF unknown when WMI is not available' {
        It 'marks UWF unknown when WMI is not available' {
            Mock Get-CrFilterDriverInfo -ParameterFilter { $Service -eq 'uwfvol' } { return @{ Installed = $true; Start = 0 } }
            $uwf = @(@((Get-CrWriteFilterState)['Filters']) | Where-Object { $_['Type'] -eq 'UWF' })[0]
            $uwf['DriverInstalled'] | Should Be $true
            $uwf['StateKnown'] | Should Be $false
        }
    }
}

Describe 'Get-CrWriteFilterDecision (D19)' {
    $master = @('D:\SQLData\master.mdf', 'D:\SQLData\mastlog.ldf')

    It 'blocks nothing without an installed filter' {
        $wf = @{ Filters = @((New-TestFilter -Installed $false), (New-TestFilter -Type 'UWF' -Installed $false -Known $false)); Error = $null }
        $d = Get-CrWriteFilterDecision -WriteFilter $wf -SystemDrive 'C:' -SqlMasterFiles $master
        $d['BlockApply'] | Should Be $false
        $d['BlockSql'] | Should Be $false
    }
    It 'blocks -Apply when the system volume is protected in the current session' {
        $wf = @{ Filters = @((New-TestFilter -Volumes @('C:'))); Error = $null }
        $d = Get-CrWriteFilterDecision -WriteFilter $wf -SystemDrive 'C:' -SqlMasterFiles $master
        $d['BlockApply'] | Should Be $true
        $d['BlockSql'] | Should Be $false
    }
    It 'does not count a volume with a pending whole-volume commit' {
        $wf = @{ Filters = @((New-TestFilter -Commit $true -Volumes @('C:'))); Error = $null }
        (Get-CrWriteFilterDecision -WriteFilter $wf -SystemDrive 'C:' -SqlMasterFiles $master)['BlockApply'] | Should Be $false
    }
    It 'does not count a filter enabled only for the next session' {
        $wf = @{ Filters = @((New-TestFilter -Current $false -Next $true -Volumes @('C:'))); Error = $null }
        (Get-CrWriteFilterDecision -WriteFilter $wf -SystemDrive 'C:' -SqlMasterFiles $master)['BlockApply'] | Should Be $false
    }
    It 'counts a filter disabled for the next session but enabled now' {
        $wf = @{ Filters = @((New-TestFilter -Type 'UWF' -Current $true -Next $false -Volumes @('c:'))); Error = $null }
        (Get-CrWriteFilterDecision -WriteFilter $wf -SystemDrive 'C:' -SqlMasterFiles @())['BlockApply'] | Should Be $true
    }
    It 'blocks only the SQL slots when the master volume is protected' {
        $wf = @{ Filters = @((New-TestFilter -Type 'FBWF' -Volumes @('D:'))); Error = $null }
        $d = Get-CrWriteFilterDecision -WriteFilter $wf -SystemDrive 'C:' -SqlMasterFiles $master
        $d['BlockApply'] | Should Be $false
        $d['BlockSql'] | Should Be $true
    }
    It 'does not block SQL when master files are on an unprotected volume' {
        $wf = @{ Filters = @((New-TestFilter -Volumes @('E:'))); Error = $null }
        (Get-CrWriteFilterDecision -WriteFilter $wf -SystemDrive 'C:' -SqlMasterFiles $master)['BlockSql'] | Should Be $false
    }
    It 'treats an unknown state with an installed driver as protected everywhere' {
        $wf = @{ Filters = @((New-TestFilter -Known $false -Current $null -Next $null -Volumes @())); Error = $null }
        $d = Get-CrWriteFilterDecision -WriteFilter $wf -SystemDrive 'C:' -SqlMasterFiles $master
        $d['BlockApply'] | Should Be $true
        $d['BlockSql'] | Should Be $true
        (Get-CrWriteFilterDecision -WriteFilter $wf -SystemDrive 'C:' -SqlMasterFiles @())['BlockSql'] | Should Be $false
    }
    It 'treats an unreadable write-filter state as protected' {
        $d = Get-CrWriteFilterDecision -WriteFilter @{ Filters = @(); Error = 'failed' } -SystemDrive 'C:' -SqlMasterFiles @()
        $d['BlockApply'] | Should Be $true
        @($d['Reasons']).Count | Should Not Be 0
    }
    It 'blocks SQL for a master file without drive letter while a filter is active' {
        $wf = @{ Filters = @((New-TestFilter -Volumes @('E:'))); Error = $null }
        (Get-CrWriteFilterDecision -WriteFilter $wf -SystemDrive 'C:' -SqlMasterFiles @('\\?\Volume{0}\master.mdf'))['BlockSql'] | Should Be $true
    }
}

Describe 'Get-CrPreflightSlots' {
    It 'returns the slots of the managed Windows entries, not of Disable and Check entries' {
        $slots = Get-CrPreflightSlots -Config $TestConfig -Kind 'Windows'
        @($slots).Count | Should Be 4
        foreach ($slot in $WindowsSlotNames) { (@($slots) -contains $slot) | Should Be $true }
    }
    It 'returns the SQL slots' {
        $slots = Get-CrPreflightSlots -Config $TestConfig -Kind 'SqlLogin'
        (@($slots) -join ',') | Should Be 'SQLApplication,SQLScript,SQLService'
    }
    It 'includes the slots of candidates' {
        $cfg = @{ Accounts = @(@{ Id = 'AppUser'; Kind = 'Windows'
                                  Candidates = @(@{ Name = 'ApplicationUser'; Credential = 'AppUserApplication' }, @{ Sid = 'RID-500'; Credential = 'AppUserBuiltinAdmin' }) }) }
        $slots = Get-CrPreflightSlots -Config $cfg -Kind 'Windows'
        (@($slots) -join ',') | Should Be 'AppUserApplication,AppUserBuiltinAdmin'
    }
}

Describe 'Get-CrDependentDiscoveryErrors' {
    It 'returns nothing when the sections were read or are absent' {
        $s = @{
            Services = @(@{ Name = 'TestSvc'; StartName = '.\ApplicationUser'; StartNameSid = 'S-1-5-21-1000-2000-3000-1003' })
            Tasks    = @()
            ComPlus  = @(@{ Name = 'TestApp'; Activation = 'Server'; Identity = 'ApplicationUser'; IdentitySid = 'S-1-5-21-1000-2000-3000-1003' })
        }
        # Comma-returned: assign the result before wrapping it in @().
        $e = Get-CrDependentDiscoveryErrors -State $s
        @($e).Count | Should Be 0
        $e = Get-CrDependentDiscoveryErrors -State @{}
        @($e).Count | Should Be 0
    }
    It 'reports a failed section as "Section: message"' {
        $s = @{ Services = @(); Tasks = @(); ComPlus = @{ Error = 'catalog unreachable' } }
        $e = Get-CrDependentDiscoveryErrors -State $s
        @($e).Count | Should Be 1
        $e[0] | Should Be 'ComPlus: catalog unreachable'
    }
    It 'reports every failed section in the order Services, Tasks, ComPlus' {
        $s = @{ ComPlus = @{ Error = 'c failed' }; Tasks = @{ Error = 't failed' }; Services = @{ Error = 's failed' } }
        $e = Get-CrDependentDiscoveryErrors -State $s
        @($e).Count | Should Be 3
        ($e -join '|') | Should Be 'Services: s failed|Tasks: t failed|ComPlus: c failed'
    }
    It 'ignores per-item errors in a section that was read (not a hashtable)' {
        # One unreadable task folder is an item with Error in the Tasks array (a Plan finding), not a failed section.
        $s = @{ Services = @(); Tasks = @(@{ Path = '\Locked'; UserId = $null; UserSid = $null; LogonType = $null; Enabled = $null; Error = 'Tasks: access denied' }); ComPlus = @() }
        $e = Get-CrDependentDiscoveryErrors -State $s
        @($e).Count | Should Be 0
    }
    It 'ignores a section hashtable without an error' {
        $s = @{ Services = @{ Error = $null }; Tasks = @{ Error = '' } }
        $e = Get-CrDependentDiscoveryErrors -State $s
        @($e).Count | Should Be 0
    }
}

Describe 'Invoke-CrPreflight' {
    Mock Test-CrNativeReady { return $true }

    It 'passes a healthy machine' {
        $r = Invoke-CrPreflight -State (New-TestPreflightState) -Config $TestConfig
        $r['MachineBlocked'] | Should Be $false
        $r['BlockedSlots'].Count | Should Be 0
        (Test-AnyFinding $r 'Blocked' '.') | Should Be $false
    }
    It 'accepts Windows 7 SP1 and rejects Windows 7 RTM and Windows 8.1' {
        $s = New-TestPreflightState; $s['Computer']['OsVersion'] = '6.1.7601'
        (Invoke-CrPreflight -State $s -Config $TestConfig)['MachineBlocked'] | Should Be $false
        $s['Computer']['OsVersion'] = '6.1.7600'
        (Invoke-CrPreflight -State $s -Config $TestConfig)['MachineBlocked'] | Should Be $true
        $s['Computer']['OsVersion'] = '6.3.9600'
        (Invoke-CrPreflight -State $s -Config $TestConfig)['MachineBlocked'] | Should Be $true
    }
    It 'blocks a 32-bit OS, a 32-bit process, a restricted language mode and a non-elevated run' {
        foreach ($case in @(@{ Is64BitOs = $false }, @{ Is64BitProcess = $false }, @{ LanguageMode = 'ConstrainedLanguage' }, @{ IsElevated = $false })) {
            $s = New-TestPreflightState
            foreach ($k in $case.Keys) { $s['Computer'][$k] = $case[$k] }
            $r = Invoke-CrPreflight -State $s -Config $TestConfig
            $r['MachineBlocked'] | Should Be $true
            (Test-AnyFinding $r 'Blocked' '.') | Should Be $true
        }
    }
    Context 'blocks when the native helpers did not compile' {
        It 'blocks when the native helpers did not compile' {
            Mock Test-CrNativeReady { return $false }
            $r = Invoke-CrPreflight -State (New-TestPreflightState) -Config $TestConfig
            $r['MachineBlocked'] | Should Be $true
            (Test-AnyFinding $r 'Blocked' 'Add-Type') | Should Be $true
        }
    }
    It 'blocks when the computer information failed' {
        $s = New-TestPreflightState; $s['Computer'] = @{ Error = 'WMI broken' }
        (Invoke-CrPreflight -State $s -Config $TestConfig)['MachineBlocked'] | Should Be $true
    }
    It 'reports a domain-joined machine as a warning only' {
        $s = New-TestPreflightState; $s['Computer']['PartOfDomain'] = $true
        $r = Invoke-CrPreflight -State $s -Config $TestConfig
        $r['MachineBlocked'] | Should Be $false
        (Test-AnyFinding $r 'Info' 'domain-joined') | Should Be $true
    }
    It 'blocks all of -Apply when the system volume is protected (D19)' {
        $s = New-TestPreflightState
        $s['WriteFilter'] = @{ Filters = @((New-TestFilter -Type 'UWF' -Volumes @('C:'))); Error = $null }
        $r = Invoke-CrPreflight -State $s -Config $TestConfig
        $r['MachineBlocked'] | Should Be $true
        (Test-AnyFinding $r 'Blocked' 'system volume') | Should Be $true
    }
    It 'blocks the SQL slots when the master volume is protected (D19)' {
        $s = New-TestPreflightState
        $s['Sql']['MasterFiles'] = @('D:\SQLData\master.mdf')
        $s['WriteFilter'] = @{ Filters = @((New-TestFilter -Type 'EWF' -Volumes @('D:'))); Error = $null }
        $r = Invoke-CrPreflight -State $s -Config $TestConfig
        $r['MachineBlocked'] | Should Be $false
        foreach ($slot in $SqlSlotNames) { $r['BlockedSlots'].ContainsKey($slot) | Should Be $true }
        $r['BlockedSlots'].Count | Should Be 3
        $r['BlockedSlots']['SQLScript'] | Should Match 'write filter'
    }
    It 'blocks the SQL slots for unsupported versions and accepts 9 to 14' {
        foreach ($v in @(8, 15)) {
            $s = New-TestPreflightState; $s['Sql']['MajorVersion'] = $v
            $r = Invoke-CrPreflight -State $s -Config $TestConfig
            $r['BlockedSlots'].ContainsKey('SQLApplication') | Should Be $true
            $r['BlockedSlots']['SQLApplication'] | Should Match 'version'
        }
        foreach ($v in @(9, 10, 14)) {
            $s = New-TestPreflightState; $s['Sql']['MajorVersion'] = $v
            (Invoke-CrPreflight -State $s -Config $TestConfig)['BlockedSlots'].Count | Should Be 0
        }
    }
    It 'blocks the SQL slots for each readiness failure' {
        $cases = @(
            @{ Key = 'ServiceState'; Value = 'Stopped'; Pattern = 'not running' },
            @{ Key = 'ConnectedAsSysadmin'; Value = $false; Pattern = 'not sysadmin' },
            @{ Key = 'IsIntegratedSecurityOnly'; Value = $true; Pattern = 'mixed-mode' },
            @{ Key = 'Connected'; Value = $false; Pattern = 'no connection' },
            @{ Key = 'DefaultInstancePresent'; Value = $false; Pattern = 'no default' }
        )
        foreach ($c in $cases) {
            $s = New-TestPreflightState; $s['Sql'][$c['Key']] = $c['Value']
            $r = Invoke-CrPreflight -State $s -Config $TestConfig
            $r['MachineBlocked'] | Should Be $false
            foreach ($slot in $SqlSlotNames) { $r['BlockedSlots'][$slot] | Should Match $c['Pattern'] }
            foreach ($slot in $WindowsSlotNames) { $r['BlockedSlots'].ContainsKey($slot) | Should Be $false }
        }
    }
    It 'does not check SQL without SQL slots in the config' {
        $s = New-TestPreflightState; $s['Sql'] = @{ DefaultInstancePresent = $false; Error = 'none' }
        $cfg = @{ Accounts = @(@{ Id = 'BiCAAdmin'; Kind = 'Windows'; Credential = 'BiCAAdmin' }) }
        (Invoke-CrPreflight -State $s -Config $cfg)['BlockedSlots'].Count | Should Be 0
    }
    It 'blocks the Windows slots when the lockout policy is unknown' {
        $s = New-TestPreflightState; $s['Policy'] = @{ Error = 'NetUserModalsGet failed' }
        $r = Invoke-CrPreflight -State $s -Config $TestConfig
        $r['MachineBlocked'] | Should Be $false
        foreach ($slot in $WindowsSlotNames) { $r['BlockedSlots'].ContainsKey($slot) | Should Be $true }
        foreach ($slot in $SqlSlotNames) { $r['BlockedSlots'].ContainsKey($slot) | Should Be $false }
    }
    It 'reports ForceGuest and unknown complexity as information' {
        $s = New-TestPreflightState; $s['Policy']['ForceGuest'] = $true; $s['Policy']['ComplexityEnabled'] = $null
        $r = Invoke-CrPreflight -State $s -Config $TestConfig
        (Test-AnyFinding $r 'Info' 'ForceGuest') | Should Be $true
        (Test-AnyFinding $r 'Info' 'complexity') | Should Be $true
    }
    It 'blocks the Windows slots, not the SQL slots or the machine, when a dependent discovery section failed (D24)' {
        $s = New-TestPreflightState
        $s['Services'] = @(); $s['Tasks'] = @()
        $s['ComPlus'] = @{ Error = 'catalog unreachable' }
        $r = Invoke-CrPreflight -State $s -Config $TestConfig
        $r['MachineBlocked'] | Should Be $false
        $r['BlockedSlots'].Count | Should Be 4
        foreach ($slot in $WindowsSlotNames) {
            $r['BlockedSlots'].ContainsKey($slot) | Should Be $true
            ([string]$r['BlockedSlots'][$slot]).StartsWith('Dependents unknown') | Should Be $true
            $r['BlockedSlots'][$slot] | Should Match 'ComPlus: catalog unreachable'
        }
        foreach ($slot in $SqlSlotNames) { $r['BlockedSlots'].ContainsKey($slot) | Should Be $false }
        $slotFindings = @(Get-TestFindings $r 'Blocked' '^Dependents unknown')
        $slotFindings.Count | Should Be 4
        foreach ($f in $slotFindings) { $f['Area'] | Should Be 'Discovery' }
    }
    It 'adds one Blocked finding that no account is disabled in this run' {
        $s = New-TestPreflightState
        $s['ComPlus'] = @{ Error = 'catalog unreachable' }
        $r = Invoke-CrPreflight -State $s -Config $TestConfig
        $f = @(Get-TestFindings $r 'Blocked' '^No account is disabled')
        $f.Count | Should Be 1
        $f[0]['Area'] | Should Be 'Discovery'
        $f[0]['Slot'] | Should BeNullOrEmpty
        $f[0]['Detail'] | Should Be 'ComPlus: catalog unreachable'
    }
    It 'names every failed section once, in the slot reasons and the finding' {
        $s = New-TestPreflightState
        $s['Services'] = @{ Error = 'WMI broken' }
        $s['Tasks'] = @{ Error = 'scheduler not available' }
        $r = Invoke-CrPreflight -State $s -Config $TestConfig
        $r['MachineBlocked'] | Should Be $false
        $r['BlockedSlots']['AppUser'] | Should Be 'Dependents unknown (discovery failed): Services: WMI broken; Tasks: scheduler not available'
        $f = @(Get-TestFindings $r 'Blocked' '^No account is disabled')
        $f.Count | Should Be 1
        $f[0]['Detail'] | Should Be 'Services: WMI broken; Tasks: scheduler not available'
    }
    It 'adds the discovery reason to a slot blocked for another reason' {
        $s = New-TestPreflightState
        $s['Policy'] = @{ Error = 'NetUserModalsGet failed' }
        $s['Tasks'] = @{ Error = 'scheduler not available' }
        $r = Invoke-CrPreflight -State $s -Config $TestConfig
        $r['BlockedSlots']['BiCARemote'] | Should Match 'lockout budget'
        $r['BlockedSlots']['BiCARemote'] | Should Match '; Dependents unknown \(discovery failed\): Tasks: scheduler not available$'
    }
    It 'blocks nothing for dependents that were read, even with an unreadable task folder' {
        $s = New-TestPreflightState
        $s['Services'] = @()
        $s['Tasks'] = @(@{ Path = '\Locked'; UserId = $null; UserSid = $null; LogonType = $null; Enabled = $null; Error = 'Tasks: access denied' })
        $s['ComPlus'] = @()
        $r = Invoke-CrPreflight -State $s -Config $TestConfig
        $r['BlockedSlots'].Count | Should Be 0
        (Test-AnyFinding $r 'Blocked' '.') | Should Be $false
    }
}
