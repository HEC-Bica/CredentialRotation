# Preflight.ps1 - environment, local password policy, write filter (D19), preflight checks (docs/PLAN.md section 6 step 2).
# Read-only. External calls (WMI, secedit, tools, registry) are behind small internal functions for tests.

#region External calls (internal, mocked in tests)

# System32 of the OS; a 32-bit process on 64-bit Windows reaches it via sysnative.
function Get-CrSystemDirectory {
    $windir = $env:windir
    if (-not $windir) { $windir = $env:SystemRoot }
    $sysnative = Join-Path $windir 'sysnative'
    if ([IntPtr]::Size -eq 4 -and (Test-Path -LiteralPath $sysnative)) { return $sysnative }
    return (Join-Path $windir 'System32')
}

function Get-CrPreflightWmi {
    param([string]$Class, [string]$Namespace = 'root\cimv2', [string]$Filter)
    if ($Filter) {
        return @(Get-WmiObject -Namespace $Namespace -Class $Class -Filter $Filter -ErrorAction Stop)
    }
    return @(Get-WmiObject -Namespace $Namespace -Class $Class -ErrorAction Stop)
}

function Get-CrProcessEnvironment {
    $principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
    $psv = $PSVersionTable.PSVersion
    return @{
        Is64BitProcess = ([IntPtr]::Size -eq 8)
        Wow64          = [bool]$env:PROCESSOR_ARCHITEW6432
        PSVersion      = ('{0}.{1}' -f $psv.Major, $psv.Minor)
        ClrVersion     = [string]$PSVersionTable.CLRVersion
        LanguageMode   = [string]$ExecutionContext.SessionState.LanguageMode
        IsElevated     = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        SystemDrive    = $env:SystemDrive
    }
}

# Display-only call of a System32 tool. Returns @{ Present; Output (string[]); ExitCode }.
function Invoke-CrSystemTool {
    param([string]$Name, [string[]]$Arguments)
    $ErrorActionPreference = 'Continue'
    $path = Join-Path (Get-CrSystemDirectory) $Name
    if (-not (Test-Path -LiteralPath $path)) { return @{ Present = $false; Output = @(); ExitCode = $null } }
    $out = @(& $path $Arguments 2>&1 | ForEach-Object { [string]$_ } | Where-Object { $_ -and $_.Trim() })
    return @{ Present = $true; Output = $out; ExitCode = $LASTEXITCODE }
}

# secedit /export into Path (no secrets involved).
function Invoke-CrSeceditExport {
    param([string]$Path)
    $ErrorActionPreference = 'Continue'
    $exe = Join-Path (Get-CrSystemDirectory) 'secedit.exe'
    $null = & $exe /export /cfg $Path /areas SECURITYPOLICY /quiet 2>&1
    return $LASTEXITCODE
}

function Get-CrFilterDriverInfo {
    param([string]$Service)
    $v = Get-CrRegistryValue -Path ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $Service) -Name 'Start'
    return @{ Installed = [bool]$v['Exists']; Start = $v['Value'] }
}

#endregion

#region Computer and policy

function Get-CrRestrictedComputerPattern {
    param($Config)
    if ($Config -is [hashtable]) {
        foreach ($a in (ConvertTo-CrArray $Config['Accounts'])) {
            if ($a -is [hashtable] -and $a['AutoLogon'] -is [hashtable] -and $a['AutoLogon']['RestrictedComputerPattern']) {
                return [string]$a['AutoLogon']['RestrictedComputerPattern']
            }
        }
    }
    return '^SM'
}

function Get-CrComputerInfo {
    param($Config)
    $info = @{
        Name = $env:COMPUTERNAME; IsSm = $false; OsVersion = $null; OsCaption = $null; Is64BitOs = $null
        Is64BitProcess = $null; PSVersion = $null; ClrVersion = $null; LanguageMode = $null; IsElevated = $null
        PartOfDomain = $null; MachineSid = $null; SystemDrive = $env:SystemDrive; Error = $null
    }
    try {
        $p = Get-CrProcessEnvironment
        foreach ($k in @('Is64BitProcess', 'PSVersion', 'ClrVersion', 'LanguageMode', 'IsElevated')) { $info[$k] = $p[$k] }
        if ($p['SystemDrive']) { $info['SystemDrive'] = $p['SystemDrive'] }

        $os = @(Get-CrPreflightWmi -Class 'Win32_OperatingSystem')[0]
        $cs = @(Get-CrPreflightWmi -Class 'Win32_ComputerSystem')[0]
        if ($cs -and $cs.Name) { $info['Name'] = [string]$cs.Name }
        if ($cs) { $info['PartOfDomain'] = [bool]$cs.PartOfDomain }
        if ($os) {
            $info['OsVersion'] = [string]$os.Version
            $info['OsCaption'] = [string]$os.Caption
            if ($os.SystemDrive) { $info['SystemDrive'] = [string]$os.SystemDrive }
            if ($os.OSArchitecture) {
                $info['Is64BitOs'] = ([string]$os.OSArchitecture -match '64')
            } else {
                $info['Is64BitOs'] = ([bool]$p['Is64BitProcess'] -or [bool]$p['Wow64'])
            }
        }
    } catch {
        $info['Error'] = $_.Exception.Message
    }
    try {
        $pattern = Get-CrRestrictedComputerPattern -Config $Config
        $info['IsSm'] = [regex]::IsMatch([string]$info['Name'], $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    } catch {
        if (-not $info['Error']) { $info['Error'] = 'RestrictedComputerPattern: ' + $_.Exception.Message }
    }
    try {
        $info['MachineSid'] = Get-CrMachineSid
    } catch {
        $info['MachineSid'] = $null
    }
    return $info
}

# [System Access] of a secedit export. The temporary file is always deleted.
function Get-CrSeceditSystemAccess {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('cr-secedit-{0}.inf' -f [guid]::NewGuid().ToString())
    $result = @{}
    try {
        $code = Invoke-CrSeceditExport -Path $tmp
        if (-not (Test-Path -LiteralPath $tmp)) { throw ('secedit export produced no file (exit code {0}).' -f $code) }
        $section = ''
        foreach ($line in @(Get-Content -LiteralPath $tmp)) {
            if ($null -eq $line) { continue }
            if ($line -match '^\s*\[(.+)\]\s*$') { $section = $Matches[1]; continue }
            if ($section -ne 'System Access') { continue }
            if ($line -match '^\s*([^=]+?)\s*=\s*(.*?)\s*$') { $result[$Matches[1]] = $Matches[2] }
        }
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
    return $result
}

function Get-CrPasswordPolicy {
    $p = @{
        MinPasswordLength = $null; MaxPasswordAgeSeconds = $null; MinPasswordAgeSeconds = $null; PasswordHistoryLength = $null
        LockoutThreshold = $null; LockoutDurationSeconds = $null; LockoutObservationSeconds = $null
        ComplexityEnabled = $null; ForceGuest = $null; ComplexityError = $null; Error = $null
    }
    try {
        $m = Get-CrUserModals
        foreach ($k in @('MinPasswordLength', 'PasswordHistoryLength', 'LockoutThreshold')) {
            if ($null -ne $m[$k]) { $p[$k] = [int]$m[$k] }
        }
        foreach ($k in @('MaxPasswordAgeSeconds', 'MinPasswordAgeSeconds', 'LockoutDurationSeconds', 'LockoutObservationSeconds')) {
            if ($null -ne $m[$k]) { $p[$k] = [long]$m[$k] }
        }
        # TIMEQ_FOREVER (0xFFFFFFFF) = never
        if ($null -ne $p['MaxPasswordAgeSeconds'] -and ($p['MaxPasswordAgeSeconds'] -eq 4294967295 -or $p['MaxPasswordAgeSeconds'] -lt 0)) {
            $p['MaxPasswordAgeSeconds'] = [long]-1
        }
    } catch {
        $p['Error'] = 'NetUserModalsGet failed: ' + $_.Exception.Message
    }
    try {
        $sa = Get-CrSeceditSystemAccess
        if ($sa.ContainsKey('PasswordComplexity')) {
            $p['ComplexityEnabled'] = ([int]$sa['PasswordComplexity'] -ne 0)
        } else {
            $p['ComplexityError'] = 'PasswordComplexity missing from the secedit export.'
        }
    } catch {
        $p['ComplexityError'] = 'secedit export failed: ' + $_.Exception.Message
    }
    try {
        $fg = Get-CrRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'forceguest'
        if ($fg['Exists']) { $p['ForceGuest'] = ([int]$fg['Value'] -ne 0) } else { $p['ForceGuest'] = $false }
    } catch {
        $p['ForceGuest'] = $null
    }
    return $p
}

#endregion

#region Write filter (D19)

function ConvertTo-CrDriveKey {
    param([string]$Path)
    if (-not $Path) { return $null }
    $m = [regex]::Match($Path.Trim(), '^([A-Za-z]):')
    if ($m.Success) { return ($m.Groups[1].Value.ToUpperInvariant() + ':') }
    return $null
}

# ewfmgr <drive> output: "State ENABLED|DISABLED" and "Boot Command <cmd>".
function ConvertFrom-CrEwfMgrOutput {
    param([string[]]$Lines)
    $r = @{ Parsed = $false; CurrentEnabled = $null; NextEnabled = $null; CommitPending = $false; BootCommand = $null }
    foreach ($line in (ConvertTo-CrArray $Lines)) {
        if (-not $line) { continue }
        if ($line -match '^\s*State\s+(ENABLED|DISABLED)\s*$') {
            $r['Parsed'] = $true
            $r['CurrentEnabled'] = ($Matches[1] -eq 'ENABLED')
        } elseif ($line -match '^\s*Boot Command\s+(\S+)') {
            $r['BootCommand'] = $Matches[1].ToUpperInvariant()
        }
    }
    if (-not $r['Parsed']) { return $r }
    $cmd = [string]$r['BootCommand']
    $r['NextEnabled'] = $r['CurrentEnabled']
    if ($cmd -match 'COMMIT') { $r['CommitPending'] = $true }
    if ($cmd -match 'DISABLE') {
        $r['NextEnabled'] = $false
    } elseif ($cmd -match 'ENABLE') {
        $r['NextEnabled'] = $true
    }
    return $r
}

# fbwfmgr /displayconfig output: a current-session and a next-session block with "filter state:" and
# "protected volume list:". Volumes given as device paths can't be mapped to drive letters reliably.
function ConvertFrom-CrFbwfMgrOutput {
    param([string[]]$Lines)
    $r = @{ Parsed = $false; CurrentEnabled = $null; NextEnabled = $null; CurrentVolumes = @(); NextVolumes = @(); Unmapped = @() }
    $vols = @{ current = (New-Object System.Collections.ArrayList); next = (New-Object System.Collections.ArrayList) }
    $unmapped = New-Object System.Collections.ArrayList
    $section = $null
    $inList = $false
    foreach ($line in (ConvertTo-CrArray $Lines)) {
        if (-not $line) { continue }
        if ($line -match 'current session') { $section = 'current'; $inList = $false; continue }
        if ($line -match 'next session') { $section = 'next'; $inList = $false; continue }
        if (-not $section) { continue }
        if ($line -match '^\s*filter state:\s*(enabled|disabled)') {
            $inList = $false
            $enabled = ($Matches[1] -ieq 'enabled')
            if ($section -eq 'current') { $r['CurrentEnabled'] = $enabled; $r['Parsed'] = $true } else { $r['NextEnabled'] = $enabled }
            continue
        }
        $items = @()
        if ($line -match '^\s*protected volume list:\s*(.*)$') {
            $inList = $true
            $items = @($Matches[1] -split '[\s,;]+' | Where-Object { $_ })
        } elseif ($inList -and $line -match '^\s*([A-Za-z]:\\?|\\Device\\[^\s:]+)\s*$') {
            $items = @($Matches[1])
        } else {
            $inList = $false
            continue
        }
        foreach ($it in $items) {
            $k = ConvertTo-CrDriveKey $it
            if ($k) {
                if ($vols[$section] -notcontains $k) { [void]$vols[$section].Add($k) }
            } elseif ($unmapped -notcontains $it) {
                [void]$unmapped.Add($it)
            }
        }
    }
    $r['CurrentVolumes'] = $vols['current'].ToArray()
    $r['NextVolumes'] = $vols['next'].ToArray()
    $r['Unmapped'] = $unmapped.ToArray()
    return $r
}

function New-CrWriteFilterEntry {
    param([string]$Type)
    return @{ Type = $Type; DriverInstalled = $false; StateKnown = $true; CurrentEnabled = $false; NextEnabled = $false
              CommitPending = $false; ProtectedVolumes = @(); Detail = $null }
}

function Get-CrOutputSummary {
    param($Lines)
    $a = ConvertTo-CrArray $Lines
    if ($a.Count -eq 0) { return '(no output)' }
    $max = 12
    if ($a.Count -lt $max) { $max = $a.Count }
    $text = ($a[0..($max - 1)] | ForEach-Object { ([string]$_).Trim() }) -join ' | '
    if ($a.Count -gt $max) { $text = $text + ' | ...' }
    return $text
}

# Names of the EWF protected-volume configuration keys (Volume0, Volume1, ...). Separate for mocking.
function Get-CrEwfProtectedVolumeKeys {
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\ewf\Parameters\Protected'
    if (-not (Test-Path -LiteralPath $key)) { return }
    foreach ($k in @(Get-ChildItem -LiteralPath $key -ErrorAction SilentlyContinue)) {
        if ($k.PSChildName -like 'Volume*') { $k.PSChildName }
    }
}

function Get-CrEwfState {
    $entries = New-Object System.Collections.ArrayList
    $drv = Get-CrFilterDriverInfo -Service 'ewf'
    if (-not $drv['Installed']) {
        $e = New-CrWriteFilterEntry 'EWF'
        $e['Detail'] = 'ewf driver not installed'
        [void]$entries.Add($e)
        return , $entries.ToArray()
    }
    # The driver is often present on Windows Embedded images without protecting anything. Without a
    # configured protected volume (or with the driver disabled) EWF can't protect C:; ewfmgr then only
    # prints an error text that would otherwise count as "unknown" and block the machine.
    $configured = @(Get-CrEwfProtectedVolumeKeys)
    if ($drv['Start'] -eq 4 -or $configured.Count -eq 0) {
        $e = New-CrWriteFilterEntry 'EWF'
        $e['DriverInstalled'] = $true
        $e['Detail'] = ('ewf driver present (Start={0}) but no protected volume configured' -f $drv['Start'])
        [void]$entries.Add($e)
        return , $entries.ToArray()
    }
    $drives = New-Object System.Collections.ArrayList
    try {
        foreach ($d in @(Get-CrPreflightWmi -Class 'Win32_LogicalDisk' -Filter 'DriveType=3')) {
            $k = ConvertTo-CrDriveKey ([string]$d.DeviceID)
            if ($k -and $drives -notcontains $k) { [void]$drives.Add($k) }
        }
    } catch { }
    $sys = ConvertTo-CrDriveKey $env:SystemDrive
    if (-not $sys) { $sys = 'C:' }
    if ($drives -notcontains $sys) { [void]$drives.Insert(0, $sys) }

    $outputs = New-Object System.Collections.ArrayList
    $toolPresent = $true
    foreach ($drive in $drives) {
        $res = Invoke-CrSystemTool -Name 'ewfmgr.exe' -Arguments @($drive)
        if (-not $res['Present']) { $toolPresent = $false; break }
        $parsed = ConvertFrom-CrEwfMgrOutput -Lines $res['Output']
        [void]$outputs.Add(@{ Drive = $drive; Output = $res['Output']; Parsed = $parsed })
    }
    foreach ($o in $outputs) {
        if (-not $o['Parsed']['Parsed']) { continue }
        $e = New-CrWriteFilterEntry 'EWF'
        $e['DriverInstalled'] = $true
        $e['CurrentEnabled'] = $o['Parsed']['CurrentEnabled']
        $e['NextEnabled'] = $o['Parsed']['NextEnabled']
        $e['CommitPending'] = $o['Parsed']['CommitPending']
        $e['ProtectedVolumes'] = @($o['Drive'])
        $e['Detail'] = ('ewfmgr {0}: state {1}, boot command {2}' -f $o['Drive'], $(if ($o['Parsed']['CurrentEnabled']) { 'ENABLED' } else { 'DISABLED' }), $o['Parsed']['BootCommand'])
        [void]$entries.Add($e)
    }
    if ($entries.Count -eq 0) {
        # Driver installed, but no volume configuration could be parsed: state unknown (D19: protected).
        $e = New-CrWriteFilterEntry 'EWF'
        $e['DriverInstalled'] = $true
        $e['StateKnown'] = $false
        $e['CurrentEnabled'] = $null
        $e['NextEnabled'] = $null
        if (-not $toolPresent) {
            $e['Detail'] = ('ewf driver installed (Start={0}), ewfmgr.exe not found' -f $drv['Start'])
        } else {
            $first = $null
            if ($outputs.Count -gt 0) { $first = $outputs[0]['Output'] }
            $e['Detail'] = ('ewf driver installed (Start={0}), ewfmgr output not parsed: {1}' -f $drv['Start'], (Get-CrOutputSummary $first))
        }
        [void]$entries.Add($e)
    }
    return , $entries.ToArray()
}

function Get-CrFbwfState {
    $e = New-CrWriteFilterEntry 'FBWF'
    $drv = Get-CrFilterDriverInfo -Service 'fbwf'
    if (-not $drv['Installed']) { $e['Detail'] = 'fbwf driver not installed'; return $e }
    $e['DriverInstalled'] = $true
    $res = Invoke-CrSystemTool -Name 'fbwfmgr.exe' -Arguments @('/displayconfig')
    if (-not $res['Present']) {
        $e['StateKnown'] = $false; $e['CurrentEnabled'] = $null; $e['NextEnabled'] = $null
        $e['Detail'] = ('fbwf driver installed (Start={0}), fbwfmgr.exe not found' -f $drv['Start'])
        return $e
    }
    $parsed = ConvertFrom-CrFbwfMgrOutput -Lines $res['Output']
    if (-not $parsed['Parsed']) {
        $e['StateKnown'] = $false; $e['CurrentEnabled'] = $null; $e['NextEnabled'] = $null
        $e['Detail'] = 'fbwfmgr output not parsed: ' + (Get-CrOutputSummary $res['Output'])
        return $e
    }
    $e['CurrentEnabled'] = $parsed['CurrentEnabled']
    $e['NextEnabled'] = $parsed['NextEnabled']
    $e['ProtectedVolumes'] = $parsed['CurrentVolumes']
    $e['CommitPending'] = $false   # FBWF commits single files only, never a whole volume
    $e['Detail'] = ('fbwfmgr: current {0}, next {1}, volumes {2}' -f $parsed['CurrentEnabled'], $parsed['NextEnabled'], ((ConvertTo-CrArray $parsed['CurrentVolumes']) -join ','))
    if ($parsed['CurrentEnabled'] -and @($parsed['Unmapped']).Count -gt 0) {
        $e['StateKnown'] = $false
        $e['Detail'] = $e['Detail'] + '; volumes not mappable to drive letters: ' + (@($parsed['Unmapped']) -join ',')
    }
    return $e
}

function Get-CrUwfState {
    $e = New-CrWriteFilterEntry 'UWF'
    $drv = Get-CrFilterDriverInfo -Service 'uwfvol'
    if (-not $drv['Installed']) { $e['Detail'] = 'uwfvol driver not installed'; return $e }
    $e['DriverInstalled'] = $true
    $tool = Invoke-CrSystemTool -Name 'uwfmgr.exe' -Arguments @('get-config')
    $toolText = 'uwfmgr.exe not found'
    if ($tool['Present']) { $toolText = 'uwfmgr get-config: ' + (Get-CrOutputSummary $tool['Output']) }
    try {
        $filter = @(Get-CrPreflightWmi -Namespace 'root\standardcimv2\embedded' -Class 'UWF_Filter')
        if ($filter.Count -eq 0 -or $null -eq $filter[0]) { throw 'UWF_Filter returned no instance.' }
        $volumes = @(Get-CrPreflightWmi -Namespace 'root\standardcimv2\embedded' -Class 'UWF_Volume')
        $e['CurrentEnabled'] = [bool]$filter[0].CurrentEnabled
        $e['NextEnabled'] = [bool]$filter[0].NextEnabled
        $prot = New-Object System.Collections.ArrayList
        foreach ($v in $volumes) {
            if (-not $v) { continue }
            if (-not [bool]$v.CurrentSession -or -not [bool]$v.Protected) { continue }
            $k = ConvertTo-CrDriveKey ([string]$v.DriveLetter)
            if ($k) {
                if ($prot -notcontains $k) { [void]$prot.Add($k) }
            } elseif ($e['CurrentEnabled']) {
                $e['StateKnown'] = $false
                $e['Detail'] = 'a protected UWF volume has no drive letter'
            }
        }
        $e['ProtectedVolumes'] = $prot.ToArray()
        $text = ('UWF WMI: current {0}, next {1}, protected {2}' -f $e['CurrentEnabled'], $e['NextEnabled'], ($prot.ToArray() -join ','))
        if ($e['Detail']) { $text = $text + '; ' + $e['Detail'] }
        $e['Detail'] = $text + '; ' + $toolText
    } catch {
        $e['StateKnown'] = $false; $e['CurrentEnabled'] = $null; $e['NextEnabled'] = $null
        $e['Detail'] = ('UWF WMI not available ({0}); {1}' -f $_.Exception.Message, $toolText)
    }
    return $e
}

function Get-CrWriteFilterState {
    $result = @{ Filters = @(); Error = $null }
    try {
        $list = New-Object System.Collections.ArrayList
        foreach ($e in (ConvertTo-CrArray (Get-CrEwfState))) { [void]$list.Add($e) }
        [void]$list.Add((Get-CrFbwfState))
        [void]$list.Add((Get-CrUwfState))
        $result['Filters'] = $list.ToArray()
    } catch {
        $result['Error'] = $_.Exception.Message
    }
    return $result
}

# D19: a volume is protected if a filter protects it in the current session, unless a whole-volume commit
# is pending; an installed driver with unknown state protects every volume.
function Get-CrWriteFilterDecision {
    param($WriteFilter, [string]$SystemDrive, $SqlMasterFiles)
    $reasons = New-Object System.Collections.ArrayList
    $sys = ConvertTo-CrDriveKey $SystemDrive
    if (-not $sys) { $sys = ConvertTo-CrDriveKey $env:SystemDrive }
    $protected = @{}
    $all = $false
    $allBy = New-Object System.Collections.ArrayList

    if (-not ($WriteFilter -is [hashtable]) -or $WriteFilter['Error']) {
        $all = $true
        $msg = 'Write-filter state could not be determined'
        if ($WriteFilter -is [hashtable] -and $WriteFilter['Error']) { $msg = $msg + ': ' + $WriteFilter['Error'] }
        [void]$allBy.Add($msg)
    } else {
        foreach ($f in (ConvertTo-CrArray $WriteFilter['Filters'])) {
            if (-not ($f -is [hashtable]) -or -not $f['DriverInstalled']) { continue }
            if (-not $f['StateKnown']) {
                $all = $true
                [void]$allBy.Add(('{0} driver installed but its state is unknown' -f $f['Type']))
                continue
            }
            if (-not $f['CurrentEnabled']) { continue }
            foreach ($v in (ConvertTo-CrArray $f['ProtectedVolumes'])) {
                $k = ConvertTo-CrDriveKey ([string]$v)
                if ($f['CommitPending']) {
                    [void]$reasons.Add(('{0} protects {1}, but a whole-volume commit is pending for the next shutdown: not counted as protected.' -f $f['Type'], $v))
                    continue
                }
                if (-not $k) {
                    $all = $true
                    [void]$allBy.Add(('{0} protects volume {1}, which has no drive letter' -f $f['Type'], $v))
                    continue
                }
                $protected[$k] = $f['Type']
            }
        }
    }
    if ($all) {
        [void]$reasons.Add(((@($allBy.ToArray()) -join '; ') + ': every volume counts as protected.'))
    }

    $blockApply = $false
    if ($all -or ($sys -and $protected.ContainsKey($sys))) {
        $blockApply = $true
        $by = 'unknown write-filter state'
        if ($sys -and $protected.ContainsKey($sys)) { $by = $protected[$sys] }
        [void]$reasons.Add(('System volume {0} is protected ({1}) in the current session: all of -Apply is blocked, changes would vanish at the next reboot.' -f $sys, $by))
    }

    $blockSql = $false
    $sqlDrives = New-Object System.Collections.ArrayList
    foreach ($file in (ConvertTo-CrArray $SqlMasterFiles)) {
        if (-not $file) { continue }
        $k = ConvertTo-CrDriveKey ([string]$file)
        if (-not $k) {
            if ($all -or $protected.Count -gt 0) {
                $blockSql = $true
                [void]$reasons.Add(('SQL master file {0} is on a volume without a drive letter while a write filter is active: SQL slots blocked.' -f $file))
            }
            continue
        }
        if ($sqlDrives -contains $k) { continue }
        [void]$sqlDrives.Add($k)
        if ($all -or $protected.ContainsKey($k)) {
            $blockSql = $true
            [void]$reasons.Add(('Volume {0} holding SQL master data or log files is protected: SQL slots blocked.' -f $k))
        }
    }

    return @{ BlockApply = $blockApply; BlockSql = $blockSql; Reasons = $reasons.ToArray() }
}

#endregion

#region Preflight checks

# The discovery sections the dependents come from (services, scheduled tasks, COM+) that failed as a whole.
# A failed section means the dependents of every account are unknown (PLAN 6 step 2, D24).
# Returns 'Section: message' strings (comma-returned).
function Get-CrDependentDiscoveryErrors {
    param($State)
    $list = New-Object System.Collections.ArrayList
    foreach ($section in @('Services', 'Tasks', 'ComPlus')) {
        $part = $State[$section]
        if (($part -is [hashtable]) -and $part['Error']) { [void]$list.Add(('{0}: {1}' -f $section, $part['Error'])) }
    }
    return , $list.ToArray()
}

# Slot names of the config's Windows or SqlLogin entries (incl. candidates).
function Get-CrPreflightSlots {
    param($Config, [string]$Kind)
    $slots = New-Object System.Collections.ArrayList
    if (-not ($Config -is [hashtable])) { return , $slots.ToArray() }
    foreach ($a in (ConvertTo-CrArray $Config['Accounts'])) {
        if (-not ($a -is [hashtable]) -or [string]$a['Kind'] -ne $Kind) { continue }
        $creds = New-Object System.Collections.ArrayList
        if ($a['Credential']) { [void]$creds.Add([string]$a['Credential']) }
        foreach ($c in (ConvertTo-CrArray $a['Candidates'])) {
            if ($c -is [hashtable] -and $c['Credential']) { [void]$creds.Add([string]$c['Credential']) }
        }
        foreach ($s in $creds) { if ($slots -notcontains $s) { [void]$slots.Add($s) } }
    }
    return , $slots.ToArray()
}

function Invoke-CrPreflight {
    param($State, $Config)
    $findings = New-Object System.Collections.ArrayList
    $blocked = @{}
    $machineBlocked = $false

    $blockMachine = {
        param([string]$Area, [string]$Message, [string]$Detail)
        [void]$findings.Add((New-CrFinding -Severity 'Blocked' -Area $Area -Message $Message -Detail $Detail))
    }
    $blockSlots = {
        param([string[]]$Slots, [string]$Area, [string]$Reason)
        foreach ($s in (ConvertTo-CrArray $Slots)) {
            if ($blocked.ContainsKey($s)) { $blocked[$s] = $blocked[$s] + '; ' + $Reason } else { $blocked[$s] = $Reason }
            [void]$findings.Add((New-CrFinding -Severity 'Blocked' -Area $Area -Slot $s -Message $Reason))
        }
    }

    # Environment
    $c = $State['Computer']
    if (-not ($c -is [hashtable]) -or $c['Error']) {
        $machineBlocked = $true
        $err = 'missing'
        if ($c -is [hashtable]) { $err = $c['Error'] }
        & $blockMachine 'Preflight' 'Computer information could not be read.' $err
        $c = @{}
    } else {
        $v = $null
        try { $v = New-Object System.Version([string]$c['OsVersion']) } catch { $v = $null }
        if (-not $v) {
            $machineBlocked = $true
            & $blockMachine 'Preflight' ('Unknown OS version "{0}".' -f $c['OsVersion']) $null
        } elseif ($v.Major -eq 6 -and $v.Minor -eq 1) {
            if ($v.Build -lt 7601) {
                $machineBlocked = $true
                & $blockMachine 'Preflight' ('Windows 7 without SP1 ({0}) is not supported.' -f $c['OsVersion']) $null
            }
        } elseif (-not ($v.Major -eq 10 -and $v.Minor -eq 0)) {
            $machineBlocked = $true
            & $blockMachine 'Preflight' ('Unsupported OS {0} ({1}); Windows 7 SP1 or Windows 10 required.' -f $c['OsVersion'], $c['OsCaption']) $null
        }
        if ($c['Is64BitOs'] -ne $true) {
            $machineBlocked = $true
            & $blockMachine 'Preflight' 'A 64-bit OS is required.' $null
        }
        if ($c['Is64BitProcess'] -ne $true) {
            $machineBlocked = $true
            & $blockMachine 'Preflight' 'PowerShell runs as a 32-bit process; start the tool with the launcher (64-bit PowerShell).' $null
        }
        if ([string]$c['LanguageMode'] -ne 'FullLanguage') {
            $machineBlocked = $true
            & $blockMachine 'Preflight' ('PowerShell language mode is {0}; FullLanguage is required.' -f $c['LanguageMode']) $null
        }
        if ($c['IsElevated'] -ne $true) {
            $machineBlocked = $true
            & $blockMachine 'Preflight' 'The tool is not running elevated (Run as administrator).' $null
        }
        [void]$findings.Add((New-CrFinding -Severity 'Info' -Area 'Preflight' -Message ('{0} {1}, PowerShell {2}, CLR {3}, SM machine: {4}.' -f $c['OsCaption'], $c['OsVersion'], $c['PSVersion'], $c['ClrVersion'], [bool]$c['IsSm'])))
        if ($c['PartOfDomain']) {
            [void]$findings.Add((New-CrFinding -Severity 'Info' -Area 'Preflight' -Message 'Warning: the machine is domain-joined; the tool only manages local accounts.'))
        }
    }

    $nativeReady = $false
    $nativeError = $null
    try { $nativeReady = [bool](Test-CrNativeReady) } catch { $nativeReady = $false; $nativeError = $_.Exception.Message }
    if (-not $nativeReady) {
        if (-not $nativeError) { $nativeError = $script:CrNativeError }
        $machineBlocked = $true
        & $blockMachine 'Preflight' 'Add-Type / native helpers are not available.' ([string]$nativeError)
    }

    # Local password and lockout policy (D12 needs the lockout threshold for every Windows probe)
    $windowsSlots = Get-CrPreflightSlots -Config $Config -Kind 'Windows'
    $pol = $State['Policy']
    if (-not ($pol -is [hashtable]) -or $pol['Error']) {
        $err = 'missing'
        if ($pol -is [hashtable]) { $err = $pol['Error'] }
        & $blockSlots $windowsSlots 'Policy' ('Local password/lockout policy could not be read (lockout budget D12 unknown): ' + $err)
    } else {
        $complexity = 'unknown'
        if ($pol['ComplexityEnabled'] -eq $true) { $complexity = 'on' } elseif ($pol['ComplexityEnabled'] -eq $false) { $complexity = 'off' }
        [void]$findings.Add((New-CrFinding -Severity 'Info' -Area 'Policy' -Message ('Password policy: min length {0}, complexity {1}, history {2}, min age {3}s, max age {4}s; lockout threshold {5}, duration {6}s, window {7}s.' -f $pol['MinPasswordLength'], $complexity, $pol['PasswordHistoryLength'], $pol['MinPasswordAgeSeconds'], $pol['MaxPasswordAgeSeconds'], $pol['LockoutThreshold'], $pol['LockoutDurationSeconds'], $pol['LockoutObservationSeconds'])))
        if ($null -eq $pol['ComplexityEnabled']) {
            [void]$findings.Add((New-CrFinding -Severity 'Info' -Area 'Policy' -Message 'Password complexity setting could not be read from secedit.' -Detail ([string]$pol['ComplexityError'])))
        }
        if ($pol['ForceGuest'] -eq $true) {
            [void]$findings.Add((New-CrFinding -Severity 'Info' -Area 'Policy' -Message 'ForceGuest = 1: network logons are mapped to Guest.'))
        }
    }

    # Dependents (PLAN 6 step 2, D24): without services, scheduled tasks or COM+ the dependents of every account are
    # unknown. A password set or change would break them, and an account to be disabled might still run some: the
    # Windows slots are blocked and no account is disabled (Apply.ps1 Get-CrApplyDisablePlan).
    $depErrors = Get-CrDependentDiscoveryErrors -State $State
    if ($depErrors.Count -gt 0) {
        $depText = $depErrors -join '; '
        & $blockSlots $windowsSlots 'Discovery' ('Dependents unknown (discovery failed): ' + $depText)
        [void]$findings.Add((New-CrFinding -Severity 'Blocked' -Area 'Discovery' -Message 'No account is disabled in this run: the dependents of the accounts are unknown (discovery failed).' -Detail $depText))
    }

    # Write filter (D19)
    $sqlMaster = $null
    if ($State['Sql'] -is [hashtable]) { $sqlMaster = $State['Sql']['MasterFiles'] }
    $wfDecision = Get-CrWriteFilterDecision -WriteFilter $State['WriteFilter'] -SystemDrive ([string]$c['SystemDrive']) -SqlMasterFiles $sqlMaster
    if ($State['WriteFilter'] -is [hashtable]) {
        foreach ($f in (ConvertTo-CrArray $State['WriteFilter']['Filters'])) {
            if ($f -is [hashtable] -and $f['DriverInstalled']) {
                [void]$findings.Add((New-CrFinding -Severity 'Info' -Area 'WriteFilter' -Message ('{0} driver installed.' -f $f['Type']) -Detail ([string]$f['Detail'])))
            }
        }
    }
    if ($wfDecision['BlockApply']) {
        $machineBlocked = $true
        & $blockMachine 'WriteFilter' 'The system volume is protected by a write filter: all of -Apply is blocked (audit continues).' ((ConvertTo-CrArray $wfDecision['Reasons']) -join ' ')
    }

    # SQL readiness: blocks the SQL slots only
    $sqlSlots = Get-CrPreflightSlots -Config $Config -Kind 'SqlLogin'
    if ($sqlSlots.Count -gt 0) {
        $problems = New-Object System.Collections.ArrayList
        $sql = $State['Sql']
        if (-not ($sql -is [hashtable])) {
            [void]$problems.Add('SQL state not available')
        } elseif (-not $sql['DefaultInstancePresent']) {
            $msg = 'no default SQL Server instance'
            if ($sql['Error']) { $msg = $msg + ' (' + $sql['Error'] + ')' }
            [void]$problems.Add($msg)
        } else {
            if ([string]$sql['ServiceState'] -ne 'Running') {
                [void]$problems.Add(('the default instance is not running (state {0})' -f $sql['ServiceState']))
            }
            if (-not $sql['Connected']) {
                $msg = 'no connection to the default instance'
                if ($sql['Error']) { $msg = $msg + ' (' + $sql['Error'] + ')' }
                [void]$problems.Add($msg)
            } else {
                $major = $null
                if ($null -ne $sql['MajorVersion']) { $major = [int]$sql['MajorVersion'] }
                if ($null -eq $major -or $major -lt 9 -or $major -gt 14) {
                    [void]$problems.Add(('SQL Server version {0} is not supported (2005-2017, major 9-14)' -f $sql['ProductVersion']))
                }
                if ($sql['ConnectedAsSysadmin'] -ne $true) {
                    [void]$problems.Add(('the operator ({0}) is not sysadmin' -f $sql['ConnectedAs']))
                }
                if ($sql['IsIntegratedSecurityOnly'] -ne $false) {
                    [void]$problems.Add('mixed-mode authentication is off or unknown (IsIntegratedSecurityOnly must be 0)')
                }
            }
            foreach ($inst in (ConvertTo-CrArray $sql['OtherInstances'])) {
                if ($inst) {
                    [void]$findings.Add((New-CrFinding -Severity 'Info' -Area 'Sql' -Message ('Other SQL Server instance {0} is ignored.' -f $inst)))
                }
            }
        }
        if ($wfDecision['BlockSql']) {
            [void]$problems.Add('write filter: ' + ((ConvertTo-CrArray $wfDecision['Reasons']) -join ' '))
        }
        if ($problems.Count -gt 0) {
            & $blockSlots $sqlSlots 'Sql' ('SQL slot blocked: ' + ($problems.ToArray() -join '; '))
        }
    }

    return @{ MachineBlocked = $machineBlocked; BlockedSlots = $blocked; Findings = $findings.ToArray() }
}

#endregion
