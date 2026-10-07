# Fixtures.ps1 - synthetic machine state ($State, docs/dev/CONTRACTS.md) and the default config for unit tests.
# Modelled on the two machine types of the test sites (docs/PLAN.md section 13.2), with synthetic names and SIDs only.
#
#   New-CrTestState -Profile 'SM'|'IPT01' [-ComputerName] [-OmitUsers] [-Parts] [-Customize]
#   New-CrTestConfig [-Path]
#   Helpers: Get-CrTestUser, Get-CrTestUserSid, Get-CrTestGroup, Add-CrTestUser, Remove-CrTestUser,
#            Add-CrTestGroup, Add-CrTestGroupMember, Remove-CrTestGroupMember, Set-CrTestRight, Add-CrTestRight
#
# Profiles (account model PLAN v10.3: D18, D21-D25):
#   SM    (SM-like, Windows Embedded Standard 7, SQL Standard): no PUB-User; built-in Administrator renamed 'LocalAdm'
#         (disabled; replaced by ApplicationUser); BiCA Admin, BiCA Remote (Administrators + Remote Desktop Users; the
#         operator's account) - managed, set; WinAutoUser (enabled, password-stored task \KioskTask, updated in place by
#         the AutoLogon slot); ApplicationUser (runs SQL Server, app services, tasks, COM+); SP Admin (enabled admin,
#         password-stored task \SpMaintenance; retired); WinUser1-3 (WinUser3 disabled; WinUser1 in RDU + hw_fn_*;
#         WinUser2 in Power Users), FTP users TEST_FTP + ftpClient in CardCenters + Users; myftpuser (enabled, not an
#         FTP user) and OtherAdmin (enabled admin) are the two "other enabled accounts" (D23); groups CardCenters,
#         hw_fn_usbstor, hw_fn_cdrom, Offer Remote Assistance Helpers (BiCA Admin, BiCA Remote).
#   IPT01 (IPT01-like, SQL Express): built-in 'Administrator' enabled (replaced by ApplicationUser); SOP-Admin exists
#         (Administrators only; retired, v10.2); BiCA Admin (runs the service AppHelper, updated in place), BiCA Remote
#         (Administrators + RDU), ApplicationUser (runs SQL Server), PUB-User and WinAutoUser; SYS Admin (enabled admin,
#         runs the service LegacySync; retired); no other enabled accounts; no CardCenters, no Offer Remote Assistance
#         Helpers.
#   Both: auto-logon on as BiCA Admin with a plain-text DefaultPassword (SM: turned off; IPT01: switched to PUB-User);
#         deny rights as on the test sites.

$CrFixturesDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path

function New-CrTestUser {
    param(
        [string]$Name,
        [int]$Rid,
        [string]$MachineSid,
        [string]$FullName = '',
        [switch]$Disabled,
        [switch]$LockedOut,
        [switch]$PasswordNeverExpires,
        [switch]$CannotChangePassword,
        [switch]$PasswordNotRequired,
        [long]$PasswordAgeSeconds = 8640000
    )
    $flags = 0x201
    if ($Disabled) { $flags = $flags -bor 0x2 }
    if ($LockedOut) { $flags = $flags -bor 0x10 }
    if ($PasswordNotRequired) { $flags = $flags -bor 0x20 }
    if ($CannotChangePassword) { $flags = $flags -bor 0x40 }
    if ($PasswordNeverExpires) { $flags = $flags -bor 0x10000 }
    return @{
        Name                 = $Name
        Sid                  = ('{0}-{1}' -f $MachineSid, $Rid)
        Rid                  = $Rid
        FullName             = $FullName
        Flags                = $flags
        Disabled             = $Disabled.IsPresent
        LockedOut            = $LockedOut.IsPresent
        PasswordNeverExpires = $PasswordNeverExpires.IsPresent
        CannotChangePassword = $CannotChangePassword.IsPresent
        PasswordNotRequired  = $PasswordNotRequired.IsPresent
        PasswordAgeSeconds   = $PasswordAgeSeconds
        BadPasswordCount     = 0
    }
}

function Get-CrTestUser {
    param($State, [string]$Name)
    foreach ($u in $State.Users) { if ($u.Name -ieq $Name) { return $u } }
    return $null
}

function Get-CrTestUserSid {
    param($State, [string]$Name)
    $u = Get-CrTestUser -State $State -Name $Name
    if ($u) { return $u.Sid }
    throw ('Fixture: no user {0}' -f $Name)
}

# By name or SID.
function Get-CrTestGroup {
    param($State, [string]$Group)
    foreach ($g in $State.Groups) { if (($g.Name -ieq $Group) -or ($g.Sid -eq $Group)) { return $g } }
    return $null
}

function Add-CrTestGroupMember {
    param($State, [string]$Group, [string[]]$MemberSids)
    $g = Get-CrTestGroup -State $State -Group $Group
    if (-not $g) { throw ('Fixture: no group {0}' -f $Group) }
    $members = New-Object System.Collections.ArrayList
    foreach ($m in $g.MemberSids) { [void]$members.Add($m) }
    foreach ($m in $MemberSids) { if ($members -notcontains $m) { [void]$members.Add($m) } }
    $g.MemberSids = $members.ToArray()
}

function Remove-CrTestGroupMember {
    param($State, [string]$Group, [string[]]$MemberSids)
    $g = Get-CrTestGroup -State $State -Group $Group
    if (-not $g) { throw ('Fixture: no group {0}' -f $Group) }
    $members = New-Object System.Collections.ArrayList
    foreach ($m in $g.MemberSids) { if ($MemberSids -notcontains $m) { [void]$members.Add($m) } }
    $g.MemberSids = $members.ToArray()
}

function Add-CrTestGroup {
    param($State, [string]$Name, [string]$Sid, [string[]]$MemberSids = @())
    if (-not $Sid) { throw 'Fixture: Add-CrTestGroup needs a SID' }
    $g = @{ Name = $Name; Sid = $Sid; MemberSids = @($MemberSids); Error = $null }
    $State.Groups = @($State.Groups) + @($g)
    return $g
}

# Adds a user with the next free RID (or -Rid) and puts it into the given groups (names or SIDs).
function Add-CrTestUser {
    param(
        $State,
        [string]$Name,
        [int]$Rid = 0,
        [string[]]$Groups = @(),
        [switch]$Disabled,
        [switch]$LockedOut,
        [switch]$PasswordNeverExpires,
        [switch]$CannotChangePassword,
        [switch]$PasswordNotRequired
    )
    if ($Rid -eq 0) {
        $Rid = 1000
        foreach ($u in $State.Users) { if ($u.Rid -ge $Rid) { $Rid = $u.Rid + 1 } }
    }
    $user = New-CrTestUser -Name $Name -Rid $Rid -MachineSid $State.Computer.MachineSid -Disabled:$Disabled -LockedOut:$LockedOut `
        -PasswordNeverExpires:$PasswordNeverExpires -CannotChangePassword:$CannotChangePassword -PasswordNotRequired:$PasswordNotRequired
    $State.Users = @($State.Users) + @($user)
    foreach ($group in $Groups) { Add-CrTestGroupMember -State $State -Group $group -MemberSids @($user.Sid) }
    return $user
}

# Removes a user from Users, every group and every right.
function Remove-CrTestUser {
    param($State, [string]$Name)
    $user = Get-CrTestUser -State $State -Name $Name
    if (-not $user) { return }
    $sid = $user.Sid
    $users = New-Object System.Collections.ArrayList
    foreach ($u in $State.Users) { if ($u.Sid -ne $sid) { [void]$users.Add($u) } }
    $State.Users = $users.ToArray()
    foreach ($g in $State.Groups) { Remove-CrTestGroupMember -State $State -Group $g.Sid -MemberSids @($sid) }
    foreach ($right in @($State.Rights.Keys)) {
        $kept = New-Object System.Collections.ArrayList
        foreach ($s in $State.Rights[$right]) { if ($s -ne $sid) { [void]$kept.Add($s) } }
        $State.Rights[$right] = $kept.ToArray()
    }
}

function Set-CrTestRight {
    param($State, [string]$Right, [string[]]$Sids = @())
    if (-not $State.Rights.ContainsKey($Right)) { throw ('Fixture: unknown right {0}' -f $Right) }
    $State.Rights[$Right] = @($Sids)
}

function Add-CrTestRight {
    param($State, [string]$Right, [string[]]$Sids)
    if (-not $State.Rights.ContainsKey($Right)) { throw ('Fixture: unknown right {0}' -f $Right) }
    $list = New-Object System.Collections.ArrayList
    foreach ($s in $State.Rights[$Right]) { [void]$list.Add($s) }
    foreach ($s in $Sids) { if ($list -notcontains $s) { [void]$list.Add($s) } }
    $State.Rights[$Right] = $list.ToArray()
}

function New-CrTestSqlLogin {
    param([string]$Name, [string]$Type = 'SQL_LOGIN', [string]$Sid, [switch]$Disabled, [switch]$Sysadmin, [switch]$PolicyChecked)
    return @{
        Name                = $Name
        Type                = $Type
        Sid                 = $Sid
        IsDisabled          = $Disabled.IsPresent
        IsPolicyChecked     = $PolicyChecked.IsPresent
        IsExpirationChecked = $false
        IsLocked            = $false
        BadPasswordCount    = 0
        PasswordLastSetTime = '2020-01-01 00:00:00'
        IsSysadmin          = $Sysadmin.IsPresent
    }
}

function New-CrTestState {
    param(
        [Alias('Profile')]
        [ValidateSet('SM', 'IPT01')]
        [string]$MachineProfile = 'SM',
        [string]$ComputerName,
        [string[]]$OmitUsers = @(),
        [hashtable]$Parts,
        [scriptblock]$Customize
    )
    $isSm = ($MachineProfile -eq 'SM')
    if ($isSm) { $machineSid = 'S-1-5-21-1000-2000-3000' } else { $machineSid = 'S-1-5-21-1000-2000-4000' }
    if (-not $ComputerName) { if ($isSm) { $ComputerName = 'SM-TEST01' } else { $ComputerName = 'IPT01-TEST01' } }
    $s = { param($rid) '{0}-{1}' -f $machineSid, $rid }

    # --- Users ---
    $users = New-Object System.Collections.ArrayList
    if ($isSm) { $adminName = 'LocalAdm' } else { $adminName = 'Administrator' }
    [void]$users.Add((New-CrTestUser -Name $adminName -Rid 500 -MachineSid $machineSid -Disabled:$isSm -PasswordNeverExpires -PasswordNotRequired))
    [void]$users.Add((New-CrTestUser -Name 'Guest' -Rid 501 -MachineSid $machineSid -Disabled -PasswordNeverExpires -CannotChangePassword -PasswordNotRequired))
    [void]$users.Add((New-CrTestUser -Name 'BiCA Admin' -Rid 1001 -MachineSid $machineSid -PasswordNeverExpires -PasswordNotRequired))
    [void]$users.Add((New-CrTestUser -Name 'BiCA Remote' -Rid 1002 -MachineSid $machineSid -PasswordNeverExpires))
    [void]$users.Add((New-CrTestUser -Name 'ApplicationUser' -Rid 1003 -MachineSid $machineSid -PasswordNeverExpires))
    [void]$users.Add((New-CrTestUser -Name 'WinAutoUser' -Rid 1004 -MachineSid $machineSid -PasswordNeverExpires))
    if (-not $isSm) {
        [void]$users.Add((New-CrTestUser -Name 'PUB-User' -Rid 1005 -MachineSid $machineSid -PasswordNeverExpires))
        [void]$users.Add((New-CrTestUser -Name 'SOP-Admin' -Rid 1006 -MachineSid $machineSid -PasswordNeverExpires -CannotChangePassword))
    }
    if ($isSm) {
        [void]$users.Add((New-CrTestUser -Name 'WinUser1' -Rid 1010 -MachineSid $machineSid -PasswordNeverExpires))
        [void]$users.Add((New-CrTestUser -Name 'WinUser2' -Rid 1011 -MachineSid $machineSid))
        [void]$users.Add((New-CrTestUser -Name 'WinUser3' -Rid 1012 -MachineSid $machineSid -Disabled -PasswordNeverExpires))
        [void]$users.Add((New-CrTestUser -Name 'TEST_FTP' -Rid 1020 -MachineSid $machineSid -PasswordNeverExpires))
        [void]$users.Add((New-CrTestUser -Name 'ftpClient' -Rid 1021 -MachineSid $machineSid))
        [void]$users.Add((New-CrTestUser -Name 'myftpuser' -Rid 1022 -MachineSid $machineSid))
    }
    if ($isSm) {
        [void]$users.Add((New-CrTestUser -Name 'OtherAdmin' -Rid 1030 -MachineSid $machineSid -PasswordNeverExpires))
        [void]$users.Add((New-CrTestUser -Name 'SP Admin' -Rid 1031 -MachineSid $machineSid -PasswordNeverExpires))
    } else {
        [void]$users.Add((New-CrTestUser -Name 'SYS Admin' -Rid 1032 -MachineSid $machineSid -PasswordNeverExpires))
    }

    $admin = & $s 500; $guest = & $s 501; $bicaAdmin = & $s 1001; $bicaRemote = & $s 1002; $appUser = & $s 1003
    $winAuto = & $s 1004; $pubUser = & $s 1005; $sopAdmin = & $s 1006; $otherAdmin = & $s 1030; $spAdmin = & $s 1031; $sysAdmin = & $s 1032
    $winUser1 = & $s 1010; $winUser2 = & $s 1011; $winUser3 = & $s 1012; $ftp1 = & $s 1020; $ftp2 = & $s 1021; $myftp = & $s 1022

    # --- Groups (members as read by NetLocalGroupGetMembers level 0, D5) ---
    $groups = New-Object System.Collections.ArrayList
    if ($isSm) {
        [void]$groups.Add(@{ Name = 'Administrators'; Sid = 'S-1-5-32-544'; MemberSids = @($admin, $bicaAdmin, $bicaRemote, $appUser, $otherAdmin, $spAdmin); Error = $null })
        [void]$groups.Add(@{ Name = 'Users'; Sid = 'S-1-5-32-545'; MemberSids = @('S-1-5-4', 'S-1-5-11', $winAuto, $winUser1, $winUser2, $winUser3, $ftp1, $ftp2, $myftp); Error = $null })
        [void]$groups.Add(@{ Name = 'Guests'; Sid = 'S-1-5-32-546'; MemberSids = @($guest); Error = $null })
        [void]$groups.Add(@{ Name = 'Power Users'; Sid = 'S-1-5-32-547'; MemberSids = @($winUser2); Error = $null })
        [void]$groups.Add(@{ Name = 'Backup Operators'; Sid = 'S-1-5-32-551'; MemberSids = @(); Error = $null })
        [void]$groups.Add(@{ Name = 'Remote Desktop Users'; Sid = 'S-1-5-32-555'; MemberSids = @($bicaRemote, $winUser1); Error = $null })
        [void]$groups.Add(@{ Name = 'Offer Remote Assistance Helpers'; Sid = (& $s 1100); MemberSids = @($bicaAdmin, $bicaRemote); Error = $null })
        [void]$groups.Add(@{ Name = 'CardCenters'; Sid = (& $s 1101); MemberSids = @($ftp1, $ftp2); Error = $null })
        [void]$groups.Add(@{ Name = 'hw_fn_usbstor'; Sid = (& $s 1102); MemberSids = @($winUser1); Error = $null })
        [void]$groups.Add(@{ Name = 'hw_fn_cdrom'; Sid = (& $s 1103); MemberSids = @($winUser1); Error = $null })
    } else {
        [void]$groups.Add(@{ Name = 'Administrators'; Sid = 'S-1-5-32-544'; MemberSids = @($admin, $bicaAdmin, $bicaRemote, $appUser, $sopAdmin, $sysAdmin); Error = $null })
        [void]$groups.Add(@{ Name = 'Users'; Sid = 'S-1-5-32-545'; MemberSids = @('S-1-5-4', 'S-1-5-11', $winAuto, $pubUser); Error = $null })
        [void]$groups.Add(@{ Name = 'Guests'; Sid = 'S-1-5-32-546'; MemberSids = @($guest); Error = $null })
        [void]$groups.Add(@{ Name = 'Power Users'; Sid = 'S-1-5-32-547'; MemberSids = @(); Error = $null })
        [void]$groups.Add(@{ Name = 'Backup Operators'; Sid = 'S-1-5-32-551'; MemberSids = @(); Error = $null })
        [void]$groups.Add(@{ Name = 'Remote Desktop Users'; Sid = 'S-1-5-32-555'; MemberSids = @($bicaRemote); Error = $null })
    }

    # --- Rights: Windows 7 workstation defaults plus the test sites' deny rights (PLAN section 13.2) ---
    $rights = @{
        SeNetworkLogonRight               = @('S-1-1-0', 'S-1-5-32-544', 'S-1-5-32-545', 'S-1-5-32-551')
        SeInteractiveLogonRight           = @($guest, 'S-1-5-32-544', 'S-1-5-32-545', 'S-1-5-32-551')
        SeRemoteInteractiveLogonRight     = @('S-1-5-32-544', 'S-1-5-32-555')
        SeBatchLogonRight                 = @('S-1-5-32-544', 'S-1-5-32-551', 'S-1-5-32-559')
        SeServiceLogonRight               = @('S-1-5-80-0', $appUser)
        SeDenyNetworkLogonRight           = @($guest)
        SeDenyInteractiveLogonRight       = @()
        SeDenyRemoteInteractiveLogonRight = @()
        SeDenyBatchLogonRight             = @()
        SeDenyServiceLogonRight           = @()
    }
    if ($isSm) {
        $rights.SeBatchLogonRight = @('S-1-5-32-544', 'S-1-5-32-551', 'S-1-5-32-559', $appUser)
        $rights.SeDenyInteractiveLogonRight = @($bicaRemote, $appUser, $winAuto, $ftp1, $ftp2)
        $rights.SeDenyRemoteInteractiveLogonRight = @($bicaAdmin, $appUser, $winAuto)
        $rights.SeDenyServiceLogonRight = @($bicaRemote, $admin)
    } else {
        $rights.SeDenyInteractiveLogonRight = @($bicaRemote, $appUser)
        $rights.SeDenyRemoteInteractiveLogonRight = @($bicaAdmin, $winAuto, $appUser)
        $rights.SeDenyBatchLogonRight = @($bicaRemote)
        $rights.SeDenyServiceLogonRight = @($bicaRemote)
    }

    # --- Computer, Policy, WriteFilter ---
    $computer = @{
        Name = $ComputerName; IsSm = ($ComputerName -match '^SM'); OsVersion = '6.1.7601'
        OsCaption = 'Microsoft Windows Embedded Standard'; Is64BitOs = $true; Is64BitProcess = $true
        PSVersion = '2.0'; ClrVersion = '2.0.50727.8806'; LanguageMode = 'FullLanguage'; IsElevated = $true
        PartOfDomain = $false; MachineSid = $machineSid; SystemDrive = 'C:'
    }
    if ($isSm) {
        $policy = @{ MinPasswordLength = 6; MaxPasswordAgeSeconds = [long]15552000; MinPasswordAgeSeconds = [long]0
                     PasswordHistoryLength = 5; LockoutThreshold = 4; LockoutDurationSeconds = [long]180
                     LockoutObservationSeconds = [long]180; ComplexityEnabled = $false; ForceGuest = $false }
    } else {
        $policy = @{ MinPasswordLength = 7; MaxPasswordAgeSeconds = [long]15552000; MinPasswordAgeSeconds = [long]86400
                     PasswordHistoryLength = 5; LockoutThreshold = 4; LockoutDurationSeconds = [long]180
                     LockoutObservationSeconds = [long]180; ComplexityEnabled = $true; ForceGuest = $false }
    }
    $writeFilter = @{
        Filters = @(
            @{ Type = 'EWF'; DriverInstalled = $false; StateKnown = $true; CurrentEnabled = $false; NextEnabled = $false; CommitPending = $false; ProtectedVolumes = @(); Detail = $null },
            @{ Type = 'FBWF'; DriverInstalled = $false; StateKnown = $true; CurrentEnabled = $false; NextEnabled = $false; CommitPending = $false; ProtectedVolumes = @(); Detail = $null }
        )
        Error   = $null
    }

    # --- Dependents of ApplicationUser ---
    $appStart = '.\ApplicationUser'
    $sqlExe = 'C:\Program Files\Microsoft SQL Server\MSSQL10_50.MSSQLSERVER\MSSQL\Binn\sqlservr.exe'
    $services = New-Object System.Collections.ArrayList
    if ($isSm) {
        [void]$services.Add(@{ Name = 'MSSQLSERVER'; DisplayName = 'SQL Server (MSSQLSERVER)'; StartName = $appStart; StartNameSid = $appUser; StartMode = 'Auto'; State = 'Running'; PathExecutable = $sqlExe; DependentServices = @('SQLSERVERAGENT', 'AppRetailService'); DependsOn = @() })
        [void]$services.Add(@{ Name = 'SQLSERVERAGENT'; DisplayName = 'SQL Server Agent (MSSQLSERVER)'; StartName = $appStart; StartNameSid = $appUser; StartMode = 'Auto'; State = 'Running'; PathExecutable = 'C:\Program Files\Microsoft SQL Server\MSSQL10_50.MSSQLSERVER\MSSQL\Binn\SQLAGENT.EXE'; DependentServices = @(); DependsOn = @('MSSQLSERVER') })
        [void]$services.Add(@{ Name = 'AppRetailService'; DisplayName = 'App Retail Service'; StartName = $appStart; StartNameSid = $appUser; StartMode = 'Auto'; State = 'Running'; PathExecutable = 'C:\App\RetailService.exe'; DependentServices = @(); DependsOn = @('MSSQLSERVER') })
        [void]$services.Add(@{ Name = 'AppBootService'; DisplayName = 'App Boot Service'; StartName = $appStart; StartNameSid = $appUser; StartMode = 'Auto'; State = 'Running'; PathExecutable = 'C:\Windows\srvany.exe'; DependentServices = @(); DependsOn = @() })
    } else {
        [void]$services.Add(@{ Name = 'MSSQLSERVER'; DisplayName = 'SQL Server (MSSQLSERVER)'; StartName = $appStart; StartNameSid = $appUser; StartMode = 'Auto'; State = 'Running'; PathExecutable = $sqlExe; DependentServices = @(); DependsOn = @() })
        [void]$services.Add(@{ Name = 'SQLSERVERAGENT'; DisplayName = 'SQL Server Agent (MSSQLSERVER)'; StartName = 'NT AUTHORITY\NetworkService'; StartNameSid = 'S-1-5-20'; StartMode = 'Disabled'; State = 'Stopped'; PathExecutable = 'C:\Program Files\Microsoft SQL Server\MSSQL10_50.MSSQLSERVER\MSSQL\Binn\SQLAGENT.EXE'; DependentServices = @(); DependsOn = @('MSSQLSERVER') })
        # Dependents of a managed account (updated in place) and of a retired one (operator decision, O5)
        [void]$services.Add(@{ Name = 'AppHelper'; DisplayName = 'App Helper'; StartName = '.\BiCA Admin'; StartNameSid = $bicaAdmin; StartMode = 'Auto'; State = 'Running'; PathExecutable = 'C:\App\Helper.exe'; DependentServices = @(); DependsOn = @() })
        [void]$services.Add(@{ Name = 'LegacySync'; DisplayName = 'Legacy Sync'; StartName = '.\SYS Admin'; StartNameSid = $sysAdmin; StartMode = 'Manual'; State = 'Stopped'; PathExecutable = 'C:\App\Sync.exe'; DependentServices = @(); DependsOn = @() })
    }

    $tasks = @()
    $comPlus = @()
    if ($isSm) {
        $taskUser = '{0}\ApplicationUser' -f $ComputerName
        $tasks = @(
            @{ Path = '\AppTask1'; UserId = $taskUser; UserSid = $appUser; LogonType = 1; Enabled = $true; Error = $null },
            @{ Path = '\AppTask2'; UserId = $taskUser; UserSid = $appUser; LogonType = 1; Enabled = $true; Error = $null },
            @{ Path = '\AppServerTask'; UserId = $taskUser; UserSid = $appUser; LogonType = 6; Enabled = $true; Error = $null },
            # Dependents of a managed auto-logon account (updated in place) and of a retired one (operator decision, O5)
            @{ Path = '\KioskTask'; UserId = ('{0}\WinAutoUser' -f $ComputerName); UserSid = $winAuto; LogonType = 1; Enabled = $true; Error = $null },
            @{ Path = '\SpMaintenance'; UserId = ('{0}\SP Admin' -f $ComputerName); UserSid = $spAdmin; LogonType = 1; Enabled = $true; Error = $null }
        )
        $comPlus = @(
            @{ Name = 'App Manager'; Id = '{00000000-0000-0000-0000-000000000001}'; Activation = 'Server'; Identity = 'ApplicationUser'; IdentitySid = $appUser; IsEnabled = $true; IsSystem = $false }
        )
    }

    $iis = @{ Installed = $true; Version = '7.5'; Error = $null
              AppPools = @(@{ Name = 'DefaultAppPool'; IdentityType = 'ApplicationPoolIdentity'; UserName = $null; UserSid = $null })
              VirtualDirectories = @() }
    if ($isSm) {
        $iis.VirtualDirectories = @(@{ Site = 'FTP_Site'; Application = '/'; Path = '/'; PhysicalPath = 'C:\inetpub\ftproot'; UserName = $null; UserSid = $null; Protocols = @('ftp') })
    }

    # --- SQL Server (default instance, run by ApplicationUser) ---
    $logins = @(
        (New-CrTestSqlLogin -Name 'sa' -Sid '0x01' -Disabled -Sysadmin -PolicyChecked),
        (New-CrTestSqlLogin -Name 'SQLApplication' -Sid '0x1A2B3C4D5E6F708192A3B4C5D6E7F801' -Sysadmin -PolicyChecked),
        (New-CrTestSqlLogin -Name 'SQLScript' -Sid '0x1A2B3C4D5E6F708192A3B4C5D6E7F802' -Sysadmin -PolicyChecked),
        (New-CrTestSqlLogin -Name 'SQLService' -Sid '0x1A2B3C4D5E6F708192A3B4C5D6E7F803' -Sysadmin -PolicyChecked),
        (New-CrTestSqlLogin -Name 'OLD-NAME01\BiCA Admin' -Type 'WINDOWS_LOGIN' -Sid $bicaAdmin -Sysadmin),
        (New-CrTestSqlLogin -Name 'OLD-NAME01\ApplicationUser' -Type 'WINDOWS_LOGIN' -Sid $appUser -Sysadmin)
    )
    $agentJobs = @()
    if ($isSm) {
        $agentJobs = @(@{ Name = 'Nightly maintenance'; Owner = 'SQLService'; Enabled = $true }, @{ Name = 'Cleanup'; Owner = 'SQLService'; Enabled = $true })
    } else {
        $logins = $logins + @(New-CrTestSqlLogin -Name 'BUILTIN\Users' -Type 'WINDOWS_GROUP' -Sid 'S-1-5-32-545')
    }
    $edition = 'Standard Edition (64-bit)'
    if (-not $isSm) { $edition = 'Express Edition (64-bit)' }
    $sql = @{
        DefaultInstancePresent = $true; ServiceName = 'MSSQLSERVER'; ServiceState = 'Running'; ServiceAccount = $appStart
        ServiceAccountSid = $appUser; OtherInstances = @(); Connected = $true; Error = $null; MajorVersion = 10
        ProductVersion = '10.50.6000.34'; Edition = $edition; IsExpress = (-not $isSm); IsIntegratedSecurityOnly = $false
        ConnectedAs = ('{0}\BiCA Remote' -f $ComputerName); ConnectedAsSysadmin = $true; Logins = $logins
        MasterFiles = @('C:\Program Files\Microsoft SQL Server\MSSQL10_50.MSSQLSERVER\MSSQL\DATA\master.mdf', 'C:\Program Files\Microsoft SQL Server\MSSQL10_50.MSSQLSERVER\MSSQL\DATA\mastlog.ldf')
        AgentJobs = $agentJobs; Credentials = @(); Proxies = @(); LinkedLogins = @()
    }

    # --- Auto-logon: on as BiCA Admin with a plain-text DefaultPassword (both machine types) ---
    $autoLogonName = 'BiCA Admin'
    if (-not $isSm) { $autoLogonName = 'Bica Admin' }
    $autoLogon = @{
        AutoAdminLogon = '1'; AutoAdminLogonKind = 'String'; DefaultUserName = $autoLogonName; DefaultDomainName = $ComputerName
        DefaultPasswordPresent = $true; AutoLogonCountPresent = $false; ForceAutoLogon = $null; AutoLogonSidValue = $null
        OtherMechanisms = @(); LegalNoticeCaptionSet = $false; LegalNoticeTextSet = $true; Error = $null
    }

    $state = @{
        Computer    = $computer
        Policy      = $policy
        WriteFilter = $writeFilter
        Users       = $users.ToArray()
        Groups      = $groups.ToArray()
        Rights      = $rights
        Services    = $services.ToArray()
        Tasks       = $tasks
        ComPlus     = $comPlus
        Dcom        = @()
        Iis         = $iis
        Sql         = $sql
        AutoLogon   = $autoLogon
        Errors      = (New-Object System.Collections.ArrayList)
    }

    foreach ($name in $OmitUsers) { Remove-CrTestUser -State $state -Name $name }
    if ($Parts) { foreach ($key in @($Parts.Keys)) { $state[$key] = $Parts[$key] } }
    if ($Customize) { [void](& $Customize $state) }
    return $state
}

# The default config (config\CredentialRotation.psd1), loaded like Import-CrConfig does (PLAN section 5).
function New-CrTestConfig {
    param([string]$Path)
    if (-not $Path) { $Path = Join-Path (Join-Path (Split-Path -Parent $CrFixturesDirectory) 'config') 'CredentialRotation.psd1' }
    $full = (Resolve-Path -LiteralPath $Path).ProviderPath
    $cfg = $null
    Import-LocalizedData -BindingVariable cfg -BaseDirectory (Split-Path -Parent $full) -FileName (Split-Path -Leaf $full) -UICulture en-US -ErrorAction Stop
    return $cfg
}
