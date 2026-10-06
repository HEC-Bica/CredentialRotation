# Log.ps1 - local log file, CSV summary, console report (docs/PLAN.md section 7.10). Never logs secrets.

$script:CrLogFile = $null
$script:CrLogDirectory = $null

# Creates %ProgramData%\CredentialRotation\logs with a protected ACL (Administrators + SYSTEM, by SID).
# JournalTrusted is $false when the folder had a foreign owner or loose ACL that had to be corrected.
function Initialize-CrLog {
    param([string]$Root, [string]$RunId)
    if (-not $Root) { $Root = Join-Path $env:ProgramData 'CredentialRotation' }
    $trusted = $true
    $corrected = $false
    if (Test-Path -LiteralPath $Root) {
        if (-not (Test-CrFolderSecure -Path $Root)) {
            $trusted = $false
            $corrected = $true
        }
    } else {
        [void](New-Item -ItemType Directory -Path $Root -Force)
    }
    Set-CrFolderAcl -Path $Root
    $logs = Join-Path $Root 'logs'
    if (-not (Test-Path -LiteralPath $logs)) { [void](New-Item -ItemType Directory -Path $logs -Force) }
    $script:CrLogDirectory = $logs
    $script:CrLogFile = Join-Path $logs ('CredentialRotation_{0}_{1}.log' -f $env:COMPUTERNAME, $RunId)
    Write-CrLog ('Log started, run {0}' -f $RunId)
    if ($corrected) { Write-CrLog 'Log folder had a non-admin owner or write access for non-admins; ownership and ACL corrected, existing journal ignored.' 'Warning' }
    return @{ Root = $Root; Directory = $logs; File = $script:CrLogFile; JournalTrusted = $trusted; Corrected = $corrected }
}

$script:CrTrustedSids = @('S-1-5-32-544', 'S-1-5-18', 'S-1-3-0')

function Test-CrFolderSecure {
    param([string]$Path)
    try {
        $acl = Get-Acl -LiteralPath $Path
        $owner = (New-Object System.Security.Principal.NTAccount($acl.Owner)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        if (@('S-1-5-32-544', 'S-1-5-18') -notcontains $owner) { return $false }
        $writeRights = [System.Security.AccessControl.FileSystemRights]'Write, Modify, FullControl, ChangePermissions, TakeOwnership, Delete, CreateFiles, AppendData'
        foreach ($rule in @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))) {
            if ($rule.AccessControlType -ne 'Allow') { continue }
            if (($rule.FileSystemRights -band $writeRights) -eq 0) { continue }
            if ($script:CrTrustedSids -notcontains $rule.IdentityReference.Value) { return $false }
        }
        return $true
    } catch {
        return $false
    }
}

function Set-CrFolderAcl {
    param([string]$Path)
    $sddl = 'O:BAG:SYD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)'
    try {
        $acl = Get-Acl -LiteralPath $Path
        $acl.SetSecurityDescriptorSddlForm($sddl)
        Set-Acl -LiteralPath $Path -AclObject $acl
    } catch {
        # Fallback when WRITE_OWNER is missing: take ownership for Administrators, then retry.
        # Local 'Continue': under 'Stop' a stderr line from takeown would abort the run.
        $ErrorActionPreference = 'Continue'
        $takeown = Join-Path $env:windir 'System32\takeown.exe'
        [void](& $takeown /F $Path /A 2>&1)
        if ($LASTEXITCODE -ne 0) { throw ('takeown failed with exit code ' + $LASTEXITCODE + ' for ' + $Path) }
        $ErrorActionPreference = 'Stop'
        $acl = Get-Acl -LiteralPath $Path
        $acl.SetSecurityDescriptorSddlForm($sddl)
        Set-Acl -LiteralPath $Path -AclObject $acl
    }
}

function Write-CrLog {
    param([string]$Message, [string]$Level = 'Info')
    $line = '{0} [{1}] {2}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Verbose $line
    if ($script:CrLogFile) {
        $utf8 = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::AppendAllText($script:CrLogFile, $line + "`r`n", $utf8)
    }
}

function Export-CrFindingsCsv {
    param($Findings, [string]$Path)
    $rows = @(foreach ($f in (ConvertTo-CrArray $Findings)) {
        New-Object PSObject -Property @{
            Severity = $f['Severity']; Area = $f['Area']; Slot = $f['Slot']; Account = $f['Account']
            Message = $f['Message']; Detail = $f['Detail']
        }
    })
    if ($rows.Count -eq 0) { return }
    $rows | Select-Object Severity, Area, Slot, Account, Message, Detail |
        Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
}

# Console report grouped by severity, most important first.
function Write-CrFindingsReport {
    param($Findings)
    $order = @('Blocked', 'Ambiguous', 'HighImpact', 'Drift', 'FollowUp', 'Info')
    $all = ConvertTo-CrArray $Findings
    foreach ($sev in $order) {
        $group = @($all | Where-Object { $_['Severity'] -eq $sev })
        if ($group.Count -eq 0) { continue }
        Write-Host ''
        Write-Host ('=== {0} ({1}) ===' -f $sev, $group.Count)
        foreach ($f in $group) {
            $who = @($f['Slot'], $f['Account'] | Where-Object { $_ }) -join ' / '
            if ($who) { $who = '[' + $who + '] ' }
            Write-Host ('- {0}{1}: {2}' -f $who, $f['Area'], $f['Message'])
            if ($f['Detail']) { Write-Host ('    ' + $f['Detail']) }
        }
    }
}
