# Compat.ps1 - shared helpers for PowerShell 2.0 and later (docs/dev/CONTRACTS.md)

function ConvertTo-CrSidString {
    param($Bytes)
    if ($null -eq $Bytes) { return $null }
    try { return (New-Object System.Security.Principal.SecurityIdentifier([byte[]]$Bytes, 0)).Value } catch { return $null }
}

function Resolve-CrSidToName {
    param([string]$Sid)
    if (-not $Sid) { return $null }
    try {
        return (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value
    } catch { return $null }
}

function Resolve-CrNameToSid {
    param([string]$Name)
    if (-not $Name) { return $null }
    $n = $Name.Trim()
    if (-not $n) { return $null }
    if ($n -match '^S-1-\d+(-\d+)+$') { return $n }
    if ($n -ieq 'LocalSystem') { return 'S-1-5-18' }
    if ($n.StartsWith('.\')) { $n = $env:COMPUTERNAME + $n.Substring(1) }
    $candidates = New-Object System.Collections.ArrayList
    if ($n.IndexOf('\') -lt 0) { [void]$candidates.Add($env:COMPUTERNAME + '\' + $n) }
    [void]$candidates.Add($n)
    foreach ($c in $candidates) {
        try {
            return (New-Object System.Security.Principal.NTAccount($c)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        } catch { }
    }
    return $null
}

function Get-CrRegistryValue {
    param([string]$Path, [string]$Name)
    $result = @{ Exists = $false; Value = $null; Kind = $null }
    try {
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
    } catch {
        return $result
    }
    if (@($key.GetValueNames()) -notcontains $Name) { return $result }
    $result['Exists'] = $true
    $result['Value'] = $key.GetValue($Name)
    $result['Kind'] = $key.GetValueKind($Name).ToString()
    return $result
}

function Test-CrBuiltinServiceSid {
    param([string]$Sid)
    if (-not $Sid) { return $false }
    if (@('S-1-5-18', 'S-1-5-19', 'S-1-5-20') -contains $Sid) { return $true }
    return ($Sid.StartsWith('S-1-5-80-') -or $Sid.StartsWith('S-1-5-82-'))
}

function New-CrFinding {
    param(
        [ValidateSet('Drift', 'HighImpact', 'Blocked', 'Ambiguous', 'FollowUp', 'Info')]
        [string]$Severity,
        [string]$Area,
        [string]$Message,
        [string]$Slot,
        [string]$Account,
        [string]$Detail
    )
    return @{
        Severity = $Severity
        Area     = $Area
        Slot     = $Slot
        Account  = $Account
        Message  = $Message
        Detail   = $Detail
    }
}

# Returns the input as an array; $null becomes an empty array (PS 2.0: @($null) has one element).
function ConvertTo-CrArray {
    param($Value)
    if ($null -eq $Value) { return , @() }
    return , @($Value)
}
