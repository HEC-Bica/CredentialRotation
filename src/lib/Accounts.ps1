# Accounts.ps1 - local users via ADSI WinNT (docs/PLAN.md section 7.1). M1: read side only.

# Internal: the raw ADSI user entries of the local computer. Separate so tests can mock it.
function Get-CrAdsiUserEntries {
    param([string]$ComputerName = $env:COMPUTERNAME)
    $computer = [ADSI]('WinNT://' + $ComputerName + ',computer')
    $list = New-Object System.Collections.ArrayList
    foreach ($child in $computer.psbase.Children) {
        if ($child.psbase.SchemaClassName -eq 'User') { [void]$list.Add($child) }
    }
    return , $list.ToArray()
}

# Internal: one ADSI property via InvokeGet; throws when the property can't be read. Separate so tests can mock it.
function Get-CrAdsiValue {
    param($Entry, [string]$Name)
    return $Entry.psbase.InvokeGet($Name)
}

function Get-CrAdsiErrorText {
    param($ErrorRecord)
    $ex = $ErrorRecord.Exception
    while ($ex.InnerException) { $ex = $ex.InnerException }
    return $ex.Message
}

# Internal: optional property; $null when it can't be read.
function Get-CrAdsiOptionalValue {
    param($Entry, [string]$Name)
    try { return Get-CrAdsiValue -Entry $Entry -Name $Name } catch { return $null }
}

# Converts one ADSI user entry into the CONTRACTS "Users" hashtable (plus Error = $null). Throws if a required
# property (Name, objectSid, UserFlags) can't be read.
function ConvertTo-CrUserRecord {
    param($Entry)
    $name = [string](Get-CrAdsiValue -Entry $Entry -Name 'Name')
    $sid = ConvertTo-CrSidString (Get-CrAdsiValue -Entry $Entry -Name 'objectSid')
    if (-not $sid) { throw ('objectSid of user {0} could not be read' -f $name) }
    $flags = [int](Get-CrAdsiValue -Entry $Entry -Name 'UserFlags')

    $parts = $sid.Split('-')
    $rid = [int]$parts[$parts.Length - 1]

    $fullName = Get-CrAdsiOptionalValue -Entry $Entry -Name 'FullName'
    if ($null -ne $fullName) { $fullName = [string]$fullName }

    # IsAccountLocked reflects the lockout duration; the UF_LOCKOUT bit is the fallback.
    $locked = Get-CrAdsiOptionalValue -Entry $Entry -Name 'IsAccountLocked'
    if ($null -eq $locked) { $locked = [bool]($flags -band 0x10) } else { $locked = [bool]$locked }

    $age = Get-CrAdsiOptionalValue -Entry $Entry -Name 'PasswordAge'
    if ($null -ne $age) { $age = [long]$age }
    $bad = Get-CrAdsiOptionalValue -Entry $Entry -Name 'BadPasswordAttempts'
    if ($null -ne $bad) { $bad = [int]$bad }

    return @{
        Name                 = $name
        Sid                  = $sid
        Rid                  = $rid
        FullName             = $fullName
        Flags                = $flags
        Disabled             = [bool]($flags -band 0x2)
        LockedOut            = $locked
        PasswordNeverExpires = [bool]($flags -band 0x10000)
        CannotChangePassword = [bool]($flags -band 0x40)
        PasswordNotRequired  = [bool]($flags -band 0x20)
        PasswordAgeSeconds   = $age
        BadPasswordCount     = $bad
        Error                = $null
    }
}

# All local users (CONTRACTS "Users"); returns an array. A user that can't be read is returned with Error set
# and the other keys $null (Name if it could be read), so one failing user doesn't fail the others.
function Get-CrLocalUsers {
    param()
    $list = New-Object System.Collections.ArrayList
    foreach ($entry in (ConvertTo-CrArray (Get-CrAdsiUserEntries))) {
        try {
            [void]$list.Add((ConvertTo-CrUserRecord -Entry $entry))
        } catch {
            $message = Get-CrAdsiErrorText $_
            [void]$list.Add(@{
                Name                 = [string](Get-CrAdsiOptionalValue -Entry $entry -Name 'Name')
                Sid                  = $null
                Rid                  = $null
                FullName             = $null
                Flags                = $null
                Disabled             = $null
                LockedOut            = $null
                PasswordNeverExpires = $null
                CannotChangePassword = $null
                PasswordNotRequired  = $null
                PasswordAgeSeconds   = $null
                BadPasswordCount     = $null
                Error                = $message
            })
        }
    }
    return , $list.ToArray()
}
