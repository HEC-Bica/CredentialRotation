# Tasks.ps1 - scheduled tasks with a user principal, read side (docs/PLAN.md section 7.4, docs/dev/CONTRACTS.md "Tasks")

# --- internal: external access (mocked in tests) ---

# Root folder of a connected Task Scheduler 2.0 service.
function Get-CrTaskSchedulerRootFolder {
    param()
    $scheduler = New-Object -ComObject Schedule.Service
    $scheduler.Connect()
    return $scheduler.GetFolder('\')
}

# --- internal: logic ---

function Get-CrTaskErrorText {
    param($ErrorRecord)
    $ex = $ErrorRecord.Exception
    while ($ex.InnerException) { $ex = $ex.InnerException }
    return $ex.Message
}

function New-CrTaskErrorEntry {
    param([string]$Path, [string]$Message)
    return @{ Path = $Path; UserId = $null; UserSid = $null; LogonType = $null; Enabled = $null; Error = $Message }
}

# --- public ---

# Tasks whose principal has a UserId that isn't a built-in service SID (all folders, hidden tasks included).
# A task or folder that can't be read becomes an entry with Error set; the scan goes on.
function Get-CrScheduledTasks {
    param()
    $list = New-Object System.Collections.ArrayList
    $sidCache = @{}
    $queue = New-Object System.Collections.Queue
    $queue.Enqueue((Get-CrTaskSchedulerRootFolder))
    while ($queue.Count -gt 0) {
        $folder = $queue.Dequeue()
        if ($null -eq $folder) { continue }
        $folderPath = $null
        try { $folderPath = [string]$folder.Path } catch { }

        try {
            foreach ($sub in (ConvertTo-CrArray ($folder.GetFolders(0)))) {
                if ($null -ne $sub) { $queue.Enqueue($sub) }
            }
        } catch {
            [void]$list.Add((New-CrTaskErrorEntry -Path $folderPath -Message ('Subfolders: ' + (Get-CrTaskErrorText $_))))
        }

        $tasks = @()
        try {
            $tasks = ConvertTo-CrArray ($folder.GetTasks(1))   # 1 = TASK_ENUM_HIDDEN
        } catch {
            [void]$list.Add((New-CrTaskErrorEntry -Path $folderPath -Message ('Tasks: ' + (Get-CrTaskErrorText $_))))
            continue
        }

        foreach ($task in $tasks) {
            if ($null -eq $task) { continue }
            $taskPath = $null
            try {
                $taskPath = [string]$task.Path
                $principal = $task.Definition.Principal
                $userId = [string]$principal.UserId
                if (-not $userId) { continue }                       # group principal
                $logonType = [int]$principal.LogonType
                if ($logonType -eq 4) { continue }                  # TASK_LOGON_GROUP
                $key = $userId.ToLowerInvariant()
                if (-not $sidCache.ContainsKey($key)) { $sidCache[$key] = Resolve-CrNameToSid -Name $userId }
                $sid = $sidCache[$key]
                if (Test-CrBuiltinServiceSid -Sid $sid) { continue }
                [void]$list.Add(@{
                    Path      = $taskPath
                    UserId    = $userId
                    UserSid   = $sid
                    LogonType = $logonType
                    Enabled   = [bool]$task.Enabled
                    Error     = $null
                })
            } catch {
                [void]$list.Add((New-CrTaskErrorEntry -Path $taskPath -Message (Get-CrTaskErrorText $_)))
            }
        }
    }
    return , $list.ToArray()
}

# --- write side (M2/M3, v10) ---

# Folder path ('\' for the root) and name of a task path such as '\Vendor\Job'.
function Split-CrTaskPath {
    param([string]$Path)
    $i = $Path.LastIndexOf('\')
    if ($i -le 0) { return @{ Folder = '\'; Name = $Path.Substring($i + 1) } }
    return @{ Folder = $Path.Substring(0, $i); Name = $Path.Substring($i + 1) }
}

# Security descriptor of a registered task as SDDL for the given SECURITY_INFORMATION flags
# (0xF = owner, group, DACL and SACL; 0x7 = owner, group and DACL).
function Get-CrTaskSddl {
    param($Task, [int]$Flags = 0xF)
    return [string]$Task.GetSecurityDescriptor($Flags)
}

# SDDL to register a task with: @{ Sddl; WithSacl }. Owner, group, DACL and SACL (0xF, WithSacl =
# $true); if the SACL can't be read (SeSecurityPrivilege), owner, group and DACL (0x7, WithSacl =
# $false). Throws when neither can be read.
function Get-CrTaskSecurity {
    param($Task)
    try {
        $full = Get-CrTaskSddl -Task $Task -Flags 0xF
        return @{ Sddl = $full; WithSacl = $true }
    } catch {
        $reduced = Get-CrTaskSddl -Task $Task -Flags 0x7
        return @{ Sddl = $reduced; WithSacl = $false }
    }
}

# $true if an HRESULT from RegisterTaskDefinition is about the account or its password (logon failure,
# restriction, expired, disabled, locked, logon type not granted, name not mapped). Retrying with
# another SDDL can't help there and would cost another failed logon (D12).
function Test-CrTaskCredentialError {
    param($HResult)
    if ($null -eq $HResult) { return $false }
    $h = [int]$HResult
    if (($h -band 0xFFFF0000) -ne 0x80070000) { return $false }
    $code = $h -band 0xFFFF
    return (@(1326, 1327, 1328, 1329, 1330, 1331, 1332, 1385, 1793, 1907, 1909) -contains $code)
}

# Registers one task of Sid again with the given password. Reads the live task and checks that its
# principal still is Sid with LogonType 1 (password) or 6 (interactive token or password); keeps
# LogonType, the definition and the SDDL. NewUserId = $null keeps the task's UserId (password
# update); otherwise the task moves to NewUserId (D24). When the SDDL included the SACL (0xF) and the
# registration fails for a reason other than the credentials, it is retried once with owner, group
# and DACL (0x7); a successful retry is reported with SaclDropped = $true and a Warning.
# Returns @{ Path; Success; Error; SaclDropped; Warning; FromUserId; ToUserId }.
function Invoke-CrOneTaskRegistration {
    param($Root, [string]$Path, [string]$Sid, [string]$NewUserId, [System.Security.SecureString]$Secret)
    $entry = @{ Path = $Path; Success = $false; Error = $null; SaclDropped = $false; Warning = $null; FromUserId = $null; ToUserId = $null }
    if ($NewUserId) { $entry['ToUserId'] = $NewUserId }
    try {
        $parts = Split-CrTaskPath -Path $Path
        $folder = $Root
        if ($parts['Folder'] -ne '\') { $folder = $Root.GetFolder($parts['Folder']) }
        $task = $folder.GetTask($parts['Name'])
        $definition = $task.Definition
        $principal = $definition.Principal
        $userId = [string]$principal.UserId
        $logonType = [int]$principal.LogonType
        $entry['FromUserId'] = $userId
        if (-not $NewUserId) { $entry['ToUserId'] = $userId }
        if (-not (@(1, 6) -contains $logonType)) {
            $entry['Error'] = 'Task no longer stores a password (LogonType ' + $logonType + '); not updated'
            return $entry
        }
        if ((Resolve-CrNameToSid -Name $userId) -ne $Sid) {
            $entry['Error'] = 'Task principal changed since the audit (' + $userId + '); not updated'
            return $entry
        }
        $security = Get-CrTaskSecurity -Task $task
        $sddl = [string]$security['Sddl']
        if (-not $sddl) {
            $entry['Error'] = 'Task security descriptor could not be read; not updated'
            return $entry
        }
        $r = Invoke-CrTaskRegistrationAdapter -Folder $folder -TaskName $parts['Name'] -Definition $definition -UserId $entry['ToUserId'] -Secret $Secret -LogonType $logonType -Sddl $sddl
        if (-not ($r -is [hashtable])) { $r = @{ Success = $false; Error = 'RegisterTaskDefinition adapter returned no result'; HResult = $null } }
        if ((-not $r['Success']) -and $security['WithSacl'] -and (-not (Test-CrTaskCredentialError -HResult $r['HResult']))) {
            $reduced = $null
            try { $reduced = Get-CrTaskSddl -Task $task -Flags 0x7 } catch { $reduced = $null }
            if ($reduced -and ($reduced -cne $sddl)) {
                $firstError = [string]$r['Error']
                $r = Invoke-CrTaskRegistrationAdapter -Folder $folder -TaskName $parts['Name'] -Definition $definition -UserId $entry['ToUserId'] -Secret $Secret -LogonType $logonType -Sddl $reduced
                if (-not ($r -is [hashtable])) { $r = @{ Success = $false; Error = 'RegisterTaskDefinition adapter returned no result'; HResult = $null } }
                if ($r['Success']) {
                    $entry['SaclDropped'] = $true
                    $entry['Warning'] = 'SACL dropped: registering with the full security descriptor failed (' + $firstError + '); registered with owner, group and DACL only'
                } else {
                    $r['Error'] = [string]$r['Error'] + ' (retried without the SACL; first attempt: ' + $firstError + ')'
                }
            }
        }
        $entry['Success'] = [bool]$r['Success']
        $entry['Error'] = $r['Error']
    } catch {
        $entry['Success'] = $false
        $entry['Error'] = Get-CrTaskErrorText $_
    }
    return $entry
}

# Registers every password-stored task (LogonType 1 or 6) of Sid from $State.Tasks again, keeping
# its UserId (NewUserId = $null) or moving it to NewUserId. Tasks are not run or stopped.
# Returns an array of per-task entries (Invoke-CrOneTaskRegistration); one failure doesn't stop the
# others. If $State.Tasks failed to load, the only entry has Path = $null and Success = $false.
function Invoke-CrTaskRegistrations {
    param($State, [string]$Sid, [string]$NewUserId, [System.Security.SecureString]$Secret)
    $results = New-Object System.Collections.ArrayList
    $part = $State['Tasks']
    if ($part -is [hashtable]) {
        [void]$results.Add(@{ Path = $null; Success = $false; Error = ('Scheduled tasks could not be read: ' + [string]$part['Error']); SaclDropped = $false; Warning = $null; FromUserId = $null; ToUserId = $null })
        return , $results.ToArray()
    }
    $targets = New-Object System.Collections.ArrayList
    $all = ConvertTo-CrArray $part
    foreach ($t in $all) {
        if ($null -eq $t -or $t['Error']) { continue }
        if ($t['UserSid'] -ne $Sid) { continue }
        if (-not (@(1, 6) -contains [int]$t['LogonType'])) { continue }
        [void]$targets.Add([string]$t['Path'])
    }
    if ($targets.Count -eq 0) { return , $results.ToArray() }

    $root = $null
    $rootError = $null
    try {
        $root = Get-CrTaskSchedulerRootFolder
    } catch {
        $rootError = 'Task Scheduler not available: ' + (Get-CrTaskErrorText $_)
    }
    foreach ($path in $targets) {
        if ($rootError) {
            [void]$results.Add(@{ Path = $path; Success = $false; Error = $rootError; SaclDropped = $false; Warning = $null; FromUserId = $null; ToUserId = $null })
            continue
        }
        [void]$results.Add((Invoke-CrOneTaskRegistration -Root $root -Path $path -Sid $Sid -NewUserId $NewUserId -Secret $Secret))
    }
    return , $results.ToArray()
}

# Re-registers every password-stored task (LogonType 1 or 6) of Sid with the new password
# (TASK_UPDATE, existing UserId, LogonType and SDDL; SACL retry as above). Tasks are not run or
# stopped. Returns an array of @{ Path; Success; Error; SaclDropped; Warning; FromUserId; ToUserId },
# one per task.
function Update-CrTaskCredentials {
    param($State, [string]$Sid, [System.Security.SecureString]$Secret)
    if (-not $Sid) { throw 'Update-CrTaskCredentials: Sid is required' }
    if ($null -eq $Secret) { throw 'Update-CrTaskCredentials: no new password given' }
    return , (Invoke-CrTaskRegistrations -State $State -Sid $Sid -NewUserId $null -Secret $Secret)
}

# Moves every password-stored task (LogonType 1 or 6) of FromSid to ToUserId ('<COMPUTER>\<name>')
# with that account's password (D24): TASK_UPDATE with the new UserId; LogonType, definition and SDDL
# kept (SACL retry as above). The live principal is re-checked before writing. Tasks are not run or
# stopped. Returns an array of @{ Path; Success; Error; SaclDropped; Warning; FromUserId; ToUserId },
# one per task.
function Move-CrTaskAccount {
    param($State, [string]$FromSid, [string]$ToUserId, [System.Security.SecureString]$Secret)
    if (-not $FromSid) { throw 'Move-CrTaskAccount: FromSid is required' }
    if (-not $ToUserId) { throw 'Move-CrTaskAccount: ToUserId is required' }
    if ($null -eq $Secret) { throw 'Move-CrTaskAccount: no password of the new account given' }
    return , (Invoke-CrTaskRegistrations -State $State -Sid $FromSid -NewUserId $ToUserId -Secret $Secret)
}
