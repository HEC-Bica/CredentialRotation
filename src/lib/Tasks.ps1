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
