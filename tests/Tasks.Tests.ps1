# Pester 3.4 tests for src\lib\Tasks.ps1. Synthetic data only.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here '..\src\lib\Compat.ps1')
. (Join-Path $here '..\src\lib\Tasks.ps1')

function Get-TestTaskSid {
    param([string]$Name)
    switch ($Name.ToLowerInvariant()) {
        'applicationuser'             { return 'S-1-5-21-1000-2000-3000-1005' }
        'sm-test01\applicationuser'   { return 'S-1-5-21-1000-2000-3000-1005' }
        'testadmin'                   { return 'S-1-5-21-1000-2000-3000-1001' }
        'system'                      { return 'S-1-5-18' }
        'nt authority\network service' { return 'S-1-5-20' }
        'nt service\testsvc'          { return 'S-1-5-80-1000-2000-3000-4000-5000' }
    }
    return $null
}

function New-TestTask {
    param([string]$Path, [string]$UserId, $LogonType, [bool]$Enabled = $true, [string]$GroupId = '')
    $principal = New-Object PSObject -Property @{ UserId = $UserId; LogonType = $LogonType; GroupId = $GroupId }
    $definition = New-Object PSObject -Property @{ Principal = $principal }
    return (New-Object PSObject -Property @{ Path = $Path; Enabled = $Enabled; Definition = $definition })
}

function New-TestFolder {
    param([string]$Path, [object[]]$Tasks = @(), [object[]]$Folders = @(), [string]$TaskError = '')
    $f = New-Object PSObject -Property @{ Path = $Path; TaskList = $Tasks; FolderList = $Folders; TaskError = $TaskError }
    Add-Member -InputObject $f -MemberType ScriptMethod -Name GetTasks -Value {
        param($Flags)
        if ($this.TaskError) { throw $this.TaskError }
        if ($Flags -ne 1) { throw 'GetTasks must be called with TASK_ENUM_HIDDEN (1)' }
        $this.TaskList
    }
    Add-Member -InputObject $f -MemberType ScriptMethod -Name GetFolders -Value { param($Flags) $this.FolderList }
    return $f
}

function New-TestTaskTree {
    $vendor = New-TestFolder -Path '\Vendor' -Tasks @(
        (New-TestTask -Path '\Vendor\SIMServer' -UserId 'SM-TEST01\ApplicationUser' -LogonType 6 -Enabled $false),
        (New-TestTask -Path '\Vendor\Updater' -UserId 'NT SERVICE\TestSvc' -LogonType 5)
    )
    $deep = New-TestFolder -Path '\Vendor\Deep' -Tasks @(
        (New-TestTask -Path '\Vendor\Deep\Broken' -UserId 'TestAdmin' -LogonType 'not-a-number'),
        (New-TestTask -Path '\Vendor\Deep\AdminJob' -UserId 'TestAdmin' -LogonType 1)
    )
    $vendor.FolderList = @($deep)
    $locked = New-TestFolder -Path '\Locked' -TaskError 'Access is denied.'
    return (New-TestFolder -Path '\' -Folders @($vendor, $locked) -Tasks @(
        (New-TestTask -Path '\TestExport' -UserId 'ApplicationUser' -LogonType 1),
        (New-TestTask -Path '\SystemJob' -UserId 'SYSTEM' -LogonType 5),
        (New-TestTask -Path '\NetSvcJob' -UserId 'NT AUTHORITY\Network Service' -LogonType 5),
        (New-TestTask -Path '\GroupJob' -UserId '' -LogonType 4 -GroupId 'Users')
    ))
}

Describe 'Get-CrScheduledTasks' {
    Mock Resolve-CrNameToSid { Get-TestTaskSid -Name $Name }

    Context 'synthetic task tree' {
        Mock Get-CrTaskSchedulerRootFolder { New-TestTaskTree }
        $r = Get-CrScheduledTasks
        $ok = @($r | Where-Object { -not $_['Error'] })

        It 'returns an array' {
            ($r -is [array]) | Should Be $true
        }
        It 'walks subfolders recursively and keeps user principals only' {
            (@($ok | ForEach-Object { $_['Path'] } | Sort-Object) -join ',') | Should Be '\TestExport,\Vendor\Deep\AdminJob,\Vendor\SIMServer'
        }
        It 'resolves UserId to a SID and keeps LogonType as int' {
            $t = @($ok | Where-Object { $_['Path'] -eq '\TestExport' })[0]
            $t['UserId'] | Should Be 'ApplicationUser'
            $t['UserSid'] | Should Be 'S-1-5-21-1000-2000-3000-1005'
            $t['LogonType'] | Should Be 1
            ($t['LogonType'] -is [int]) | Should Be $true
            $t['Enabled'] | Should Be $true
            $s = @($ok | Where-Object { $_['Path'] -eq '\Vendor\SIMServer' })[0]
            $s['UserSid'] | Should Be 'S-1-5-21-1000-2000-3000-1005'
            $s['LogonType'] | Should Be 6
            $s['Enabled'] | Should Be $false
        }
        It 'skips built-in service SIDs and group principals' {
            @($r | Where-Object { @('\SystemJob', '\NetSvcJob', '\GroupJob', '\Vendor\Updater') -contains $_['Path'] }).Count | Should Be 0
        }
        It 'records a per-task error and continues the scan' {
            $broken = @($r | Where-Object { $_['Path'] -eq '\Vendor\Deep\Broken' })
            $broken.Count | Should Be 1
            $broken[0]['Error'] | Should Not BeNullOrEmpty
            @($ok | Where-Object { $_['Path'] -eq '\Vendor\Deep\AdminJob' }).Count | Should Be 1
        }
        It 'records a folder that cannot be enumerated' {
            $locked = @($r | Where-Object { $_['Path'] -eq '\Locked' })
            $locked.Count | Should Be 1
            $locked[0]['Error'] | Should Match 'Access is denied'
        }
        It 'has exactly the contract keys' {
            ((@($ok[0].Keys) | Sort-Object) -join ',') | Should Be 'Enabled,Error,LogonType,Path,UserId,UserSid'
        }
    }

    Context 'empty scheduler' {
        Mock Get-CrTaskSchedulerRootFolder { New-TestFolder -Path '\' }
        $r = Get-CrScheduledTasks

        It 'returns an empty array' {
            ($r -is [array]) | Should Be $true
            @($r).Count | Should Be 0
        }
    }
}
