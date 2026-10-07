# Pester 3.4 tests for src\lib\Tasks.ps1. Synthetic data only.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here '..\src\lib\Compat.ps1')
. (Join-Path $here '..\src\lib\Tasks.ps1')

# Stub for the Adapters.ps1 function (another module); mocked below.
function Invoke-CrTaskRegistrationAdapter { param($Folder, [string]$TaskName, $Definition, [string]$UserId, $Secret, [int]$LogonType, [string]$Sddl) }

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
        (New-TestTask -Path '\Vendor\TestServerJob' -UserId 'SM-TEST01\ApplicationUser' -LogonType 6 -Enabled $false),
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
            (@($ok | ForEach-Object { $_['Path'] } | Sort-Object) -join ',') | Should Be '\TestExport,\Vendor\Deep\AdminJob,\Vendor\TestServerJob'
        }
        It 'resolves UserId to a SID and keeps LogonType as int' {
            $t = @($ok | Where-Object { $_['Path'] -eq '\TestExport' })[0]
            $t['UserId'] | Should Be 'ApplicationUser'
            $t['UserSid'] | Should Be 'S-1-5-21-1000-2000-3000-1005'
            $t['LogonType'] | Should Be 1
            ($t['LogonType'] -is [int]) | Should Be $true
            $t['Enabled'] | Should Be $true
            $s = @($ok | Where-Object { $_['Path'] -eq '\Vendor\TestServerJob' })[0]
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

# --- write side ---

function New-TestTaskState {
    $app = 'S-1-5-21-1000-2000-3000-1005'
    return @{
        Tasks = @(
            @{ Path = '\TestExport'; UserId = 'ApplicationUser'; UserSid = $app; LogonType = 1; Enabled = $true; Error = $null },
            @{ Path = '\Vendor\TestServerJob'; UserId = 'SM-TEST01\ApplicationUser'; UserSid = $app; LogonType = 6; Enabled = $false; Error = $null },
            @{ Path = '\Vendor\InteractiveOnly'; UserId = 'ApplicationUser'; UserSid = $app; LogonType = 3; Enabled = $true; Error = $null },
            @{ Path = '\Vendor\Deep\AdminJob'; UserId = 'TestAdmin'; UserSid = 'S-1-5-21-1000-2000-3000-1001'; LogonType = 1; Enabled = $true; Error = $null },
            @{ Path = '\Vendor\Deep\AppJob'; UserId = 'ApplicationUser'; UserSid = $app; LogonType = 1; Enabled = $true; Error = $null },
            @{ Path = '\Broken'; UserId = $null; UserSid = $null; LogonType = $null; Enabled = $null; Error = 'Access is denied.' }
        )
    }
}

# Live registered task: GetSecurityDescriptor(15) returns an SDDL with a SACL, (7) one without;
# SaclFails makes 15 throw like a missing SeSecurityPrivilege.
function New-TestLiveTask {
    param([string]$Path, [string]$UserId, [int]$LogonType, [bool]$SaclFails = $false)
    $principal = New-Object PSObject -Property @{ UserId = $UserId; LogonType = $LogonType }
    $definition = New-Object PSObject -Property @{ Marker = $Path; Principal = $principal }
    $t = New-Object PSObject -Property @{ Path = $Path; Definition = $definition; SaclFails = $SaclFails }
    Add-Member -InputObject $t -MemberType ScriptMethod -Name GetSecurityDescriptor -Value {
        param($Flags)
        if ([int]$Flags -eq 15) {
            if ($this.SaclFails) { throw 'A required privilege is not held by the client.' }
            return 'O:BAG:SYD:(A;;FA;;;BA)S:(AU;FA;FA;;;WD)'
        }
        if ([int]$Flags -eq 7) { return 'O:BAG:SYD:(A;;FA;;;BA)' }
        throw ('unexpected flags ' + $Flags)
    }
    return $t
}

function New-TestLiveFolder {
    param([string]$Path, [hashtable]$Tasks = @{}, [hashtable]$Folders = @{})
    $f = New-Object PSObject -Property @{ Path = $Path; TaskMap = $Tasks; FolderMap = $Folders }
    Add-Member -InputObject $f -MemberType ScriptMethod -Name GetTask -Value {
        param($Name)
        if (-not $this.TaskMap.ContainsKey($Name)) { throw 'The system cannot find the file specified.' }
        $this.TaskMap[$Name]
    }
    Add-Member -InputObject $f -MemberType ScriptMethod -Name GetFolder -Value {
        param($FolderPath)
        if (-not $this.FolderMap.ContainsKey($FolderPath)) { throw 'The system cannot find the path specified.' }
        $this.FolderMap[$FolderPath]
    }
    return $f
}

# Live tree matching New-TestTaskState. GetFolder on the root takes absolute folder paths.
function New-TestLiveTree {
    param([switch]$SaclFails, [switch]$ChangedPrincipal, [string]$MissingTask = '')
    $sacl = [bool]$SaclFails
    $exportUser = 'ApplicationUser'
    if ($ChangedPrincipal) { $exportUser = 'TestAdmin' }
    $rootTasks = @{ 'TestExport' = (New-TestLiveTask -Path '\TestExport' -UserId $exportUser -LogonType 1 -SaclFails $sacl) }
    $vendorTasks = @{
        'TestServerJob'   = (New-TestLiveTask -Path '\Vendor\TestServerJob' -UserId 'SM-TEST01\ApplicationUser' -LogonType 6 -SaclFails $sacl)
        'InteractiveOnly' = (New-TestLiveTask -Path '\Vendor\InteractiveOnly' -UserId 'ApplicationUser' -LogonType 3)
    }
    $deepTasks = @{
        'AdminJob' = (New-TestLiveTask -Path '\Vendor\Deep\AdminJob' -UserId 'TestAdmin' -LogonType 1)
        'AppJob'   = (New-TestLiveTask -Path '\Vendor\Deep\AppJob' -UserId 'ApplicationUser' -LogonType 1 -SaclFails $sacl)
    }
    if ($MissingTask) {
        foreach ($m in @($rootTasks, $vendorTasks, $deepTasks)) { if ($m.ContainsKey($MissingTask)) { $m.Remove($MissingTask) } }
    }
    $vendor = New-TestLiveFolder -Path '\Vendor' -Tasks $vendorTasks
    $deep = New-TestLiveFolder -Path '\Vendor\Deep' -Tasks $deepTasks
    return (New-TestLiveFolder -Path '\' -Tasks $rootTasks -Folders @{ '\Vendor' = $vendor; '\Vendor\Deep' = $deep })
}

Describe 'Update-CrTaskCredentials' {
    $appSid = 'S-1-5-21-1000-2000-3000-1005'
    $secret = ConvertTo-SecureString 'Dummy-1a' -AsPlainText -Force
    Mock Resolve-CrNameToSid { Get-TestTaskSid -Name $Name }

    Context 'password-stored tasks of the account' {
        Mock Get-CrTaskSchedulerRootFolder { New-TestLiveTree }
        Mock Invoke-CrTaskRegistrationAdapter { @{ Success = $true; Error = $null; HResult = $null } }
        $r = Update-CrTaskCredentials -State (New-TestTaskState) -Sid $appSid -Secret $secret

        It 'returns one successful result per password-stored task of the SID' {
            ($r -is [array]) | Should Be $true
            (@($r | ForEach-Object { $_['Path'] }) -join ',') | Should Be '\TestExport,\Vendor\TestServerJob,\Vendor\Deep\AppJob'
            @($r | Where-Object { $_['Success'] }).Count | Should Be 3
            ((@($r[0].Keys) | Sort-Object) -join ',') | Should Be 'Error,FromUserId,Path,SaclDropped,Success,ToUserId,Warning'
        }
        It 'touches only those tasks' {
            Assert-MockCalled Invoke-CrTaskRegistrationAdapter -Times 3 -Exactly
            Assert-MockCalled Invoke-CrTaskRegistrationAdapter -Times 0 -Exactly -ParameterFilter { @('AdminJob', 'InteractiveOnly') -contains $TaskName }
        }
        It 'keeps UserId, LogonType, the definition and the folder of a LogonType 6 task' {
            Assert-MockCalled Invoke-CrTaskRegistrationAdapter -Times 1 -Exactly -ParameterFilter {
                $TaskName -eq 'TestServerJob' -and $UserId -ceq 'SM-TEST01\ApplicationUser' -and $LogonType -eq 6 -and
                $Folder.Path -eq '\Vendor' -and $Definition.Marker -eq '\Vendor\TestServerJob'
            }
        }
        It 'registers root and nested tasks in their own folder' {
            Assert-MockCalled Invoke-CrTaskRegistrationAdapter -Times 1 -Exactly -ParameterFilter { $TaskName -eq 'TestExport' -and $Folder.Path -eq '\' -and $LogonType -eq 1 -and $UserId -ceq 'ApplicationUser' }
            Assert-MockCalled Invoke-CrTaskRegistrationAdapter -Times 1 -Exactly -ParameterFilter { $TaskName -eq 'AppJob' -and $Folder.Path -eq '\Vendor\Deep' }
        }
        It 'passes the full task SDDL from GetSecurityDescriptor(0xF)' {
            Assert-MockCalled Invoke-CrTaskRegistrationAdapter -Times 3 -Exactly -ParameterFilter { $Sddl -ceq 'O:BAG:SYD:(A;;FA;;;BA)S:(AU;FA;FA;;;WD)' }
        }
        It 'passes the SecureString' {
            Assert-MockCalled Invoke-CrTaskRegistrationAdapter -Times 3 -Exactly -ParameterFilter { $Secret -is [System.Security.SecureString] }
        }
        It 'connects to the scheduler once' {
            Assert-MockCalled Get-CrTaskSchedulerRootFolder -Times 1 -Exactly
        }
        It 'reports the unchanged UserId and no dropped SACL' {
            $t = @($r | Where-Object { $_['Path'] -eq '\Vendor\TestServerJob' })[0]
            $t['FromUserId'] | Should Be 'SM-TEST01\ApplicationUser'
            $t['ToUserId'] | Should Be 'SM-TEST01\ApplicationUser'
            $t['SaclDropped'] | Should Be $false
            $t['Warning'] | Should BeNullOrEmpty
        }
    }

    Context 'one task fails' {
        Mock Get-CrTaskSchedulerRootFolder { New-TestLiveTree }
        Mock Invoke-CrTaskRegistrationAdapter { @{ Success = $true; Error = $null; HResult = $null } }
        Mock Invoke-CrTaskRegistrationAdapter -ParameterFilter { $TaskName -eq 'TestServerJob' } { @{ Success = $false; Error = 'RegisterTaskDefinition failed (COMException, 0x8007052E)'; HResult = -2147023570 } }
        $r = Update-CrTaskCredentials -State (New-TestTaskState) -Sid $appSid -Secret $secret

        It 'reports the failure for that task and updates the others' {
            $job = @($r | Where-Object { $_['Path'] -eq '\Vendor\TestServerJob' })[0]
            $job['Success'] | Should Be $false
            $job['Error'] | Should Match '8007052E'
            @($r | Where-Object { $_['Success'] }).Count | Should Be 2
        }
        It 'does not retry a credential error (D12)' {
            Assert-MockCalled Invoke-CrTaskRegistrationAdapter -Times 1 -Exactly -ParameterFilter { $TaskName -eq 'TestServerJob' }
        }
    }

    Context 'registration with the SACL fails' {
        Mock Get-CrTaskSchedulerRootFolder { New-TestLiveTree }
        Mock Invoke-CrTaskRegistrationAdapter { @{ Success = $true; Error = $null; HResult = $null } }
        Mock Invoke-CrTaskRegistrationAdapter -ParameterFilter { $Sddl -ceq 'O:BAG:SYD:(A;;FA;;;BA)S:(AU;FA;FA;;;WD)' } { @{ Success = $false; Error = 'RegisterTaskDefinition failed (COMException, 0x80070522)'; HResult = -2147023582 } }
        $r = Update-CrTaskCredentials -State (New-TestTaskState) -Sid $appSid -Secret $secret

        It 'retries each task once with owner, group and DACL (0x7)' {
            Assert-MockCalled Invoke-CrTaskRegistrationAdapter -Times 3 -Exactly -ParameterFilter { $Sddl -ceq 'O:BAG:SYD:(A;;FA;;;BA)S:(AU;FA;FA;;;WD)' }
            Assert-MockCalled Invoke-CrTaskRegistrationAdapter -Times 3 -Exactly -ParameterFilter { $Sddl -ceq 'O:BAG:SYD:(A;;FA;;;BA)' }
            Assert-MockCalled Invoke-CrTaskRegistrationAdapter -Times 6 -Exactly
        }
        It 'keeps UserId and LogonType on the retry' {
            Assert-MockCalled Invoke-CrTaskRegistrationAdapter -Times 1 -Exactly -ParameterFilter { $Sddl -ceq 'O:BAG:SYD:(A;;FA;;;BA)' -and $TaskName -eq 'TestServerJob' -and $UserId -ceq 'SM-TEST01\ApplicationUser' -and $LogonType -eq 6 }
        }
        It 'reports success with the dropped SACL' {
            @($r | Where-Object { $_['Success'] }).Count | Should Be 3
            foreach ($e in $r) {
                $e['SaclDropped'] | Should Be $true
                $e['Warning'] | Should Match 'SACL dropped'
                $e['Warning'] | Should Match '80070522'
            }
        }
    }

    Context 'registration fails with and without the SACL' {
        Mock Get-CrTaskSchedulerRootFolder { New-TestLiveTree }
        Mock Invoke-CrTaskRegistrationAdapter { @{ Success = $false; Error = 'RegisterTaskDefinition failed (COMException, 0x80070005)'; HResult = -2147024891 } }
        $r = Update-CrTaskCredentials -State (New-TestTaskState) -Sid $appSid -Secret $secret

        It 'retries once and reports both attempts' {
            Assert-MockCalled Invoke-CrTaskRegistrationAdapter -Times 6 -Exactly
            foreach ($e in $r) {
                $e['Success'] | Should Be $false
                $e['SaclDropped'] | Should Be $false
                $e['Error'] | Should Match 'retried without the SACL'
            }
        }
    }

    Context 'SACL not readable' {
        Mock Get-CrTaskSchedulerRootFolder { New-TestLiveTree -SaclFails }
        Mock Invoke-CrTaskRegistrationAdapter { @{ Success = $true; Error = $null; HResult = $null } }
        $r = Update-CrTaskCredentials -State (New-TestTaskState) -Sid $appSid -Secret $secret

        It 'falls back to owner, group and DACL (0x7)' {
            @($r | Where-Object { $_['Success'] }).Count | Should Be 3
            Assert-MockCalled Invoke-CrTaskRegistrationAdapter -Times 3 -Exactly -ParameterFilter { $Sddl -ceq 'O:BAG:SYD:(A;;FA;;;BA)' }
        }
    }

    Context 'SACL not readable and registration fails' {
        Mock Get-CrTaskSchedulerRootFolder { New-TestLiveTree -SaclFails }
        Mock Invoke-CrTaskRegistrationAdapter { @{ Success = $false; Error = 'RegisterTaskDefinition failed (COMException, 0x80070005)'; HResult = -2147024891 } }
        $r = Update-CrTaskCredentials -State (New-TestTaskState) -Sid $appSid -Secret $secret

        It 'does not retry (no SACL was sent)' {
            Assert-MockCalled Invoke-CrTaskRegistrationAdapter -Times 3 -Exactly
            @($r | Where-Object { $_['Success'] }).Count | Should Be 0
        }
    }

    Context 'principal changed since the audit' {
        Mock Get-CrTaskSchedulerRootFolder { New-TestLiveTree -ChangedPrincipal }
        Mock Invoke-CrTaskRegistrationAdapter { @{ Success = $true; Error = $null; HResult = $null } }
        $r = Update-CrTaskCredentials -State (New-TestTaskState) -Sid $appSid -Secret $secret

        It 'does not register that task and reports it' {
            $t = @($r | Where-Object { $_['Path'] -eq '\TestExport' })[0]
            $t['Success'] | Should Be $false
            $t['Error'] | Should Match 'changed since the audit'
            Assert-MockCalled Invoke-CrTaskRegistrationAdapter -Times 0 -Exactly -ParameterFilter { $TaskName -eq 'TestExport' }
            Assert-MockCalled Invoke-CrTaskRegistrationAdapter -Times 2 -Exactly
        }
    }

    Context 'task deleted since the audit' {
        Mock Get-CrTaskSchedulerRootFolder { New-TestLiveTree -MissingTask 'TestServerJob' }
        Mock Invoke-CrTaskRegistrationAdapter { @{ Success = $true; Error = $null; HResult = $null } }
        $r = Update-CrTaskCredentials -State (New-TestTaskState) -Sid $appSid -Secret $secret

        It 'reports the COM error for that task and continues' {
            $t = @($r | Where-Object { $_['Path'] -eq '\Vendor\TestServerJob' })[0]
            $t['Success'] | Should Be $false
            $t['Error'] | Should Match 'cannot find the file'
            @($r | Where-Object { $_['Success'] }).Count | Should Be 2
        }
    }

    Context 'Task Scheduler not available' {
        Mock Get-CrTaskSchedulerRootFolder { throw 'The service cannot be started.' }
        Mock Invoke-CrTaskRegistrationAdapter { @{ Success = $true; Error = $null; HResult = $null } }
        $r = Update-CrTaskCredentials -State (New-TestTaskState) -Sid $appSid -Secret $secret

        It 'fails every task of the SID' {
            @($r).Count | Should Be 3
            foreach ($e in $r) {
                $e['Success'] | Should Be $false
                $e['Error'] | Should Match 'The service cannot be started'
            }
            Assert-MockCalled Invoke-CrTaskRegistrationAdapter -Times 0 -Exactly
        }
    }

    Context 'no task of the account' {
        Mock Get-CrTaskSchedulerRootFolder { New-TestLiveTree }
        Mock Invoke-CrTaskRegistrationAdapter { @{ Success = $true; Error = $null; HResult = $null } }
        $r = Update-CrTaskCredentials -State (New-TestTaskState) -Sid 'S-1-5-21-1000-2000-3000-1099' -Secret $secret

        It 'returns an empty array without connecting' {
            ($r -is [array]) | Should Be $true
            @($r).Count | Should Be 0
            Assert-MockCalled Get-CrTaskSchedulerRootFolder -Times 0 -Exactly
        }
    }

    Context 'tasks could not be read' {
        Mock Get-CrTaskSchedulerRootFolder { New-TestLiveTree }
        Mock Invoke-CrTaskRegistrationAdapter { @{ Success = $true; Error = $null; HResult = $null } }
        $r = Update-CrTaskCredentials -State @{ Tasks = @{ Error = 'Schedule.Service failed' } } -Sid $appSid -Secret $secret

        It 'returns a single failed entry' {
            @($r).Count | Should Be 1
            $r[0]['Success'] | Should Be $false
            $r[0]['Error'] | Should Match 'Schedule.Service failed'
            Assert-MockCalled Invoke-CrTaskRegistrationAdapter -Times 0 -Exactly
        }
    }
}

Describe 'Move-CrTaskAccount' {
    $appSid = 'S-1-5-21-1000-2000-3000-1005'
    $newUserId = 'SM-TEST01\CrTestNewUser'
    $secret = ConvertTo-SecureString 'Dummy-2b' -AsPlainText -Force
    Mock Resolve-CrNameToSid { Get-TestTaskSid -Name $Name }

    Context 'password-stored tasks of the old account' {
        Mock Get-CrTaskSchedulerRootFolder { New-TestLiveTree }
        Mock Invoke-CrTaskRegistrationAdapter { @{ Success = $true; Error = $null; HResult = $null } }
        $r = Move-CrTaskAccount -State (New-TestTaskState) -FromSid $appSid -ToUserId $newUserId -Secret $secret

        It 'returns one successful result per password-stored task of FromSid' {
            ($r -is [array]) | Should Be $true
            (@($r | ForEach-Object { $_['Path'] }) -join ',') | Should Be '\TestExport,\Vendor\TestServerJob,\Vendor\Deep\AppJob'
            @($r | Where-Object { $_['Success'] }).Count | Should Be 3
            ((@($r[0].Keys) | Sort-Object) -join ',') | Should Be 'Error,FromUserId,Path,SaclDropped,Success,ToUserId,Warning'
        }
        It 'moves only those tasks' {
            Assert-MockCalled Invoke-CrTaskRegistrationAdapter -Times 3 -Exactly
            Assert-MockCalled Invoke-CrTaskRegistrationAdapter -Times 0 -Exactly -ParameterFilter { @('AdminJob', 'InteractiveOnly') -contains $TaskName }
        }
        It 'passes the new UserId for every task' {
            Assert-MockCalled Invoke-CrTaskRegistrationAdapter -Times 3 -Exactly -ParameterFilter { $UserId -ceq 'SM-TEST01\CrTestNewUser' }
        }
        It 'keeps LogonType, the definition, the folder and the full SDDL' {
            Assert-MockCalled Invoke-CrTaskRegistrationAdapter -Times 1 -Exactly -ParameterFilter {
                $TaskName -eq 'TestServerJob' -and $LogonType -eq 6 -and $Folder.Path -eq '\Vendor' -and
                $Definition.Marker -eq '\Vendor\TestServerJob' -and $Sddl -ceq 'O:BAG:SYD:(A;;FA;;;BA)S:(AU;FA;FA;;;WD)'
            }
            Assert-MockCalled Invoke-CrTaskRegistrationAdapter -Times 1 -Exactly -ParameterFilter { $TaskName -eq 'TestExport' -and $LogonType -eq 1 -and $Folder.Path -eq '\' }
            Assert-MockCalled Invoke-CrTaskRegistrationAdapter -Times 3 -Exactly -ParameterFilter { $Sddl -ceq 'O:BAG:SYD:(A;;FA;;;BA)S:(AU;FA;FA;;;WD)' }
        }
        It 'passes the SecureString' {
            Assert-MockCalled Invoke-CrTaskRegistrationAdapter -Times 3 -Exactly -ParameterFilter { $Secret -is [System.Security.SecureString] }
        }
        It 'reports the old and the new UserId' {
            $t = @($r | Where-Object { $_['Path'] -eq '\Vendor\TestServerJob' })[0]
            $t['FromUserId'] | Should Be 'SM-TEST01\ApplicationUser'
            $t['ToUserId'] | Should Be 'SM-TEST01\CrTestNewUser'
            $t['SaclDropped'] | Should Be $false
        }
    }

    Context 'principal changed since the audit' {
        Mock Get-CrTaskSchedulerRootFolder { New-TestLiveTree -ChangedPrincipal }
        Mock Invoke-CrTaskRegistrationAdapter { @{ Success = $true; Error = $null; HResult = $null } }
        $r = Move-CrTaskAccount -State (New-TestTaskState) -FromSid $appSid -ToUserId $newUserId -Secret $secret

        It 'does not move that task and reports it' {
            $t = @($r | Where-Object { $_['Path'] -eq '\TestExport' })[0]
            $t['Success'] | Should Be $false
            $t['Error'] | Should Match 'changed since the audit'
            Assert-MockCalled Invoke-CrTaskRegistrationAdapter -Times 0 -Exactly -ParameterFilter { $TaskName -eq 'TestExport' }
            Assert-MockCalled Invoke-CrTaskRegistrationAdapter -Times 2 -Exactly
        }
    }

    Context 'one task fails' {
        Mock Get-CrTaskSchedulerRootFolder { New-TestLiveTree }
        Mock Invoke-CrTaskRegistrationAdapter { @{ Success = $true; Error = $null; HResult = $null } }
        Mock Invoke-CrTaskRegistrationAdapter -ParameterFilter { $TaskName -eq 'AppJob' } { @{ Success = $false; Error = 'RegisterTaskDefinition failed (COMException, 0x80070569)'; HResult = -2147023511 } }
        $r = Move-CrTaskAccount -State (New-TestTaskState) -FromSid $appSid -ToUserId $newUserId -Secret $secret

        It 'reports that task and moves the others' {
            $t = @($r | Where-Object { $_['Path'] -eq '\Vendor\Deep\AppJob' })[0]
            $t['Success'] | Should Be $false
            $t['Error'] | Should Match '80070569'
            @($r | Where-Object { $_['Success'] }).Count | Should Be 2
        }
        It 'does not retry a credential error (logon type not granted)' {
            Assert-MockCalled Invoke-CrTaskRegistrationAdapter -Times 1 -Exactly -ParameterFilter { $TaskName -eq 'AppJob' }
        }
    }

    Context 'registration with the SACL fails' {
        Mock Get-CrTaskSchedulerRootFolder { New-TestLiveTree }
        Mock Invoke-CrTaskRegistrationAdapter { @{ Success = $true; Error = $null; HResult = $null } }
        Mock Invoke-CrTaskRegistrationAdapter -ParameterFilter { $Sddl -ceq 'O:BAG:SYD:(A;;FA;;;BA)S:(AU;FA;FA;;;WD)' } { @{ Success = $false; Error = 'RegisterTaskDefinition failed (COMException, 0x80070522)'; HResult = -2147023582 } }
        $r = Move-CrTaskAccount -State (New-TestTaskState) -FromSid $appSid -ToUserId $newUserId -Secret $secret

        It 'retries with the 0x7 SDDL and the new UserId' {
            Assert-MockCalled Invoke-CrTaskRegistrationAdapter -Times 3 -Exactly -ParameterFilter { $Sddl -ceq 'O:BAG:SYD:(A;;FA;;;BA)' -and $UserId -ceq 'SM-TEST01\CrTestNewUser' }
            Assert-MockCalled Invoke-CrTaskRegistrationAdapter -Times 6 -Exactly
        }
        It 'reports the moves with the dropped SACL' {
            foreach ($e in $r) {
                $e['Success'] | Should Be $true
                $e['SaclDropped'] | Should Be $true
                $e['Warning'] | Should Match 'SACL dropped'
            }
        }
    }

    Context 'Task Scheduler not available' {
        Mock Get-CrTaskSchedulerRootFolder { throw 'The service cannot be started.' }
        Mock Invoke-CrTaskRegistrationAdapter { @{ Success = $true; Error = $null; HResult = $null } }
        $r = Move-CrTaskAccount -State (New-TestTaskState) -FromSid $appSid -ToUserId $newUserId -Secret $secret

        It 'fails every task of FromSid' {
            @($r).Count | Should Be 3
            @($r | Where-Object { $_['Success'] }).Count | Should Be 0
            Assert-MockCalled Invoke-CrTaskRegistrationAdapter -Times 0 -Exactly
        }
    }

    Context 'tasks could not be read' {
        Mock Get-CrTaskSchedulerRootFolder { New-TestLiveTree }
        Mock Invoke-CrTaskRegistrationAdapter { @{ Success = $true; Error = $null; HResult = $null } }
        $r = Move-CrTaskAccount -State @{ Tasks = @{ Error = 'Schedule.Service failed' } } -FromSid $appSid -ToUserId $newUserId -Secret $secret

        It 'returns a single failed entry' {
            @($r).Count | Should Be 1
            $r[0]['Success'] | Should Be $false
            $r[0]['Error'] | Should Match 'Schedule.Service failed'
            Assert-MockCalled Invoke-CrTaskRegistrationAdapter -Times 0 -Exactly
        }
    }

    Context 'missing arguments' {
        Mock Get-CrTaskSchedulerRootFolder { New-TestLiveTree }
        Mock Invoke-CrTaskRegistrationAdapter { @{ Success = $true; Error = $null; HResult = $null } }

        It 'throws without a target UserId, FromSid or password and touches nothing' {
            { Move-CrTaskAccount -State (New-TestTaskState) -FromSid $appSid -ToUserId '' -Secret $secret } | Should Throw
            { Move-CrTaskAccount -State (New-TestTaskState) -FromSid '' -ToUserId $newUserId -Secret $secret } | Should Throw
            { Move-CrTaskAccount -State (New-TestTaskState) -FromSid $appSid -ToUserId $newUserId -Secret $null } | Should Throw
            Assert-MockCalled Invoke-CrTaskRegistrationAdapter -Times 0 -Exactly
            Assert-MockCalled Get-CrTaskSchedulerRootFolder -Times 0 -Exactly
        }
    }
}

Describe 'Test-CrTaskCredentialError' {
    It 'recognizes logon and account errors' {
        foreach ($hr in @(-2147023570, -2147023511, -2147023565, -2147022987)) {
            Test-CrTaskCredentialError -HResult $hr | Should Be $true
        }
    }
    It 'does not treat other errors as credential errors' {
        foreach ($hr in @(-2147023582, -2147024891, -2147216609, 0)) {
            Test-CrTaskCredentialError -HResult $hr | Should Be $false
        }
        Test-CrTaskCredentialError -HResult $null | Should Be $false
    }
}

Describe 'Split-CrTaskPath' {
    It 'splits root and nested paths' {
        $a = Split-CrTaskPath -Path '\Job'
        $a['Folder'] | Should Be '\'
        $a['Name'] | Should Be 'Job'
        $b = Split-CrTaskPath -Path '\Vendor\Deep\Job'
        $b['Folder'] | Should Be '\Vendor\Deep'
        $b['Name'] | Should Be 'Job'
    }
}

Describe 'Tasks.ps1 secret handling (D4)' {
    It 'never converts a secret to plaintext' {
        $text = [System.IO.File]::ReadAllText((Join-Path $here '..\src\lib\Tasks.ps1'))
        $text | Should Not Match '\$plain|PtrToStringBSTR|SecureStringToBSTR|ConvertFrom-SecureString|GetNetworkCredential'
    }
}
