# Pester 3.4 tests for src\lib\Groups.ps1. The netapi32 wrappers and name resolution are mocked.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here '..\src\lib\Compat.ps1')
. (Join-Path $here '..\src\lib\Native.ps1')
. (Join-Path $here '..\src\lib\Groups.ps1')

# Stubs for the Native.ps1 write wrappers (CONTRACTS), defined after Native.ps1 so a missing mock can never change
# a real group; mocked below.
function Add-CrLocalGroupMemberSid { param([string]$GroupName, [string]$MemberSid) throw 'Add-CrLocalGroupMemberSid is not mocked' }
function Remove-CrLocalGroupMemberSid { param([string]$GroupName, [string]$MemberSid) throw 'Remove-CrLocalGroupMemberSid is not mocked' }

Describe 'Get-CrLocalGroups' {
    Mock Resolve-CrNameToSid {
        switch ($Name) {
            'TestAdmins'  { return 'S-1-5-32-544' }
            'TestEmpty'   { return 'S-1-5-21-1000-2000-3000-1101' }
            'TestSingle'  { return 'S-1-5-21-1000-2000-3000-1102' }
            'TestBroken'  { return 'S-1-5-21-1000-2000-3000-1103' }
            default       { return $null }
        }
    }
    Mock Get-CrLocalGroupMemberSids {
        switch ($GroupName) {
            'TestAdmins'   { return , @('S-1-5-21-1000-2000-3000-500', 'S-1-5-21-1000-2000-3000-1001', 'S-1-5-4') }
            'TestEmpty'    { return , @() }
            'TestSingle'   { return 'S-1-5-11' }
            'TestBroken'   { throw 'NetLocalGroupGetMembers(TestBroken) failed: Access is denied (error 5)' }
            'TestNoSid'    { return 'S-1-5-21-1000-2000-3000-1002' }
        }
    }

    Context 'returns names, SIDs and member SIDs per group' {
        It 'returns names, SIDs and member SIDs per group' {
            Mock Get-CrLocalGroupNames { return , @('TestAdmins', 'TestEmpty', 'TestSingle') }
            $groups = Get-CrLocalGroups
            ($groups -is [array]) | Should Be $true
            $groups.Count | Should Be 3
    
            $groups[0]['Name'] | Should Be 'TestAdmins'
            $groups[0]['Sid'] | Should Be 'S-1-5-32-544'
            ($groups[0]['MemberSids'] -join ',') | Should Be 'S-1-5-21-1000-2000-3000-500,S-1-5-21-1000-2000-3000-1001,S-1-5-4'
            $groups[0]['Error'] | Should BeNullOrEmpty
    
            ($groups[1]['MemberSids'] -is [array]) | Should Be $true
            $groups[1]['MemberSids'].Count | Should Be 0
            $groups[1]['Error'] | Should BeNullOrEmpty
    
            ($groups[2]['MemberSids'] -is [array]) | Should Be $true
            $groups[2]['MemberSids'].Count | Should Be 1
            $groups[2]['MemberSids'][0] | Should Be 'S-1-5-11'
    
            foreach ($g in $groups) {
                $g.Count | Should Be 4
                foreach ($k in 'Name', 'Sid', 'MemberSids', 'Error') { $g.ContainsKey($k) | Should Be $true }
            }
        }
    }

    Context 'reads members by group name through netapi32, once per group' {
        It 'reads members by group name through netapi32, once per group' {
            Mock Get-CrLocalGroupNames { return , @('TestAdmins', 'TestSingle') }
            $null = Get-CrLocalGroups
            Assert-MockCalled Get-CrLocalGroupMemberSids -Times 2 -Exactly -Scope It
            Assert-MockCalled Get-CrLocalGroupMemberSids -Times 1 -Exactly -ParameterFilter { $GroupName -eq 'TestAdmins' }
            Assert-MockCalled Resolve-CrNameToSid -Times 1 -Exactly -ParameterFilter { $Name -eq 'TestSingle' }
        }
    }

    Context 'records a group whose members cannot be read and still returns the others' {
        It 'records a group whose members cannot be read and still returns the others' {
            Mock Get-CrLocalGroupNames { return , @('TestAdmins', 'TestBroken', 'TestSingle') }
            $groups = Get-CrLocalGroups
            $groups.Count | Should Be 3
            $groups[1]['Name'] | Should Be 'TestBroken'
            $groups[1]['Sid'] | Should Be 'S-1-5-21-1000-2000-3000-1103'
            $groups[1]['Error'] | Should Match 'Access is denied'
            ($groups[1]['MemberSids'] -is [array]) | Should Be $true
            $groups[1]['MemberSids'].Count | Should Be 0
            $groups[0]['Error'] | Should BeNullOrEmpty
            $groups[2]['Error'] | Should BeNullOrEmpty
            $groups[2]['MemberSids'].Count | Should Be 1
        }
    }

    Context 'sets Error but keeps the members when the group SID cannot be resolved' {
        It 'sets Error but keeps the members when the group SID cannot be resolved' {
            Mock Get-CrLocalGroupNames { return 'TestNoSid' }
            $groups = Get-CrLocalGroups
            $groups.Count | Should Be 1
            ($null -eq $groups[0]['Sid']) | Should Be $true
            $groups[0]['Error'] | Should Match 'SID could not be resolved'
            $groups[0]['MemberSids'].Count | Should Be 1
        }
    }

    Context 'returns an empty array when there are no groups' {
        It 'returns an empty array when there are no groups' {
            Mock Get-CrLocalGroupNames { return , @() }
            $groups = Get-CrLocalGroups
            ($null -eq $groups) | Should Be $false
            ($groups -is [array]) | Should Be $true
            $groups.Count | Should Be 0
        }
    }

    Context 'throws when the groups cannot be enumerated' {
        It 'throws when the groups cannot be enumerated' {
            Mock Get-CrLocalGroupNames { throw 'NetLocalGroupEnum failed: Access is denied (error 5)' }
            { Get-CrLocalGroups } | Should Throw 'NetLocalGroupEnum failed'
        }
    }
}

Describe 'Invoke-CrGroupMembershipChange' {
    $tcMember = 'S-1-5-21-1000-2000-3000-1001'
    $tcState = @{
        Groups = @(
            @{ Name = 'TestAdmins'; Sid = 'S-1-5-32-544'; MemberSids = @(); Error = $null },
            @{ Name = 'TestUsers'; Sid = 'S-1-5-32-545'; MemberSids = @(); Error = $null },
            @{ Name = 'TestRemote'; Sid = 'S-1-5-32-555'; MemberSids = @(); Error = $null },
            @{ Name = 'TestCustom'; Sid = 'S-1-5-21-1000-2000-3000-1101'; MemberSids = @(); Error = $null }
        )
    }

    Context 'adds and removes by SID, with the group name from $State.Groups' {
        It 'adds first, then removes, one result per group' {
            $tcCalls = New-Object System.Collections.ArrayList
            Mock Add-CrLocalGroupMemberSid { [void]$tcCalls.Add('Add:' + $GroupName + ':' + $MemberSid); return @{ Success = $true; Win32Error = 0 } }
            Mock Remove-CrLocalGroupMemberSid { [void]$tcCalls.Add('Remove:' + $GroupName + ':' + $MemberSid); return @{ Success = $true; Win32Error = 0 } }
            $r = Invoke-CrGroupMembershipChange -State $tcState -MemberSid $tcMember `
                -RemoveGroupSids @('S-1-5-32-555', 'S-1-5-21-1000-2000-3000-1101') -AddGroupSids @('S-1-5-32-545')
            ($r -is [array]) | Should Be $true
            $r.Count | Should Be 3
            ($tcCalls -join ',') | Should Be ('Add:TestUsers:{0},Remove:TestRemote:{0},Remove:TestCustom:{0}' -f $tcMember)
            $r[0]['GroupSid'] | Should Be 'S-1-5-32-545'
            $r[0]['GroupName'] | Should Be 'TestUsers'
            $r[0]['Action'] | Should Be 'Add'
            $r[0]['Success'] | Should Be $true
            $r[0]['Win32Error'] | Should Be 0
            $r[1]['Action'] | Should Be 'Remove'
            $r[1]['GroupName'] | Should Be 'TestRemote'
            $r[2]['GroupName'] | Should Be 'TestCustom'
            foreach ($x in $r) { foreach ($k in 'GroupSid', 'GroupName', 'Action', 'Success', 'Win32Error') { $x.ContainsKey($k) | Should Be $true } }
        }
    }

    Context 'one failure does not stop the others' {
        It 'reports the failing group and still changes the rest' {
            Mock Add-CrLocalGroupMemberSid { return @{ Success = $true; Win32Error = 0 } }
            Mock Remove-CrLocalGroupMemberSid {
                if ($GroupName -eq 'TestRemote') { return @{ Success = $false; Win32Error = 5 } }
                return @{ Success = $true; Win32Error = 0 }
            }
            $r = Invoke-CrGroupMembershipChange -State $tcState -MemberSid $tcMember -AddGroupSids @('S-1-5-32-544') `
                -RemoveGroupSids @('S-1-5-32-555', 'S-1-5-32-545')
            $r.Count | Should Be 3
            $r[0]['Success'] | Should Be $true
            $r[1]['Success'] | Should Be $false
            $r[1]['Win32Error'] | Should Be 5
            $r[1]['Message'] | Should Match 'TestRemote'
            $r[2]['Success'] | Should Be $true
            Assert-MockCalled Remove-CrLocalGroupMemberSid -Times 2 -Exactly
        }
    }

    Context 'a wrapper that throws' {
        It 'becomes a failed result and the next group still runs' {
            Mock Add-CrLocalGroupMemberSid {
                if ($GroupName -eq 'TestAdmins') { throw 'The native helpers are not ready.' }
                return @{ Success = $true; Win32Error = 0 }
            }
            $r = Invoke-CrGroupMembershipChange -State $tcState -MemberSid $tcMember -AddGroupSids @('S-1-5-32-544', 'S-1-5-32-545')
            $r.Count | Should Be 2
            $r[0]['Success'] | Should Be $false
            $r[0]['Message'] | Should Match 'not ready'
            $r[1]['Success'] | Should Be $true
        }
    }

    Context 'a group SID that is not in $State.Groups' {
        It 'fails that group without calling the wrapper' {
            Mock Add-CrLocalGroupMemberSid { return @{ Success = $true; Win32Error = 0 } }
            $r = Invoke-CrGroupMembershipChange -State $tcState -MemberSid $tcMember -AddGroupSids @('S-1-5-21-1000-2000-3000-1199', 'S-1-5-32-545')
            $r.Count | Should Be 2
            $r[0]['Success'] | Should Be $false
            ($null -eq $r[0]['GroupName']) | Should Be $true
            $r[0]['Message'] | Should Match 'not found'
            $r[1]['Success'] | Should Be $true
            Assert-MockCalled Add-CrLocalGroupMemberSid -Times 1 -Exactly -ParameterFilter { $GroupName -eq 'TestUsers' }
            Assert-MockCalled Add-CrLocalGroupMemberSid -Times 1 -Exactly
        }
    }

    Context 'nothing to change' {
        It 'returns an empty array and calls nothing' {
            Mock Add-CrLocalGroupMemberSid { return @{ Success = $true; Win32Error = 0 } }
            Mock Remove-CrLocalGroupMemberSid { return @{ Success = $true; Win32Error = 0 } }
            $r = Invoke-CrGroupMembershipChange -State $tcState -MemberSid $tcMember -AddGroupSids $null -RemoveGroupSids @()
            ($null -eq $r) | Should Be $false
            ($r -is [array]) | Should Be $true
            $r.Count | Should Be 0
            Assert-MockCalled Add-CrLocalGroupMemberSid -Times 0 -Exactly
            Assert-MockCalled Remove-CrLocalGroupMemberSid -Times 0 -Exactly
        }
    }

    Context 'a single group SID as a scalar' {
        It 'is handled like a one-element list' {
            Mock Remove-CrLocalGroupMemberSid { return @{ Success = $true; Win32Error = 0 } }
            $r = Invoke-CrGroupMembershipChange -State $tcState -MemberSid $tcMember -RemoveGroupSids 'S-1-5-32-544'
            $r.Count | Should Be 1
            $r[0]['GroupName'] | Should Be 'TestAdmins'
            $r[0]['Action'] | Should Be 'Remove'
        }
    }
}
