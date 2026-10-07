# Pester 3.4 tests for src\lib\Groups.ps1. The netapi32 wrappers and name resolution are mocked.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here '..\src\lib\Compat.ps1')
. (Join-Path $here '..\src\lib\Native.ps1')
. (Join-Path $here '..\src\lib\Groups.ps1')

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
