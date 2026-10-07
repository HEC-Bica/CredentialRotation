$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here '..\src\lib\Compat.ps1')
. (Join-Path $here '..\src\lib\Log.ps1')
. (Join-Path $here '..\src\lib\Journal.ps1')

# Synthetic SIDs only.
$sidA = 'S-1-5-21-1000-2000-3000-1001'
$sidB = 'S-1-5-21-1000-2000-3000-1002'

function New-CrTestJournalRoot {
    param([string]$Name)
    $root = Join-Path $TestDrive $Name
    [void](New-Item -ItemType Directory -Path $root -Force)
    return $root
}

Describe 'Open-CrJournal' {
    Context 'missing file' {
        It 'returns an empty journal that knows its path' {
            $root = New-CrTestJournalRoot 'missing'
            $j = Open-CrJournal -Root $root -Trusted $true
            $j.Runs.Count | Should Be 0
            $j.Path | Should Be (Join-Path $root 'journal.clixml')
            (Test-Path -LiteralPath $j.Path) | Should Be $false
        }
    }

    Context 'round trip' {
        It 'keeps runs, steps per SID and the finished flag across save and open' {
            $root = New-CrTestJournalRoot 'roundtrip'
            $j = Open-CrJournal -Root $root -Trusted $true
            Start-CrJournalRun -Journal $j -RunId 'R1'
            Add-CrJournalStep -Journal $j -RunId 'R1' -Sid $sidA -Step 'CcpCleared'
            Add-CrJournalStep -Journal $j -RunId 'R1' -Sid $sidA -Step 'Secret'
            Add-CrJournalStep -Journal $j -RunId 'R1' -Sid $sidA -Step 'Secret'
            Complete-CrJournalRun -Journal $j -RunId 'R1'
            Start-CrJournalRun -Journal $j -RunId 'R2'
            Add-CrJournalStep -Journal $j -RunId 'R2' -Sid $sidB -Step 'Unlocked'

            $k = Open-CrJournal -Root $root -Trusted $true
            $k.Runs.Count | Should Be 2
            $r1 = $k.Runs[0]
            $r1.RunId | Should Be 'R1'
            $r1.Finished | Should Be $true
            @($r1.Accounts[$sidA]).Count | Should Be 2
            (@($r1.Accounts[$sidA]) -contains 'CcpCleared') | Should Be $true
            (@($r1.Accounts[$sidA]) -contains 'Secret') | Should Be $true
            $r2 = $k.Runs[1]
            $r2.RunId | Should Be 'R2'
            $r2.Finished | Should Be $false
            (@($r2.Accounts[$sidB]) -contains 'Unlocked') | Should Be $true
            ($r2.Started -is [datetime]) | Should Be $true
        }
    }

    Context 'corrupt file' {
        Mock Write-CrLog { }
        It 'returns an empty journal and logs a warning' {
            $root = New-CrTestJournalRoot 'corrupt'
            Set-Content -Path (Join-Path $root 'journal.clixml') -Value 'this is not clixml <<<'
            $j = Open-CrJournal -Root $root -Trusted $true
            $j.Runs.Count | Should Be 0
            Assert-MockCalled Write-CrLog -ParameterFilter { $Level -eq 'Warning' } -Times 1
        }
    }

    Context 'unexpected content' {
        Mock Write-CrLog { }
        It 'ignores a file that holds something other than a journal' {
            $root = New-CrTestJournalRoot 'wrongshape'
            Export-Clixml -Path (Join-Path $root 'journal.clixml') -InputObject @('a', 'b')
            $j = Open-CrJournal -Root $root -Trusted $true
            $j.Runs.Count | Should Be 0
            Assert-MockCalled Write-CrLog -ParameterFilter { $Level -eq 'Warning' } -Times 1
        }
    }

    Context 'untrusted log folder' {
        Mock Write-CrLog { }
        It 'ignores the existing journal and overwrites it with the new run' {
            $root = New-CrTestJournalRoot 'untrusted'
            $old = Open-CrJournal -Root $root -Trusted $true
            Start-CrJournalRun -Journal $old -RunId 'FORGED'
            Add-CrJournalStep -Journal $old -RunId 'FORGED' -Sid $sidA -Step 'Secret'

            $j = Open-CrJournal -Root $root -Trusted $false
            $j.Runs.Count | Should Be 0
            (Test-CrJournalStepInUnfinishedRun -Journal $j -Sid $sidA -Step 'Secret' -ExceptRunId 'R9') | Should Be $false

            Start-CrJournalRun -Journal $j -RunId 'R9'
            $k = Open-CrJournal -Root $root -Trusted $true
            $k.Runs.Count | Should Be 1
            $k.Runs[0].RunId | Should Be 'R9'
        }
    }
}

Describe 'Add-CrJournalStep' {
    Context 'saving' {
        Mock Write-CrJournalFile { }
        It 'saves after every call' {
            $j = @{ Runs = (New-Object System.Collections.ArrayList); Path = 'C:\nonexistent\journal.clixml'; LastSaveError = $null }
            Start-CrJournalRun -Journal $j -RunId 'R1'
            Add-CrJournalStep -Journal $j -RunId 'R1' -Sid $sidA -Step 'PreSteps'
            Add-CrJournalStep -Journal $j -RunId 'R1' -Sid $sidA -Step 'Secret'
            Complete-CrJournalRun -Journal $j -RunId 'R1'
            Assert-MockCalled Write-CrJournalFile -Times 4 -Exactly
        }
    }

    Context 'save failure' {
        Mock Write-CrJournalFile { throw 'disk full' }
        Mock Write-CrLog { }
        It 'does not throw, logs a warning and keeps the error' {
            $j = @{ Runs = (New-Object System.Collections.ArrayList); Path = 'C:\nonexistent\journal.clixml'; LastSaveError = $null }
            { Start-CrJournalRun -Journal $j -RunId 'R1' } | Should Not Throw
            $j.LastSaveError | Should Be 'disk full'
            Assert-MockCalled Write-CrLog -ParameterFilter { $Level -eq 'Warning' } -Times 1
        }
    }

    Context 'validation' {
        Mock Write-CrJournalFile { }
        It 'rejects unknown step names' {
            $j = @{ Runs = (New-Object System.Collections.ArrayList); Path = $null; LastSaveError = $null }
            { Add-CrJournalStep -Journal $j -RunId 'R1' -Sid $sidA -Step 'Password' } | Should Throw
        }

        It 'starts the run implicitly and records each step once' {
            $j = @{ Runs = (New-Object System.Collections.ArrayList); Path = $null; LastSaveError = $null }
            Add-CrJournalStep -Journal $j -RunId 'R1' -Sid $sidA -Step 'Grants'
            Add-CrJournalStep -Journal $j -RunId 'R1' -Sid $sidA -Step 'Grants'
            $j.Runs.Count | Should Be 1
            @($j.Runs[0].Accounts[$sidA]).Count | Should Be 1
        }
    }
}

Describe 'Test-CrJournalStepInUnfinishedRun' {
    $journal = @{ Runs = (New-Object System.Collections.ArrayList); Path = $null; LastSaveError = $null }
    [void]$journal.Runs.Add(@{ RunId = 'DONE'; Started = (Get-Date); Finished = $true; Accounts = @{ $sidB = @('Secret') } })
    [void]$journal.Runs.Add(@{ RunId = 'CRASHED'; Started = (Get-Date); Finished = $false; Accounts = @{ $sidA = @('PreSteps', 'Secret') } })
    [void]$journal.Runs.Add(@{ RunId = 'NOW'; Started = (Get-Date); Finished = $false; Accounts = @{ $sidB = @('Secret') } })

    It 'finds a step of an unfinished earlier run' {
        (Test-CrJournalStepInUnfinishedRun -Journal $journal -Sid $sidA -Step 'Secret' -ExceptRunId 'NOW') | Should Be $true
    }

    It 'ignores finished runs and the current run' {
        (Test-CrJournalStepInUnfinishedRun -Journal $journal -Sid $sidB -Step 'Secret' -ExceptRunId 'NOW') | Should Be $false
    }

    It 'counts the current run when no -ExceptRunId is given' {
        (Test-CrJournalStepInUnfinishedRun -Journal $journal -Sid $sidB -Step 'Secret') | Should Be $true
    }

    It 'is false for another step or an unknown SID' {
        (Test-CrJournalStepInUnfinishedRun -Journal $journal -Sid $sidA -Step 'Verified' -ExceptRunId 'NOW') | Should Be $false
        (Test-CrJournalStepInUnfinishedRun -Journal $journal -Sid 'S-1-5-21-1000-2000-3000-1999' -Step 'Secret' -ExceptRunId 'NOW') | Should Be $false
    }

    It 'is false for an empty or missing journal' {
        $empty = @{ Runs = (New-Object System.Collections.ArrayList) }
        (Test-CrJournalStepInUnfinishedRun -Journal $empty -Sid $sidA -Step 'Secret') | Should Be $false
        (Test-CrJournalStepInUnfinishedRun -Journal $null -Sid $sidA -Step 'Secret') | Should Be $false
    }
}
