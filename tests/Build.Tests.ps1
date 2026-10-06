# Build.Tests.ps1 - tests for the PS 2.0 / D4 lint (build\Test-Ps2Syntax.ps1). Pester 3.4.
# The lint uses the PowerShell AST (PS 3.0+); on a PS 2.0 engine these tests are skipped.

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $here
$lintScript = Join-Path $repoRoot 'build\Test-Ps2Syntax.ps1'

if ($PSVersionTable.PSVersion.Major -lt 3) {
    Describe 'Test-Ps2Syntax' -Tags 'Build' {
        It 'needs the PowerShell 3.0+ AST' -Skip { }
    }
    return
}

# Defines Invoke-CrPs2Lint only; the scan itself does not run when dot-sourced.
. $lintScript

function Get-TestLintRules {
    param([string]$Text, [string]$FileName = 'src\CredentialRotation.ps1')
    $rules = New-Object System.Collections.ArrayList
    foreach ($v in @(Invoke-CrPs2Lint -ScriptText $Text -FileName $FileName)) { [void]$rules.Add($v.Rule) }
    return , $rules
}

Describe 'Test-Ps2Syntax: PS 3+ constructs' -Tags 'Build' {

    $cases = @(
        @{ Rule = 'Ps2-Accelerator'; Text = '$h = [ordered]@{ a = 1 }' }
        @{ Rule = 'Ps2-Accelerator'; Text = '$o = [pscustomobject]@{ a = 1 }' }
        @{ Rule = 'Ps2-StaticNew'; Text = '$l = [System.Collections.ArrayList]::new()' }
        @{ Rule = 'Ps2-Class'; Text = 'class Foo { [int]$A }' }
        @{ Rule = 'Ps2-Class'; Text = 'enum Color { Red }' }
        @{ Rule = 'Ps2-InOperator'; Text = 'if (1 -in @(1, 2)) { }' }
        @{ Rule = 'Ps2-InOperator'; Text = 'if (1 -notin @(1, 2)) { }' }
        @{ Rule = 'Ps2-PSItem'; Text = '$a | ForEach-Object { $PSItem }' }
        @{ Rule = 'Ps2-MagicMethod'; Text = '$a.Where({ $_ })' }
        @{ Rule = 'Ps2-MagicMethod'; Text = '$a.ForEach({ $_ })' }
        @{ Rule = 'Ps2-UsingScope'; Text = 'Invoke-Command -ScriptBlock { $using:x }' }
        @{ Rule = 'Ps2-Cmdlet'; Text = 'Get-CimInstance Win32_OperatingSystem' }
        @{ Rule = 'Ps2-Cmdlet'; Text = 'Invoke-CimMethod -ClassName X -MethodName Y' }
        @{ Rule = 'Ps2-Cmdlet'; Text = '$x | ConvertTo-Json' }
        @{ Rule = 'Ps2-Cmdlet'; Text = 'ConvertFrom-Json $s' }
        @{ Rule = 'Ps2-Cmdlet'; Text = 'Invoke-RestMethod http://localhost/' }
        @{ Rule = 'Ps2-Cmdlet'; Text = 'Invoke-WebRequest http://localhost/' }
        @{ Rule = 'Ps2-Cmdlet'; Text = 'Get-LocalUser' }
        @{ Rule = 'Ps2-ErrorActionIgnore'; Text = 'Get-Item x -ErrorAction Ignore' }
        @{ Rule = 'Ps2-ErrorActionIgnore'; Text = 'Get-Item x -ea:Ignore' }
        @{ Rule = 'Ps2-ErrorActionIgnore'; Text = '$ErrorActionPreference = ''Ignore''' }
        @{ Rule = 'Ps2-Parameter'; Text = 'Get-ChildItem C:\ -File' }
        @{ Rule = 'Ps2-Parameter'; Text = 'gci C:\ -Directory' }
        @{ Rule = 'Ps2-Parameter'; Text = 'Get-Content x -Raw' }
        @{ Rule = 'Ps2-Parameter'; Text = '$rows | Export-Csv x.csv -Append' }
        @{ Rule = 'Ps2-ScriptRoot'; Text = '$p = $PSScriptRoot' }
        @{ Rule = 'Ps2-ScriptRoot'; Text = '$p = $PSCommandPath' }
        @{ Rule = 'Ps2-SimplifiedSyntax'; Text = '$a | Where-Object Name -eq x' }
        @{ Rule = 'Ps2-SimplifiedSyntax'; Text = '$a | ? Enabled' }
        @{ Rule = 'Ps2-SimplifiedSyntax'; Text = '$a | ForEach-Object Name' }
        @{ Rule = 'Ps2-SimplifiedSyntax'; Text = '$a | % -MemberName Name' }
        @{ Rule = 'Ps2-ShiftOperator'; Text = '$x = 1 -shl 2' }
        @{ Rule = 'Ps2-ShiftOperator'; Text = '$x = 8 -shr 1' }
        @{ Rule = 'Ps2-UsingStatement'; Text = 'using namespace System.Text' }
        @{ Rule = 'Ps2-AttributeShorthand'; Text = 'function f { param([Parameter(Mandatory)]$a) }' }
        @{ Rule = 'Ps2-Redirection'; Text = 'Get-Item x 3> $null' }
        @{ Rule = 'Ps2-Redirection'; Text = 'Get-Item x *>&1' }
    )

    It 'flags <Rule> in: <Text>' -TestCases $cases {
        param($Rule, $Text)
        (Get-TestLintRules $Text) -contains $Rule | Should Be $true
    }

    $clean = @(
        @{ Text = '$o = New-Object PSObject -Property @{ a = 1 }' }
        @{ Text = 'if (@(1, 2) -contains 1) { }' }
        @{ Text = '$a | Where-Object { $_.Name -eq ''x'' }' }
        @{ Text = '$a | ForEach-Object -Process { $_ }' }
        @{ Text = '$a | % $block' }
        @{ Text = '$a | ? -FilterScript { $_ }' }
        @{ Text = 'foreach ($i in $a) { $i }' }
        @{ Text = 'Get-Item x -ErrorAction SilentlyContinue 2>&1' }
        @{ Text = 'Get-ChildItem C:\ -Recurse -Filter *.ps1' }
        @{ Text = 'function f { param([ValidateNotNullOrEmpty()][string]$Name, [Parameter(Mandatory = $true)]$x) }' }
        @{ Text = '$l = New-Object System.Collections.ArrayList; [void]$l.Add(1)' }
        @{ Text = '[Array]::ForEach' }
        @{ Text = '$s = ''Invoke-Expression [ordered] -in $PSItem''' }
    )

    It 'accepts PS 2.0 code: <Text>' -TestCases $clean {
        param($Text)
        (Get-TestLintRules $Text).Count | Should Be 0
    }

    It 'reports parse errors' {
        (Get-TestLintRules 'function f {') -contains 'Parse' | Should Be $true
    }

    It 'reports the line and column of the construct' {
        $v = @(Invoke-CrPs2Lint -ScriptText "`$a = 1`r`n`$b = [ordered]@{}" -FileName 'x.ps1')
        $v.Count | Should Be 1
        $v[0].Line | Should Be 2
        $v[0].Column | Should Be 6
        $v[0].File | Should Be 'x.ps1'
    }
}

Describe 'Test-Ps2Syntax: D4 secret rules' -Tags 'Build' {

    $cases = @(
        @{ Rule = 'D4-InvokeExpression'; Text = 'Invoke-Expression $s' }
        @{ Rule = 'D4-InvokeExpression'; Text = 'iex $s' }
        @{ Rule = 'D4-PlainVariable'; Text = '$plainText = 1' }
        @{ Rule = 'D4-PlainArgument'; Text = 'Set-CrThing -Value $plainText' }
        @{ Rule = 'D4-SecretOutput'; Text = 'Write-Host $password' }
        @{ Rule = 'D4-SecretOutput'; Text = 'Write-Output "x $newSecret"' }
        @{ Rule = 'D4-SecretOutput'; Text = 'Write-Verbose (''a'' + $adminPassword)' }
        @{ Rule = 'D4-SecretOutput'; Text = 'Write-CrLog -Message $script:SqlSecret' }
        @{ Rule = 'D4-SecretOutput'; Text = 'Export-Csv -Path $p -InputObject $passwordList' }
        @{ Rule = 'D4-SecretOutput'; Text = '$password | Write-Output' }
        @{ Rule = 'D4-SecretExternal'; Text = '& net.exe user x $password' }
        @{ Rule = 'D4-SecretExternal'; Text = 'net user x $password' }
    )

    It 'flags <Rule> in: <Text>' -TestCases $cases {
        param($Rule, $Text)
        (Get-TestLintRules $Text) -contains $Rule | Should Be $true
    }

    It 'allows $plain* variables in src\lib\Adapters.ps1' {
        (Get-TestLintRules '$plainText = 1' 'C:\x\src\lib\Adapters.ps1').Count | Should Be 0
    }

    It 'still flags $plain* command arguments in src\lib\Adapters.ps1' {
        (Get-TestLintRules 'Set-CrThing $plainText' 'src/lib/Adapters.ps1') -contains 'D4-PlainArgument' | Should Be $true
    }

    It 'does not flag property names that contain password' {
        (Get-TestLintRules 'Write-CrLog ("MinPasswordLength {0}" -f $p.MinPasswordLength)').Count | Should Be 0
    }
}

Describe 'Test-Ps2Syntax: lib function names' -Tags 'Build' {

    It 'requires Verb-CrNoun with an approved verb in src\lib' {
        $text = 'function Get-Thing { }; function Fetch-CrX { }; function Get-CrThing { }; function get-crX { }'
        $naming = @((Get-TestLintRules $text 'src\lib\Compat.ps1') | Where-Object { $_ -eq 'Naming' })
        $naming.Count | Should Be 3
    }

    It 'does not check names outside src\lib' {
        (Get-TestLintRules 'function Get-Thing { }' 'src\CredentialRotation.ps1').Count | Should Be 0
    }
}

Describe 'Test-Ps2Syntax: suppression' -Tags 'Build' {

    It 'honours a trailing lint-ignore comment for the named rule' {
        (Get-TestLintRules 'if (1 -in 2) { } # lint-ignore: Ps2-InOperator').Count | Should Be 0
    }

    It 'accepts several rules in one comment' {
        (Get-TestLintRules '$x = [ordered]@{ a = 1 -shl 2 } # lint-ignore: Ps2-ShiftOperator, Ps2-Accelerator').Count | Should Be 0
    }

    It 'does not suppress other rules' {
        (Get-TestLintRules 'if (1 -in 2) { } # lint-ignore: Ps2-ShiftOperator') -contains 'Ps2-InOperator' | Should Be $true
    }

    It 'does not suppress from the previous line' {
        (Get-TestLintRules "# lint-ignore: Ps2-InOperator`r`nif (1 -in 2) { }") -contains 'Ps2-InOperator' | Should Be $true
    }
}

Describe 'Test-Ps2Syntax: script' -Tags 'Build' {

    It 'prints file:line rule message and exits 1 on violations' {
        $file = Join-Path $TestDrive 'Bad.ps1'
        Set-Content -LiteralPath $file -Value "`$a = 1`r`nif (1 -in 2) { }"
        $output = @(& $lintScript -Path $file)
        $LASTEXITCODE | Should Be 1
        $output.Count | Should Be 1
        $output[0] | Should Match '^.*Bad\.ps1:2 Ps2-InOperator \S'
    }

    It 'exits 0 when there is nothing to report' {
        $file = Join-Path $TestDrive 'Good.ps1'
        Set-Content -LiteralPath $file -Value 'if (@(1) -contains 1) { }'
        $output = @(& $lintScript -Path $file)
        $LASTEXITCODE | Should Be 0
        $output.Count | Should Be 0
    }

    It 'does not flag the build and test scripts themselves' {
        $own = @(
            $lintScript,
            (Join-Path $repoRoot 'build\Build.ps1'),
            (Join-Path $repoRoot 'tests\Invoke-Tests.ps1'),
            (Join-Path $repoRoot 'tests\Build.Tests.ps1')
        )
        foreach ($f in $own) {
            $found = @(Invoke-CrPs2Lint -Path $f | ForEach-Object { '{0}:{1} {2}' -f $f, $_.Line, $_.Rule })
            ($found -join '; ') | Should Be ''
        }
    }
}
