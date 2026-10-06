<#
.SYNOPSIS
PS 2.0 syntax + D4 secret-rule lint for the credential rotation tool (docs/PLAN.md sections 9 and 11).

.DESCRIPTION
Parses every script with the PowerShell AST (Windows PowerShell 5.1 parser) and reports
PS 3+ constructs, D4 violations and lib function names that are not Verb-CrNoun.
Output: one line per violation, "file:line rule message". Exit code 1 if anything was found.

Suppress a finding with a trailing comment on the same line:  # lint-ignore: <Rule>[, <Rule>]

Runs on Windows PowerShell 5.1 (not shipped). Dot-sourcing the script only defines
Invoke-CrPs2Lint (used by tests\Build.Tests.ps1); it does not run the scan.

.PARAMETER Path
Files or folders to scan (folders recursively, *.ps1). Default: src.

.PARAMETER IncludeTests
Also scan the tests folder.

.EXAMPLE
powershell.exe -NoProfile -ExecutionPolicy Bypass -File build\Test-Ps2Syntax.ps1
#>
param(
    [string[]]$Path,
    [switch]$IncludeTests
)

# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------

function Invoke-CrPs2Lint {
    <#
    .SYNOPSIS
    Lints one script for PS 3+ constructs, D4 secret rules and lib function names.
    Returns objects with File, Line, Column, Rule, Message.
    .PARAMETER FileName
    With -ScriptText: the path the text pretends to have. It decides the
    path-dependent rules (D4-PlainVariable outside src\lib\Adapters.ps1, Naming in src\lib).
    #>
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Path', Position = 0)]
        [string]$Path,
        [Parameter(Mandatory = $true, ParameterSetName = 'Text')]
        [string]$ScriptText,
        [Parameter(ParameterSetName = 'Text')]
        [string]$FileName = 'script.ps1'
    )

    # --- rule data ---------------------------------------------------------------

    # Approved verbs of Windows PowerShell 5.1 (Get-Verb), hard-coded so the result
    # does not depend on the host.
    $CrLintApprovedVerbs = @(
        'Add', 'Approve', 'Assert', 'Backup', 'Block', 'Checkpoint', 'Clear', 'Close', 'Compare', 'Complete',
        'Compress', 'Confirm', 'Connect', 'Convert', 'ConvertFrom', 'ConvertTo', 'Copy', 'Debug', 'Deny', 'Disable',
        'Disconnect', 'Dismount', 'Edit', 'Enable', 'Enter', 'Exit', 'Expand', 'Export', 'Find', 'Format', 'Get',
        'Grant', 'Group', 'Hide', 'Import', 'Initialize', 'Install', 'Invoke', 'Join', 'Limit', 'Lock', 'Measure',
        'Merge', 'Mount', 'Move', 'New', 'Open', 'Optimize', 'Out', 'Ping', 'Pop', 'Protect', 'Publish', 'Push',
        'Read', 'Receive', 'Redo', 'Register', 'Remove', 'Rename', 'Repair', 'Request', 'Reset', 'Resize', 'Resolve',
        'Restart', 'Restore', 'Resume', 'Revoke', 'Save', 'Search', 'Select', 'Send', 'Set', 'Show', 'Skip', 'Split',
        'Start', 'Step', 'Stop', 'Submit', 'Suspend', 'Switch', 'Sync', 'Test', 'Trace', 'Unblock', 'Undo',
        'Uninstall', 'Unlock', 'Unprotect', 'Unpublish', 'Unregister', 'Update', 'Use', 'Wait', 'Watch', 'Write'
    )

    # Aliases resolved before the command rules are applied (lower case).
    $CrLintAliases = @{
        'gci' = 'get-childitem'; 'dir' = 'get-childitem'; 'ls' = 'get-childitem'
        'gc' = 'get-content'; 'cat' = 'get-content'; 'type' = 'get-content'
        'ac' = 'add-content'; 'sc' = 'set-content'; 'epcsv' = 'export-csv'; 'ipmo' = 'import-module'
        'iex' = 'invoke-expression'; 'irm' = 'invoke-restmethod'; 'iwr' = 'invoke-webrequest'
        'curl' = 'invoke-webrequest'; 'wget' = 'invoke-webrequest'
        '?' = 'where-object'; 'where' = 'where-object'; '%' = 'foreach-object'; 'foreach' = 'foreach-object'
        'echo' = 'write-output'; 'write' = 'write-output'
    }

    # Cmdlets that do not exist on PowerShell 2.0 / Windows 7 (lower case; wildcards allowed).
    $CrLintPs3Cmdlets = @(
        '*-cim*', 'convertto-json', 'convertfrom-json', 'invoke-restmethod', 'invoke-webrequest',
        'get-filehash', 'new-temporaryfile', 'unblock-file', 'compress-archive', 'expand-archive',
        'get-clipboard', 'set-clipboard', 'format-hex', 'convertfrom-string', 'new-guid', 'write-information',
        'get-computerinfo', 'get-timezone', 'set-timezone', 'get-runspace', 'test-netconnection', 'resolve-dnsname',
        '*-localuser', '*-localgroup', '*-localgroupmember', '*-scheduledtask', '*-scheduledtaskinfo'
    )

    # Parameters added after PowerShell 2.0, per cmdlet (lower case).
    $CrLintPs3Parameters = @{
        'get-childitem' = @('file', 'directory', 'attributes', 'hidden', 'readonly', 'system', 'depth', 'followsymlink',
                            'ad', 'af', 'ah', 'ar', 'as')
        'get-content'   = @('raw', 'stream')
        'set-content'   = @('nonewline', 'stream')
        'add-content'   = @('nonewline', 'stream')
        'out-file'      = @('nonewline')
        'out-string'    = @('nonewline')
        'export-csv'    = @('append', 'includetypeinformation')
        'add-member'    = @('notepropertyname', 'notepropertyvalue', 'notepropertymembers', 'typename')
        'import-module' = @('requiredversion', 'maximumversion', 'minimumversion')
        'test-path'     = @('newerthan', 'olderthan')
        'get-item'      = @('stream')
        'remove-item'   = @('stream')
        'split-path'    = @('leafbase', 'extension')
        'select-object' = @('skiplast')
    }
    # Common parameters added after PowerShell 2.0 (any command).
    $CrLintPs3CommonParameters = @('informationaction', 'informationvariable', 'pipelinevariable')

    $CrLintPs3TypeNames = @('ordered', 'pscustomobject', 'ciminstance', 'cimclass', 'cimsession', 'cimtype', 'cimconverter')
    $CrLintPs3Attributes = @('supportswildcards', 'argumentcompleter', 'validatedrive', 'validateuserdrive', 'validatetrusteddata')

    # D4: commands whose arguments end up in output, logs or files.
    $CrLintOutputCommands = @(
        'write-host', 'write-output', 'write-verbose', 'write-debug', 'write-warning', 'write-error', 'write-information',
        'write-crlog', 'export-csv', 'out-file', 'out-host', 'add-content', 'set-content'
    )
    # D4: external programs commonly called by this kind of tool (no extension needed).
    $CrLintExternalCommands = @('net', 'net1', 'sqlcmd', 'osql', 'schtasks', 'runas', 'psexec', 'cmd', 'reg', 'wmic', 'secedit', 'setx')

    $tokens = $null
    $parseErrors = $null
    if ($PSCmdlet.ParameterSetName -eq 'Path') {
        $fullPath = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($fullPath, [ref]$tokens, [ref]$parseErrors)
        $fileLabel = $Path
        $fileKey = $fullPath
    } else {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($ScriptText, $FileName, [ref]$tokens, [ref]$parseErrors)
        $fileLabel = $FileName
        $fileKey = $FileName
    }
    $fileKey = '\' + ($fileKey -replace '/', '\')
    $isAdapters = $fileKey -like '*\src\lib\Adapters.ps1'
    $isLib = $fileKey -like '*\src\lib\*'

    # Suppressions: trailing "# lint-ignore: Rule[, Rule]" comments, per line.
    $suppressed = @{}
    foreach ($tok in $tokens) {
        if ($tok.Kind -ne [System.Management.Automation.Language.TokenKind]::Comment) { continue }
        $m = [regex]::Match($tok.Text, '^#\s*lint-ignore\s*:\s*(.+)$')
        if (-not $m.Success) { continue }
        $line = $tok.Extent.StartLineNumber
        if (-not $suppressed.ContainsKey($line)) { $suppressed[$line] = @{} }
        foreach ($r in ($m.Groups[1].Value -split '[,\s]+')) {
            if ($r) { $suppressed[$line][$r.ToLowerInvariant()] = $true }
        }
    }

    $found = New-Object System.Collections.ArrayList
    $add = {
        param($Extent, [string]$Rule, [string]$Message)
        $ln = $Extent.StartLineNumber
        if ($suppressed.ContainsKey($ln) -and $suppressed[$ln].ContainsKey($Rule.ToLowerInvariant())) { return }
        [void]$found.Add((New-Object PSObject -Property @{
            File = $fileLabel; Line = $ln; Column = $Extent.StartColumnNumber; Rule = $Rule; Message = $Message
        }))
    }

    # Variable name without scope prefix ($script:x -> x); $null for env:/function: etc.
    $varName = {
        param($VariableAst)
        $vp = $VariableAst.VariablePath
        if (-not $vp.IsVariable) { return $null }
        $n = $vp.UserPath
        $i = $n.LastIndexOf(':')
        if ($i -ge 0) { $n = $n.Substring($i + 1) }
        return $n
    }
    $isSensitiveName = {
        param([string]$Name)
        if (-not $Name) { return $false }
        return (($Name -like '*password*') -or ($Name -like '*secret*') -or ($Name -like 'plain*'))
    }
    # Names of the variables referenced anywhere below the given ASTs.
    $referencedVariables = {
        param($Asts)
        $names = New-Object System.Collections.ArrayList
        foreach ($a in $Asts) {
            if ($null -eq $a) { continue }
            $vars = $a.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)
            foreach ($v in $vars) {
                $n = & $varName $v
                if ($n) { [void]$names.Add($n) }
            }
        }
        return , $names
    }
    $constantText = {
        param($ElementAst)
        if ($null -eq $ElementAst) { return $null }
        if ($ElementAst -is [System.Management.Automation.Language.StringConstantExpressionAst]) { return $ElementAst.Value }
        if ($ElementAst -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) { return $ElementAst.Value }
        return $ElementAst.Extent.Text
    }
    $isIgnoreValue = {
        param([string]$Text)
        if (-not $Text) { return $false }
        $t = $Text.Trim().Trim("'", '"')
        return (($t -eq 'Ignore') -or ($t -match '::Ignore$'))
    }

    foreach ($e in $parseErrors) {
        & $add $e.Extent 'Parse' $e.Message
    }

    $nodes = $ast.FindAll({ param($n) $true }, $true)
    foreach ($node in $nodes) {

        # --- type literals, casts and attributes --------------------------------
        if (($node -is [System.Management.Automation.Language.TypeExpressionAst]) -or
            ($node -is [System.Management.Automation.Language.TypeConstraintAst])) {
            $tn = $node.TypeName.FullName.ToLowerInvariant()
            if ($CrLintPs3TypeNames -contains $tn) {
                & $add $node.Extent 'Ps2-Accelerator' ("[{0}] does not exist in PS 2.0; use New-Object PSObject -Property / a hashtable" -f $node.TypeName.FullName)
            }
            continue
        }
        if ($node -is [System.Management.Automation.Language.AttributeAst]) {
            $an = $node.TypeName.FullName.ToLowerInvariant()
            if ($CrLintPs3Attributes -contains $an) {
                & $add $node.Extent 'Ps2-Attribute' ("attribute [{0}] does not exist in PS 2.0" -f $node.TypeName.FullName)
            }
            foreach ($na in $node.NamedArguments) {
                if ($na.ExpressionOmitted) {
                    & $add $node.Extent 'Ps2-AttributeShorthand' ("'{0}' without '= `$true' needs PS 3.0; write {0} = `$true" -f $na.ArgumentName)
                }
            }
            continue
        }

        # --- members ---------------------------------------------------------------
        if ($node -is [System.Management.Automation.Language.InvokeMemberExpressionAst]) {
            if ($node.Member -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                $mn = $node.Member.Value
                if ($node.Static -and ($mn -eq 'new')) {
                    & $add $node.Extent 'Ps2-StaticNew' '::new() needs PS 5.0; use New-Object'
                } elseif ((-not $node.Static) -and (($mn -eq 'Where') -or ($mn -eq 'ForEach'))) {
                    & $add $node.Extent 'Ps2-MagicMethod' (".{0}() needs PS 4.0; use a foreach loop or the cmdlet with a script block" -f $mn)
                }
            }
            continue
        }

        # --- variables ---------------------------------------------------------------
        if ($node -is [System.Management.Automation.Language.UsingExpressionAst]) {
            & $add $node.Extent 'Ps2-UsingScope' '$using: needs PS 3.0'
            continue
        }
        if ($node -is [System.Management.Automation.Language.VariableExpressionAst]) {
            $vn = & $varName $node
            if (-not $vn) { continue }
            if ($vn -eq 'PSItem') {
                & $add $node.Extent 'Ps2-PSItem' '$PSItem needs PS 3.0; use $_'
            } elseif (($vn -eq 'PSScriptRoot') -or ($vn -eq 'PSCommandPath')) {
                & $add $node.Extent 'Ps2-ScriptRoot' ("`${0} is not set in PS 2.0 scripts; use Split-Path -Parent `$MyInvocation.MyCommand.Path at script scope" -f $vn)
            }
            if (($vn -like 'plain*') -and (-not $isAdapters)) {
                & $add $node.Extent 'D4-PlainVariable' ("`${0}: plaintext variables are allowed only in src\lib\Adapters.ps1 (D4)" -f $vn)
            }
            continue
        }

        # --- operators and redirections ---------------------------------------------
        if ($node -is [System.Management.Automation.Language.BinaryExpressionAst]) {
            $op = $node.Operator.ToString()
            if (@('Iin', 'Inotin', 'Cin', 'Cnotin') -contains $op) {
                & $add $node.Extent 'Ps2-InOperator' '-in/-notin need PS 3.0; use -contains/-notcontains with the operands swapped'
            } elseif (($op -eq 'Shl') -or ($op -eq 'Shr')) {
                & $add $node.Extent 'Ps2-ShiftOperator' '-shl/-shr need PS 3.0; multiply/divide by powers of 2'
            }
            continue
        }
        if ($node -is [System.Management.Automation.Language.FileRedirectionAst]) {
            $fs = $node.FromStream.ToString()
            if (($fs -ne 'Output') -and ($fs -ne 'Error')) {
                & $add $node.Extent 'Ps2-Redirection' 'PS 2.0 redirects only the output (>) and error (2>) streams'
            }
            continue
        }
        if ($node -is [System.Management.Automation.Language.MergingRedirectionAst]) {
            if (($node.FromStream.ToString() -ne 'Error') -or ($node.ToStream.ToString() -ne 'Output')) {
                & $add $node.Extent 'Ps2-Redirection' 'PS 2.0 supports only 2>&1 as a merging redirection'
            }
            continue
        }
        if ($node -is [System.Management.Automation.Language.AssignmentStatementAst]) {
            if ($node.Left -is [System.Management.Automation.Language.VariableExpressionAst]) {
                $ln = & $varName $node.Left
                if ((($ln -eq 'ErrorActionPreference') -or ($ln -eq 'WarningPreference')) -and (& $isIgnoreValue $node.Right.Extent.Text)) {
                    & $add $node.Extent 'Ps2-ErrorActionIgnore' "'Ignore' needs PS 3.0; use SilentlyContinue"
                }
            }
            continue
        }

        # --- statements -------------------------------------------------------------
        if ($node -is [System.Management.Automation.Language.TypeDefinitionAst]) {
            & $add $node.Extent 'Ps2-Class' 'class/enum definitions need PS 5.0; use hashtables or Add-Type (C# 2.0)'
            continue
        }
        if ($node -is [System.Management.Automation.Language.UsingStatementAst]) {
            & $add $node.Extent 'Ps2-UsingStatement' 'using namespace/module/assembly needs PS 5.0'
            continue
        }
        if ($node -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
            if ($node.IsWorkflow) {
                & $add $node.Extent 'Ps2-Workflow' 'workflows need PS 3.0'
            }
            if ($isLib) {
                $fn = $node.Name
                $fm = [regex]::Match($fn, '^([A-Za-z]+)-Cr[A-Z][A-Za-z0-9]*$')
                if (-not $fm.Success) {
                    & $add $node.Extent 'Naming' ("function '{0}' must be named Verb-CrNoun" -f $fn)
                } elseif ($CrLintApprovedVerbs -cnotcontains $fm.Groups[1].Value) {
                    & $add $node.Extent 'Naming' ("function '{0}': '{1}' is not an approved verb (Get-Verb)" -f $fn, $fm.Groups[1].Value)
                }
            }
            continue
        }

        # --- commands ---------------------------------------------------------------
        if (-not ($node -is [System.Management.Automation.Language.CommandAst])) { continue }

        $elements = $node.CommandElements
        $rawName = $node.GetCommandName()
        $cmd = $null
        if ($rawName) {
            $cmd = $rawName.ToLowerInvariant()
            if ($CrLintAliases.ContainsKey($cmd)) { $cmd = $CrLintAliases[$cmd] }
        }
        $arguments = @()
        if ($elements.Count -gt 1) { $arguments = @($elements | Select-Object -Skip 1) }

        if ($cmd -eq 'invoke-expression') {
            & $add $node.Extent 'D4-InvokeExpression' 'Invoke-Expression is forbidden (D4)'
        }
        # ConvertTo-CrArray returns ", @(...)": wrapping it in @() nests the array, piping it sends the
        # whole array as one object. Assign it to a variable first.
        if ($cmd -eq 'convertto-crarray') {
            $pipe = $node.Parent
            $piped = ($pipe -is [System.Management.Automation.Language.PipelineAst]) -and ($pipe.PipelineElements.Count -gt 1)
            $wrapped = ($pipe -and $pipe.Parent -and $pipe.Parent.Parent -is [System.Management.Automation.Language.ArrayExpressionAst])
            if ($piped -or $wrapped) {
                & $add $node.Extent 'Cr-ArrayHelper' 'ConvertTo-CrArray must not be piped or wrapped in @(); assign it to a variable first'
            }
        }
        if ($cmd) {
            foreach ($pattern in $CrLintPs3Cmdlets) {
                if ($cmd -like $pattern) {
                    & $add $node.Extent 'Ps2-Cmdlet' ("{0} does not exist in PS 2.0 / on Windows 7" -f $rawName)
                    break
                }
            }
        }

        # parameters
        for ($i = 0; $i -lt $arguments.Count; $i++) {
            $p = $arguments[$i]
            if (-not ($p -is [System.Management.Automation.Language.CommandParameterAst])) { continue }
            $pn = $p.ParameterName.ToLowerInvariant()
            if ($CrLintPs3CommonParameters -contains $pn) {
                & $add $p.Extent 'Ps2-Parameter' ("-{0} needs PS 3.0 or later" -f $p.ParameterName)
            }
            if ($cmd -and $CrLintPs3Parameters.ContainsKey($cmd) -and ($CrLintPs3Parameters[$cmd] -contains $pn)) {
                & $add $p.Extent 'Ps2-Parameter' ("{0} -{1} does not exist in PS 2.0" -f $rawName, $p.ParameterName)
            }
            $isActionParam = ($pn -eq 'ea') -or ($pn -eq 'wa') -or
                (($pn.Length -ge 6) -and 'erroraction'.StartsWith($pn)) -or
                (($pn.Length -ge 8) -and 'warningaction'.StartsWith($pn))
            if ($isActionParam) {
                $valueAst = $p.Argument
                if (($null -eq $valueAst) -and (($i + 1) -lt $arguments.Count)) { $valueAst = $arguments[$i + 1] }
                if (& $isIgnoreValue (& $constantText $valueAst)) {
                    & $add $p.Extent 'Ps2-ErrorActionIgnore' ("-{0} Ignore needs PS 3.0; use SilentlyContinue" -f $p.ParameterName)
                }
            }
        }

        # simplified Where-Object / ForEach-Object syntax
        if ((($cmd -eq 'where-object') -or ($cmd -eq 'foreach-object')) -and ($arguments.Count -gt 0)) {
            $first = $arguments[0]
            $simplified = $false
            if ($first -is [System.Management.Automation.Language.CommandParameterAst]) {
                $okParams = @('filterscript', 'process', 'begin', 'end', 'inputobject', 'remainingscripts',
                              'erroraction', 'ea', 'errorvariable', 'ev', 'outvariable', 'ov', 'outbuffer', 'ob',
                              'warningaction', 'wa', 'warningvariable', 'wv', 'verbose', 'vb', 'debug', 'db')
                $simplified = -not ($okParams -contains $first.ParameterName.ToLowerInvariant())
            } elseif (($first -is [System.Management.Automation.Language.StringConstantExpressionAst]) -or
                      ($first -is [System.Management.Automation.Language.ExpandableStringExpressionAst])) {
                $simplified = $true
            }
            if ($simplified) {
                & $add $node.Extent 'Ps2-SimplifiedSyntax' ("{0} without a script block needs PS 3.0; use {{ `$_.Prop ... }}" -f $rawName)
            }
        }

        # D4: secrets in output, as plaintext arguments, or on external command lines
        if ($arguments.Count -gt 0) {
            $argVars = & $referencedVariables $arguments
            $rawArgHits = @($argVars | Where-Object { $_ -like 'plain*' })
            if ($rawArgHits.Count -gt 0) {
                & $add $node.Extent 'D4-PlainArgument' ("plaintext `${0} passed as a command argument (D4)" -f $rawArgHits[0])
            }
        } else {
            $argVars = @()
        }
        if ($cmd -and ($CrLintOutputCommands -contains $cmd)) {
            $outVars = New-Object System.Collections.ArrayList
            foreach ($v in $argVars) { [void]$outVars.Add($v) }
            $pipeline = $node.Parent
            if ($pipeline -is [System.Management.Automation.Language.PipelineAst]) {
                $before = @()
                foreach ($pe in $pipeline.PipelineElements) {
                    if ([object]::ReferenceEquals($pe, $node)) { break }
                    $before += $pe
                }
                foreach ($v in (& $referencedVariables $before)) { [void]$outVars.Add($v) }
            }
            $hits = @($outVars | Where-Object { & $isSensitiveName $_ })
            if ($hits.Count -gt 0) {
                & $add $node.Extent 'D4-SecretOutput' ("{0} with `${1}: secrets must never be printed or logged (D4)" -f $rawName, $hits[0])
            }
        }
        $isExternal = ($node.InvocationOperator -ne [System.Management.Automation.Language.TokenKind]::Unknown -and -not $rawName) -or
            ($cmd -and (($cmd -match '\.(exe|com|bat|cmd)$') -or ($CrLintExternalCommands -contains $cmd)))
        if ($isExternal) {
            $hits = @($argVars | Where-Object { & $isSensitiveName $_ })
            if ($hits.Count -gt 0) {
                & $add $node.Extent 'D4-SecretExternal' ("`${0} on an external command line (D4)" -f $hits[0])
            }
        }
    }

    $found | Sort-Object Line, Column, Rule
}

# ---------------------------------------------------------------------------
# Main (skipped when dot-sourced)
# ---------------------------------------------------------------------------

if ($MyInvocation.InvocationName -ne '.') {
    $repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

    $roots = New-Object System.Collections.ArrayList
    if ($Path) {
        foreach ($p in $Path) { [void]$roots.Add($p) }
    } else {
        [void]$roots.Add((Join-Path $repoRoot 'src'))
    }
    if ($IncludeTests) { [void]$roots.Add((Join-Path $repoRoot 'tests')) }

    $files = New-Object System.Collections.ArrayList
    $missing = 0
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) {
            Write-Host ("Path not found: {0}" -f $root) -ForegroundColor Red
            $missing++
            continue
        }
        $item = Get-Item -LiteralPath $root
        if ($item.PSIsContainer) {
            $children = Get-ChildItem -LiteralPath $item.FullName -Recurse -Filter '*.ps1' |
                Where-Object { -not $_.PSIsContainer } | Sort-Object FullName
            foreach ($c in $children) { [void]$files.Add($c.FullName) }
        } else {
            [void]$files.Add($item.FullName)
        }
    }

    $total = 0
    $filesWithFindings = 0
    foreach ($f in $files) {
        $display = $f
        if ($f.StartsWith($repoRoot + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
            $display = $f.Substring($repoRoot.Length + 1)
        }
        $results = @(Invoke-CrPs2Lint -Path $f)
        if ($results.Count -gt 0) { $filesWithFindings++ }
        foreach ($r in $results) {
            Write-Output ('{0}:{1} {2} {3}' -f $display, $r.Line, $r.Rule, $r.Message)
            $total++
        }
    }

    Write-Host ''
    Write-Host ('Test-Ps2Syntax: {0} file(s) scanned, {1} violation(s) in {2} file(s).' -f $files.Count, $total, $filesWithFindings)
    if (($total -gt 0) -or ($missing -gt 0)) { exit 1 }
    exit 0
}
