<#
.SYNOPSIS
Bundles the tool into dist\CredentialRotation-<version>\ (docs/PLAN.md section 3).

.DESCRIPTION
1. Runs build\Test-Ps2Syntax.ps1 (unless -SkipLint); stops on violations.
2. Reads $script:CrToolVersion = '<x.y.z>' from src\CredentialRotation.ps1.
3. Writes dist\CredentialRotation-<version>\:
   - CredentialRotation.ps1        entry point; the block from the line containing
                                   "# <CR-LIB-IMPORT>" to the line containing
                                   "# </CR-LIB-IMPORT>" is replaced by the lib files in
                                   the load order of docs/dev/CONTRACTS.md, each wrapped in
                                   #region lib\<file> / #endregion
   - Start-CredentialRotation.cmd  launcher (ASCII, CRLF)
   - CredentialRotation.psd1       default config from config\
   - SHA256SUMS.txt                "<sha256 lowercase hex>  <file>" per file
   .ps1/.psd1 are written as UTF-8 with BOM and CRLF line endings.
The output folder is recreated on every build.

Runs on Windows PowerShell 5.1 (not shipped).

.EXAMPLE
powershell.exe -NoProfile -ExecutionPolicy Bypass -File build\Build.ps1
#>
param(
    [switch]$SkipLint
)

$ErrorActionPreference = 'Stop'

# Lib load order (docs/dev/CONTRACTS.md "Layout and ownership"). Every file must exist.
$libOrder = @(
    'Compat.ps1', 'Log.ps1', 'Config.ps1', 'Native.ps1', 'Accounts.ps1', 'Groups.ps1', 'Rights.ps1',
    'Principals.ps1', 'Services.ps1', 'Tasks.ps1', 'ComPlus.ps1', 'IisReport.ps1', 'Sql.ps1',
    'AutoLogon.ps1', 'Preflight.ps1', 'Plan.ps1'
)
$importStartMarker = '# <CR-LIB-IMPORT>'
$importEndMarker = '# </CR-LIB-IMPORT>'

$buildDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $buildDir
$srcDir = Join-Path $repoRoot 'src'
$libDir = Join-Path $srcDir 'lib'
$entryPath = Join-Path $srcDir 'CredentialRotation.ps1'
$launcherPath = Join-Path $srcDir 'Start-CredentialRotation.cmd'
$configPath = Join-Path (Join-Path $repoRoot 'config') 'CredentialRotation.psd1'

$utf8Bom = New-Object System.Text.UTF8Encoding($true)
$ascii = New-Object System.Text.ASCIIEncoding

# Splits text into lines, whatever the line endings; drops one trailing empty line.
function Split-BuildLines {
    param([string]$Text)
    $lines = @($Text -split "`r`n|`n|`r")
    if (($lines.Count -gt 0) -and ($lines[$lines.Count - 1] -eq '')) {
        if ($lines.Count -eq 1) { return @() }
        $lines = $lines[0..($lines.Count - 2)]
    }
    return $lines
}

function Write-BuildFile {
    param([string]$Path, [string[]]$Lines, [System.Text.Encoding]$Encoding)
    $text = ($Lines -join "`r`n") + "`r`n"
    [System.IO.File]::WriteAllText($Path, $text, $Encoding)
}

function Get-BuildSha256 {
    param([string]$Path)
    $sha = New-Object System.Security.Cryptography.SHA256CryptoServiceProvider
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $bytes = $sha.ComputeHash($stream)
    } finally {
        $stream.Close()
        $sha.Clear()
    }
    $sb = New-Object System.Text.StringBuilder
    foreach ($b in $bytes) { [void]$sb.Append($b.ToString('x2')) }
    return $sb.ToString()
}

try {
    # --- 1. lint --------------------------------------------------------------
    if (-not $SkipLint) {
        Write-Host 'Running build\Test-Ps2Syntax.ps1 ...'
        $global:LASTEXITCODE = 0
        & (Join-Path $buildDir 'Test-Ps2Syntax.ps1')
        if ($LASTEXITCODE -ne 0) { throw ('Lint failed (exit code {0}). Fix the violations or use -SkipLint.' -f $LASTEXITCODE) }
    }

    # --- 2. inputs --------------------------------------------------------------
    foreach ($required in @($entryPath, $launcherPath, $configPath)) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw ('Missing input file: {0}' -f $required) }
    }
    $missingLibs = @($libOrder | Where-Object { -not (Test-Path -LiteralPath (Join-Path $libDir $_) -PathType Leaf) })
    if ($missingLibs.Count -gt 0) { throw ('Missing lib file(s) in src\lib: {0}' -f ($missingLibs -join ', ')) }
    $extraLibs = @(Get-ChildItem -LiteralPath $libDir -Filter '*.ps1' | Where-Object { $libOrder -notcontains $_.Name })
    foreach ($x in $extraLibs) {
        Write-Warning ('src\lib\{0} is not in the load order and is NOT bundled.' -f $x.Name)
    }

    $entryLines = @(Split-BuildLines ([System.IO.File]::ReadAllText($entryPath)))

    $versionMatch = $null
    foreach ($line in $entryLines) {
        $m = [regex]::Match($line, '^\s*\$script:CrToolVersion\s*=\s*[''"](\d+\.\d+\.\d+)[''"]')
        if ($m.Success) { $versionMatch = $m.Groups[1].Value; break }
    }
    if (-not $versionMatch) { throw "No `$script:CrToolVersion = '<x.y.z>' line in src\CredentialRotation.ps1." }
    $version = $versionMatch

    # --- 3. bundle the entry point -----------------------------------------------
    $startIdx = @()
    $endIdx = @()
    for ($i = 0; $i -lt $entryLines.Count; $i++) {
        if ($entryLines[$i].Contains($importStartMarker)) { $startIdx += $i }
        if ($entryLines[$i].Contains($importEndMarker)) { $endIdx += $i }
    }
    if (($startIdx.Count -ne 1) -or ($endIdx.Count -ne 1)) {
        throw ('src\CredentialRotation.ps1 must contain exactly one "{0}" line and one "{1}" line (found {2} and {3}).' -f $importStartMarker, $importEndMarker, $startIdx.Count, $endIdx.Count)
    }
    if ($endIdx[0] -le $startIdx[0]) { throw ('"{0}" must come after "{1}".' -f $importEndMarker, $importStartMarker) }

    $bundle = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $startIdx[0]; $i++) { [void]$bundle.Add($entryLines[$i]) }
    foreach ($lib in $libOrder) {
        $libText = [System.IO.File]::ReadAllText((Join-Path $libDir $lib))
        if ($libText.Contains($importStartMarker) -or $libText.Contains($importEndMarker)) {
            throw ('src\lib\{0} contains a CR-LIB-IMPORT marker.' -f $lib)
        }
        [void]$bundle.Add(('#region lib\{0}' -f $lib))
        foreach ($l in (Split-BuildLines $libText)) { [void]$bundle.Add($l) }
        [void]$bundle.Add('#endregion')
    }
    for ($i = $endIdx[0] + 1; $i -lt $entryLines.Count; $i++) { [void]$bundle.Add($entryLines[$i]) }
    $bundleLines = [string[]]$bundle.ToArray([string])

    # The bundle must at least parse (5.1 parser; PS 2.0 syntax is the lint's job).
    $tokens = $null
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput(($bundleLines -join "`r`n"), [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) {
        $first = $parseErrors[0]
        throw ('The bundled CredentialRotation.ps1 does not parse: line {0}: {1}' -f $first.Extent.StartLineNumber, $first.Message)
    }

    # --- 4. write dist ---------------------------------------------------------------
    $distRoot = Join-Path $repoRoot 'dist'
    $outDir = Join-Path $distRoot ('CredentialRotation-' + $version)
    if (Test-Path -LiteralPath $outDir) { Remove-Item -LiteralPath $outDir -Recurse -Force }
    [void](New-Item -ItemType Directory -Path $outDir -Force)

    Write-BuildFile -Path (Join-Path $outDir 'CredentialRotation.ps1') -Lines $bundleLines -Encoding $utf8Bom

    $cmdText = [System.IO.File]::ReadAllText($launcherPath)
    if ($cmdText -match '[^\x00-\x7F]') { throw 'src\Start-CredentialRotation.cmd must contain ASCII characters only.' }
    Write-BuildFile -Path (Join-Path $outDir 'Start-CredentialRotation.cmd') -Lines (Split-BuildLines $cmdText) -Encoding $ascii

    $configLines = @(Split-BuildLines ([System.IO.File]::ReadAllText($configPath)))
    Write-BuildFile -Path (Join-Path $outDir 'CredentialRotation.psd1') -Lines $configLines -Encoding $utf8Bom

    $shipped = @('CredentialRotation.ps1', 'CredentialRotation.psd1', 'Start-CredentialRotation.cmd')
    $sums = New-Object System.Collections.ArrayList
    foreach ($name in $shipped) {
        [void]$sums.Add(('{0}  {1}' -f (Get-BuildSha256 (Join-Path $outDir $name)), $name))
    }
    Write-BuildFile -Path (Join-Path $outDir 'SHA256SUMS.txt') -Lines ([string[]]$sums.ToArray([string])) -Encoding $ascii

    Write-Host ''
    Write-Host ('Built CredentialRotation {0} -> {1}' -f $version, $outDir)
    foreach ($s in $sums) { Write-Host ('  ' + $s) }
    exit 0
} catch {
    Write-Host ('Build failed: {0}' -f $_.Exception.Message) -ForegroundColor Red
    exit 1
}
