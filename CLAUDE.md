# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A PowerShell tool that rotates local Windows and SQL Server credentials on standalone workgroup machines (Windows 7 SP1 incl. Windows Embedded Standard 7, Windows 10), enforces account roles, and updates dependents. `docs/PLAN.md` is the authoritative design (decisions D1–D25, milestones M0–M6, known gaps in §13.4). `docs/dev/CONTRACTS.md` defines module ownership, the shared data model and function signatures; read it before changing a module. `README.md` holds the test procedure for the test sites and the test results.

## Commands

All commands run in Windows PowerShell 5.1 (`powershell.exe`), not PowerShell 7:

```powershell
# All unit tests (Pester 3.4)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests\Invoke-Tests.ps1
# One test file
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests\Invoke-Tests.ps1 -Path tests\Principals.Tests.ps1
# PS 2.0 syntax + D4 lint
powershell.exe -NoProfile -ExecutionPolicy Bypass -File build\Test-Ps2Syntax.ps1
# Bundle into dist\ (single CredentialRotation.ps1 + launcher + config + SHA256SUMS.txt)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File build\Build.ps1
# Run the audit unbundled (elevated)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File src\CredentialRotation.ps1 -ConfigPath config\CredentialRotation.psd1
```

AppLocker blocks script execution on the dev machine: write code and tests, parse-check them (`[System.Management.Automation.Language.Parser]::ParseFile`) and run the lint (a static scan), but don't run the tool or the tests there. The user runs them on the test machines.

There is no real PS 2.0 engine on the dev machine either: `powershell.exe -Version 2` silently runs 5.1 on Windows 11 24H2+. PS 2.0 compatibility is enforced by the lint and checked by `/PS2` runs on the test sites (PLAN §11).

## Code rules (PS 2.0 syntax and semantics, D1)

- No PS 3+ features: `[ordered]`, `[pscustomobject]`, `::new()`, classes, `-in`/`-notin`, `$PSItem`, `.Where()`/`.ForEach()`, `$using:`, `Get-CimInstance`, `ConvertTo-Json`/`ConvertFrom-Json`, `-ErrorAction Ignore`, `Get-ChildItem -File/-Directory`, `$PSScriptRoot` outside modules, simplified `Where-Object Prop -eq x` syntax, `-shl`/`-shr`.
- PS 2.0 semantics: `foreach ($x in $null)` and `$null | ForEach-Object` run **once** → guard with `if ($x)` or wrap `@($x)` after a null check. No member enumeration (`$array.Name`); no `.Count` on scalars (wrap in `@()`).
- Data is plain hashtables and arrays; collections are built with `New-Object System.Collections.ArrayList` and `[void]$list.Add(...)`.
- `Add-Type` C# must be C# 2.0 (no `var`, lambdas, LINQ, auto-properties). Guard against re-definition with `if (-not ('Type' -as [type]))`.
- Functions are named `Verb-CrNoun`, use `param()` blocks, and throw on unexpected errors; discovery functions return a hashtable with an `Error` key instead of throwing for expected absence.
- **D4 secrets rules:** plaintext only in `src\lib\Adapters.ps1`; never pass secrets as cmdlet/function arguments or on command lines; never print or log them; no `Invoke-Expression`.
- Principals are compared by SID; names are only for display.
- No real account names, SIDs or machine data from inventories in tests or fixtures; use synthetic SIDs like `S-1-5-21-1000-2000-3000-1001`. Inventory JSON and test-site logs are never committed (`.gitignore`).
- Files are ASCII with CRLF line endings; `src/CredentialRotation.ps1` is UTF-8 with BOM. Keep them that way (Git Bash `sed -i` turns CRLF into LF).
