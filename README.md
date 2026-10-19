# CredentialRotation

A PowerShell tool that rotates the local Windows credentials on standalone workgroup machines (Windows 7 SP1 incl. Windows Embedded Standard 7, Windows 10), enforces the account roles, and updates everything that depends on the passwords.

- Design: [docs/PLAN.md](docs/PLAN.md)
- Module interfaces: [docs/dev/CONTRACTS.md](docs/dev/CONTRACTS.md)
- Conventions for development: [CLAUDE.md](CLAUDE.md)

## Status

| Milestone | Content | State |
|---|---|---|
| M1 | Read-only audit | On branch `feature/m1-audit`; **tested on `SM-QS-K1`** (Windows 10) **and `SM-102575`** (Windows Embedded 7), PS 5.1 and PS 2.0 |
| M2 | Password prompts, account model (PLAN v10.5), groups, flags, auto-logon policy | Code written (version 0.5.0); **not yet run** |
| M3 | Services, scheduled tasks, COM+ updates and moves | Code and unit tests written; **not yet run** |

AppLocker blocks scripts on the development machine, so all runs happen on the test machines.

### Test results

| Machine | Audit (PS 5.1) | Audit (`/PS2`) | Unit tests | Inventory |
|---|---|---|---|---|
| `SM-QS-K1` (Windows 10 LTSC 2019) | OK, findings match the machine | OK; SQL blocked (see below) | 417 / 417 | v1.4 OK |
| `SM-102575` (Windows Embedded 7) | OK, findings match the machine | OK, incl. SQL | not possible (no Pester) | not run |

Fixed after the first runs:
- 13 unit tests failed because of a Pester 3.4 behaviour (a mock defined in one test leaked into the next ones); each such test now has its own `Context`.
- PS 2.0 differences: `Get-Acl`/`Set-Acl`/`Export-Csv` have no `-LiteralPath`, and `Import-LocalizedData` needs `-BindingVariable`. The lint now flags both.
- Words typed after the command (e.g. `echo %ERRORLEVEL%` on the same line) were taken as parameter values; the tool now refuses unnamed arguments.

Known limitation of `/PS2` test runs: on machines with WMF 5.1 or Windows 10, `powershell.exe.config` contains a .NET 4 `<uri>` section that the PS 2.0 engine can't read, so SQL Server can't be reached and the audit can't read it (there are no SQL slots since v10.5, D27). Real runs use PS 5.1 wherever it is installed, so they are not affected.

## Next steps: test version 0.5.0

Version 0.5.0 (PLAN v10.5) has not run anywhere yet. What it changes: `SYS-Admin` is retired like `SYS Admin`, `SOP-Admin` and `SP Admin` are kept untouched, and SQL login credentials are no longer updated. Do the steps in this order and send back the listed output before going to the next one. Save console output as `ConsoleOutput_<step>_<machine>.txt` and logs under `logs\<machine>\` in the repository folder: git ignores both, and they contain account names and SIDs, so never commit them.

### A. Unit tests and lint (one Windows 10 test machine, e.g. `SM-QS-K1`)

Copy `src\`, `config\`, `tests\` and `build\` from `main` to `C:\temp\CredentialRotation\`, keeping the structure. Then, in a command prompt (no elevation needed):

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\temp\CredentialRotation\tests\Invoke-Tests.ps1 > C:\temp\ConsoleOutput_tests.txt 2>&1
echo %ERRORLEVEL%
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\temp\CredentialRotation\build\Test-Ps2Syntax.ps1 > C:\temp\ConsoleOutput_lint.txt 2>&1
echo %ERRORLEVEL%
```

| Script | What it does | Expected |
|---|---|---|
| `Invoke-Tests.ps1` | runs the Pester 3.4 unit tests on synthetic machine states (changes nothing) | last line `Engine: PS 5.1... Passed: <n>  Failed: 0 ...`; exit code 0 (the exit code is the number of failed tests) |
| `Test-Ps2Syntax.ps1` | reads `src\` without running it: PS 3+ constructs, D4 secret rules, `Verb-CrNoun` names | `Test-Ps2Syntax: <n> file(s) scanned, 0 violation(s) in 0 file(s).`; exit code 0 |

**Send back:** both text files and both exit codes. On a failure, the important lines are the `[-]` lines of the test output and the `file:line rule message` lines of the lint, but send the whole files.

### B. Audit with 0.5.0 (step 1 below) on all four test machines

Run step 1 again with version 0.5.0, PS 5.1 and `/PS2`, elevated and logged on as `BiCA Remote`. The audit asks nothing, so its output can go straight into a file:

```
C:\temp\CredentialRotation\src\Start-CredentialRotation.cmd > C:\temp\ConsoleOutput_audit.txt 2>&1
echo %ERRORLEVEL%
C:\temp\CredentialRotation\src\Start-CredentialRotation.cmd /PS2 > C:\temp\ConsoleOutput_audit_ps2.txt 2>&1
echo %ERRORLEVEL%
```

Check in the output:
- `SOP-Admin` and `SP Admin`, where they exist: only the line `Kept untouched (config: Mode Keep)`; they are not among the other enabled accounts the tool would ask about
- `SYS Admin` and `SYS-Admin`, where they exist: `Disable <name> (no replacement)`, and their services and tasks move to `ApplicationUser`
- no SQL slot, no SQL login drift and no `LOGINS` follow-up for `SQLApplication`, `SQLScript`, `SQLService`
- exit code 10 (drift) or 0, as before; 2 or 3 is a problem

**Send back:** both console files and exit codes per machine, and the `.log`/`.csv` files from `%ProgramData%\CredentialRotation\logs\`.

### C. Re-apply test (step 2 below) on test site 102575, only after A and B are reviewed

Run step 2 (`/PS2 -Apply -Only AppUser`) as described there. It asks for passwords, so don't redirect its output; afterwards copy the console text (window menu, Edit, Select All, Enter) into `ConsoleOutput_reapply_<machine>.txt`. The log files contain the full run.

Check: only the `AppUser` slot is prompted, the APPLY PLAN lists only `ApplicationUser` and the built-in Administrator (already disabled), and the exit code is 0.

**Send back:** the console text, the exit code and the `.log`/`.csv` files, including `..._apply.csv`.

Step 3 (the real rotation) follows only after step 2 has been reviewed.

### D. Rollout scripts (admin workstation)

1. Sign `rollout\ss_Generate-Secret.ps1` and `rollout\nb_Import-CredentialFolderId.ps1` again; both were changed after the last signature.
2. In Secret Server, set the password requirement on the Password field of templates 6084, 6085, 6087, 7121 and 7122: exactly 16 characters, at least one upper case letter, lower case letter, digit and one of `- _ . : + # @`, nothing else. Without it, `ss_Generate-Secret.ps1` stops before creating anything.
3. Test `ss_Generate-Secret.ps1` with one site. It reads `rollout_CredentialRotation.xlsx` from the **current folder** and writes its result CSV there, so work in a test folder with a copy of the workbook in which only one row has `GenerateSecret` = TRUE:

   ```powershell
   cd C:\temp\ss-test
   & 'C:\Repos\CredentialRotation\rollout\ss_Generate-Secret.ps1'
   ```

   Expected: `Folder '<Ortschaft>.<Jobnummer>' created (ID <n>)`, five `Secret '...' created` lines and `Result written to .\ss_Generate-Secret_<timestamp>.csv`. In Secret Server, the folder has five secrets with 16-character passwords.
4. Import the folder ID into netbox, first as a dry run. Pass the CSV explicitly: the script otherwise looks for it next to itself, not in the test folder.

   ```powershell
   & 'C:\Repos\CredentialRotation\rollout\nb_Import-CredentialFolderId.ps1' -CsvPath C:\temp\ss-test\ss_Generate-Secret_<timestamp>.csv -WhatIf
   & 'C:\Repos\CredentialRotation\rollout\nb_Import-CredentialFolderId.ps1' -CsvPath C:\temp\ss-test\ss_Generate-Secret_<timestamp>.csv
   ```

   Expected: `What if: ... Set Credential_Folder_ID to <n>`, then `Credential_Folder_ID set to <n>`. In netbox, the site shows the folder ID.

**Send back:** the console output of both scripts and the result CSV (job numbers, folder names and IDs; no passwords).

## Testing on a machine

There are three test steps. The code for all three exists (version 0.5.0), but only step 1 has been run so far. Steps 2 and 3 are untested, and the unit tests of version 0.5.0 haven't been run yet.

### Step 1: audit (read-only)

Step 1 has been done with the M1 version. Repeat it with version 0.5.0 before step 2: the audit now reports the account model of PLAN v10.5.

The audit reads the machine and reports what `-Apply` would change. It changes nothing, apart from creating its log folder `%ProgramData%\CredentialRotation`.

**1. Copy** these folders from the repository (branch `main`) to the test machine over RDP, keeping the structure:

```
C:\temp\CredentialRotation\src\        Start-CredentialRotation.cmd, CredentialRotation.ps1, lib\
C:\temp\CredentialRotation\config\     CredentialRotation.psd1
C:\temp\CredentialRotation\tests\      only for a Windows 10 machine
C:\temp\CredentialRotation\build\      only for a Windows 10 machine (lint, and needed by the unit tests)
C:\temp\CredentialRotation\tools\      Get-CRInventory.ps1 (inventory v1.3)
```

**2. Run the audit** in an elevated command prompt ("Run as administrator"), logged on as `BiCA Remote`. Type each command on its own line; anything after the command is taken as an argument and refused:

```
C:\temp\CredentialRotation\src\Start-CredentialRotation.cmd
echo %ERRORLEVEL%
C:\temp\CredentialRotation\src\Start-CredentialRotation.cmd /PS2
echo %ERRORLEVEL%
```

The second run uses the PowerShell 2.0 engine (`/PS2`). It checks the PowerShell 2.0 compatibility, which can't be tested on the development machine. On Windows 10 or WMF 5.1 machines SQL Server can't be read in this run (see "Known limitation" above).

| Exit code | Meaning |
|---|---|
| 0 | No drift |
| 10 | Drift found (expected on a first run) |
| 2 | Preflight failed, e.g. not elevated or a write filter protects `C:` |
| 3 | Aborted: a bug; please send the output |

**3. Windows 10 only** (e.g. `IPT01-QS-K1`): run the unit tests. Windows 10 ships Pester 3.4; Windows 7 doesn't.

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\temp\CredentialRotation\tests\Invoke-Tests.ps1
```

**4. Run the inventory** (v1.4) on one Windows 7 Embedded machine (e.g. `SM-102575`) and one Windows 10 machine (done on `SM-QS-K1`):

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\temp\CredentialRotation\tools\Get-CRInventory.ps1
```

**5. Send back:**
- the console output and the exit codes
- the `.log` and `.csv` files from `%ProgramData%\CredentialRotation\logs\`
- the inventory JSON (it contains account names and SIDs; never commit it)

### Step 2: re-apply the current password of `ApplicationUser` (`-Apply -Only AppUser`, version 0.5.0)

A safe first write test, done before any real rotation (PLAN D20, O9). Only `ApplicationUser` is changed with its old password, so only for it can the tool recognize a re-apply: when the new password you type equals its current password, it
- does not change the Windows password (no history rejection, DPAPI data untouched)
- still rewrites its services, scheduled tasks and COM+ identities with that password (no restarts)
- enforces groups, flags and logon rights, and runs every verification
- lists no `LOGINS` follow-up

Under `-Only AppUser` nothing else is processed: no other slot, no retired or other accounts, no check-mode fixes. The only account it disables is the built-in Administrator, which `ApplicationUser` replaces; it is already disabled on all four test machines. A full run without `-Only` is not a safe test: the other Windows accounts get their password **set** (new password age, `LOGINS` follow-up, DPAPI data of `BiCA Admin`/`BiCA Remote` lost), and retired accounts such as `SYS Admin` are disabled.

There are no SQL slots: the tool doesn't update SQL login credentials (PLAN D27, v10.5). When `ApplicationUser` runs SQL Server, the SQL Server service still gets the new Windows password.

Run it first on test site 102575 with `/PS2`, logged on as `BiCA Remote`, in an elevated command prompt:

```
C:\temp\CredentialRotation\src\Start-CredentialRotation.cmd /PS2 -Apply -Only AppUser
echo %ERRORLEVEL%
```

The tool runs the audit first and lists the enabled local accounts with what happens to each. It then asks for the **new password twice** and, for `ApplicationUser` only, its **current password**. For the re-apply, type the current password as the new password. The site password rules (at least 8 characters, complexity, no part of the account name) apply to the re-apply too: if the current password of `ApplicationUser` breaks them, step 2 isn't possible on that machine. Never put a password on the command line. An empty new password skips the slot after a Y/N question.

It then tests the old password (at most one failed logon, within the lockout budget). Where it can't decide alone, it asks:
- both passwords fail: enter again / set the password (DPAPI data lost) / skip
- the lockout budget is exhausted: wait / set / skip
- the account is disabled, or its password is too young: set / skip
- an ambiguous auto-logon: turn off / leave unchanged

Before anything is changed it prints the **APPLY PLAN**:
- per slot the accounts, the probe result and the path (`Change`, `Set`, `Create`, `Re-apply`, `Already on the new password`, `Skip`)
- the accounts to disable and where their dependents go
- the auto-logon step
- all high-impact and ambiguous items

**Typing `YES`** (upper case) confirms everything shown. Anything else, or Ctrl+C, aborts without changes.

After the apply it prints the slot results (done / error / pending steps), the **FOLLOW-UP REQUIRED** list and a re-audit with the number of drift items left. The results also go to `%ProgramData%\CredentialRotation\logs\` (`..._apply.csv`).

| Exit code | Meaning |
|---|---|
| 0 | Applied, nothing outstanding (the normal result of the `ApplicationUser` re-apply) |
| 4 | Applied, follow-up required: `LOGINS` entries or IIS identities to update (the normal result of a rotation) |
| 1 | Partial failure: a slot stopped at a step, or a selected slot or account was skipped or blocked; the report lists what is done and pending. Re-run with the same passwords to complete it |
| 2 | Preflight failed, nothing changed (e.g. not elevated, a write filter protects `C:`) |
| 3 | Aborted: not confirmed with `YES`, Ctrl+C, or an unexpected error (please send the output) |

**Send back** the console output, the exit codes and the `.log`/`.csv` files, as in step 1.

### Step 3: rotate to new credentials (`-Apply`)

The real rotation is **one full run without `-Only`**, with the **new site password** for each slot, which must never have been used before (password history). Order:
1. Re-apply test (step 2) on test site 102575 with `/PS2`.
2. Full rotation on test site 102575, also with `/PS2` (`Start-CredentialRotation.cmd /PS2 -Apply`), so the write paths run once on PowerShell 2.0. It processes all slots (`BiCA Remote` last), the retired accounts (`SYS Admin`, `SYS-Admin`), the decision on other enabled accounts and the check-mode fixes.
3. Then test site QS-K1, with PowerShell 5.1 (without `/PS2`).

If you ever split a run with `-Only`, run `-Only AutoLogon` before `-Only BiCAAdmin`: where auto-logon runs as `BiCA Admin`, the switch to `WinAutoUser` is only possible once the auto-logon slot is done.

What each slot does (PLAN v10.5):
- `BiCAAdmin` and `BiCARemote`: their passwords are **set**, each to its own new password. A missing account is created.
- `AppUser`: changed with its old password. A missing account is created. It replaces the built-in Administrator, which is disabled and whose services and tasks move to `ApplicationUser`. Exception: if `ApplicationUser` is created in this run, nothing is moved and the Administrator stays enabled (manual migration, reported).
- Retired accounts (`SYS Admin` and its hyphen spelling `SYS-Admin`), and other accounts you choose to disable: their services, tasks and COM+ applications move to `ApplicationUser`, then the account is disabled.
- `SOP-Admin` and `SP Admin`: kept untouched. The tool never changes them and doesn't ask about them, also when you are logged on as one of them.
- `AutoLogon`: one password for every existing `PUB-User` and `WinAutoUser`, also a disabled one. Neither is ever created, enabled or disabled. An active auto-logon as either of them is kept. An auto-logon as any other account is turned off (SM machines) or switched to `PUB-User`, else `WinAutoUser`.

`-Only` takes slot names (`BiCAAdmin`, `AppUser`, `AutoLogon`, `BiCARemote`), several separated by commas. An unknown slot name stops the tool with exit code 2. The auto-logon step runs when the `AutoLogon` slot or the slot of the current auto-logon account is selected. Check-mode, retired and other accounts are only processed without `-Only`. `BiCA Remote` is your own account: after its new password is set, update saved RDP credentials (the tool lists this as a follow-up); an RDP client retrying the old password locks the account.

If a run is interrupted or a slot fails, re-run with the same passwords. Accounts whose password is set simply get the same value again. For `ApplicationUser`, the run journal makes the probe test the new password first after an interrupted run, and an account already on it is not changed again (D11). The pending steps are completed.

After a real rotation, the entries in `HKLM\SOFTWARE\BICA\SYSTEM\LOGINS` must be updated manually; the tool lists them as **FOLLOW-UP REQUIRED** (exit code 4).

## Development

Commands (build, lint, tests) are in [CLAUDE.md](CLAUDE.md). On the development machine the scripts can't be executed because of AppLocker; run them on a test machine or an allowed path.
