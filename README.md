# CredentialRotation

A PowerShell tool that rotates the local Windows and SQL Server credentials on standalone workgroup machines (Windows 7 SP1 incl. Windows Embedded Standard 7, Windows 10), enforces the account roles, and updates everything that depends on the passwords.

- Design: [docs/PLAN.md](docs/PLAN.md)
- Module interfaces: [docs/dev/CONTRACTS.md](docs/dev/CONTRACTS.md)
- Conventions for development: [CLAUDE.md](CLAUDE.md)

## Status

| Milestone | Content | State |
|---|---|---|
| M1 | Read-only audit | On branch `feature/m1-audit`; **tested on `SM-QS-K1`** (Windows 10) **and `SM-102575`** (Windows Embedded 7), PS 5.1 and PS 2.0 |
| M2 | Password prompts, account model (PLAN v10.4), groups, flags, auto-logon policy | Code written (version 0.4.0); **not yet run** |
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

Known limitation of `/PS2` test runs: on machines with WMF 5.1 or Windows 10, `powershell.exe.config` contains a .NET 4 `<uri>` section that the PS 2.0 engine can't read, so SQL Server can't be reached and the SQL slots are blocked. Real runs use PS 5.1 wherever it is installed, so they are not affected. SQL under PS 2.0 has to be tested on a Windows 7 with PS 2.0 only.

## Testing on a machine

There are three test steps. The code for all three exists (version 0.4.0), but only step 1 has been run so far. Steps 2 and 3 are untested, and the unit tests of version 0.4.0 haven't been run yet.

### Step 1: audit (read-only)

Step 1 has been done with the M1 version. Repeat it with version 0.4.0 before step 2: the audit now reports the account model of PLAN v10.4.

The audit reads the machine and reports what `-Apply` would change. It changes nothing, apart from creating its log folder `%ProgramData%\CredentialRotation`.

**1. Copy** these folders from the repository (branch `feature/m1-audit`) to the test machine over RDP, keeping the structure:

```
C:\temp\CredentialRotation\src\        Start-CredentialRotation.cmd, CredentialRotation.ps1, lib\
C:\temp\CredentialRotation\config\     CredentialRotation.psd1
C:\temp\CredentialRotation\tests\      only for a Windows 10 machine
C:\temp\CredentialRotation\tools\      Get-CRInventory.ps1 (inventory v1.3)
```

**2. Run the audit** in an elevated command prompt ("Run as administrator"), logged on as `BiCA Remote`. Type each command on its own line; anything after the command is taken as an argument and refused:

```
C:\temp\CredentialRotation\src\Start-CredentialRotation.cmd
echo %ERRORLEVEL%
C:\temp\CredentialRotation\src\Start-CredentialRotation.cmd /PS2
echo %ERRORLEVEL%
```

The second run uses the PowerShell 2.0 engine (`/PS2`). It checks the PowerShell 2.0 compatibility, which can't be tested on the development machine. On Windows 10 or WMF 5.1 machines the SQL slots are blocked in this run (see "Known limitation" above).

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

### Step 2: re-apply the current password of `ApplicationUser` (`-Apply -Only AppUser`, version 0.4.0)

A safe first write test, done before any real rotation (PLAN D20, O9). Only `ApplicationUser` is changed with its old password, so only for it can the tool recognize a re-apply: when the new password you type equals its current password, it
- does not change the Windows password (no history rejection, DPAPI data untouched)
- still rewrites its services, scheduled tasks and COM+ identities with that password (no restarts)
- enforces groups, flags and logon rights, and runs every verification
- lists no `LOGINS` follow-up

Under `-Only AppUser` nothing else is processed: no other slot, no retired or other accounts, no check-mode fixes. The only account it disables is the built-in Administrator, which `ApplicationUser` replaces; it is already disabled on all four test machines. A full run without `-Only` is not a safe test: the other Windows accounts get their password **set** (new password age, `LOGINS` follow-up, DPAPI data of `BiCA Admin`/`BiCA Remote` lost), and retired accounts such as `SP Admin` are disabled.

SQL slots are never prompted in this version ("SQL rotation not available in this version").

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
2. Full rotation on test site 102575, also with `/PS2` (`Start-CredentialRotation.cmd /PS2 -Apply`), so the write paths run once on PowerShell 2.0. It processes all slots (`BiCA Remote` last), the retired accounts (`SP Admin`, `SYS Admin`, `SOP-Admin`), the decision on other enabled accounts and the check-mode fixes.
3. Then test site QS-K1, with PowerShell 5.1 (without `/PS2`).

If you ever split a run with `-Only`, run `-Only AutoLogon` before `-Only BiCAAdmin`: where auto-logon runs as `BiCA Admin`, the switch to `WinAutoUser` is only possible once the auto-logon slot is done.

What each slot does (PLAN v10.4):
- `BiCAAdmin` and `BiCARemote`: their passwords are **set**, each to its own new password. A missing account is created.
- `AppUser`: changed with its old password. A missing account is created. It replaces the built-in Administrator, which is disabled and whose services and tasks move to `ApplicationUser`. Exception: if `ApplicationUser` is created in this run, nothing is moved and the Administrator stays enabled (manual migration, reported).
- Retired accounts, and other accounts you choose to disable: their services, tasks and COM+ applications move to `ApplicationUser`, then the account is disabled.
- `AutoLogon`: one password for every existing `PUB-User` and `WinAutoUser`, also a disabled one. Neither is ever created, enabled or disabled. An active auto-logon as either of them is kept. An auto-logon as any other account is turned off (SM machines) or switched to `PUB-User`, else `WinAutoUser`.

`-Only` takes slot names (`BiCAAdmin`, `AppUser`, `AutoLogon`, `BiCARemote`), several separated by commas. An unknown slot name stops the tool with exit code 2. The auto-logon step runs when the `AutoLogon` slot or the slot of the current auto-logon account is selected. Check-mode, retired and other accounts are only processed without `-Only`. `BiCA Remote` is your own account: after its new password is set, update saved RDP credentials (the tool lists this as a follow-up); an RDP client retrying the old password locks the account.

If a run is interrupted or a slot fails, re-run with the same passwords. Accounts whose password is set simply get the same value again. For `ApplicationUser`, the run journal makes the probe test the new password first after an interrupted run, and an account already on it is not changed again (D11). The pending steps are completed.

After a real rotation, the entries in `HKLM\SOFTWARE\BICA\SYSTEM\LOGINS` must be updated manually; the tool lists them as **FOLLOW-UP REQUIRED** (exit code 4).

## Development

Commands (build, lint, tests) are in [CLAUDE.md](CLAUDE.md). On the development machine the scripts can't be executed because of AppLocker; run them on a test machine or an allowed path.
