# CredentialRotation

A PowerShell tool that rotates the local Windows and SQL Server credentials on standalone workgroup machines (Windows 7 SP1 incl. Windows Embedded Standard 7, Windows 10), enforces the account roles, and updates everything that depends on the passwords.

- Design: [docs/PLAN.md](docs/PLAN.md)
- Module interfaces: [docs/dev/CONTRACTS.md](docs/dev/CONTRACTS.md)
- Conventions for development: [CLAUDE.md](CLAUDE.md)

## Status

| Milestone | Content | State |
|---|---|---|
| M1 | Read-only audit | On branch `feature/m1-audit`; **tested on `SM-QS-K1`** (Windows 10) **and `SM-102575`** (Windows Embedded 7), PS 5.1 and PS 2.0 |
| M2 | Password prompts, rotation, groups, flags, auto-logon policy | Not started |
| M3 | Services, scheduled tasks, COM+ updates | Not started |

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

There are three test steps. Only step 1 is possible with the current code.

### Step 1: audit (read-only)

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

### Step 2: re-apply the current passwords (planned, needs M2/M3)

A safe first write test, done before any real rotation.

Simply setting the same password again would fail on most machines: password history rejects a reused password (history 5 on site 102575, 24 on `IPT01-QS-K1`). SQL Server may reject it too, because the SQL logins check the password policy.

The proposal for M2 is a **re-apply mode**: if the new password entered equals the old one, the tool
- does not change the Windows password
- still rewrites services, scheduled tasks, COM+ identities and the auto-logon secret with the same password
- enforces groups and flags and runs all verifications
- skips the SQL password change

This tests almost the whole write path without any risk of locking an account out, and the `LOGINS` registry entries stay valid. Run it first on test site 102575 with `/PS2`.

### Step 3: rotate to new credentials (needs M2/M3)

Planned order:
1. Fix what the audit runs turn up.
2. Build M2 and M3.
3. Re-apply test (step 2) on test site 102575 with `/PS2`.
4. First real rotation on test site 102575.
5. Then test site QS-K1.

After a real rotation, the entries in `HKLM\SOFTWARE\BICA\SYSTEM\LOGINS` must be updated manually; the tool lists them as **FOLLOW-UP REQUIRED** (exit code 4).

## Development

Commands (build, lint, tests) are in [CLAUDE.md](CLAUDE.md). On the development machine the scripts can't be executed because of AppLocker; run them on a test machine or an allowed path.
