# CredentialRotation

A PowerShell tool that rotates the local Windows credentials on standalone workgroup machines (Windows 7 SP1 incl. Windows Embedded Standard 7, Windows 10), enforces the account roles and updates everything that depends on the passwords.

Design: [docs/PLAN.md](docs/PLAN.md) · Interfaces: [docs/dev/CONTRACTS.md](docs/dev/CONTRACTS.md) · Conventions and dev commands: [CLAUDE.md](CLAUDE.md)

## Status (version 0.5.2, PLAN v10.5)

| Milestone | Content | State |
|---|---|---|
| M1 | Read-only audit | tested |
| M2 | Password prompts, account model, groups, flags, auto-logon policy | code written; `-Apply` of 0.5.x not yet run (see machine state) |
| M3 | Services, scheduled tasks, COM+ updates and moves | code written; `-Apply` of 0.5.x not yet run |

| Machine | Audit (PS 5.1) | Audit (`/PS2`) | Unit tests, lint |
|---|---|---|---|
| `SM-QS-K1` (Windows 10 LTSC 2019) | 0.5.1 OK, `Exit code: 10` | 0.5.1 OK, `Exit code: 10` (cmd: 0) | 0.5.1: 1119 / 1119, 0 violations; inventory v1.4 (2026-10-19) |
| `IPT01-QS-K1` (Windows 10 LTSC 2019) | 0.5.0 OK | 0.5.0 OK, see limitations | 1119 / 1119, 0 violations |
| `PIT50-QS-K1` (Windows 10 LTSC 2019) | 0.5.0 OK; auto-logon was ambiguous because of Sysinternals Autologon traces, reported only from 0.5.2 | 0.5.0 OK, see limitations | 1119 / 1119, 0 violations |
| `SM-102575` (Windows Embedded 7) | M1 OK | M1 OK | no Pester |
| `IPT01-102575` (Windows Embedded 7) | not run | not run | no Pester |

Known limitations of `/PS2` runs on the Windows 10 test machines (real runs use PS 5.1):
- cmd receives exit code 0 whatever the result. From 0.5.1 the tool prints `Exit code: <n>` as its last line; read that line.
- The auto-logon finding lacks the legal-notice reason (reported only, never blocking).
- SQL Server can't be read (the PS 2.0 engine can't parse `powershell.exe.config`); no effect, as there are no SQL slots (D27).

Machine state: on `SM-QS-K1` an intentional test `-Apply` of the untested WIP build `d22b466` (v10 account model, 2026-10-07) created `SOP-Admin` (description "Managed by CredentialRotation (SOPAdmin)"), set the passwords of `BiCA Admin`, `ApplicationUser`, `PUB-User`, `WinAutoUser` and `SOP-Admin`, and disabled `BiCA Remote` and `WinAutoUser` as replaced accounts (inventory 2026-10-19). `IPT01-QS-K1` and `PIT50-QS-K1` look the same in the audit (`SOP-Admin` present; `BiCA Admin`, on PIT50 also `BiCA Remote` and `WinAutoUser`, disabled). The QS-K1 machines stay in this test state for now; nothing is re-enabled.

AppLocker blocks scripts on the development machine, so all runs happen on the test machines.

## Testing on a test machine

**Setup:** copy `src\` and `config\` from `main` to `C:\temp\CredentialRotation\` (on Windows 10 also `tests\` and `build\`; for the inventory `tools\`). Work in an elevated **cmd** ("Run as administrator"), logged on as `BiCA Remote` (otherwise note the account). Type each command on its own line and never put a password on a command line.

**Output:** save the console output as `ConsoleOutput_<step>_<machine>.txt` and copy it, with the `.log` and `.csv` files from `%ProgramData%\CredentialRotation\logs\`, to `logs\<machine>\` in the repository. Git ignores that folder; the files contain account names and SIDs, so never commit them. Send back each step's output before starting the next one.

| Exit code | Meaning |
|---|---|
| 0 | audit: no drift · apply: done, nothing outstanding |
| 10 | audit: drift found |
| 4 | apply: done, follow-up required (`LOGINS` entries, IIS identities) |
| 1 | apply: partly failed; the report lists what is done and pending. Re-run with the same passwords |
| 2 | preflight failed or unknown `-Only` slot; nothing changed |
| 3 | aborted: no `YES`, Ctrl+C or a bug (send the output) |

| Step | Where | State |
|---|---|---|
| 1. Unit tests and lint | one Windows 10 machine | done |
| 2. Audit, PS 5.1 and `/PS2` | every machine | done on QS-K1; open on 102575 |
| 3. Re-apply test (`-Apply -Only AppUser`) | 102575 with `/PS2` first | open |
| 4. Full rotation (`-Apply`) | 102575 with `/PS2`, then QS-K1 | after step 3 is reviewed |

### 1. Unit tests and lint

No elevation needed. Expected: `Failed: 0` and `0 violation(s)` in the last lines.

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\temp\CredentialRotation\tests\Invoke-Tests.ps1 > C:\temp\ConsoleOutput_tests_%COMPUTERNAME%.txt 2>&1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\temp\CredentialRotation\build\Test-Ps2Syntax.ps1 > C:\temp\ConsoleOutput_lint_%COMPUTERNAME%.txt 2>&1
```

### 2. Audit (read-only)

Reports what `-Apply` would change; it only creates its log folder.

```
C:\temp\CredentialRotation\src\Start-CredentialRotation.cmd > C:\temp\ConsoleOutput_audit_%COMPUTERNAME%.txt 2>&1
C:\temp\CredentialRotation\src\Start-CredentialRotation.cmd /PS2 > C:\temp\ConsoleOutput_audit_ps2_%COMPUTERNAME%.txt 2>&1
```

Check: `SOP-Admin` and `SP Admin` only as "Kept untouched"; `SYS Admin` and `SYS-Admin` as "Disable … (no replacement)"; nothing about SQL logins; last line `Exit code: 10` or `0`.

Inventory, still open on one Windows Embedded 7 machine (the JSON contains account names and SIDs):

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\temp\CredentialRotation\tools\Get-CRInventory.ps1
```

### 3. Re-apply test

The safe first write test (PLAN D20). It asks for input, so don't redirect it; afterwards copy the console text (window menu, Edit, Select All, Enter). The log files hold the full run.

```
C:\temp\CredentialRotation\src\Start-CredentialRotation.cmd /PS2 -Apply -Only AppUser
```

- Type the **current** password of `ApplicationUser` as its new password (twice) and as its old password. The tool then keeps the Windows password (DPAPI data untouched), rewrites its services, tasks and COM+ identities, enforces groups, flags and rights, and verifies everything.
- Nothing else is processed. The only account it disables is the built-in Administrator, which is already disabled on the test machines.
- The site password rules (at least 8 characters, complexity, no part of the account name) apply here too. If the current password breaks them, the test isn't possible on that machine.
- If it can't decide alone (both passwords fail, lockout budget, disabled account, ambiguous auto-logon), it asks you. It then shows the APPLY PLAN; only `YES` (upper case) confirms.
- Expected: exit code 0, no follow-up.

### 4. Full rotation

`-Apply` without `-Only`, with a new site password per slot that was never used before (password history).

- `BiCAAdmin`, `BiCARemote`: password set; a missing account is created. `BiCARemote` (your account) runs last; update saved RDP credentials afterwards.
- `AppUser`: changed with its old password; created if missing. The built-in Administrator is disabled and its dependents move to `ApplicationUser`, unless `ApplicationUser` was just created (manual migration, reported).
- `AutoLogon`: one password for every `PUB-User` and `WinAutoUser`. An active auto-logon as either is kept; any other is turned off (SM machines) or switched to `PUB-User`, else `WinAutoUser`.
- Rotate all machines of a site in one session. `PUB-User`/`WinAutoUser` are probably used for MSMQ between the machines, which needs the same password on both sides; afterwards restart the machines with an active auto-logon so their sessions use the new password, then check MSMQ. Until then the failed attempts can briefly lock the account on the other machine.
- `SYS Admin`, `SYS-Admin` and other accounts you choose to disable: their dependents move to `ApplicationUser`, then they are disabled. `SOP-Admin` and `SP Admin` are never touched. SQL logins aren't changed (D27); the SQL Server service gets the new password of `ApplicationUser`.
- Afterwards update `HKLM\SOFTWARE\BICA\SYSTEM\LOGINS` manually (listed as FOLLOW-UP REQUIRED, exit code 4).
- Interrupted or failed: re-run with the same passwords. When splitting with `-Only` (`BiCAAdmin`, `AppUser`, `AutoLogon`, `BiCARemote`), run `AutoLogon` before `BiCAAdmin`; retired, other and check-mode accounts are only processed without `-Only`.

## Rollout scripts (`rollout\`, admin workstation)

1. Re-sign `ss_Generate-Secret.ps1` and `nb_Import-CredentialFolderId.ps1`; both changed after the last signature.
2. In Secret Server, set the password requirement of templates 6084, 6085, 6087, 7121 and 7122: exactly 16 characters with an upper case letter, a lower case letter, a digit and one of `- _ . : + # @`, nothing else. Without it `ss_Generate-Secret.ps1` stops before creating anything.
3. Test with one site. The script reads `rollout_CredentialRotation.xlsx` from the current folder and writes its result CSV there, so use a folder with a copy of the workbook in which only one row has `GenerateSecret` = TRUE:

   ```powershell
   cd C:\temp\ss-test
   & 'C:\Repos\CredentialRotation\rollout\ss_Generate-Secret.ps1'
   & 'C:\Repos\CredentialRotation\rollout\nb_Import-CredentialFolderId.ps1' -CsvPath .\ss_Generate-Secret_<timestamp>.csv -WhatIf
   & 'C:\Repos\CredentialRotation\rollout\nb_Import-CredentialFolderId.ps1' -CsvPath .\ss_Generate-Secret_<timestamp>.csv
   ```

   Expected: one folder `<Ortschaft>.<Jobnummer>` with five secrets with 16-character passwords, and its ID in the netbox site field `Credential_Folder_ID`. Send back both console outputs and the result CSV (no passwords in it).
