# CredentialRotation

A PowerShell tool that rotates the local Windows credentials on standalone workgroup machines (Windows 7 SP1 incl. Windows Embedded Standard 7, Windows 10), enforces the account roles and updates everything that depends on the passwords.

Design: [docs/PLAN.md](docs/PLAN.md) · Interfaces: [docs/dev/CONTRACTS.md](docs/dev/CONTRACTS.md) · Conventions and dev commands: [CLAUDE.md](CLAUDE.md)

## Status (version 0.6.0, PLAN v10.6)

Version 0.6.0 replaces `BiCA Admin` and `BiCA Remote` with `SOP-Admin` (PLAN D28) and gives `SOP-Admin` the SQL Server access of their Windows logins (D29). Its unit tests are written but not yet run; the results below are from 0.5.x.

| Milestone | Content | State |
|---|---|---|
| M1 | Read-only audit | tested (0.5.x) |
| M2 | Password prompts, account model, groups, flags, auto-logon policy | code written; `-Apply` of 0.5.x/0.6.0 not yet run (see machine state) |
| M3 | Services, scheduled tasks, COM+ updates and moves; the SQL login of `SOP-Admin` | code written; `-Apply` not yet run |

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

**Setup:** copy `src\` and `config\` from `main` to `C:\temp\CredentialRotation\` (on Windows 10 also `tests\` and `build\`; for the inventory `tools\`). Work in an elevated **cmd** ("Run as administrator"), logged on as `BiCA Remote`, or as `SOP-Admin` once it has replaced the BiCA accounts (otherwise note the account). The account must be `sysadmin` in SQL Server through its own Windows login, so the tool can give `SOP-Admin` its login. Type each command on its own line and never put a password on a command line.

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

Check: `SP Admin` only as "Kept untouched"; `SOP-Admin` as "Create SOP-Admin" or with "Password set", plus "SQL Server: create the Windows login …"; `BiCA Admin` and `BiCA Remote` as "Disable … (replaced by SOP-Admin)", or "Not disabled: …" with the reason; `SYS Admin` and `SYS-Admin` as "Disable … (no replacement)"; last line `Exit code: 10` or `0`.

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

- `AppUser`: changed with its old password; created if missing. The built-in Administrator is disabled and its dependents move to `ApplicationUser`, unless `ApplicationUser` was just created (manual migration, reported).
- `AutoLogon`: one password for every `PUB-User` and `WinAutoUser`. An active auto-logon as either is kept; any other is turned off (SM machines) or switched to `PUB-User`, else `WinAutoUser`.
- `SOPAdmin` (your account from now on) runs last: `SOP-Admin` is created, or an existing one gets the new password and is enabled; it joins Administrators, Remote Desktop Users and `Offer Remote Assistance Helpers` (where it exists), and gets a SQL Server login with the server roles of the BiCA logins (`sysadmin`). Then `BiCA Admin` is disabled, its services/tasks/COM+ moved to `SOP-Admin`, and `BiCA Remote`, if you are logged on as it, is disabled as the very last step. Your RDP session continues; log on as `SOP-Admin` next time.
- `BiCA Admin`/`BiCA Remote` stay enabled (with their old passwords, reported) if the SQL login can't be created or verified, if `SOP-Admin` couldn't log on locally or over RDP where they could, or if `SOP-Admin` was created in this run while the BiCA account runs services (a second run moves them).
- Rotate all machines of a site in one session. `PUB-User`/`WinAutoUser` are probably used for MSMQ between the machines, which needs the same password on both sides; afterwards restart the machines with an active auto-logon so their sessions use the new password, then check MSMQ. Until then the failed attempts can briefly lock the account on the other machine.
- `SYS Admin`, `SYS-Admin` and other accounts you choose to disable: their dependents move to `ApplicationUser`, then they are disabled. `SP Admin` is never touched. SQL credentials aren't changed (D27); the SQL Server service gets the new password of `ApplicationUser`.
- Afterwards update `HKLM\SOFTWARE\BICA\SYSTEM\LOGINS` manually: the `ApplicationUser` entry, and the `BiCA Admin`/`BiCA Remote` entries, which now take `SOP-Admin` and its password (listed as FOLLOW-UP REQUIRED, exit code 4).
- QS-K1 machines (`SOP-Admin` exists, `BiCA Remote` disabled by the WIP build): run as `BiCA Admin` at the console, or as any account that is `sysadmin` through its own login. Logged on as `SOP-Admin` without a SQL login, the SQL step fails with "not sysadmin" or "no connection" and the BiCA accounts stay enabled.
- Interrupted or failed: re-run with the same passwords. When splitting with `-Only` (`AppUser`, `AutoLogon`, `SOPAdmin`), run `AutoLogon` before `SOPAdmin`; retired, other and check-mode accounts are only processed without `-Only`.

## Rollout scripts (`rollout\`, admin workstation)

1. Test with one site. The script reads `rollout_CredentialRotation.xlsx` from the current folder and writes its result CSV there, so use a folder with a fresh copy of the workbook (with column `FolderId`) in which only one row has `GenerateSecret` = TRUE. The import writes the folder IDs into the workbook next to the CSV:

   ```powershell
   cd C:\temp\ss-test
   & 'C:\Repos\CredentialRotation\rollout\ss_Generate-Secret.ps1'
   & 'C:\Repos\CredentialRotation\rollout\nb_Import-CredentialFolderId.ps1' -CsvPath .\ss_Generate-Secret_<timestamp>.csv -WhatIf
   & 'C:\Repos\CredentialRotation\rollout\nb_Import-CredentialFolderId.ps1' -CsvPath .\ss_Generate-Secret_<timestamp>.csv
   ```

   Expected: one folder `<Ortschaft>.<Jobnummer>` with four secrets (`SOP-Admin`, `ApplicationUser`, `PUB-User`, `WinAutoUser`) with passwords generated by Secret Server, and its ID in column `FolderId` of the workbook copy and in the netbox site field `Credential_Folder_ID`. Close the workbook in Excel before the import, or it aborts before netbox. Send back both console outputs and the result CSV (no passwords in it).
