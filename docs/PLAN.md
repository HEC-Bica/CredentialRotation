# Credential Rotation Tool — Implementation Plan

Status: draft v9.4 · 2026-10-07 (adds D20 re-apply mode; M1 audit validated on both test sites).
- Eleven rounds of independent review (Appendix A).
- Updated with the **M0 inventories of two test sites** (§13.2) and the user's decisions on their findings:
  - **QS-K1:** `SM-QS-K1` and `IPT01-QS-K1`, Windows 10 LTSC 2019
  - **102575:** `SM-102575` and `IPT01-102575`, Windows Embedded Standard 7 SP1
- Every environment fact and policy decision comes from the user's answers or the inventories (§13). Anything not yet known is listed as open, not assumed.

## 1. Goal and scope

A PowerShell tool run **locally** on standalone workgroup machines (Windows 7 SP1 x64 incl. Windows Embedded Standard 7, Windows 10 x64). The operator copies it over RDP to `C:\temp` and runs it from there while logged on as `BiCA Remote`. **The tool only cares about the local credentials of the machine it runs on.** It:

1. Rotates the passwords of the managed local Windows accounts and 3 SQL Server logins. The operator enters each new password, and the old one for Windows accounts, when prompted.
2. Enforces the role of the rotated accounts. It also checks and fixes the settings of the non-rotated user and FTP accounts.
3. Updates everything on the machine that depends on the rotated passwords: services, scheduled tasks and COM+ applications. It also enforces the **auto-logon policy** (D18): auto-logon only ever runs as `PUB-User` or `WinAutoUser`, never as an admin, and SM machines keep at most those two.
4. **Reports** what it doesn't change:
   - IIS identities using a rotated account
   - DCOM `RunAs` identities
   - SQL Agent dependencies
   - the entries in the application's registry key `HKLM\SOFTWARE\BICA\SYSTEM\LOGINS` that must be updated outside the tool

### 1.1 Managed accounts

| Account | Selection rule | Action | Target state | LOGINS entry |
|---|---|---|---|---|
| `BiCA Admin` | by name | rotate | Administrators only · PNE · CCP · PR | yes |
| `BiCA Remote` | by name; the operator's logon account | rotate, as the **last** slot (§8) | Administrators + `Offer Remote Assistance Helpers` (added if the group exists) only · PNE · CCP · PR. **Allowed extra group** (kept, never added): `Remote Desktop Users` | yes |
| Application user | `ApplicationUser` if it exists, otherwise the **built-in Administrator** (RID 500, possibly renamed, e.g. `WIN-Admin`). Separate site passwords for the two variants | rotate, plus dependents: services, scheduled tasks, COM+ | `ApplicationUser`: Administrators only · PNE · CCP · PR. **Built-in Administrator: rotate only** | yes (both) |
| Auto-logon users | **every existing** account of `PUB-User`, `WinAutoUser`, all with the auto-logon slot password | rotate. The auto-logon policy (D18, §7.5) uses `PUB-User` if it exists and is enabled, otherwise `WinAutoUser` | Users only · PNE · CCP · PR | no |
| `WinUser1`, `WinUser2`, `WinUser3` | by name | **check + fix**, no password change | Users · PNE · CCP. **Allowed extra groups** (kept, never added): `Remote Desktop Users`, groups named `hw_fn_*`. All other groups are removed | — |
| FTP users (0–3 per machine) | name starts or ends with `ftp`, case-insensitive | **check + fix**, no password change | CardCenters only · PNE · CCP. **Removed from Users** too (confirmed; `SM-102575` has `AG_FTP` and `LVSTG_FTP` in CardCenters + Users). If `CardCenters` doesn't exist: report, leave groups unchanged | — |
| `SQLApplication`, `SQLScript`, `SQLService` | SQL logins on the default instance | rotate | member of `sysadmin` | yes |

- PNE = password never expires. CCP = user cannot change password. PR = password required: the flag `UF_PASSWD_NOTREQD` (0x20) is cleared after the new password is set. `BiCA Admin` has that flag on all four test machines today.
- "X only" = member of X and removed from all other local groups, except the listed allowed extra groups.
- Each rotated account (slot) has its own password. The same password is used on every machine of a **site** (2–3 machines). `ApplicationUser` and the built-in Administrator have separate site passwords; only the variant resolved on a machine is prompted.
- Missing accounts are reported, never created. No managed account is the renamed built-in Administrator (confirmed). The tool still checks for SID overlap (§5).
- **Not touched:**
  - the built-in Administrator when `ApplicationUser` exists
  - `sa`
  - **`SP Admin`** (an enabled administrator found on `IPT01-QS-K1`; confirmed: leave untouched)
  - `WinPrep`, `DefaultUser`, `DefaultAccount`, `Guest`/`GST-User`, `WDAGUtilityAccount`
  - any other account, e.g. `USBAdmin` (an enabled administrator on `SM-102575`)

### 1.2 Scope boundaries

**Out of scope for v1:**
- reading or writing `BICA\SYSTEM\LOGINS` (report only, §7.8)
- other machines of the site, and cross-machine effects
- domain/AD/Entra/MDM
- Windows XP, x86
- SQL Server 2000 and versions after 2017; named instances
- password generation
- automatic rollback
- central push
- LAPS
- code signing
- changes to audit, lockout or password policy
- cleanup of other Administrators/sysadmin members
- adding or removing user rights other than the grants dependents need (§7.3); deny rights are never touched
- **writing IIS credentials** (detect + report only, confirmed)
- kiosk lockdown and app autostart

**Report-only:**
- IIS identities and "connect as" credentials using a rotated account
- DCOM `RunAs`
- SQL Agent credentials/proxies/linked logins and job owners
- the `LOGINS` follow-up list
- the locked state of managed accounts

## 2. Key decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | **PowerShell, limited to PS 2.0 syntax *and semantics*, .NET 2.0/3.5 APIs.** | PS 2.0 is the default on Windows 7. The Windows 7 test site (102575) has WMF 5.1, but other machines may not. Windows 10 runs PS 2.0 code unchanged; all four test machines have the PS 2.0 engine + .NET 3.5 installed. |
| D2 | **Executed locally, elevated, by an operator logged on as `BiCA Remote` over RDP**, from a copy in `C:\temp`. That account is rotated too (§8). Only local credentials are in scope. The SM inventories of both test sites ran at the console as `BiCA Admin`; that is not the operating model on real sites (confirmed). | Confirmed operating model. |
| D3 | **Non-interactive core + interactive front-end.** Core functions accept `SecureString`s only. | Testable, and keeps a later per-site orchestrator possible. |
| D4 | **Secrets never on a command line, never as a PowerShell command parameter, never printed.** Plaintext is passed only to .NET/COM/ADSI methods or property setters, inside the adapter layer. | Process list, event 4688, Module Logging, transcripts. |
| D5 | **Principals are resolved by SID.** This covers built-in accounts, well-known groups, and SQL Windows logins (whose names carry **old computer names** on both test sites, e.g. `DESKTOP-4ALF524\BiCA Admin`, `WIN-DJPP3T59SJL\BiCA Admin`). Managed accounts are resolved by their selection rule. Custom groups (`CardCenters`, `Offer Remote Assistance Helpers`, `hw_fn_*`) are resolved by name. **Group membership is read and changed by SID through `netapi32`** (`NetLocalGroupGetMembers`/`AddMembers`/`DelMembers`, level 0), not through ADSI: on Windows Embedded Standard 7 (test site 102575) ADSI returned no name or SID for any local-account member. | Localization, renamed built-in accounts, machines renamed after imaging. |
| D6 | **One declarative, unsigned `.psd1` config.** It holds no secrets. | No signing (confirmed); integrity risk accepted (§9). |
| D7 | **Audit by default; `-Apply` makes changes after a single `YES`.** The `YES` covers rotations and check-fixes. Exception: runtime ambiguities (D13). | Confirmed. |
| D8 | **The credential slot is the unit of apply** for local dependents. `LOGINS` entries and IIS identities are outside the tool and are reported as follow-ups. | Confirmed. |
| D9 | **Windows accounts: password *change* with the validated old password is the default.** SQL logins are changed as sysadmin. | Old passwords are usually known. Managed accounts on both test sites hold DPAPI data, so a reset would lose it. |
| D10 | **Group exclusivity with explicit allow-lists. No other privilege reductions.** | Confirmed, incl. the `WinUser` allow-list. |
| D11 | **Re-runs are idempotent.** | Recover from a crash by re-running with the same input. |
| D12 | **Lockout budget for the tool's own logon attempts.** The threshold and duration are **read per machine**: QS-K1 has 4/5 min on SM and 10/15 min on IPT01, 102575 has 4/3 min on both. The counter and the locked state are re-read immediately before every attempt and before `ChangePassword`. An attempt is made only if at least two attempts remain below the threshold. The probe order minimizes failures (§6 step 7). Failures from other sources are not under the tool's control. | Protects especially `BiCA Remote`. |
| D13 | **Ambiguity → ask the operator, never guess.** | Explicit requirement. |
| D14 | **All three SQL logins are `sysadmin`.** Deliberate and user-confirmed; matches both test sites. | Confirmed. |
| D15 | **Site password rules = the strictest rule of any machine**, enforced by the tool on every machine in addition to the local OS policy. Default: minimum length **8** + an **emulation of Windows complexity**, the strictest found on the test sites (`IPT01-QS-K1`). Configurable in `SitePasswordRules`. The emulation: 3 of 5 categories (Unicode upper, lower, digits, non-alphanumeric, other letters), and no case-insensitive token of 3+ characters from the `SamAccountName` or `FullName` of any account in the slot (split on `, . - _ #`, space, tab), nor from the SQL login name. It is implemented in `Native.ps1` over the BSTR, so plaintext stays out of PowerShell. | Confirmed. A shared site password must be accepted on every machine; otherwise the site diverges. |
| D16 | **Logon type for probe and verification is chosen from the account's effective logon rights.** Both test sites have deny rights on managed accounts, e.g. `BiCA Remote` is denied local logon and `ApplicationUser` is denied local and RDP logon. If no type is clearly allowed, Network is used and 1385 is interpreted per spike item 14. | Avoids refused logons and failed-logon noise. |
| D17 | **The tool never restarts the application user's dependents** (SQL Server, Agent, retail services, COM+ applications). SCM, task and COM+ credentials are updated and reported as "restart pending". They take effect at the next start (maintenance window, reboot, or after the `LOGINS` update). | Confirmed. A password change doesn't need an immediate restart. A restart would cause an outage and make the app re-read stale `LOGINS` entries. |
| D18 | **Auto-logon policy.** Auto-logon only ever runs as a usable `PUB-User` or `WinAutoUser` (enabled, unlocked, interactive logon allowed), **never as an admin**. On **SM machines** (computer name starts with `SM`, case-insensitive) an admin or any other account is turned off, while `PUB-User`/`WinAutoUser` is kept. On other machines, any other account is switched to the selected user (`PUB-User` preferred, also over a running `WinAutoUser` auto-logon). Auto-logon that is off stays off. Rules in §7.5. | Confirmed. Test site 102575 runs auto-logon as `BiCA Admin` on both machines, with the password in plain text in the registry. |
| D19 | **Write-filter guard.** Preflight detects EWF/FBWF (Windows Embedded Standard 7) and UWF (Windows 10). A volume counts as protected if the filter protects it in the **current session**, unless a whole-volume commit is pending for the next shutdown (EWF `-commit`). If the state can't be determined while a filter driver is installed, the volume counts as protected.<br>• **System volume protected → all of `-Apply` is blocked** (confirmed): slots, auto-logon step, enforcement phase. The tool's own journal and logs would vanish too. Audit still runs and explains why.<br>• Otherwise, a protected volume holding SQL `master` data or log files (`sys.master_files`) blocks the SQL slots. | Confirmed: unknown whether the machines use a write filter. Changes on a protected volume vanish at the next reboot. |
| D20 | **Re-apply mode.** A Windows account whose entered new password equals its validated old password is treated as "already on the new secret" (D11): **no password change** (no history rejection, DPAPI untouched), but its dependents (SCM, tasks, COM+, auto-logon secret) are rewritten with that password, groups and flags are enforced, and every verification runs. No `LOGINS` follow-up for that account. SQL slots are left empty, which skips them (§6 step 6). | Confirmed as the safe first write test (README step 2), before any real rotation. Exercises almost the whole write path without risk of lockout. |

## 3. Execution model

**Distribution.** The operator copies a versioned folder over the **RDP session** (drive redirection or clipboard) to **`C:\temp\CredentialRotation-<version>\`** and runs it from there (confirmed). It contains:
- `Start-CredentialRotation.cmd`
- `CredentialRotation.ps1` (bundled)
- `CredentialRotation.psd1`

There is no code signing. Each release publishes the **expected SHA-256 hashes** separately from the package, e.g. in the release notes. The tool displays the hashes of its files at start, so the operator can compare them manually.

**No protection of the run folder (accepted risk, confirmed).** Local users can usually write below `C:\temp`, so they could change the scripts before an admin runs them. The tool doesn't copy itself elsewhere and doesn't change the folder's ACL (§9).

**Launcher (`.cmd`):**
- Started with "Run as administrator" from `C:\temp\CredentialRotation-<version>\`; it finds the tool via `%~dp0`.
- Calls every executable by its **absolute path** (`%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`, `%SystemRoot%\sysnative\…`), because `cmd` searches the current folder first.
- Starts 64-bit PowerShell via `%windir%\sysnative\` when needed, with `-NoProfile -ExecutionPolicy Bypass`.
- A test switch `/PS2` adds `-Version 2`; all test machines have the PS 2.0 engine. Until a PS 2.0 test host exists (§11, O3), it's used for audit runs on both test sites and for the **first M2 apply on test site 102575**, so the write paths also run once on PS 2.0: adapters, LSA secret, `ChangePassword`, netapi32 group changes, task re-registration. The execution policy is `Undefined` at the machine and user scopes on all four test machines (`RemoteSigned` at `LocalMachine`).
- Explains a local Group Policy execution policy that overrides `Bypass`.

**Runtime:**
- elevation, a named mutex, and `FullLanguage` mode are required
- file hashes are computed with `SHA256CryptoServiceProvider` (`Add-Type -AssemblyName System.Core` on PS 2.0), then displayed and logged
- the tool leaves its folder in place; logs go to `%ProgramData%` (§7.10)

**Modes and parameters:**
- default: audit
- `-Apply`
- `-Only <slot names>`: a slot is always processed completely; a slot that doesn't apply on this machine is reported as "not applicable"
- `-LogPath`

## 4. Architecture

```
src/
  Start-CredentialRotation.cmd   launcher: run from C:\temp\CredentialRotation-<version>, 64-bit PS, policy diagnostics
  CredentialRotation.ps1         entry point: modes, front-end, phase orchestration
  lib/
    Compat.ps1        PS 2.0 helpers
    Native.ps1        Add-Type C# (C# 3.0 max): LsaStorePrivateData (write/delete only), LSA account rights
                      (enumerate accounts per right), LsaQueryInformationPolicy (machine SID), LogonUser,
                      NetValidatePasswordPolicy, NetUserModalsGet (policy), NetLocalGroupGetMembers /
                      AddMembers / DelMembers (by SID), write-filter state, BSTR compare
    Adapters.ps1      the only place where plaintext is materialized (§9)
    Secrets.ps1       prompting, site rules + local policy checks, credential probe, lockout budget
    Config.ps1        load + schema validation
    Principals.ps1    SID resolution, selection rules, SID-overlap check, group lookup by SID/name/pattern
    Rights.ps1        effective logon rights per account (grants/denies via SID + group SIDs); grants for dependents
    Accounts.ps1      rotation (change/reset), flags, check mode, unlock
    Groups.ps1        membership incl. exclusivity, allow-lists and rails
    Services.ps1      discovery by SID, SCM update (no restarts, D17)
    Tasks.ps1         Task Scheduler 2.0 COM
    ComPlus.ps1       COM+ identities; DCOM RunAs report
    IisReport.ps1     IIS identities using rotated accounts (read only)
    AutoLogon.ps1     detection of existing variants + auto-logon policy (D18: keep, standardize, switch, turn off)
    LoginsReport.ps1  LOGINS follow-up list (no registry access)
    Sql.ps1           default instance, SqlClient, version-aware T-SQL for 2005–2017
    Preflight.ps1     environment, write filter (D19), local password/lockout policy, SQL/COM+ readiness
    Plan.ps1          desired vs. actual -> change plan
    Apply.ps1         slot sequencing, enforcement phase (§8)
    Log.ps1           local log file + CSV summary; run journal (§7.10)
config/CredentialRotation.psd1
build/Build.ps1 (bundle + SHA-256 list), build/Test-Ps2Syntax.ps1 (lint)
tests/*.Tests.ps1     Pester 3.4.x; target: a real PS 2.0 engine (host pending, O3), meanwhile PS 5.1
tools/Get-CRInventory.ps1   read-only M0 inventory (PS 2.0 and later)
```

## 5. Configuration

The config is loaded with `Import-LocalizedData -BaseDirectory <dir> -FileName CredentialRotation.psd1 -UICulture en-US`, with no culture subfolders.

**Principal references:**

| Form | Meaning |
|---|---|
| `S-1-…` | well-known SID (e.g. `S-1-5-32-544` Administrators, `S-1-5-32-545` Users, `S-1-5-32-555` Remote Desktop Users) |
| `RID-500` | local account by RID (machine SID via `LsaQueryInformationPolicy`) |
| `Name:<group>` | custom local group by name; must exist, otherwise the role's `IfGroupMissing` applies |
| `Name:<group>?` | custom local group by name; added if it exists, ignored if it doesn't |
| `Pattern:<regex>` | custom local groups whose name matches (case-insensitive); only valid in `AllowedExtraGroups` |

```powershell
@{
    SchemaVersion = 1

    # D15: enforced on every machine in addition to the local OS policy
    SitePasswordRules = @{ MinLength = 8; RequireComplexity = $true }

    Roles = @{
        Admin       = @{ Groups = @('S-1-5-32-544'); ExclusiveGroups = $true; PasswordNeverExpires = $true; CannotChangePassword = $true
                         PasswordRequired = $true }
        AdminRemote = @{ Groups = @('S-1-5-32-544','Name:Offer Remote Assistance Helpers?'); ExclusiveGroups = $true
                         AllowedExtraGroups = @('S-1-5-32-555')                                  # kept if present, never added
                         PasswordNeverExpires = $true; CannotChangePassword = $true; PasswordRequired = $true }
        User        = @{ Groups = @('S-1-5-32-545'); ExclusiveGroups = $true; PasswordNeverExpires = $true; CannotChangePassword = $true
                         PasswordRequired = $true }
        WinUser     = @{ Groups = @('S-1-5-32-545'); ExclusiveGroups = $true; PasswordNeverExpires = $true; CannotChangePassword = $true
                         AllowedExtraGroups = @('S-1-5-32-555', 'Pattern:^hw_fn_') }      # kept if present, never added
        Ftp         = @{ Groups = @('Name:CardCenters'); ExclusiveGroups = $true; PasswordNeverExpires = $true; CannotChangePassword = $true
                         IfGroupMissing = 'ReportKeepGroups' }
        RotateOnly  = @{ }
    }

    # One prompt per slot, applied in ascending Order. Windows slots also ask for the old password (D9).
    # AppUser* slots: only the variant resolved on this machine is prompted; the prompt shows the resolved account.
    Credentials = @(
        @{ Slot = 'BiCAAdmin';           Order = 10; Label = 'BiCA Admin' }
        @{ Slot = 'AppUserApplication';  Order = 20; Label = 'Application user: ApplicationUser' }
        @{ Slot = 'AppUserBuiltinAdmin'; Order = 21; Label = 'Application user: built-in Administrator' }
        @{ Slot = 'AutoLogon';           Order = 30; Label = 'Auto-logon users (PUB-User / WinAutoUser)' }
        @{ Slot = 'SQLApplication';      Order = 40; Label = 'SQL login SQLApplication'; MaxLength = 128 }
        @{ Slot = 'SQLScript';           Order = 50; Label = 'SQL login SQLScript';      MaxLength = 128 }
        @{ Slot = 'SQLService';          Order = 60; Label = 'SQL login SQLService';     MaxLength = 128 }
        @{ Slot = 'BiCARemote';          Order = 90; Label = 'BiCA Remote (your own logon account)' }
    )

    Accounts = @(
        @{ Id = 'BiCAAdmin';  Kind = 'Windows'; Name = 'BiCA Admin';  Role = 'Admin';       Credential = 'BiCAAdmin';  LoginsEntry = $true }
        @{ Id = 'BiCARemote'; Kind = 'Windows'; Name = 'BiCA Remote'; Role = 'AdminRemote'; Credential = 'BiCARemote'; LoginsEntry = $true }
        @{ Id = 'AppUser';    Kind = 'Windows'; LoginsEntry = $true
           Candidates = @( @{ Name = 'ApplicationUser'; Role = 'Admin';      Credential = 'AppUserApplication' },
                           @{ Sid  = 'RID-500';         Role = 'RotateOnly'; Credential = 'AppUserBuiltinAdmin' } )   # first match wins
           Services = 'Auto'; ScheduledTasks = 'Auto'; ComPlus = 'Auto'; IisReport = 'Auto' }   # no restarts (D17)
        @{ Id = 'AutoLogon';  Kind = 'Windows'; Role = 'User'; Credential = 'AutoLogon'
           Names = @('PUB-User','WinAutoUser')                                   # every existing one is rotated
           AutoLogonUser = @( @{ Name = 'PUB-User'; RequireEnabled = $true }, @{ Name = 'WinAutoUser' } )   # first match
           AutoLogon = @{ Mode = 'IfAlreadyOn'                                   # D18, §7.5
                          RestrictedComputerPattern = '^SM' } }                  # SM machines: no admin/other auto-logon
        @{ Id = 'WinUsers';   Kind = 'Windows'; Names = @('WinUser1','WinUser2','WinUser3'); Role = 'WinUser'; Mode = 'Check' }
        @{ Id = 'FtpUsers';   Kind = 'Windows'; NamePattern = '(?i)^ftp|ftp$'; Role = 'Ftp'; Mode = 'Check' }
        @{ Id = 'SqlApp';     Kind = 'SqlLogin'; Name = 'SQLApplication'; ServerRoles = @('sysadmin'); Credential = 'SQLApplication'; LoginsEntry = $true }
        @{ Id = 'SqlScript';  Kind = 'SqlLogin'; Name = 'SQLScript';      ServerRoles = @('sysadmin'); Credential = 'SQLScript';      LoginsEntry = $true }
        @{ Id = 'SqlService'; Kind = 'SqlLogin'; Name = 'SQLService';     ServerRoles = @('sysadmin'); Credential = 'SQLService';     LoginsEntry = $true }
    )
}
```

**Validation** (fatal):
- unknown keys, roles or slots
- every `Credential` (including those of candidates) must refer to an existing slot
- invalid SIDs
- duplicate `Order` or `Id`
- a regex that doesn't compile. Regexes are compiled with `IgnoreCase`.
- `Pattern:` outside `AllowedExtraGroups`

**Runtime resolution:** all selection rules are resolved to SIDs first.
- A duplicate SID across entries is an ambiguity (D13).
- Explicitly named accounts are excluded from `NamePattern`.

## 6. Run flow (`-Apply`; audit stops after step 5)

1. **Load and validate config.** Display file hashes (§3).
2. **Preflight** (read-only). Machine-wide failures abort; everything else blocks only the affected slots.
   - Windows 7 SP1 (incl. Embedded Standard 7) or 10, x64, PS version, language mode, `Add-Type` works.
   - **Write filter (D19):** EWF, FBWF and UWF state for the current and the next session, pending commits, and the protected volumes. A protected system volume blocks all of `-Apply` (machine-wide preflight failure, exit 2; audit continues). A protected volume holding SQL `master` data or log files blocks the SQL slots.
   - **Local password and lockout policy** via `NetUserModalsGet`, plus **complexity** from `secedit /export /areas SECURITYPOLICY` (`NetUserModalsGet` doesn't return it), cross-checked with the per-user ADSI properties `MaxBadPasswordsAllowed`, `MinPasswordAge`, `AutoUnlockInterval` and `LockoutObservationInterval`. Reading the computer object returns nothing; this was observed on all test machines. The values are shown and **deviations between machines are expected**. Test sites, SM / IPT01:
     - QS-K1: length 6/8, complexity off/on, history 0/24, minimum age 0/1 day, threshold 4/10, duration 5/15 min
     - 102575: length 6/7, complexity off/on, history 5/5, minimum age 0/1 day, threshold 4/4, duration 3/3 min
     - Nothing is changed.
   - Per account: `PasswordAge` vs `MinPasswordAge`, `BadPasswordAttempts`, locked state, **effective logon rights** (D16).
   - **SQL:**
     - the default instance is running
     - its version is **9.x–14.x** (2005–2017); others block the SQL slots
     - integrated sysadmin as the operator
     - `IsIntegratedSecurityOnly = 0`
     - per login: `CHECK_POLICY`, `CHECK_EXPIRATION`, `IsLocked`
     - other instances are reported and ignored
   - **COM+:** the catalog is reachable. **IIS** (if installed): read-only discovery.
   - A domain-joined machine is reported as a warning.
3. **Resolve accounts**, including the SID-overlap check. Ambiguities go to the operator.
4. **Discovery.** Collects:
   - account state and groups
   - services, password-stored tasks and COM+ applications per account SID
   - IIS identities and DCOM `RunAs` (report)
   - auto-logon variant and the D18 action (§7.5)
   - SQL logins, `sysadmin`, Agent/linked logins and job owners (report)
5. **Plan.** Per slot:
   - changes, and the services/COM+ applications that will be "restart pending" (D17)
   - **high-impact items:**
     - reset instead of change
     - a blocked slot (incl. D19)
     - **SQL Server running as a rotated account** (it starts with the new password at its next start)
     - "application keeps using the old password until LOGINS is updated"
     - IIS identities to update manually
     - **auto-logon turned off or switched to another user** (D18). It takes effect at the next reboot. After a switch, the console session runs as a standard user, so startup programs and per-user settings of the previous account no longer apply.
     - group removals. For FTP users leaving Users, two more checks are listed:
       - the effective Network logon right **without** Users (Rights.ps1; e.g. `IPT01-QS-K1` grants network logon only to Administrators and Remote Desktop Users)
       - permissions on the FTP virtual-directory roots that are granted **only** through Users (read-only check)

   Then the enforcement phase. Audit mode exits with code 0 (no drift) or 10 (drift).
6. **Prompt:**
   - Per slot (only the resolved `AppUser*` variant): the new password twice (compared on BSTRs).
   - Windows slots: the old password, **separately per account** of the slot (the auto-logon slot may have `PUB-User` and `WinAutoUser`, whose current passwords differ, confirmed), with a "same as previous? Y/N" shortcut. The prompt names each resolved account.
   - **Checks** for each new password:
     - the site rules (D15)
     - the local OS policy (`NetValidatePasswordPolicy`)
     - `MaxLength` 128 for SQL
     - the complexity emulation from D15 (name/full-name tokens, character categories)
   - A notice reminds the operator that machines with password history (24 on `IPT01-QS-K1`, 5 on both machines of 102575) reject previously used passwords, and the tool can't check this in advance. **Site passwords must never have been used before.**
   - An empty entry skips the slot after confirmation.
   - **Re-apply mode (D20):** if an account's new password equals its entered old password (BSTR comparison, no plaintext), the plan marks that account "re-apply: password unchanged".
7. **Credential probe** for Windows accounts (D12, D16):
   - **Logon type:** the first type the account is allowed (granted directly or via one of its groups, and not denied), in the order Network → Interactive → Batch → Service. Examples from the test sites:
     - `BiCA Remote` → Network (denied local logon, and batch/service on IPT01)
     - `ApplicationUser` → Network
     - `PUB-User` on `IPT01-QS-K1` → Interactive (network logon is only granted to Administrators and Remote Desktop Users there)
   - **Order:**
     - If the run journal (§7.10) shows an unfinished earlier run that completed this account's password step, test the **new** password first.
     - Otherwise test the **old** password first. A successful logon resets the counter.
     - Only if the first test fails, test the other.
     - Normally at most one failure; at most two, always bounded by D12.
   - **Outcomes:**
     - old password works → change path
     - new password works → **already on the new secret** (D11)
     - re-apply (D20): the old password works, and it equals the new one → treated as **already on the new secret**; no password change
     - both fail → the operator may re-enter the old password within the budget, or choose reset (DPAPI warning) or skip
   - **Locked accounts:** no probe. Unlock after `YES`, then validate the old password once (apply step 1). If unlocking doesn't reset the counter (spike item 2) and the budget forbids the attempt, the operator chooses: wait, reset, or skip.
   - **Minimum password age** (1 day on both IPT01 machines): if `PasswordAge < MinPasswordAge`, `ChangePassword` is impossible. The plan shows "reset instead of change (DPAPI impact)" or "skip"; the operator decides.
   - Each account is probed with **its own** old password.
   - **SQL logins:** no probe. On a re-run, `ALTER LOGIN` is skipped when the journal records that login's password step in the unfinished run and `LOGINPROPERTY(name,'PasswordLastSetTime')` is at or after that time. This avoids a history rejection (spike item 13) without any logon attempt.
8. **Confirm:** show the final plan; the operator types `YES`.
9. **Apply** slots in ascending `Order` (§8).
10. **Enforcement phase** (§8).
11. **Report:**
    - console table, local log and CSV
    - per managed account, a "locked: yes/no" line
    - the **FOLLOW-UP REQUIRED** section: `LOGINS` entries and IIS identities
    - **Exit codes:**
      - 0 = OK, nothing outstanding
      - 4 = applied, follow-up required (the normal result of a full rotation)
      - 1 = partial failure
      - 2 = preflight failed
      - 3 = aborted
      - 10 = drift (audit)

## 7. Component design

### 7.1 Accounts (`Accounts.ps1`)
- ADSI `WinNT://<computer>/<name>,user`. The built-in Administrator is resolved via the machine SID + `-500`; it is renamed on `SM-QS-K1` (`WIN-Admin`).
- **Change vs reset:**
  - **change** (`ChangePassword(old, new)`): the old password was validated (probe or apply step 1), the minimum age allows it, and the account is enabled
  - **reset** (`SetPassword`): otherwise, with a DPAPI warning. On both test sites, `BiCA Admin`, `BiCA Remote` and `ApplicationUser` have DPAPI master keys, up to 34 key files on 102575; `PUB-User` has them on `IPT01-QS-K1`.
- **CCP:** cleared just before `ChangePassword` and re-set immediately after; this is recorded in the run journal. `RotateOnly` keeps its flags; CCP is only cleared temporarily if it is set. None of the managed accounts on the test sites has CCP set today.
- **PR (password required):** `UF_PASSWD_NOTREQD` (0x20) is cleared in step 4 (grants) of every rotated account, after its new password is set. `RotateOnly` keeps its flags, e.g. the built-in Administrator on 102575 keeps the flag.
- **Unlocking:**
  - `$user.psbase.InvokeSet('IsAccountLocked', $false)` + `CommitChanges()`; the fallback is clearing `UF_LOCKOUT` (0x10)
  - the lock state is re-checked immediately before `ChangePassword` and before verification
  - an account that relocks within seconds is reported and the slot stops
- **Check mode** (`WinUser1–3`, FTP users):
  - PNE, CCP and groups are fixed
  - enabled and locked state is reported only (`WinUser3` is disabled on SM)
  - the password is never touched

### 7.2 Groups (`Groups.ps1`)
- Target groups are added if missing. `Name:…?` groups are added if they exist. For `BiCA Remote` this means `Offer Remote Assistance Helpers`, which exists on both QS-K1 machines and on neither 102575 machine. On QS-K1 `BiCA Admin` is also a member; exclusivity **removes it** (confirmed: Administrators only).
- **Exclusive groups:** the account is removed from every other local group **except** those matching `AllowedExtraGroups`. Allowed groups are kept but never added:
  - `WinUser1–3`: `Remote Desktop Users` and all `hw_fn_*` USB-device groups (created by USB-Blocker PLUS)
  - `BiCA Remote`: `Remote Desktop Users` (a member on both 102575 machines)
  - FTP users: none, so they leave `Users` (confirmed)
- **Membership by SID via `netapi32` (D5):**
  - all local groups are enumerated, and `NetLocalGroupGetMembers` level 0 builds a SID → groups map
  - changes use `NetLocalGroupAddMembers`/`NetLocalGroupDelMembers` level 0, with the member's SID
  - names are never parsed, so localized group names and old computer names don't matter
  - Background: ADSI `Groups()` worked on all four test machines. ADSI `Members()` returned the right number of members on Windows Embedded Standard 7, but no name or SID for any local account, so the rails couldn't be checked. Spike item 8.
- **`CardCenters` missing:** reported; groups left unchanged. **`RotateOnly`:** no group changes.
- **Rails:**
  - `BiCA Remote`, the running account, and process-token groups are never removed from Administrators
  - Administrators always keeps at least one enabled member that is the running account or was verified in this run
- Removals run in the enforcement phase (§8).

### 7.3 Logon rights (`Rights.ps1`)
- **Effective rights** per account: `LsaEnumerateAccountsWithUserRight` for each logon right and deny right, matched against the account SID and its token SIDs.
  - The token SIDs are:
    - the local groups, including groups that contain well-known SIDs, e.g. Authenticated Users in Remote Desktop Users
    - `Everyone` (S-1-1-0), `Authenticated Users` (S-1-5-11), `Users`
    - `Local account` (S-1-5-113); for admins also S-1-5-114
    - the logon-type SID of the evaluated type: `NETWORK` S-1-5-2, `INTERACTIVE` S-1-5-4, `BATCH` S-1-5-3, `SERVICE` S-1-5-6, `LOCAL` S-1-2-0
  - `ForceGuest = 1` is read and reported, because network logons are then mapped to Guest.
  - These rights are used for D16 and are reported.
- **Grants** only what discovered dependents need: `SeServiceLogonRight` for accounts running services, `SeBatchLogonRight` for password-stored tasks.
  - On both SM machines `ApplicationUser` already holds both. On `IPT01-102575` it runs SQL Server and holds `SeServiceLogonRight`; on `IPT01-QS-K1` it runs nothing.
  - If a needed right is **denied** to the account, the conflict is reported and the rotation continues. The dependent already can't log on today, so blocking would protect nothing.
- Deny rights and other rights are never modified.

### 7.4 Services and scheduled tasks (`Services.ps1`, `Tasks.ps1`)
- **Services:**
  - discovered when the normalized `StartName` resolves to the account SID
  - updated via `Win32_Service.Change(…StartName, StartPassword…)`
  - **never restarted (D17).** Report state: `SCM updated – restart pending`. The account's new password is verified with `LogonUser` (service logon type if allowed, D16).
  - a dependency-aware restart helper isn't needed in v1
  - **`ApplicationUser` runs:**
    - on `SM-QS-K1`: `MSSQLSERVER` with its dependents `SQLSERVERAGENT` and `SmashRetailService`; `BiCA.Smash.Business.Voucher.Server`, `BiCA.Smash.Services.Voucher.Server`; `BootABMS` (srvany); `Eaton IntelligentPowerManager`
    - on `SM-102575`: the same without the voucher services (they run as LocalSystem there), plus `ReportServer` (SSRS 2008 R2, disabled)
    - on `IPT01-102575`: `MSSQLSERVER` (Express; the Agent is disabled and runs as NetworkService)
    - Because of D17, rotating it does **not** restart SQL Server or the retail application. The plan shows "restart pending" for all of them; the new password takes effect at the next service start. If a service crashes or the machine reboots before then, it starts with the new password, which is correct.
- **Tasks:**
  - `Schedule.Service` COM, `GetTasks(1)`, `LogonType` 1 or 6, `UserId` resolved to SID
  - re-registered with `TASK_UPDATE` and the existing SDDL
  - `ApplicationUser` tasks: 7 on `SM-QS-K1` (6 × LogonType 1, `SIMServer` LogonType 6), 6 on `SM-102575` (5 × LogonType 1, `SIMServer` LogonType 6), none on the IPT01 machines

### 7.5 Auto-logon policy (`AutoLogon.ps1`)

**Requirement (D18, confirmed):**
- Auto-logon only ever runs as `PUB-User` or `WinAutoUser`, **never as an admin**.
  - A **usable** account exists, is enabled, isn't locked, is allowed interactive logon (D16), and isn't an admin.
  - The **selected user** is `PUB-User` if usable, otherwise `WinAutoUser` if usable. A `WinAutoUser` auto-logon on a non-SM machine with a usable `PUB-User` is **switched to `PUB-User`** (confirmed).
  - "Admin" means a member of Administrators (S-1-5-32-544), checked by SID (D5). The built-in Administrator counts.
- **Auto-logon that is off stays off.** The tool never turns it on.
- **SM machines** (computer name matches `RestrictedComputerPattern`, default `^SM`, case-insensitive):
  - auto-logon as `PUB-User` or `WinAutoUser` is kept as it is; there's no switch between the two
  - any other account is turned off
- **Other machines:** auto-logon as anything other than the selected user is switched to the selected user.
- The auto-logon password is used only for auto-logon (confirmed). `PUB-User` and `WinAutoUser` are both rotated with the auto-logon slot password, so a switch needs no extra prompt.

**Detection** (Winlogon key plus inventory-defined mechanisms):
- `AutoAdminLogon` is accepted as REG_SZ or REG_DWORD.
- The current account is `DefaultUserName`, resolved to a SID; an empty domain means this computer.
  - These are standalone workgroup machines, so the name is always resolved against the local accounts.
  - A `DefaultDomainName` that differs from the computer name is reported as a mismatch. Example: `SM-QS-K1` holds the old name `SM-105002`.

| Current state | SM machine | Other machine |
|---|---|---|
| Off: `AutoAdminLogon` missing or `"0"`, no other mechanism | leave off | leave off |
| On as `PUB-User` or `WinAutoUser` | **keep** the user, standardize | selected user: **standardize**; the other one: **switch** |
| On as an admin (e.g. `BiCA Admin`) | **turn off** | **switch** |
| On as any other account (e.g. `WinUser1`) | **turn off** | **switch** |
| **Ambiguous** (any of the following) | ask the operator (D13): turn off or leave unchanged | same |

The ambiguous cases are:
- a non-Winlogon mechanism
- an account that can't be resolved
- `AutoLogonCount` present (a count-limited auto-logon)
- **no usable target** for a switch, or a kept/standardized account that isn't usable. Example: `WinAutoUser` is denied local logon on both SM machines.
- `PUB-User`/`WinAutoUser` is itself an admin, and its slot (whose group step would remove that) didn't complete in this run

**Password source, per target account:**
- **When it's written:** the step writes a password only for a target account that was **verified on the new secret in this run**, whether it was changed or already on it (D11). This applies even when the slot's other account failed.
- **Current account unchanged in this run:** the stored password is still valid, so standardize changes nothing. A plain-text `DefaultPassword` is reported.
- **Switch impossible** (the target isn't verified on the new secret: slot skipped, failed, or not selected under `-Only`): the operator chooses (D13): turn off, or leave unchanged. A third option, **standardize the current account**, is offered if the current account is `PUB-User` or `WinAutoUser`, is usable and is verified on the new secret. Example: `PUB-User` failed, `WinAutoUser` succeeded.
- **Current account changed, but the step can't run** (abort, operator chose "leave unchanged"): a high-impact item says **"auto-logon broken until re-run"**. A stale auto-logon costs one failed logon per boot; the lockout threshold is 4 on 102575.

**When:**
- The auto-logon step runs after all slots and **after** the group removals of the enforcement phase (§8). Admin status is therefore judged after this run's removals, e.g. an admin `PUB-User` whose slot completed is no longer an admin when the step runs.
- Under `-Only` it runs when the auto-logon slot, or the slot of the current auto-logon account, is selected.
- After an abort (exit 3) that follows completed slots, the step is still offered for those slots. If it's declined, it's reported as outstanding.

**Actions,** in a crash-safe order:
- **Standardize** (same user) and **switch** (new user):
  1. the password is stored as the LSA secret `DefaultPassword` (write only)
  2. the plain-text `DefaultPassword` and `AutoLogonCount` are deleted
  3. `DefaultUserName` = the target user; `DefaultDomainName` = the current computer name. `AutoLogonSID` is left unchanged when standardizing; on a switch it is updated or deleted, depending on spike item 11.
  4. `AutoAdminLogon` = REG_SZ `"1"`
- **Turn off:**
  1. `AutoAdminLogon` = REG_SZ `"0"`
  2. the plain-text `DefaultPassword`, the LSA secret `DefaultPassword` and `AutoLogonCount` are deleted. Deleting a secret that doesn't exist (`STATUS_OBJECT_NAME_NOT_FOUND`) counts as success.
  3. `DefaultUserName` is left as it is; it is only the last-user display
- A plain-text `DefaultPassword` while auto-logon is off is reported, not changed.

**Audit:** the LSA secret is never read. "Standardized" means all of these readable values match:
- `AutoAdminLogon` = REG_SZ `"1"`
- `DefaultUserName` = the target account
- `DefaultDomainName` = the computer name
- no plain-text `DefaultPassword`
- no `AutoLogonCount`

The secret is rewritten only under the "password source" rule above, so a standardized machine shows no drift.

**Test sites:**

| Machine | Today | D18 action |
|---|---|---|
| `IPT01-QS-K1` | on as `PUB-User`, LSA secret, `AutoLogonSID` set | standardize |
| `SM-QS-K1` | off; `DefaultUserName = WinUser1`, old computer name `SM-105002` in `DefaultDomainName` | leave off; mismatch reported |
| `SM-102575` | on as `BiCA Admin`, **plain-text password in the registry** | turn off |
| `IPT01-102575` | on as `BiCA Admin` (written `Bica Admin`), **plain-text password in the registry** | switch to `WinAutoUser`. `PUB-User` doesn't exist there. `WinAutoUser` may log on locally there; it's only denied RDP. |

No machine shows Sysinternals Autologon traces, a shell replacement, or an auto-logon tool in its Run entries or installed software.

**Consequences, shown before `YES`:**
- After a switch, the console session runs as a standard user. `BiCA Admin`'s startup programs and per-user settings no longer apply, e.g. the POS and touch software on `IPT01-102575`.
- After turning it off, the machine waits at the logon screen after a reboot.
- Test site 102575 is where both are tried first.

**Reported:**
- legal notice settings: a policy legal-notice **text** without a caption is set on `IPT01-QS-K1` and both 102575 machines, and auto-logon works there; reported, not blocking
- `DevicePasswordLessBuildVersion = 2`, `ForceAutoLogon`, a `DefaultDomainName` mismatch

Everything takes effect at the next logon. The tool never reboots. The auto-logon policy is built in M2 together with the rotation, so no apply on a test site leaves a rotated admin auto-logon behind; reboot verification on every OS/language is M4.

### 7.6 IIS (`IisReport.ps1`) — report only
- Read-only discovery via `Microsoft.Web.Administration`, which loads on all test machines with IIS, in PS 5.1 and PS 2.0. It covers application pools with `SpecificUser` identity and "connect as" credentials whose user name resolves to a rotated account.
- Matches are reported as **FOLLOW-UP REQUIRED** (manual update in IIS Manager) and count towards exit code 4. Nothing is written.
- Test sites:
  - `SM-QS-K1`: IIS 10 with built-in pool identities only, plus the FTP site `FTP_CardCenters` (Windows authentication, no stored credentials)
  - both 102575 machines: IIS 7.5 with built-in pool identities only. `SM-102575` also has `FTP_CardCenters`, with 5 virtual directories on `D:`/`E:` and no stored credentials.
  - `IPT01-QS-K1`: no IIS

### 7.7 COM+ applications (`ComPlus.ps1`)
- **Discovery:** server applications only; `Identity` normalized like `StartName`; built-in tokens excluded by string. Both SM machines have **`SIM Manager +`** (server, running) with identity `ApplicationUser`; the format is a plain account name.
- **Update:** `Value('Password')` via the adapter, then `SaveChanges()`.
- **Restart:** none (D17). Report state "committed – restart pending"; the next activation logs on with the new password.
- **DCOM `RunAs`:** report only, from both `HKCR\AppID` views (none on either test site).

### 7.8 `LOGINS` follow-up report (`LoginsReport.ps1`)
- `HKLM\SOFTWARE\BICA\SYSTEM\LOGINS` holds credentials for `BiCA Admin`, `BiCA Remote`, `ApplicationUser`/`Administrator`, `SQLApplication`, `SQLScript` and `SQLService`.
- Registry handling is **out of scope** (confirmed). The tool does not read or write the key.
- Per rotated account with `LoginsEntry`:
  - a high-impact item in the plan before `YES`
  - a **FOLLOW-UP REQUIRED** entry, with exit code 4
- The update is done later, by someone else. Possible local lockouts by the application retrying stale credentials are an accepted risk.

### 7.9 SQL Server 2005 – 2017 (`Sql.ps1`)
- **Connection:** default instance, `Data Source=.`, `Pooling=false`, integrated auth. The connection object is created without arguments, and `.ConnectionString` is set in the adapter. On all test machines `BiCA Remote` and `BiCA Admin` are `sysadmin` via their Windows logins; `ApplicationUser` is too, except on `IPT01-102575`, where it has no login.
- **Dialect by major version:**

  | Version | Password | Roles |
  |---|---|---|
  | 9.x–10.x (2005–2008 R2) | `ALTER LOGIN … WITH PASSWORD` | `sp_addsrvrolemember` |
  | 11.x–14.x (2012–2017) | `ALTER LOGIN … WITH PASSWORD` | `ALTER SERVER ROLE … ADD MEMBER` |

- **Rotation:**
  - `ALTER LOGIN [<name>] WITH PASSWORD = N'…'`, with `UNLOCK` appended when `LOGINPROPERTY(name,'IsLocked') = 1`
  - plain batch text; the name is bracket-quoted, the password literal has `'` doubled, maximum 128 characters
  - all three logins have `CHECK_POLICY = ON` on both test sites, so SQL enforces the machine's Windows policy (complexity on both IPT01 machines); D15 covers this
- **Role:** `sysadmin` ensured (D14). No removals. `CHECK_POLICY`/`CHECK_EXPIRATION`/enabled state are reported per login.
- **Principals:** SQL logins are resolved by name. Windows logins are resolved by **SID**, because on both test sites their names still carry old computer names (`DESKTOP-…`, `WIN-…`). Stale names are reported as information only. A `BUILTIN\Users` login (`IPT01-102575`, not `sysadmin`) is reported as information.
- **Verify:** a new non-pooled SQL-auth connection + `IS_SRVROLEMEMBER('sysadmin')`. `BadPasswordCount` is re-read first.
- **Report:**
  - Agent credentials, proxies, linked logins
  - **job owners**: `SQLService` owns 7 Agent jobs on `SM-QS-K1` and 8 on `SM-102575`; ownership doesn't depend on the password
  - the Agent service account (both SM machines: `ApplicationUser`)
  - Express edition = no Agent (both IPT01 machines)

### 7.10 Logging and run journal (`Log.ps1`)
- Local only: `%ProgramData%\CredentialRotation\logs\` (ACL by SID: Administrators/SYSTEM), log file + CSV.
- If `%ProgramData%\CredentialRotation` already exists with a non-admin owner or with write access for non-admins, the tool takes ownership (Administrators) and sets a protected ACL before it reads the journal. A standard user can create that folder in advance, and an edited journal would change the probe order (D12). **If the owner or the ACL had to be corrected, the existing journal is ignored and reported.** The probe then tests the old password first, which is the default and stays within the lockout budget.
- No secrets or hashes of secrets.
- **Run journal:** per run ID, records per account (keyed by SID) the steps completed, including a CCP flag temporarily cleared, and whether the run finished. The probe order only considers runs that did not finish.

## 8. Sequencing, verification, enforcement, failure handling

**Slot order:**
1. `BiCA Admin`
2. application user (whichever variant resolved; no restarts, D17)
3. auto-logon users
4. `SQLApplication`
5. `SQLScript`
6. `SQLService`
7. **`BiCA Remote` last**

`BiCA Admin` first serves the Administrators rail: a second enabled admin is verified early. It is not a reconnect path, because `BiCA Admin` is denied RDP logon on three of the four test machines (both SM machines and `IPT01-102575`). The operator's own account goes last. The RDP session survives the change; the tool reminds the operator to update saved RDP credentials.

**Steps within a slot:**

```
1  pre-steps    unlock if locked (+ single old-password validation if probe was deferred) / clear CCP (change path);
                recorded; undone on failure before step 2
2  secret       skip if "already on new secret" (incl. re-apply, D20); lock state re-checked; ChangePassword/SetPassword for every
                account of the slot, or ALTER LOGIN (+UNLOCK); test each new secret immediately
                (logon type per D16), budget re-checked first
3  dependents   SCM -> tasks -> COM+   (auto-logon is a separate step after all slots, §7.5)
4  grants       target groups added (incl. '?' groups that exist), PNE/CCP set, NOTREQD cleared (PR),
                required rights, sysadmin ensured
5  restart      none (D17): services and COM+ applications are reported as "restart pending"
6  verify       per account and dependent; LOGINS / IIS follow-ups recorded
```

The auto-logon slot may contain two accounts (`PUB-User`, `WinAutoUser`), each with its own validated old password. Both are rotated in step 2. If the second one fails after the first succeeded, the slot stops with an exact updated/pending report, as for any other failure.

**Verification:** `LogonUser` with the logon type chosen per D16. 1385 counts as "password valid" if spike item 2 confirms it.

**Enforcement phase**, after all slots, in this order:
1. exclusive-group removals for completed slots (respecting allow-lists)
2. the **auto-logon step** (D18, §7.5): standardize, switch or turn off. It judges admin status after step 1, and uses the auto-logon slot's new password, which is held only in memory.
3. check-mode fixes (`WinUser1–3`, FTP users), part of the `YES` run

- Under `-Only`, only selected slots; the auto-logon step as described in §7.5; check-mode accounts only without `-Only`.
- Rails apply.
- After a crash between the auto-logon slot and the auto-logon step, a re-run with the same passwords finds the slot already on the new secret (D11) and then runs the step.

**Failure handling** (no automatic revert):
- **Failure before step 2:** pre-steps are undone; the slot is skipped.
- **Failure at or after step 2:** the slot stops. The report shows what is on the new secret and what is pending. The tool offers a retry of the pending steps.
- **Crash or abort:** re-run with the same passwords. The run journal, the probe order and D11 complete it.
- **Slots are independent.** Secrets are never printed or stored.

**Per-site consistency:** a skipped, failed or mistyped machine diverges from its site. Mitigations:
- D15 site rules, so no machine rejects a password another accepted
- the "never used before" notice (history)
- double entry
- the per-machine report
- a re-run with the correct site password

## 9. Security requirements

- **Plaintext lifetime is minimized:**
  - plaintext exists only in `Adapters.ps1`, cleared after use
  - LSA and `NetValidatePasswordPolicy` calls receive unmanaged buffers
  - prompt comparison happens on BSTRs
- **D4 lint rules:**
  - no `Invoke-Expression`
  - `$plain*` variables only in `Adapters.ps1`
  - no plaintext as a cmdlet or function argument, or in output
  - no external executables called with secrets
- **Accepted risks (user-confirmed):**
  - no code signing (mitigations: controlled source, published hashes, logged hashes)
  - **the tool runs from `C:\temp` without protecting its folder**; a local user with write access there could tamper with it before an admin runs it
  - shared site passwords (lateral movement)
  - `LOGINS` entries stay on old passwords until updated by someone else
- **Plain-text auto-logon passwords:** both 102575 machines store `BiCA Admin`'s password in plain text in the Winlogon key, which local users can read. D18 removes it, by turning auto-logon off or switching it, and the rotation makes the exposed password worthless.
- **AV/EDR:** none in the field. QS-K1's Windows 10 shows the Defender systray in Run entries; to be confirmed during M6 that it doesn't interfere.
- **Canary test:** canary values for the new and the old password, with Module Logging, Script Block Logging and Transcription enabled through local policy. Then search the PowerShell logs, transcripts, Security log, `%TEMP%`, the tool's logs and SQL traces.

## 10. Compatibility

| Target | PowerShell | Notes |
|---|---|---|
| Windows 7 SP1 x64 | 2.0 (default), up to 5.1 with WMF | test site 102575: **Windows Embedded Standard 7 SP1** with WMF 5.1 (PS 5.1.14409), PS 2.0 engine (CLR 2.0.50727) and .NET 4.6.2/4.8 installed, `FullLanguage` |
| Windows 10 x64 | 5.0/5.1 | test site QS-K1: **LTSC 2019 (build 17763)**, PS 2.0 engine + .NET 3.5 installed, `FullLanguage` |

- **OS languages:** EN/FR/DE/IT. Test machines: EN OS, with DE MUI (`SM-QS-K1`), with DE/FR/IT MUI and a de-DE UI (`SM-102575`), or EN only (both IPT01). All use de-CH formats. Built-in principals are referenced by SID.
- **PS 2.0:** lint for syntax; semantics via tests on a real PS 2.0 engine once a host exists (O3), meanwhile `/PS2` audits on the test sites. `Add-Type` compiles C# 2.0 by default on PS 2.0; C# 3.0 needs `-Language CSharpVersion3`. `System.Core` is loaded explicitly.
- **PS 2.0 on the test machines:** SHA-256 CSP, Task Scheduler COM, COMAdmin COM, IIS MWA and SqlClient load on both sites. Whether `Add-Type` compiles is still unknown: all four inventories ran with script v1.0, whose bug drops that result (fixed since v1.1).
- **Windows Embedded:** possible write filters (D19); ADSI `Members()` doesn't return local members (§7.2).
- **PS 2.0 engine on a machine with WMF 5.1 / Windows 10 (`/PS2` test runs):** `powershell.exe.config` contains a .NET 4 `<uri>` section that CLR 2.0 doesn't know. Every component that reads the configuration then fails; SqlClient does so when it starts ("Unknown configuration section 'uri'", seen on `SM-QS-K1`). The tool reports this and blocks the SQL slots. Real runs use PS 5.1 wherever it's installed, so this affects only `/PS2` test runs; SQL under PS 2.0 must therefore be tested on a Windows 7 with PS 2.0 only (O1), and the `/PS2` apply on test site 102575 (M2) doesn't cover SQL.

## 11. Testing

- **Lint (CI):** PSScriptAnalyzer plus `Test-Ps2Syntax.ps1`.
- **Unit (CI):** Pester 3.4.x.
  - **Target host:** a real PS 2.0 engine (Windows 10 LTSC 2019 or Windows 7 VM with .NET 3.5). The test bootstrap labels a run "PS 2.0" only if `$PSVersionTable.PSVersion.Major -eq 2` and the CLR is 2.0. On Windows 11 24H2 and later, `-Version 2` silently runs 5.1; this was observed on the dev machine.
  - **Until such a host exists (confirmed: none yet):**
    - unit tests run on PS 5.1 and are labelled as such
    - PS 2.0 coverage comes from the lint and from read-only audit runs on the test sites with the launcher's `/PS2` switch
    - the residual risk is listed in §14
  - Covers:
    - selection rules (incl. two auto-logon accounts), SID overlap, `AppUser*` slot choice, "not applicable" under `-Only`
    - candidate `Credential` validation
    - **D16 logon-type selection** from grant/deny sets (test-site rights as fixtures)
    - **D15 site rules** + local policy
    - probe order, locked accounts, minimum-age handling, lockout budget with thresholds 4 and 10
    - exclusive groups with **allow-lists** (`Pattern:^hw_fn_`, `Remote Desktop Users` for `BiCA Remote`), `?` semantics, rails, SID → groups map from `NetLocalGroupGetMembers` fixtures
    - the **D18 decision table**, with fixtures from all four test machines:
      - SM / other machine × off / `PUB-User` / `WinAutoUser` / admin / other account / ambiguous
      - usable-target rules; `AutoLogonCount`; REG_SZ vs REG_DWORD; a stale `DefaultDomainName`
      - an admin `PUB-User`
      - password source per target account, incl. an auto-logon slot where only one of two accounts succeeded
      - `-Only`, abort, and the write order
    - D19 decisions from write-filter states (current/next session, pending commit, unknown state)
    - the T-SQL builder for both dialects incl. `UNLOCK`
    - the `LOGINS`/IIS follow-up report and exit codes
- **Integration VMs** (all x64; none available yet, O3 — until then the test sites and `/PS2` cover what they can):
  - Windows 7 SP1 with PS 2.0 (DE, FR)
  - Windows 7 with WMF 5.1 (EN)
  - **Windows Embedded Standard 7 SP1** with WMF 5.1 (EN + DE/FR/IT MUI), with EWF and with FBWF enabled
  - Windows 10 LTSC 2019 (EN with DE MUI, IT), once with UWF enabled
  - SQL Server 2005, 2008 R2 (Express + Standard), 2012 and **2017 (Express + Standard)**, default instance
  - a COM+ server application, incl. one running as an NT service
  - launch from `C:\temp\CredentialRotation-<version>`
  - **policy profiles** from both test sites: QS-K1 SM (6 / no complexity / threshold 4), QS-K1 IPT01 (8 / complexity / history 24 / min age 1 / threshold 10), 102575 (6 or 7 / history 5 / threshold 4, 3 min)
  - **deny rights** as found on both test sites
- **Scenarios:**
  - `ApplicationUser` vs renamed built-in Administrator
  - `PUB-User` + `WinAutoUser` both present (both rotated)
  - 0, 1 and 3 FTP users, with and without `CardCenters`, incl. FTP users in CardCenters + Users (Users removed) while the FTP site keeps working, or the removal is listed as the cause
  - `WinUser` in `Remote Desktop Users` + `hw_fn_*` groups (kept) + another group (removed); `BiCA Remote` in `Remote Desktop Users` (kept)
  - `UF_PASSWD_NOTREQD` set on a rotated account (cleared) and on `RotateOnly` (kept)
  - auto-logon (D18), each checked after a reboot:
    - on as `PUB-User` (IPT01-QS-K1 style): standardize
    - off with a stale `DefaultUserName` (SM-QS-K1 style): leave off
    - on as `BiCA Admin` with a plain-text password, on an SM machine: turn off
    - the same on an IPT01 machine: switch to `WinAutoUser`
    - the auto-logon slot skipped while `BiCA Admin` is rotated: the operator chooses
  - **re-apply (D20)** on test site 102575 with `/PS2`: every Windows slot entered with its current password, SQL slots empty. Expected: no password changed (password age unchanged), dependents and auto-logon rewritten, groups/flags enforced, re-audit clean, no `LOGINS` follow-up
  - **`ApplicationUser` running SQL Server**: rotation leaves SQL running ("restart pending"); a later manual restart or reboot starts SQL, the Agent and the retail services with the new password
- **Failure injection:**
  - wrong old password with the counter at threshold−2
  - minimum age not reached
  - a reused password rejected by history
  - an account already locked or relocked
  - a service that won't start
  - SQL down after the application-user slot
  - kill-and-rerun
- **Canary test** (§9).

## 12. Milestones

| M | Content | Exit criterion |
|---|---|---|
| M0 | Inventory (**test sites QS-K1 and 102575 done** with v1.0, §13.2); **v1.3 on one Windows Embedded 7 and one Windows 10 machine** (`Add-Type` and netapi32 under PS 2.0, group members, write filter); further sites, esp. FR/IT and PS-2.0-only Windows 7; spike, schema freeze, VM matrix | inventory + spike results in `docs/`. The v1.3 results are the entry gate for the `Native.ps1` parts of M1; the rest of M1 can start before. |
| M1 | Launcher, config, principals, selection + SID overlap, **effective rights**, preflight (policy via `NetUserModalsGet`, write filter D19), discovery incl. the D18 decision, audit | correct audit on VMs and both test sites, incl. one `/PS2` audit per test machine |
| M2 | Prompting with **site rules**, probe + lockout budget + D16, run journal, adapters, rotation, check mode, groups with allow-lists and rails, **auto-logon policy (D18)**, verification, follow-up reports, exit codes | apply + re-audit clean; D9 confirmed; no apply leaves a rotated account in auto-logon; the first apply on test site 102575 is a **re-apply (D20)** with `/PS2` |
| M3 | Slot sequencing, services (incl. SQL Server as a dependent), tasks, COM+, IIS report, retry, idempotent re-run | after a reboot every dependent starts with the new password; kill-and-rerun passes |
| M4 | Auto-logon reboot verification | standardize, switch and turn off each behave as planned after a reboot, on every OS/language |
| M5 | SQL rotation 2005–2017 incl. `UNLOCK` | SQL slots rotate cleanly on 2008 R2 and 2017 |
| M6 | Canary test, full matrix | all green → v1 release |

**M0 spike** (status after the inventories of both test sites):
1. `ChangePassword` vs `SetPassword` and DPAPI, logged off and logged on; with `NetUserChangePassword` / `NetUserSetInfo` (levels 1003/1008) as the fallback if ADSI user objects misbehave on Windows Embedded 7 as its group members did. *Open (VM).*
2. `LogonUser` codes 1385/1331/1909; a successful logon resets the counter; unlocking via `InvokeSet` vs `UF_LOCKOUT`; whether unlocking resets `BadPasswordAttempts`. *Open (VM).*
3. `ChangePassword` prerequisites: CCP, locked, disabled, **minimum age**; the same for the netapi32 fallback. *Open (VM).*
4. `Win32_Service.Change` and `SeServiceLogonRight`. *Open (VM).*
5. `RegisterTaskDefinition` keeps the SDDL. *Open (VM).*
6. ~~`.cmd` from `\\tsclient` elevated~~ **Obsolete:** the tool is copied to `C:\temp` and run from there (confirmed).
7. `NetValidatePasswordPolicy` against the local policy. *Open (VM).*
8. **Group membership.**
   - ADSI `Groups()` works on all four test machines (EN/DE MUI).
   - ADSI `Members()` returned no name or SID for local-account members on Windows Embedded Standard 7 (PS 5.1); built-in principals resolved.
   - **Decision:** use `netapi32` by SID (D5).
   - *Open:* `NetLocalGroupGetMembers` under PS 2.0 and 5.1 on Windows 7 (inventory v1.3 probes both), and FR/IT.
   - `Offer Remote Assistance Helpers` keeps its English name where it exists.
9. ~~IIS write path~~ reduced to read-only discovery: MWA loads in PS 5.1 and PS 2.0. **Done.**
10. COM+ `Identity` format: a plain account name (`ApplicationUser`). **Done.** Password set + shutdown/start: *open (VM).*
11. Winlogon behaviour with the LSA secret and after a failed auto-logon; whether `AutoLogonSID` must match, be updated or be deleted on a **switch** (D18); which value wins when both a plain-text and an LSA-secret `DefaultPassword` exist; turning auto-logon off deletes both. *Open (VM).*
12. SQL `ALTER LOGIN … UNLOCK` on 2005–2017. *Open (VM).*
13. Does SQL Server enforce password history for `CHECK_POLICY = ON` logins (IPT01-QS-K1 profile: history 24)? *Open (VM).*
14. The `LogonUser` result per logon type under the test sites' deny rights, to confirm D16 and the 1385 semantics. *Open (VM).*
15. **New:** write-filter detection (D19). EWF and FBWF on Windows Embedded Standard 7 via `ewfapi`/`fbwflib` or the read-only `ewfmgr`/`fbwfmgr` output; UWF on Windows 10 via WMI `root\standardcimv2\embedded`. Current vs next session, pending commits, protected volumes, and exclusions. *Open:* inventory v1.3 detects them on the test sites; the VMs cover the enabled cases.

**Deferred:**
- automating `LOGINS` updates
- writing IIS credentials
- per-site orchestrator
- DCOM `RunAs` changes
- cleanup of other members
- event log entry
- code signing

## 13. Answers, inventory, open items

### 13.1 User answers (2026-10-06)

| Topic | Answer | Plan impact |
|---|---|---|
| Accounts | Local only; not domain-joined; pure standalone | No domain logic, no LAPS |
| Access | Local run over RDP only; operator = BiCA Remote (rotated). On real sites the session is always `BiCA Remote`; the console runs as `BiCA Admin` on the test SMs are not the model | D2; BiCA Remote last |
| Scope principle | The tool only cares about its local credentials | Cross-machine handling out of scope |
| Site | 2–3 machines; same passwords per site | §1.1 |
| Test sites | QS-K1 and **102575** are test sites | §13.2 |
| Distribution | Copied over RDP **to `C:\temp`** and run from there | §3 |
| Run folder | **No protection** of `C:\temp`; tampering risk accepted | §3, §9 |
| OS | Windows 7 SP1 / 10, all x64; EN/FR/DE/IT; XP dropped | §10 |
| App user | `ApplicationUser` first, otherwise built-in Administrator (rotate only); separate site passwords | Two `AppUser*` slots |
| Auto-logon | Auto-logon only, only where already on; `PUB-User` preferred if enabled, otherwise `WinAutoUser`; **both are rotated** with the auto-logon slot password | §1.1, §7.5 |
| Auto-logon user | **Only `PUB-User` or `WinAutoUser`, never an admin.** An admin auto-logon is changed. Other machines: an admin or any other account is switched to `PUB-User`/`WinAutoUser` | D18 |
| SM machines | Recognized by a computer name **starting with `SM`**. Generally no auto-logon there: **admin and any other account → turned off**; `PUB-User`/`WinAutoUser` kept | D18 |
| WinUser1–3 | Check + fix: Users, PNE, CCP; **keep `Remote Desktop Users` and `hw_fn_*`** | `WinUser` role allow-list |
| FTP | 0–3 users; check + fix: CardCenters only, PNE, CCP; missing CardCenters → report. **Removal from Users confirmed** (102575) | Check mode |
| `SP Admin` | **Leave untouched** | §1.1 |
| Fixes | Only with `-Apply`, part of the single `YES` | D7 |
| Rotated accounts | Each its own password; PNE, CCP, exclusive groups; **`UF_PASSWD_NOTREQD` cleared** (not for rotate-only) | D8, D10, §7.1 |
| BiCA Remote | `Offer Remote Assistance Helpers` added where it exists; **`Remote Desktop Users` kept if present** | `?` semantics, allow-list |
| Write filter | Unknown whether used → **detect**. System volume protected → **block all of `-Apply`**; a protected SQL `master` volume → block the SQL slots | D19 |
| `WinAutoUser` → `PUB-User` | Non-SM machine with a `WinAutoUser` auto-logon and a usable `PUB-User`: **switch to `PUB-User`** | D18 |
| PS 2.0 test host | **None available yet**; unit tests on PS 5.1 meanwhile, `/PS2` audits on the test sites | §11, O3 |
| Re-apply test | Before the first real rotation, re-apply the current passwords as a safe write test | D20, README step 2 |
| BiCA Admin | Administrators only; **removed** from `Offer Remote Assistance Helpers` | `Admin` role |
| Old passwords | Usually known | D9 |
| Password policy | Earlier answer "uniform" was **contradicted by the inventory** (§13.2). Decision: **strictest rule on every machine** | D15 |
| SQL | **2005–2017** must be supported; default instance; integrated sysadmin; `sa` not managed; all three `sysadmin` | §7.9 |
| IIS | **Detect + report only** | §7.6 |
| Registry `LOGINS` | Out of scope; report-only follow-up; local lockouts by the app = accepted risk | §7.8 |
| Restarts | **Never restart** SQL / app services / COM+ (supersedes "anytime with a prompt") | D17 |
| Auto-logon old passwords | `PUB-User` and `WinAutoUser` passwords differ | Old password asked per account |
| Reports / internet / signing / AV | Local only / offline / no signing / none | §3, §9 |

### 13.2 M0 inventories (script v1.0, 2026-10-06)

**Test site QS-K1**

| Fact | SM-QS-K1 | IPT01-QS-K1 |
|---|---|---|
| OS | Windows 10 Enterprise LTSC 2019 (17763), x64, EN + DE MUI | same, EN |
| PS / .NET | 5.1; PS 2.0 engine + .NET 3.5 present | same |
| Password policy | length 6, no complexity, history 0, min age 0, max age 180 | **length 8, complexity, history 24, min age 1 day**, max age 60 |
| Lockout | threshold 4, duration 5 min, window 5 min | threshold 10, duration 15 min, window 15 min |
| Built-in Administrator | renamed `WIN-Admin`, disabled | `Administrator`, disabled |
| Managed accounts present | all incl. `WinAutoUser` and `WinUser1–3` (`WinUser3` disabled) | `BiCA Admin`, `BiCA Remote`, `ApplicationUser`, `PUB-User` |
| Other enabled accounts | — | `SP Admin` (Administrators) |
| Deny rights | local logon: `BiCA Remote`, `ApplicationUser`, `WinAutoUser`; RDP: `BiCA Admin`, `ApplicationUser` | local logon: `BiCA Remote`, `ApplicationUser`; RDP: `ApplicationUser`; batch + service: `BiCA Remote` |
| `ApplicationUser` dependents | SQL Server + Agent, 5 app services, 7 tasks, COM+ `SIM Manager +` | none |
| Auto-logon | Off (stale `DefaultUserName = WinUser1`, old computer name) | On, `PUB-User`, LSA secret |
| IIS | IIS 10, built-in pool identities, FTP site `FTP_CardCenters` | not installed |
| SQL | 2017 Standard, default instance, runs as `ApplicationUser` | 2017 Express, default instance, `NT Service\MSSQLSERVER` |
| SQL logins | 3 managed logins, `CHECK_POLICY` on, `sysadmin`; `sa` disabled; Windows logins with old computer names | same |
| Groups | `CardCenters` (empty), `Offer Remote Assistance Helpers` (`BiCA Admin`, `BiCA Remote`), 7 × `hw_fn_*` | `Offer Remote Assistance Helpers` (`BiCA Admin`, `BiCA Remote`) |

**Test site 102575**

| Fact | SM-102575 | IPT01-102575 |
|---|---|---|
| OS | **Windows Embedded Standard 7 SP1** (7601), x64, EN + DE/FR/IT MUI, de-DE UI | same, EN only |
| PS / .NET | **WMF 5.1** (5.1.14409); PS 2.0 engine (CLR 2.0.50727); .NET 4.8 | same; .NET 4.6.2 |
| Password policy | length 6, no complexity, history 5, min age 0, max age 180 | length 7, **complexity**, history 5, **min age 1 day**, max age 180 |
| Lockout | threshold 4, duration 3 min, window 3 min | same |
| Built-in Administrator | `Administrator`, disabled, `UF_PASSWD_NOTREQD` | same |
| Managed accounts present | `BiCA Admin`, `BiCA Remote`, `ApplicationUser`, `WinAutoUser`, `WinUser1–3` (`WinUser3` disabled), FTP users `AG_FTP` + `LVSTG_FTP`; **no `PUB-User`** | `BiCA Admin`, `BiCA Remote`, `ApplicationUser`, `WinAutoUser`; no `PUB-User` |
| Other enabled accounts | `USBAdmin` (Administrators) | — |
| Password age `BiCA Admin` | 5300 days | 2140 days (old passwords may differ between machines of a site) |
| Deny rights | local logon: `BiCA Remote`, `ApplicationUser`, `WinAutoUser`, `AG_FTP`, `LVSTG_FTP`; RDP: `BiCA Admin`, `ApplicationUser`, `WinAutoUser`; service: `BiCA Remote`, `Administrator` | local logon: `BiCA Remote`, `ApplicationUser`; RDP: `BiCA Admin`, `WinAutoUser`, `ApplicationUser` |
| `ApplicationUser` dependents | SQL Server + Agent, `BootABMS`, Eaton IPM, `SmashRetailService`, SSRS (disabled), 6 tasks, COM+ `SIM Manager +` | **SQL Server** |
| Auto-logon | **On as `BiCA Admin`, plain-text `DefaultPassword`** → D18: turn off | **On as `BiCA Admin`, plain-text `DefaultPassword`** → D18: switch to `WinAutoUser` |
| IIS | IIS 7.5, built-in pool identities, FTP site `FTP_CardCenters` | IIS 7.5, built-in pool identities |
| SQL | **2008 R2 SP3** Standard, default instance, runs as `ApplicationUser` | **2008 R2 SP3** Express, default instance, runs as `ApplicationUser` |
| SQL logins | 3 managed logins, `CHECK_POLICY` on, `sysadmin`; `sa` disabled; Windows logins named `WIN-…`; 8 Agent jobs owned by `SQLService` | same without Agent jobs; plus a `BUILTIN\Users` login (not `sysadmin`) |
| Groups | `CardCenters` (`AG_FTP`, `LVSTG_FTP`, which are also in Users); 7 × `hw_fn_*`; `BiCA Remote` in Administrators + Remote Desktop Users; no `Offer Remote Assistance Helpers` | `BiCA Remote` in Administrators + Remote Desktop Users; no `CardCenters`, no `Offer Remote Assistance Helpers` |
| Group members via ADSI | **not readable** for local accounts (count only) | same |
| Inventory session | console logon as `BiCA Admin`, from `H:\scripts` | RDP as `BiCA Remote`, from `C:\temp` |
| Other software | pcAnywhere 12.5, USB-Blocker PLUS, Fujitsu SystemGuard, system backup tasks | pcAnywhere 12.5 |

### 13.3 Open items
- **O1** Inventory v1.3 on one Windows Embedded 7 machine (e.g. `SM-102575`) and one Windows 10 machine (e.g. `IPT01-QS-K1`): `Add-Type` and netapi32 under PS 2.0, group members, write filter. This is the entry gate for the `Native.ps1` parts of M1. Then further sites, especially FR/IT machines and a Windows 7 with PS 2.0 only.
- **O2** `LOGINS` automation (deferred by the user).
- **O3** A test host with a real PS 2.0 engine (Windows 10 LTSC 2019 or Windows 7 VM). None is available yet (user, 2026-10-06).
- ~~O4~~ `BiCA Admin` in `Offer Remote Assistance Helpers`: **remove it** (user, 2026-10-06).

## 14. Risks

| Risk | Mitigation |
|---|---|
| `BiCA Remote` locked by the tool | Lockout budget per machine (D12), logon type per D16, rotated last, live session persists, auto-unlock |
| Services of the application user keep running on the old logon until restarted | D17: no restarts by the tool; "restart pending" in the report; the new password applies at the next start (verified beforehand via `LogonUser`) |
| Site password rejected on one machine (complexity, length) | D15 strictest site rules checked on every machine |
| Site password rejected by history on one machine | "Never used before" notice; slot failure is reported precisely; operator chooses a new site password |
| Minimum password age blocks a change (both IPT01 machines) | Detected in the plan; operator chooses reset (DPAPI warning) or skip |
| App uses old passwords until `LOGINS` is updated; possible local lockouts | Shown before `YES`, FOLLOW-UP REQUIRED, exit code 4; accepted |
| Half-rotated local dependents | Slot as unit (D8), retry, run journal, idempotent re-run (D11) |
| Verification refused because of deny rights | D16 logon-type selection; spike item 14 |
| Exclusive groups remove a needed membership, e.g. FTP folder access granted through Users | Allow-lists (`WinUser`, `BiCA Remote`), `?` groups, admin rails, every removal listed before `YES`; FTP users leaving Users is a confirmed decision, tried first on test site 102575 |
| Group membership misread (ADSI on Windows Embedded Standard 7) | `netapi32` by SID (D5); spike item 8 |
| Auto-logon switched to a standard user breaks the console application (e.g. POS software on `IPT01-102575`) | Confirmed policy (D18); shown before `YES`; tried first on test site 102575; M4 reboot tests |
| Auto-logon turned off on an SM machine: the console session no longer starts by itself | Confirmed policy (D18); shown before `YES` |
| A write filter discards the changes at the next reboot | D19: detected in preflight; a protected system volume blocks all of `-Apply` |
| Third-party auto-logon breaks | Detection → ambiguous → operator decides; inventory (none found on either test site) |
| Same account selected twice | SID-overlap check |
| DPAPI data loss via reset | Change by default (D9) |
| Secret leakage | D4, adapter-only plaintext, lint, canary test |
| Tampered script (no signing, unprotected `C:\temp`) | Accepted; published hashes, logged hashes |
| A system image taken before the rotation is restored later (`SM-102575` runs daily/monthly system backups) and brings back old passwords | Out of the tool's scope; to be covered by the site procedure |
| PS 2.0 incompatibility | Lint; `/PS2` audit runs on the test sites; a real PS 2.0 test host once available (O3), until then unit tests on PS 5.1 only (confirmed) |
| Stale auto-logon after a partial run (one failed logon per boot, threshold 4 on 102575) | Password source per target account (§7.5); "auto-logon broken until re-run" as a high-impact item; the step is still offered after an abort |

---

## Appendix A — Review log

| Round | Version reviewed | Score | Concerns | Main themes |
|---|---|---|---|---|
| 1 | v1 | 6 | 1 Blocker, 9 Major, 8 Minor | shared slots, signature enforcement, logon types, module logging, PS 2.0 semantics, revert, wildcard instances |
| 2 | v2 | 8 | 5 Major, 11 Minor | reductions before verification, non-idempotent re-run, printed old password, SQL built-ins, registry readers |
| 3 | v3 | 8.5 | 8 Minor | reset end-state, unlock on reset, token groups, reduction scope, SQL lockout |
| 4 | v4 | 8.5 | 4 Major, 8 Minor | COM+ identity format, IIS verification, SQL credential order, default-instance data source |
| 5 | v5 | 8.5 | 4 Major, 6 Minor | third-party auto-logon, SID overlap, registry granularity, operator's remote-access group |
| 6 | v6 | 8 | 1 Major, 8 Minor | stale LOGINS causing lockouts, probe accounting, locked accounts, exit code |
| 7 | v7 | 8 | 2 Major, 8 Minor | site procedure, LOGINS convergence → resolved by scope decisions |
| 8 | v8 | 8.5 | 5 Minor | no Blocker/Major; minor fixes applied in v8.1 |
| 9 | v9 | 8 | 3 Major, 7 Minor | SQL restart before SQL slots, D15 weaker than Windows complexity, one old password for two accounts → resolved in v9.1 (D17 no restarts, complexity emulation, per-account old password, token-model SIDs, secedit for complexity, SQL re-run skip, auto-logon right check, deny conflicts reported only) |
| 10 | v9.2 | 7.5 | 4 Major, 6 Minor | D18 table gaps (no usable target, admin `PUB-User`, `AutoLogonCount`, REG_DWORD, stale domain), password source per account, D19 vs journal/enforcement, no real PS 2.0 in CI → resolved in v9.3 (usable-target rule, per-account password source, crash-safe write order, readable audit definition, all of `-Apply` blocked on a protected system volume, `master` data + log files, `/PS2` audits, D18 moved into M2, FTP network-right/ACL warnings, absolute launcher paths, log-folder ownership, v1.3 gate) |
| 11 | v9.3 | 8.5 | 4 Minor | removals vs auto-logon step order, standardize option when a switch fails, planted journal, `/PS2` only for audits → fixed in v9.3 (removals before the auto-logon step, third operator option, journal ignored after an ownership fix, `/PS2` for the first apply on 102575, PS 2.0 VMs marked pending) |

v9.2 was an inventory-driven update from test site 102575 (Windows Embedded Standard 7). Changes:
- D18 auto-logon policy
- D19 write-filter guard
- group membership via netapi32
- run from `C:\temp`
- the PR flag
- `Remote Desktop Users` kept for `BiCA Remote`
- FTP users removed from Users

v9 was an inventory-driven update. Changes:
- SQL 2005–2017 with two dialects
- D15 site password rules and D16 logon-type selection
- per-machine policy
- the `WinUser` allow-list
- both auto-logon accounts rotated
- IIS report-only
- `SP Admin` untouched
- SQL Windows logins by SID
- `ApplicationUser` running SQL Server
