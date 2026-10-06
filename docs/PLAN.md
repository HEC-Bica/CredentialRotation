# Credential Rotation Tool — Implementation Plan

Status: draft v8.1 · 2026-10-06.
- Eight rounds of independent review (Appendix A). The final round found no Blocker or Major issues: ready for M0.
- Every environment fact and policy decision comes from the user's answers (§13). Anything not yet known is listed as open, not assumed.

## 1. Goal and scope

A PowerShell tool run **locally** on standalone workgroup machines (Windows 7 SP1 x64, Windows 10 x64). The operator copies it over RDP and runs it while logged on as `BiCA Remote`. **The tool only cares about the local credentials of the machine it runs on.** The tool:

1. Rotates the passwords of **4 local Windows accounts and 3 SQL Server logins**. The operator enters each new password, and the old one for Windows accounts, when prompted.
2. Enforces the role of the rotated accounts. It also checks and fixes the settings of the non-rotated user and FTP accounts.
3. Updates everything on the machine that depends on the rotated passwords: services, scheduled tasks, IIS, COM+, and a **standardized auto-logon** that replaces today's inconsistent variants.
4. **Reports** which entries in the application's registry key `HKLM\SOFTWARE\BICA\SYSTEM\LOGINS` must be updated outside the tool.

### 1.1 Managed accounts

| Account | Selection rule | Action | Target state | LOGINS entry |
|---|---|---|---|---|
| `BiCA Admin` | by name | rotate | Administrators only · PNE · CCP | yes |
| `BiCA Remote` | by name; the operator's logon account | rotate, as the **last** slot (§8) | Administrators + `Offer Remote Assistance Helpers` (**added if the group exists**) only · PNE · CCP | yes |
| Application user | `ApplicationUser` if it exists, otherwise the **built-in Administrator** (RID 500; e.g. `Administrateur` on French Windows). **Separate site passwords** for the two variants | rotate, plus dependents: services, scheduled tasks, IIS, COM+ | `ApplicationUser`: Administrators only · PNE · CCP. **Built-in Administrator: rotate only** | yes (both) |
| Auto-logon user | `PUB-User` if it exists and is enabled, otherwise `WinAutoUser` | rotate, plus standardized auto-logon **if auto-logon is already on** (§7.5) | Users only · PNE · CCP | no |
| `WinUser1`, `WinUser2`, `WinUser3` | by name | **check + fix**, no password change | Users only · PNE · CCP | — |
| FTP users (0–3 per machine) | name starts or ends with `ftp`, case-insensitive | **check + fix**, no password change | CardCenters only · PNE · CCP. If `CardCenters` doesn't exist: report, leave groups unchanged | — |
| `SQLApplication`, `SQLScript`, `SQLService` | SQL logins on the default instance | rotate | member of `sysadmin` | yes |

- PNE = password never expires. CCP = user cannot change password.
- "X only" = member of X and removed from all other local groups. The user confirmed that no account needs extra groups.
- Each rotated account has its own password. The same password is used on every machine of a **site** (2–3 machines). `ApplicationUser` and the built-in Administrator have separate site passwords; only the variant resolved on a machine is prompted.
- Missing accounts are reported, never created. No managed account is the renamed built-in Administrator (confirmed). The tool still checks for SID overlap (§5).
- **Not touched:** the built-in Administrator when `ApplicationUser` exists, `sa`, and any other account.

### 1.2 Scope boundaries

**Out of scope for v1:**
- reading or writing `BICA\SYSTEM\LOGINS` (report only, §7.8)
- other machines of the site, and cross-machine effects
- domain/AD/Entra/MDM
- Windows XP, x86
- SQL 2000 / 2012+, named instances
- password generation and stricter-than-OS rules
- automatic rollback
- central push
- LAPS
- code signing
- changes to audit or lockout policy
- cleanup of other Administrators/sysadmin members
- removal of user rights, deny rights
- kiosk lockdown and app autostart

**Report-only:**
- DCOM `RunAs`
- SQL Agent credentials/proxies/linked logins
- the `LOGINS` follow-up list
- the locked state of managed accounts

## 2. Key decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | **PowerShell, limited to PS 2.0 syntax *and semantics*, .NET 2.0/3.5 APIs.** | PS 2.0 is the default on Windows 7; Windows 10 runs it unchanged. |
| D2 | **Executed locally, elevated, by an operator logged on as `BiCA Remote` over RDP.** That account is rotated too (§8). Only local credentials are in scope. | Confirmed operating model. |
| D3 | **Non-interactive core + interactive front-end.** Core functions accept `SecureString`s only. | Testable, and keeps a later per-site orchestrator possible. |
| D4 | **Secrets never on a command line, never as a PowerShell command parameter, never printed.** Plaintext is passed only to .NET/COM/ADSI methods or property setters, inside the adapter layer. | Process list, event 4688, Module Logging, transcripts. |
| D5 | **Built-in accounts and well-known groups are resolved by SID.** Managed accounts are resolved by their selection rule. Custom groups (`CardCenters`, `Offer Remote Assistance Helpers`) are resolved by name. | EN/FR/DE/IT localize built-in names. Custom groups have machine-specific SIDs. |
| D6 | **One declarative, unsigned `.psd1` config.** It holds no secrets. | No signing (confirmed); integrity risk accepted (§9). |
| D7 | **Audit by default; `-Apply` makes changes after a single `YES`.** The `YES` covers rotations and check-fixes. Exceptions: restart prompts and runtime ambiguities (D13). | Confirmed. |
| D8 | **The credential slot is the unit of apply** for local dependents. `LOGINS` entries are outside the tool and are reported as follow-ups (§7.8). | Confirmed: registry is report-only. |
| D9 | **Windows accounts: password *change* with the validated old password is the default.** SQL logins are changed as sysadmin. | Old passwords are usually known; a reset loses DPAPI data. |
| D10 | **Group exclusivity is enforced as configured. No other privilege reductions.** | Confirmed. |
| D11 | **Re-runs are idempotent.** | Recover from a crash by re-running with the same input. |
| D12 | **Lockout budget for the tool's own logon attempts.** The threshold is 4, with auto-unlock. The counter and the locked state are re-read immediately before every attempt and before `ChangePassword`. An attempt is made only if at least two attempts remain below the threshold. The probe order minimizes failures (§6 step 7). Failures from other sources are not under the tool's control. | Protects especially `BiCA Remote` (the operator's RDP account). |
| D13 | **Ambiguity → ask the operator, never guess.** | Explicit requirement. |
| D14 | **All three SQL logins are `sysadmin`.** Deliberate and user-confirmed. | Confirmed account list. |

## 3. Execution model

**Distribution.** The operator copies a versioned folder over the **RDP session** (drive redirection or clipboard). It contains:
- `Start-CredentialRotation.cmd`
- `CredentialRotation.ps1` (bundled)
- `CredentialRotation.psd1`

There is no code signing. Each release publishes the **expected SHA-256 hashes** separately from the package, e.g. in the release notes. The tool displays the hashes of its files at start, so the operator can compare them manually.

**Launcher (`.cmd`):**
- Started with "Run as administrator". Works from a redirected drive path (`\\tsclient\…`) via `%~dp0`, without relying on a UNC current directory.
- **Copies** the folder to `%ProgramW6432%\CredentialRotation\<version>\`.
  - The ACL is set with SIDs: `icacls … /inheritance:r /grant *S-1-5-32-544:(OI)(CI)F *S-1-5-18:(OI)(CI)F`.
  - The tool runs from this local copy. `\\tsclient` disappears if RDP disconnects mid-run, and a local copy has no internet-zone mark.
- Starts 64-bit PowerShell via `%windir%\sysnative\` when needed, with `-NoProfile -ExecutionPolicy Bypass`.
- Explains a local Group Policy execution policy that overrides `Bypass`.

**Runtime:**
- elevation, a named mutex, and `FullLanguage` mode are required
- file hashes are computed with `SHA256CryptoServiceProvider` (`Add-Type -AssemblyName System.Core` on PS 2.0), then displayed and logged

**Local copy retention:**
- The copy stays after audit runs and after incomplete or failed runs (exit code 1, 2, 3 or 10), so an apply or a re-run is possible.
- After an `-Apply` run ending with 0 or 4, the tool offers to delete the copy. The deletion is done by a small detached `cmd /c` helper started from `%TEMP%` after the launcher has exited, because a batch file can't delete itself while running.
- Logs remain in `%ProgramData%`.

**Modes and parameters:**
- default: audit
- `-Apply`
- `-Only <slot names>`: a slot is always processed completely; a slot that doesn't apply on this machine is reported as "not applicable"
- `-SkipServiceRestart`
- `-LogPath`

## 4. Architecture

```
src/
  Start-CredentialRotation.cmd   launcher: UNC-safe, local copy with SID-based ACL, 64-bit PS, policy diagnostics
  CredentialRotation.ps1         entry point: modes, front-end, phase orchestration
  lib/
    Compat.ps1        PS 2.0 helpers
    Native.ps1        Add-Type C# (C# 3.0 max): LsaStorePrivateData (write only), LSA account rights,
                      LsaQueryInformationPolicy (machine SID), LogonUser, NetValidatePasswordPolicy, BSTR compare
    Adapters.ps1      the only place where plaintext is materialized (§9)
    Secrets.ps1       prompting, credential probe, lockout budget
    Config.ps1        load + schema validation
    Principals.ps1    SID resolution, selection rules, SID-overlap check, group lookup by SID or name
    Accounts.ps1      rotation (change/reset), flags, check mode, unlock
    Groups.ps1        membership incl. exclusivity and rails
    UserRights.ps1    grants required by discovered dependents
    Services.ps1      discovery by SID, SCM update, dependency-aware restart
    Tasks.ps1         Task Scheduler 2.0 COM
    Iis.ps1           app pools + virtual-directory credentials
    ComPlus.ps1       COM+ identities; DCOM RunAs report
    AutoLogon.ps1     detection of existing variants + standardized auto-logon
    LoginsReport.ps1  LOGINS follow-up list (no registry access)
    Sql.ps1           default instance, SqlClient, T-SQL for 2005–2008 R2
    Preflight.ps1     environment, local password/lockout policy, SQL/IIS/COM+ readiness
    Plan.ps1          desired vs. actual -> change plan
    Apply.ps1         slot sequencing, enforcement phase (§8)
    Log.ps1           local log file + CSV summary; run journal (§7.10)
config/CredentialRotation.psd1
build/Build.ps1 (bundle + SHA-256 list), build/Test-Ps2Syntax.ps1 (lint)
tests/*.Tests.ps1     Pester 3.4.x on a real PS 2.0 engine
```

## 5. Configuration

The config is loaded with `Import-LocalizedData -BaseDirectory <dir> -FileName CredentialRotation.psd1 -UICulture en-US`, with no culture subfolders.

**Principal references:**

| Form | Meaning |
|---|---|
| `S-1-…` | well-known SID (e.g. `S-1-5-32-544` Administrators, `S-1-5-32-545` Users) |
| `RID-500` | local account by RID (machine SID via `LsaQueryInformationPolicy`) |
| `Name:<group>` | custom local group by name; must exist, otherwise the role's `IfGroupMissing` applies |
| `Name:<group>?` | custom local group by name; **added if it exists**, ignored if it doesn't |

```powershell
@{
    SchemaVersion = 1

    Roles = @{
        Admin       = @{ Groups = @('S-1-5-32-544'); ExclusiveGroups = $true; PasswordNeverExpires = $true; CannotChangePassword = $true }
        AdminRemote = @{ Groups = @('S-1-5-32-544','Name:Offer Remote Assistance Helpers?'); ExclusiveGroups = $true
                         PasswordNeverExpires = $true; CannotChangePassword = $true }
        User        = @{ Groups = @('S-1-5-32-545'); ExclusiveGroups = $true; PasswordNeverExpires = $true; CannotChangePassword = $true }
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
        @{ Slot = 'AutoLogon';           Order = 30; Label = 'Auto-logon user' }
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
           Services = 'Auto'; ScheduledTasks = 'Auto'; IisAppPools = 'Auto'; IisVirtualDirs = 'Auto'; ComPlus = 'Auto'
           Restart = 'Prompt' }
        @{ Id = 'AutoLogon';  Kind = 'Windows'; Role = 'User'; Credential = 'AutoLogon'
           Candidates = @( @{ Name = 'PUB-User'; RequireEnabled = $true }, @{ Name = 'WinAutoUser' } )
           AutoLogon = 'IfAlreadyOn' }
        @{ Id = 'WinUsers';   Kind = 'Windows'; Names = @('WinUser1','WinUser2','WinUser3'); Role = 'User'; Mode = 'Check' }
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
- a regex that doesn't compile. Regexes are compiled with `IgnoreCase` in addition to `(?i)`.

**Runtime resolution:** all selection rules are resolved to SIDs first.
- A duplicate SID across entries is an ambiguity (D13).
- Explicitly named accounts are excluded from `NamePattern`.

## 6. Run flow (`-Apply`; audit stops after step 5)

1. **Load and validate config.** Display file hashes (§3).
2. **Preflight** (read-only). Machine-wide failures abort; everything else blocks only the affected slots.
   - Windows 7 SP1 or 10, x64, PS version, language mode, `Add-Type` works.
   - The local password and lockout policy is read and shown, including the lockout duration. The confirmed baseline is: minimum length 6, complexity off, minimum age 0, history 0, threshold 4, auto-unlock. Deviations are reported, not changed.
   - Per account: `PasswordAge`/`MinPasswordAge`, `BadPasswordAttempts`, locked state.
   - **SQL:**
     - the default instance is running
     - its version is 9.x or 10.x
     - integrated sysadmin as the operator
     - `IsIntegratedSecurityOnly = 0`
     - per login: `CHECK_POLICY` and `IsLocked`
     - other instances are reported and ignored
   - **IIS** (if installed): WAS/W3SVC; the API loads.
   - **COM+:** the catalog is reachable.
   - A domain-joined machine is reported as a warning.
3. **Resolve accounts**, including the SID-overlap check. Ambiguities go to the operator.
4. **Discovery.** Collects:
   - account state and groups
   - services, password-stored tasks, IIS and COM+ per account SID
   - DCOM `RunAs` (report)
   - auto-logon variant (§7.5)
   - SQL logins, `sysadmin`, Agent/linked logins (report)
5. **Plan.** Per slot:
   - changes and restarts
   - **high-impact items:** reset instead of change, a SQL instance restart, a blocked slot, and "application keeps using the old password until LOGINS is updated" for each `LoginsEntry` account

   Then the enforcement phase. Audit mode exits with code 0 (no drift) or 10 (drift).
6. **Prompt:**
   - Per slot (only the resolved `AppUser*` variant): the new password twice (compared on BSTRs).
   - Windows slots: the old password. The prompt names the resolved account, e.g. "Administrateur (built-in, RID 500)".
   - The only rules are the local OS policy (`NetValidatePasswordPolicy`) and `MaxLength` 128 for SQL.
   - An empty entry skips the slot after confirmation.
7. **Credential probe** for Windows accounts (D12):
   - **Order:**
     - If the run journal (§7.10) shows an **unfinished** earlier run that completed this account's password step, test the **new** password first.
     - Otherwise test the **old** password first. A successful logon resets the counter.
     - Only if the first test fails, test the other.
     - Normally this costs at most one failure; at most two, always bounded by D12.
   - **Outcomes:**
     - old password works → change path
     - new password works → **already on the new secret** (D11) → the password step is skipped, the dependents are completed
     - both fail → the operator may re-enter the old password within the budget, or choose reset (DPAPI warning) or skip
   - **Locked accounts:** no probe. The plan says "unlock after YES, then validate the old password once" (apply step 1). If that fails, the operator chooses reset or skip.
   - **SQL logins:** no probe. Setting the same password again is harmless (history 0).
8. **Confirm:** show the final plan; the operator types `YES`.
9. **Apply** slots in ascending `Order` (§8).
10. **Enforcement phase** (§8).
11. **Report:**
    - console table, local log and CSV
    - per managed account, a "locked: yes/no" line
    - the **FOLLOW-UP REQUIRED** section (§7.8)
    - **Exit codes:**
      - 0 = OK, nothing outstanding
      - 4 = applied, `LOGINS` follow-up required. 6 of the 7 rotated accounts have a `LOGINS` entry, so **4 is the normal result of a full rotation**, and the operator notes say so.
      - 1 = partial failure
      - 2 = preflight failed
      - 3 = aborted
      - 10 = drift (audit)

## 7. Component design

### 7.1 Accounts (`Accounts.ps1`)
- ADSI `WinNT://<computer>/<name>,user`. The built-in Administrator is resolved via the machine SID + `-500`.
- **Change vs reset:**
  - **change** (`ChangePassword(old, new)`): the old password was validated (probe or apply step 1), the minimum age allows it, and the account is enabled
  - **reset** (`SetPassword`): otherwise, with a DPAPI warning
- **CCP:** cleared just before `ChangePassword` and re-set immediately after. This is recorded in the run journal, so a crash is repaired by a re-run. `RotateOnly` keeps its flags; CCP is only cleared temporarily if it is set.
- **Unlocking** (apply step 1, for accounts locked at preflight):
  - `$user.psbase.InvokeSet('IsAccountLocked', $false)` + `$user.psbase.CommitChanges()`/`SetInfo()` (PS 2.0 form); the fallback is clearing `UF_LOCKOUT` (0x10) in `UserFlags` (spike item 2)
  - If spike item 2 shows that unlocking does **not** reset `BadPasswordAttempts`, D12 may forbid the single validation attempt. The operator then chooses between waiting out the lockout observation window (the tool shows it), reset (DPAPI warning), or skip.
  - the lock state is re-checked immediately before `ChangePassword` and before verification (D12)
  - an account that relocks within seconds is reported as "relocked by another source", and the slot stops instead of retrying
- **Check mode** (`WinUser1–3`, FTP users):
  - PNE, CCP and groups are fixed
  - enabled and locked state is reported only
  - the password is never touched

### 7.2 Groups (`Groups.ps1`)
- Target groups are added if missing. `Name:…?` groups are added if they exist and ignored if they don't. For `BiCA Remote` this means `Offer Remote Assistance Helpers` is added wherever it exists (confirmed).
- **Exclusive groups:** the account is removed from every other local group. Groups are enumerated via ADSI `Groups()` and compared by SID.
- **`CardCenters` missing:** reported; that user's groups are left unchanged. **`RotateOnly`:** no group changes.
- **Rails:**
  - `BiCA Remote`, the running account, and process-token groups are never removed from Administrators
  - Administrators always keeps at least one enabled member that is the running account or was verified in this run
- Removals run in the enforcement phase (§8).
- The localized name of `Offer Remote Assistance Helpers` is spike item 8. If it is localized, the role lists the localized names.

### 7.3 User rights (`UserRights.ps1`)
Grants only what discovered dependents need: `SeServiceLogonRight` for service accounts, `SeBatchLogonRight` for password-stored tasks. No removals.

### 7.4 Services and scheduled tasks (`Services.ps1`, `Tasks.ps1`)
- **Services:**
  - discovered when the normalized `StartName` resolves to the account SID
  - updated via `Win32_Service.Change(…StartName, StartPassword…)`
  - restarted only if running, according to `Restart` (`Prompt` by default; restarts are acceptable at any time with a prompt)
  - dependency-aware; wait for `Running` (60 s)
  - report states: `restarted+running`, `SCM updated – restart pending`, `failed`
- **Tasks:**
  - `Schedule.Service` COM, `GetTasks(1)`, `LogonType` 1 or 6, `UserId` resolved to SID
  - re-registered with `TASK_UPDATE` and the existing SDDL

### 7.5 Standardized auto-logon (`AutoLogon.ps1`)

**Requirement:** auto-logon only, applied only where it is **already on**, replacing whatever variant is there. The auto-logon password is used only for auto-logon (confirmed). Variants are identified by the M0 inventory and discovery.

**Detection** (Winlogon key plus inventory-defined mechanisms):

| State | Signals | Action |
|---|---|---|
| On | `AutoAdminLogon = "1"` and `DefaultUserName` = the auto-logon user | standardize |
| Off | `AutoAdminLogon` missing or `"0"`, `DefaultUserName` empty or a different user, and no other mechanism detected | leave alone (the password is still rotated) |
| Ambiguous | any other combination, or a non-Winlogon mechanism detected | ask the operator (D13) |

**Standardized configuration:**
- set `AutoAdminLogon` = REG_SZ `"1"`
- set `DefaultUserName`, and `DefaultDomainName` = computer name
- store the password as the LSA secret `DefaultPassword` (write only)
- delete the plaintext `DefaultPassword` and `AutoLogonCount`
- leave other values unchanged

**Reported:** `LegalNoticeCaption`/`Text`, `DevicePasswordLessBuildVersion = 2`, `ForceAutoLogon`, a `DefaultDomainName` mismatch.

Takes effect at the next logon. The tool never reboots; reboot tests are part of M4.

### 7.6 IIS application pools and virtual directories (`Iis.ps1`)
Applies only where IIS is installed. Which pools and virtual directories use the application user is established by the M0 inventory.

- **API:** `Microsoft.Web.Administration` (64-bit), with the `WritableAdminManager` COM object as fallback (spike item 9). No `appcmd`.
- **Discovery:** `SpecificUser` pools and "connect as" credentials whose user name resolves to the account SID.
- **Update:** set `password` via the adapter, then `CommitChanges()`.
- **Restart:**
  - identity-changed pools are recycled if started, according to `Restart`
  - `Never` = committed, recycle pending
  - virtual-directory credentials need no recycle (spike confirms)
  - WAS/W3SVC stopped = committed only
- **Verify:**
  - The account password is already verified, and IIS receives the identical value.
  - WAS events 5021/5057 are checked within 30 s after a recycle; this is meaningful with `AlwaysRunning`.
  - Otherwise the report state is "committed; identity used at next worker start".

### 7.7 COM+ applications (`ComPlus.ps1`)
Which server applications use the application user is established by the M0 inventory.

- **Discovery:** server applications only; `Identity` normalized like `StartName`; built-in tokens excluded by string.
- **Update:** `Value('Password')` via the adapter, then `SaveChanges()`.
- **Restart and verify:**
  - applications that were running get `ShutdownApplication` + `StartApplication` (if `Restart` allows)
  - applications that weren't running are not started ("committed, not start-verified")
- **DCOM `RunAs`:** report only, from both `HKCR\AppID` views.

### 7.8 `LOGINS` follow-up report (`LoginsReport.ps1`)
- `HKLM\SOFTWARE\BICA\SYSTEM\LOGINS` holds credentials for `BiCA Admin`, `BiCA Remote`, `ApplicationUser`/`Administrator`, `SQLApplication`, `SQLScript` and `SQLService`.
- Registry handling is **out of scope** (confirmed). The tool does not read or write the key.
- Per rotated account with `LoginsEntry`:
  - a high-impact item in the plan before `YES`
  - a **FOLLOW-UP REQUIRED** entry in the report, with exit code 4
- The update is done **later, by someone else** (confirmed). How the application behaves until then is outside the tool.

### 7.9 SQL Server 2005 – 2008 R2 (`Sql.ps1`)
- **Connection:** default instance, `Data Source=.`, `Pooling=false`, integrated auth. The connection object is created without arguments, and `.ConnectionString` is set in the adapter.
- **Rotation:**
  - `ALTER LOGIN [<name>] WITH PASSWORD = N'…'`, with **`UNLOCK` appended when `LOGINPROPERTY(name,'IsLocked') = 1`**
  - plain batch text; the name is bracket-quoted, the password literal has `'` doubled, maximum 128 characters
- **Role:** `sysadmin` ensured (D14). No removals. `CHECK_POLICY`/`CHECK_EXPIRATION`/enabled state are reported per login.
- **Verify:** a new non-pooled SQL-auth connection + `IS_SRVROLEMEMBER('sysadmin')`. For `CHECK_POLICY = ON` logins, `BadPasswordCount` is re-read first.
- **Report:** Agent credentials, proxies and linked logins that reference rotated logins; the locked state per login.

### 7.10 Logging and run journal (`Log.ps1`)
- Local only: `%ProgramData%\CredentialRotation\logs\` (ACL by SID: Administrators/SYSTEM), log file + CSV.
- No secrets or hashes of secrets.
- **Run journal:** per run ID, records per account (keyed by **SID**) the steps completed, including a CCP flag temporarily cleared, and whether the run finished.
  - The probe order (§6 step 7) only considers runs that did **not** finish.
  - Records from finished runs never influence later rotations.

## 8. Sequencing, verification, enforcement, failure handling

**Slot order:**
1. `BiCA Admin`
2. application user (whichever variant resolved)
3. auto-logon user
4. `SQLApplication`
5. `SQLScript`
6. `SQLService`
7. **`BiCA Remote` last**

`BiCA Admin` first gives a second verified admin early. The operator's own account goes last. The RDP session survives the change, and the tool reminds the operator to update saved RDP credentials before disconnecting.

**Steps within a slot:**

```
1  pre-steps    unlock if locked (+ single old-password validation if probe was deferred) / clear CCP (change path);
                recorded; undone on failure before step 2
2  secret       skip if "already on new secret"; lock state re-checked; ChangePassword/SetPassword or ALTER LOGIN (+UNLOCK);
                test the new secret immediately, budget re-checked first
3  dependents   SCM -> tasks -> IIS -> COM+ -> auto-logon (LSA secret)
4  grants       target groups added (incl. '?' groups that exist), PNE/CCP set, required rights, sysadmin ensured
5  restart      services, pool recycles, COM+ restarts per Restart policy (prompt by default)
6  verify       per account and dependent; LOGINS follow-up recorded
```

**Verification:**

| Account | Logon type |
|---|---|
| Admin and user accounts | `LOGON32_LOGON_INTERACTIVE` |
| Application user, if it runs services | `LOGON32_LOGON_SERVICE` |

1385 counts as "password valid" if spike item 2 confirms it.

**Enforcement phase**, after all slots:
- exclusive-group removals for completed slots
- check-mode fixes (`WinUser1–3`, FTP users), part of the `YES` run
- Under `-Only`, only selected slots; check-mode accounts only without `-Only`.
- Rails apply.

**Failure handling** (no automatic revert):
- **Failure before step 2:** pre-steps are undone; the slot is skipped.
- **Failure at or after step 2:** the slot stops. The report shows what is on the new secret and what is pending. The tool offers a retry of the pending steps.
- **Crash or abort:** re-run with the same passwords. The run journal, the probe order and D11 complete it.
- **Slots are independent.** Secrets are never printed or stored.

**Per-site consistency:** a skipped, failed or mistyped machine diverges from its site. Mitigations: double entry, the per-machine report, and a re-run with the correct site password.

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
  - **No code signing:** a tampered copy runs as admin and sees all entered passwords. Mitigations: a controlled source, published hashes compared by the operator, a local ACL'd copy, logged hashes.
  - **Shared site passwords:** lateral movement within a site.
  - **`LOGINS` entries** stay on old passwords until updated by someone else.
- **AV/EDR:** none in the field.
- **Canary test:** canary values for the new and the old password, with Module Logging, Script Block Logging and Transcription enabled through local policy. Then search the PowerShell logs, transcripts, Security log, `%TEMP%`, the tool's logs, SQL traces and `inetpub\history`.

## 10. Compatibility

| Target | PowerShell | Notes |
|---|---|---|
| Windows 7 SP1 x64 | 2.0 (default), up to 5.1 with WMF | IIS 7.5 |
| Windows 10 x64 | 5.0/5.1 | IIS 10, `DevicePasswordLessBuildVersion` |

- **OS languages:** EN/FR/DE/IT. Built-in principals by SID; the launcher ACL by SID; custom group names are a spike item.
- **PS 2.0:** lint for syntax, tests on the PS 2.0 engine for semantics; `Add-Type` C# 3.0 at most; `System.Core` loaded explicitly.

## 11. Testing

- **Lint (CI):** PSScriptAnalyzer plus `Test-Ps2Syntax.ps1`.
- **Unit (CI):** Pester 3.4.x via `powershell.exe -Version 2` (a Windows 10 or Server 2019/2022 agent with PS 2.0 + .NET 3.5).
  - Covers:
    - selection rules, SID overlap, the `AppUser*` slot choice and "not applicable" under `-Only`
    - candidate `Credential` validation
    - probe order (journal-based, unfinished runs only), locked-account deferral and relock detection, lockout budget
    - exclusive groups, `?` semantics, rails
    - auto-logon detection
    - T-SQL incl. `UNLOCK`
    - the `LOGINS` report and exit codes
- **Integration VMs** (all x64):
  - Windows 7 SP1 with PS 2.0, in **German** and **French**
  - Windows 7 with WMF 5.1, in **English**
  - Windows 10, in **Italian** and **English**
  - SQL Server 2005, 2008 and 2008 R2 (default instance)
  - IIS
  - COM+ (incl. an NT-service application)
  - launch from `\\tsclient` with "Run as administrator"; deletion of the local copy after the run
- **Scenarios:**
  - `ApplicationUser` vs built-in Administrator (separate slots)
  - `PUB-User` enabled, disabled, or missing next to `WinAutoUser`
  - 0, 1 and 3 FTP users (one uppercase), with and without `CardCenters`
  - `Offer Remote Assistance Helpers` present or absent
  - auto-logon on, off and ambiguous
- **Failure injection:**
  - wrong old password with the counter at 2
  - an account already locked at preflight
  - an account relocked during the run
  - a service that won't start
  - a SQL 2012 instance present
  - kill-and-rerun, incl. a second rotation months later (no journal influence)
- **Canary test** (§9).

## 12. Milestones

| M | Content | Exit criterion |
|---|---|---|
| M0 | **Inventory** (below), spike, schema freeze, VM matrix | inventory + spike results in `docs/` |
| M1 | Launcher (UNC, `%ProgramW6432%`, SID ACL, hash display, cleanup helper), config, principals, selection + SID overlap, preflight, discovery, audit | correct audit on VMs and inventory machines |
| M2 | Prompting, probe + lockout budget + locked-account handling, run journal, adapters, rotation, check mode, groups/rails, verification, `LOGINS` follow-up report, exit codes | apply + re-audit clean; D9 confirmed |
| M3 | Slot sequencing, services, tasks, IIS/COM+ (per inventory), retry, idempotent re-run | dependents survive; kill-and-rerun passes |
| M4 | Standardized auto-logon | works after reboot on every OS/language |
| M5 | SQL rotation incl. `UNLOCK` | SQL slots rotate cleanly |
| M6 | Canary test, full matrix | all green → v1 release |

**M0 inventory** (a few real machines per site):
- the auto-logon variant
- IIS and COM+ use of the application user
- services and tasks per rotated account
- SQL Agent/linked servers
- current memberships and flags
- the `Offer Remote Assistance Helpers` name per language
- execution-policy overrides

**M0 spike:**
1. `ChangePassword` vs `SetPassword` and DPAPI, with the user logged off and logged on.
2. `LogonUser` codes 1385/1331/1909; a successful logon resets the counter. Unlocking via `InvokeSet('IsAccountLocked')` + `SetInfo()` vs clearing `UF_LOCKOUT`, and whether unlocking resets `BadPasswordAttempts`. On both OSes.
3. `ChangePassword` prerequisites: CCP, locked, disabled.
4. `Win32_Service.Change` and `SeServiceLogonRight`.
5. `RegisterTaskDefinition` keeps the SDDL.
6. `.cmd` from `\\tsclient` with "Run as administrator": the elevated process can read `\\tsclient`; `%ProgramW6432%`; the SID-based `icacls`; policy diagnostics; detached self-cleanup.
7. `NetValidatePasswordPolicy` against the local policy.
8. ADSI group enumeration and removal on all four languages; the localized name of `Offer Remote Assistance Helpers`.
9. The IIS API in PS 2.0; virtual-directory change without a recycle; WAS events.
10. COM+ `Identity` format; password set + shutdown/start.
11. Winlogon behaviour with the LSA secret and after a failed auto-logon, on Windows 7 and 10.
12. SQL `ALTER LOGIN … WITH PASSWORD … UNLOCK` on 2005/2008/2008 R2.

**Deferred:**
- automating `LOGINS` updates
- per-site orchestrator
- DCOM `RunAs` changes
- cleanup of other members
- event log entry
- code signing

## 13. Answers and open items

| Topic | Answer (user, 2026-10-06) | Plan impact |
|---|---|---|
| Accounts | Local only; not domain-joined; pure standalone | No domain logic, no LAPS |
| Access | Local run over **RDP only**; operator = **BiCA Remote** (rotated) | D2; BiCA Remote last |
| Scope principle | **The tool only cares about its local credentials**; users won't be locked out by logons from other site machines | Cross-machine handling removed |
| Site | 2–3 machines; same passwords per site | §1.1 |
| Distribution | Copied over RDP | §3 launcher |
| OS | Windows 7 SP1 / 10, all x64; EN/FR/DE/IT; XP dropped | §10, §11 |
| Account list | §1.1 | §1.1, §5 |
| App user | `ApplicationUser` first, otherwise built-in Administrator (rotate only); separate site passwords; no renamed RID-500 | Two `AppUser*` slots |
| Auto-logon | `PUB-User` if it exists and is enabled, otherwise `WinAutoUser`; standardized, auto-logon only, only where already on; password used only for auto-logon | §7.5 |
| WinUser1–3 / FTP | Check + fix only (groups, PNE, CCP); FTP 0–3, missing CardCenters → report, keep groups | Check mode |
| Fixes | Only with `-Apply`, part of the single `YES` | D7 |
| Rotated accounts | Each its own password; PNE, CCP, exclusive groups; no extra groups | D8, D10 |
| BiCA Remote | `Offer Remote Assistance Helpers` added where the group exists | `?` semantics |
| Old passwords | Usually known | D9 |
| Password policy | OS policy only; length ≥ 6, no complexity, min age 0, history 0, threshold 4, auto-unlock | D12 |
| Audit/lockout policy | Not changed by the tool (report only) | §1.2 |
| App rights | App accounts rely on admin/interactive logon | No deny rights |
| Restarts | Anytime, with a prompt | `Restart = 'Prompt'` |
| SQL | Full editions, one default instance, 2005–2008 R2; integrated sysadmin; `sa` not managed; all three `sysadmin` | §7.9, D14 |
| Registry `LOGINS` | Out of scope; report-only follow-up; updated later by someone else. Possible local lockouts by the app retrying stale credentials: **accepted risk** | §7.8, §14 |
| Lock watch / `-Unlock` | **Removed** (user-confirmed simplification) | §1.2 |
| IIS / COM+ | Both in use; specifics unknown | M0 inventory |
| Reports / internet / signing / AV | Local only / offline / no signing / none | §7.10, §3, §9 |

**Open items** (established in M0, not assumed):
- **O1** Inventory results: auto-logon variants, IIS/COM+, services/tasks, memberships, group names per language.
- **O2** `LOGINS` automation (deferred by the user).

## 14. Risks

| Risk | Mitigation |
|---|---|
| `BiCA Remote` locked by the tool | Lockout budget (D12), rotated last, live session persists, auto-unlock |
| App uses old passwords until `LOGINS` is updated | Shown before `YES`, FOLLOW-UP REQUIRED, exit code 4; accepted (out of scope) |
| The local application, retrying stale `LOGINS` credentials, repeatedly locks `BiCA Remote`/`BiCA Admin` on this machine until `LOGINS` is updated, which blocks RDP reconnects | **Accepted risk** (user-confirmed): the operator waits for the `LOGINS` update. The live session is unaffected. |
| Half-rotated local dependents | Slot as unit (D8), retry, run journal, idempotent re-run (D11) |
| Service / pool / COM+ app fails after rotation | Restart prompt, rights before restart, verification, distinct report states |
| Third-party auto-logon breaks | Detection → ambiguous → operator decides; inventory; reboot tests |
| Same account selected twice | SID-overlap check |
| Exclusive groups remove a needed membership | No extra groups (confirmed); admin rails; every removal listed before `YES` |
| DPAPI data loss via reset | Change by default (D9); locked accounts unlocked and validated instead of reset |
| Secret leakage | D4, adapter-only plaintext, lint, canary test |
| Tampered script (no signing) | Accepted; published hashes, local ACL'd copy, logged hashes |
| Shared site passwords → lateral movement | Accepted |
| PS 2.0 incompatibility | PS 2.0 engine in CI, Windows 7 VMs in every milestone |

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
| 7 | v7 | 8 | 2 Major, 8 Minor | see below |
| 8 | v8 | **8.5** | 5 Minor | see below; **no Blocker/Major, ready for M0** |

All concerns of rounds 1–6 were resolved. Their per-concern tables were in drafts v2–v7, which were not committed, so only this summary remains.

### Round 7 (v7 → v8)
v7 scored **8/10** (coverage 9, correctness 8, security 7, operational safety 7, compatibility 9, feasibility 8, clarity 9).

| ID | Sev. | Concern | Resolution in v8 |
|---|---|---|---|
| Y1 | Major | Site procedure could lock the operator out of machines not yet visited | User: the tool only cares about local credentials; no lockouts from site peers → cross-machine handling removed |
| Y2 | Major | Procedure never converges if the app logs on with `LOGINS` | User: `LOGINS` is out of scope → report-only follow-up stays; no go/no-go gate |
| Y3 | Minor | SQL `CHECK_POLICY` toggle fails with `CHECK_EXPIRATION` | Moot: `-Unlock` mode removed (user-confirmed); `UNLOCK` during rotation stays |
| Y4 | Minor | Windows lock-watch data sources | Moot: lock watch removed; no audit policy changes (user) |
| Y5 | Minor | SQL failed-logon sources | Moot: lock watch removed |
| Y6 | Minor | Journal-based probe order had no scope | Only unfinished runs count; keyed by SID |
| Y7 | Minor | External failures during the run | D12 states its limit; lock state re-checked before `ChangePassword` and verify; relock → report and stop |
| Y8 | Minor | `IsAccountLocked` via the ADSI adapter | `InvokeSet` + `SetInfo`, `UF_LOCKOUT` fallback; spike item 2 |
| Y9 | Minor | Self-deletion of the running batch file | Detached helper from `%TEMP%` after exit |
| Y10 | Minor | `-Only` on a non-applicable `AppUser*` slot; candidate credential refs | "Not applicable" report; validation of candidate `Credential` refs |

Decisions C1–C5 were put to the user:
- **C1/C5:** the tool only cares about local credentials; no lockouts from peers expected.
- **C2:** `LOGINS` out of scope.
- **C3:** no auditing changes.
- **C4:** 2–3 machines per site.
- The user also confirmed removing lock watch and `-Unlock`.

### Round 8 (v8 → v8.1)
v8 scored **8.5/10** (coverage 9, correctness 9, security 7, operational safety 8, compatibility 9, feasibility 9, clarity 9). Y1–Y10 were all resolved or moot, with no Blocker or Major issues.

| # | Minor concern | Resolution in v8.1 |
|---|---|---|
| 1 | Local lockouts by the app retrying stale `LOGINS` credentials weren't in §14 | Put to the user: **accepted risk**; added to §13 and §14 |
| 2 | Unlock-then-validate if unlocking doesn't reset the counter | Operator chooses wait / reset / skip (§7.1) |
| 3 | `InvokeSet` syntax on PS 2.0 | `psbase.InvokeSet` + commit (§7.1) |
| 4 | Copy deletion was offered after audit runs | Only after `-Apply` with 0/4; retained after 1/2/3/10 (§3) |
| 5 | Exit code 4 is the normal result | Stated in §6 and the operator notes |

The reviewer confirmed that no further design-relevant assumption remains unconfirmed.
