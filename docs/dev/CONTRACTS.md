# Module contracts (M1: read-only audit)

Developer reference for `src/`. The design is in `docs/PLAN.md`; this file fixes the interfaces so modules can be built in parallel. Change a contract only together with every caller.

## Layout and ownership

```
src/Start-CredentialRotation.cmd     launcher (PLAN §3)
src/CredentialRotation.ps1           entry point: params, lib loading, orchestration, exit codes
src/lib/Compat.ps1                   shared helpers (SID/name, registry, lists)
src/lib/Log.ps1                      log file, findings, CSV, console report
src/lib/Config.ps1                   load + validate the .psd1
src/lib/Native.ps1                   Add-Type C# 2.0 + thin PowerShell wrappers
src/lib/Accounts.ps1                 local users (read side in M1)
src/lib/Groups.ps1                   local groups + members (read side in M1)
src/lib/Rights.ps1                   effective logon rights, D16 logon type
src/lib/Principals.ps1               selection rules, resolution, SID overlap
src/lib/Services.ps1, Tasks.ps1, ComPlus.ps1, IisReport.ps1, Sql.ps1   dependents (read side in M1)
src/lib/AutoLogon.ps1                Winlogon read + D18 decision
src/lib/Preflight.ps1                environment, policy, write filter (D19)
src/lib/Plan.ps1                     desired vs actual -> findings
config/CredentialRotation.psd1       default config (PLAN §5)
build/Test-Ps2Syntax.ps1, build/Build.ps1
tests/Invoke-Tests.ps1, tests/*.Tests.ps1, tests/Fixtures.ps1
```

Lib files are dot-sourced by the entry point in this order: Compat, Log, Config, Native, Accounts, Groups, Rights, Principals, Services, Tasks, ComPlus, IisReport, Sql, AutoLogon, Preflight, Plan. A lib file only defines functions (and, for Native, types); it runs nothing at load time except `Add-Type` guarded by a type check.

## Shared helpers (Compat.ps1)

| Function | Returns |
|---|---|
| `ConvertTo-CrSidString -Bytes <byte[]>` | SID string or `$null` |
| `Resolve-CrSidToName -Sid <string>` | `DOMAIN\Name` or `$null` |
| `Resolve-CrNameToSid -Name <string>` | SID string or `$null`; understands `.\x`, `LocalSystem`, `NT AUTHORITY\…`, plain local names (resolved as `<COMPUTER>\name` first) |
| `Get-CrRegistryValue -Path <string> -Name <string>` | `@{ Exists; Value; Kind }` (`Kind` = `String`, `DWord`, `ExpandString`, `MultiString`, `Binary`, `QWord` or `$null`) |
| `Test-CrBuiltinServiceSid -Sid <string>` | `$true` for S-1-5-18/19/20, S-1-5-80-*, S-1-5-82-* |
| `New-CrFinding -Severity -Area -Message [-Slot] [-Account] [-Detail]` | finding hashtable (below) |
| `ConvertTo-CrArray -Value $x` | always an array; `$null` → empty array. Assign it (`$a = ConvertTo-CrArray $x`) or use it in parentheses (`(ConvertTo-CrArray $x) -contains $y`, `foreach ($i in (ConvertTo-CrArray $x))`). **Never** wrap it in `@()` or pipe it: that nests the array (lint rule `Cr-ArrayHelper`). The same applies to every function that returns with `return , $array`. |

## The machine state (`$State`)

Built by the entry point from the discovery functions. Every part is a hashtable; a part that failed is `@{ Error = '<message>' }`.

```powershell
$State = @{
  Computer    = Get-CrComputerInfo -Config $Config        # Preflight.ps1
  Policy      = Get-CrPasswordPolicy                      # Native.ps1 wrapper + secedit (Preflight.ps1)
  WriteFilter = Get-CrWriteFilterState                    # Preflight.ps1
  Users       = Get-CrLocalUsers                          # Accounts.ps1  -> array
  Groups      = Get-CrLocalGroups                         # Groups.ps1    -> array
  Rights      = Get-CrLsaRightsMap                        # Native.ps1    -> hashtable
  Services    = Get-CrServices                            # Services.ps1  -> array
  Tasks       = Get-CrScheduledTasks                      # Tasks.ps1     -> array
  ComPlus     = Get-CrComPlusApplications                 # ComPlus.ps1   -> array
  Dcom        = Get-CrDcomRunAs                           # ComPlus.ps1   -> array
  Iis         = Get-CrIisIdentities                       # IisReport.ps1
  Sql         = Get-CrSqlState                            # Sql.ps1
  AutoLogon   = Get-CrAutoLogonState                      # AutoLogon.ps1
  Errors      = ArrayList of @{ Section; Message }        # filled by the entry point
}
```

### Computer
`@{ Name; IsSm; OsVersion ('6.1.7601'); OsCaption; Is64BitOs; Is64BitProcess; PSVersion ('2.0'); ClrVersion; LanguageMode; IsElevated; PartOfDomain; MachineSid; SystemDrive ('C:') }`. `IsSm` = name matches the auto-logon `RestrictedComputerPattern` (case-insensitive).

### Policy
`@{ MinPasswordLength; MaxPasswordAgeSeconds; MinPasswordAgeSeconds; PasswordHistoryLength; LockoutThreshold; LockoutDurationSeconds; LockoutObservationSeconds; ComplexityEnabled; ForceGuest }`. Numbers are `[int]`/`[long]`; `ComplexityEnabled` and `ForceGuest` are `$true`/`$false`/`$null` (unknown). Max age "never" = `-1`.

### Users (array)
`@{ Name; Sid; Rid; FullName; Flags; Disabled; LockedOut; PasswordNeverExpires; CannotChangePassword; PasswordNotRequired; PasswordAgeSeconds; BadPasswordCount }`. `Flags` is the raw `UserFlags` int. `Rid` is `[int]` (last SID part).

### Groups (array)
`@{ Name; Sid; MemberSids = @(<sid strings>); Error }`. Members come from `NetLocalGroupGetMembers` level 0 (D5). `Error` is `$null` or the message for that group.

### Rights
Hashtable keyed by right name, value = array of SID strings (possibly empty), for exactly: `SeNetworkLogonRight`, `SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeBatchLogonRight`, `SeServiceLogonRight`, `SeDenyNetworkLogonRight`, `SeDenyInteractiveLogonRight`, `SeDenyRemoteInteractiveLogonRight`, `SeDenyBatchLogonRight`, `SeDenyServiceLogonRight`.

### Services (array)
`@{ Name; DisplayName; StartName; StartNameSid; StartMode; State; PathExecutable; DependentServices = @(); DependsOn = @() }`. Only `PathExecutable` (the executable, never arguments).

### Tasks (array)
`@{ Path; UserId; UserSid; LogonType ([int]); Enabled; Error }`. Only tasks whose principal has a `UserId` that isn't a built-in service SID.

### ComPlus (array) / Dcom (array)
ComPlus: `@{ Name; Id; Activation ('Library'|'Server'); Identity; IdentitySid; IsEnabled; IsSystem }`. Dcom: `@{ View; AppId; Name; RunAs; RunAsSid }` (excluding `Interactive User` and built-ins).

### Iis
`@{ Installed; Version; Error; AppPools = @(@{ Name; IdentityType; UserName; UserSid }); VirtualDirectories = @(@{ Site; Application; Path; PhysicalPath; UserName; UserSid; Protocols }) }`. `Protocols` lists the site's binding protocols (e.g. `ftp`).

### Sql
`@{ DefaultInstancePresent; ServiceName; ServiceState; ServiceAccount; ServiceAccountSid; OtherInstances = @(); Connected; Error; MajorVersion ([int]); ProductVersion; Edition; IsExpress; IsIntegratedSecurityOnly; ConnectedAs; ConnectedAsSysadmin; Logins = @(); MasterFiles = @(<physical paths>); AgentJobs = @(@{ Name; Owner; Enabled }); Credentials = @(); Proxies = @(); LinkedLogins = @() }`.
Login: `@{ Name; Type ('SQL_LOGIN'|'WINDOWS_LOGIN'|'WINDOWS_GROUP'); Sid (Windows principals: SID string; SQL logins: hex '0x…'); IsDisabled; IsPolicyChecked; IsExpirationChecked; IsLocked; BadPasswordCount; PasswordLastSetTime; IsSysadmin }`.

### AutoLogon
`@{ AutoAdminLogon (string or $null); AutoAdminLogonKind ('String'|'DWord'|$null); DefaultUserName; DefaultDomainName; DefaultPasswordPresent; AutoLogonCountPresent; ForceAutoLogon; AutoLogonSidValue; OtherMechanisms = @(<text>); LegalNoticeCaptionSet; LegalNoticeTextSet; Error }`. Never reads the `DefaultPassword` value or the LSA secret.

### WriteFilter
`@{ Filters = @(@{ Type ('EWF'|'FBWF'|'UWF'); DriverInstalled; StateKnown; CurrentEnabled; NextEnabled; CommitPending; ProtectedVolumes = @('C:') ; Detail }) ; Error }`.

## Logic functions

### Config.ps1
- `Import-CrConfig -Path <psd1>` → hashtable (via `Import-LocalizedData`, PLAN §5). Throws on syntax error.
- `Test-CrConfig -Config <hashtable>` → array of error strings (empty = valid), per PLAN §5 "Validation".
- `Get-CrRole -Config -Name` → role hashtable.

### Rights.ps1
- `Get-CrTokenSids -UserSid -State -LogonType <'Network'|'Interactive'|'RemoteInteractive'|'Batch'|'Service'>` → SID array: the account, every local group whose `MemberSids` contains the account or any well-known SID in the token (iterate until stable), S-1-1-0, S-1-5-11, S-1-5-113, S-1-5-114 if in Administrators, the logon-type SID (Network S-1-5-2, Interactive S-1-5-4 + S-1-2-0 + S-1-2-1, RemoteInteractive S-1-5-14 + S-1-5-4 + S-1-2-0, Batch S-1-5-3, Service S-1-5-6).
- `Get-CrEffectiveLogonRights -UserSid -State` → `@{ Network; Interactive; RemoteInteractive; Batch; Service }` each `$true`/`$false` (granted to any token SID and not denied to any).
- `Select-CrProbeLogonType -UserSid -State` → `@{ LogonType; Fallback }`: first allowed of Network → Interactive → Batch → Service; if none, `LogonType = 'Network'`, `Fallback = $true` (D16).
- `Test-CrIsAdmin -UserSid -State` → `$true` if the SID is a member of S-1-5-32-544.

### Principals.ps1
- `Resolve-CrAccounts -Config -State` → array of resolved entries:
  `@{ Id; Kind ('Windows'|'SqlLogin'); Mode ('Rotate'|'Check'); RoleName; Role; Slot; LoginsEntry; Accounts = @(@{ Name; Sid; User }) ; Missing = @(<names>); Candidate (index or $null); NotApplicable ($true if nothing resolved) ; AutoLogon (the config's AutoLogon block or $null); AutoLogonUser (selection list or $null); Config (the original config entry hashtable, e.g. for `Services`, `ServerRoles`) }`.
  `User` = the `$State.Users` entry; for SQL logins `User` is the `$State.Sql.Logins` entry and `Sid` its hex SID.
  `Mode` is `Check` when the config entry has `Mode='Check'`, otherwise `Rotate`. `Slot` = the entry's or matched candidate's `Credential`.
- `Find-CrSidOverlap -Resolved` → array of findings (Severity `Ambiguous`) for any SID claimed by two entries (D13); named accounts are excluded from `NamePattern` matches before this check.
- `Resolve-CrGroupReference -Reference <'S-1-…'|'RID-500'|'Name:x'|'Name:x?'|'Pattern:re'> -State` → `@{ Sids = @(); Optional; Missing }`.

### AutoLogon.ps1
- `Get-CrAutoLogonState` (read, above).
- `Get-CrAutoLogonDecision -State -Resolved -Config -VerifiedSids <string[]> -RemovedAdminSids <string[]>` → `@{ Action ('LeaveOff'|'Standardize'|'Switch'|'TurnOff'|'Ambiguous'|'NoChange'); CurrentSid; CurrentName; TargetSid; TargetName; Reasons = @(); OperatorOptions = @('TurnOff','LeaveUnchanged','StandardizeCurrent'); HighImpact = @(<text>) }` implementing PLAN §7.5 exactly. `VerifiedSids` = accounts on the new secret after the slots (audit passes the accounts the plan would rotate); `RemovedAdminSids` = accounts whose Administrators membership this run removes. `Test-CrAutoLogonStandardized -State -TargetSid` → bool (PLAN §7.5 "Audit").

### Preflight.ps1
- `Get-CrComputerInfo -Config`, `Get-CrPasswordPolicy` (calls Native + secedit complexity), `Get-CrWriteFilterState`.
- `Get-CrWriteFilterDecision -WriteFilter -SystemDrive -SqlMasterFiles` → `@{ BlockApply; BlockSql; Reasons = @() }` (D19).
- `Invoke-CrPreflight -State -Config` → `@{ MachineBlocked; BlockedSlots = @{ <slot> = <reason> }; Findings = @() }`: OS (6.1 SP1 / 10.0, 64-bit OS, 64-bit process), FullLanguage, elevation, `Add-Type`/Native ready, domain-joined warning, D19, SQL readiness (default instance running, major 9–14, connected as sysadmin, mixed mode) blocking SQL slots.

### Plan.ps1
- `New-CrPlan -State -Config -Resolved -Preflight` → `@{ Findings = ArrayList; Drift ($true/$false); HighImpact = @(); FollowUps = @() }`.

## Findings

`@{ Severity; Area; Slot; Account; Message; Detail }`. Severity is one of:
- `Drift`: desired ≠ actual and `-Apply` would change it (audit exit 10)
- `HighImpact`: shown before `YES` (PLAN §6 step 5)
- `Blocked`: slot or machine blocked (reason in `Message`)
- `Ambiguous`: needs an operator decision (D13)
- `FollowUp`: LOGINS / IIS (exit 4 after apply)
- `Info`: everything else worth reporting

## Native.ps1 (C# 2.0, namespace-free static classes prefixed `Cr`)

| Wrapper | Native |
|---|---|
| `Get-CrMachineSid` | `LsaQueryInformationPolicy(PolicyAccountDomainInformation)` |
| `Get-CrLsaRightsMap` | `LsaEnumerateAccountsWithUserRight` per right; `STATUS_NO_MORE_ENTRIES` / `STATUS_OBJECT_NAME_NOT_FOUND` = empty |
| `Get-CrUserModals` | `NetUserModalsGet` levels 0 and 3 → `@{ MinPasswordLength; MaxPasswordAgeSeconds; MinPasswordAgeSeconds; PasswordHistoryLength; LockoutDurationSeconds; LockoutObservationSeconds; LockoutThreshold }` |
| `Get-CrLocalGroupNames` | `NetLocalGroupEnum` level 0 |
| `Get-CrLocalGroupMemberSids -GroupName` | `NetLocalGroupGetMembers` level 0 |
| `Initialize-CrNative` | compiles the C# once (`Add-Type`, guarded); called by the entry point after loading the libs; never throws, sets `$script:CrNativeReady` / `$script:CrNativeError` |
| `Test-CrNativeReady` | `$true` once the types compiled; else the compile error is in `$script:CrNativeError` |

## Entry point (`src/CredentialRotation.ps1`)

Parameters: `-Apply` (switch; refused in M1 with exit 2), `-Only <string[]>` (slot names), `-ConfigPath <string>` (default: `CredentialRotation.psd1` next to the script), `-LogPath <string>` (log root, default `%ProgramData%\CredentialRotation`). Unbundled, it dot-sources `lib\*.ps1` in the order above; the bundle (`build/Build.ps1`) replaces the line `# <CR-LIB-IMPORT>` and the block up to `# </CR-LIB-IMPORT>` with the concatenated lib files. Version: `$script:CrToolVersion`. Exit codes per PLAN §6 step 11 (audit: 0 no drift, 10 drift, 2 preflight failed, 3 aborted).

## Verification on the dev machine

AppLocker blocks `.ps1` files under `C:\Repos`, and the user decided: **write code and tests, but don't run them here**. Do not work around AppLocker (no `Invoke-Expression`/`[scriptblock]::Create` of repo files, no copying them to allowed folders). Allowed checks: parsing with `[System.Management.Automation.Language.Parser]::ParseFile` in an inline `powershell.exe -Command`, reading, and compiling C# snippets with `Add-Type` inline. Tests run later on an allowed host.
