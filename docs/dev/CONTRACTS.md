# Module contracts (M1 audit, M2/M3 apply)

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
src/lib/AutoLogon.ps1                Winlogon read + D18 decision + auto-logon actions
src/lib/Preflight.ps1                environment, policy, write filter (D19), dependent discovery errors
src/lib/Plan.ps1                     desired vs actual -> findings
src/lib/Adapters.ps1                 the only plaintext boundary (D4): Task Scheduler and COM+ password setters
src/lib/Journal.ps1                  run journal (PLAN 7.10)
src/lib/Secrets.ps1                  prompts, site rules, credential probe (PLAN 6 steps 6-7)
src/lib/Apply.ps1                    -Apply: slots, enforcement phase, summary, exit code (PLAN 8)
config/CredentialRotation.psd1       default config (PLAN §5)
build/Test-Ps2Syntax.ps1, build/Build.ps1
tests/Invoke-Tests.ps1, tests/*.Tests.ps1, tests/Fixtures.ps1
```

Lib files are dot-sourced by the entry point in this order: Compat, Log, Config, Native, Adapters, Journal, Secrets, Accounts, Groups, Rights, Principals, Services, Tasks, ComPlus, IisReport, Sql, AutoLogon, Preflight, Plan, Apply. (M2 added Adapters, Journal, Secrets, Apply.) A lib file only defines functions (and, for Native, types); it runs nothing at load time except `Add-Type` guarded by a type check.

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
- `Import-CrConfig -Path <psd1>` → hashtable (via `Import-LocalizedData`, PLAN §5). Throws on syntax error, and when a copy of the file exists in an `en-US\` or `en\` subfolder next to it (it would be loaded instead of the hashed file, v10.4).
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
- `Get-CrAutoLogonDecision -State -Resolved -Config -VerifiedSids <string[]> -RemovedAdminSids <string[]>` → `@{ Action ('LeaveOff'|'Standardize'|'Switch'|'TurnOff'|'Ambiguous'|'NoChange'); CurrentSid; CurrentName; TargetSid; TargetName; Reasons = @(); OperatorOptions = @('TurnOff','LeaveUnchanged'); HighImpact = @(<text>) }` implementing PLAN §7.5 exactly. `VerifiedSids` = accounts on the new secret after the slots (audit passes the accounts the plan would rotate); `RemovedAdminSids` = accounts whose Administrators membership this run removes. `Test-CrAutoLogonStandardized -State -TargetSid` → bool (PLAN §7.5 "Audit").

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

Parameters: `-Apply` (switch; refused in M1 with exit 2), `-Only <string[]>` (slot names), `-ConfigPath <string>` (default: `CredentialRotation.psd1` next to the script). There is no log-path parameter (removed in v10.4): logs always go to `%ProgramData%\CredentialRotation`. Unbundled, it dot-sources `lib\*.ps1` in the order above; the bundle (`build/Build.ps1`) replaces the line `# <CR-LIB-IMPORT>` and the block up to `# </CR-LIB-IMPORT>` with the concatenated lib files. Version: `$script:CrToolVersion`. Exit codes per PLAN §6 step 11 (audit: 0 no drift, 10 drift, 2 preflight failed, 3 aborted).

## Verification on the dev machine

AppLocker blocks `.ps1` files under `C:\Repos`, and the user decided: **write code and tests, but don't run them here**. Do not work around AppLocker (no `Invoke-Expression`/`[scriptblock]::Create` of repo files, no copying them to allowed folders). Allowed checks: parsing with `[System.Management.Automation.Language.Parser]::ParseFile` in an inline `powershell.exe -Command`, reading, and compiling C# snippets with `Add-Type` inline. Tests run later on an allowed host.

# M2/M3: apply (`-Apply`)

PLAN §6 steps 6–11, §7.1–7.5, §7.7, §7.10, §8, D4, D9, D11, D12, D16, D18, D20. SQL rotation is M5: in this version SQL slots are never prompted and are reported as "SQL rotation not available in this version".

## Secret handling (D4) — applies to every M2 file

- A secret is a `[System.Security.SecureString]`. Parameters holding one are named `-Secret`, `-OldSecret` or `-NewSecret`.
- Native wrappers turn a SecureString into a BSTR with `[Runtime.InteropServices.Marshal]::SecureStringToBSTR`, pass the `IntPtr` to C#, and call `ZeroFreeBSTR` in `finally`. The C# methods take `IntPtr` (a BSTR is a valid null-terminated `LPWSTR`). No plaintext ever becomes a managed string there.
- Only `src/lib/Adapters.ps1` converts a secret to a managed string (Task Scheduler and COM+ need one). Variables holding it are named `$plain*` and set to `$null` right after use.
- Never log, print, export or compare secrets in PowerShell; never put them in hashtables that are logged; never pass them to external programs. Log messages must not reference variables named `*secret*` / `*password*` (lint rule `D4-SecretOutput`).
- Results report success and Win32 error codes only, never secret material. A complexity check result says *that* a name token was found, never *which* one.

## Native.ps1 additions (C# 2.0, write APIs)

All wrappers compile through `Initialize-CrNative`. Each returns `@{ Success = $bool; Win32Error = <int> }` unless noted, and throws only when the native helpers aren't ready.

| Wrapper | Native |
|---|---|
| `Test-CrSecretEqual -A <SecureString> -B <SecureString>` → bool | byte-wise BSTR compare in C# (length first) |
| `Get-CrSecretLength -Secret` → int | `SysStringLen` / BSTR length prefix |
| `Test-CrSecretComplexity -Secret -MinLength <int> -RequireComplexity <bool> -Tokens <string[]>` → `@{ Ok; TooShort; Categories; MissingCategories; ContainsNameToken }` | D15 emulation over the BSTR: 5 categories (upper, lower, digit, non-alphanumeric, other letters via `char.IsLetter` without case), at least 3 when required; `ContainsNameToken` = any token of 3+ chars occurs case-insensitively (`char.ToUpperInvariant`). Tokens are computed in PowerShell by `Get-CrNameTokens` (below). |
| `Test-CrLocalPasswordPolicy -UserName -Secret` → `@{ Ok; Status; Win32Error }` | `NetValidatePasswordPolicy(NULL, NULL, NetValidatePasswordChange, NET_VALIDATE_PASSWORD_CHANGE_INPUT_ARG{ ClearPassword = BSTR, UserAccountName, PasswordMatch = TRUE }, …)`; `NetValidatePasswordPolicyFree` |
| `Invoke-CrLogonTest -UserName -Secret -LogonType <'Network'\|'Interactive'\|'Batch'\|'Service'>` | `LogonUserW(user, ".", BSTR, 3\|2\|4\|5, LOGON32_PROVIDER_DEFAULT)`; the token is closed immediately; `Win32Error` = `GetLastError` on failure (1326 wrong password, 1385 logon type not granted, 1909 locked, 1331 disabled, 1330 expired) |
| `Get-CrUserInfo -UserName` → `@{ Success; Win32Error; Flags; BadPasswordCount; PasswordAgeSeconds }` | `NetUserGetInfo` level 3 (never reads a password) |
| `Set-CrUserFlags -UserName -Flags <int>` | `NetUserSetInfo` level 1008 |
| `Invoke-CrNetPasswordChange -UserName -OldSecret -NewSecret` | `NetUserChangePassword(<computer name>, user, old BSTR, new BSTR)` — a *change* (keeps DPAPI, D9); 86 = wrong old password, 2245 = policy/history/min age |
| `Invoke-CrNetPasswordReset -UserName -NewSecret` | `NetUserSetInfo` level 1003 (reset, DPAPI warning is the caller's job) |
| `Add-CrLocalGroupMemberSid -GroupName -MemberSid` / `Remove-CrLocalGroupMemberSid -GroupName -MemberSid` | `NetLocalGroupAddMembers` / `NetLocalGroupDelMembers` level 0 (SID); 1378 (already a member) / 1377 (not a member) count as success |
| `Grant-CrAccountRight -Sid -Right` | `LsaAddAccountRights` (adds only; never removes rights, PLAN §7.3) |
| `Set-CrLsaSecret -Name -Secret` / `Remove-CrLsaSecret -Name` | `LsaStorePrivateData` with the BSTR as `LSA_UNICODE_STRING.Buffer` (Length = chars × 2) / with `NULL`; `STATUS_OBJECT_NAME_NOT_FOUND` on delete = success. Never `LsaRetrievePrivateData`. |
| `Set-CrServiceLogonPassword -ServiceName -Account -Secret` | `OpenSCManagerW` + `OpenServiceW(SERVICE_CHANGE_CONFIG)` + `ChangeServiceConfigW(SERVICE_NO_CHANGE ×3, NULL…, lpServiceStartName = Account, lpPassword = BSTR, NULL)` |

## Adapters.ps1 (the only plaintext boundary)

| Function | Does |
|---|---|
| `Invoke-CrTaskRegistrationAdapter -Folder <COM ITaskFolder> -TaskName -Definition <COM> -UserId -Secret -LogonType <int> -Sddl` → `@{ Success; Error }` | `RegisterTaskDefinition(TaskName, Definition, 4 /*TASK_UPDATE*/, UserId, $plainPassword, LogonType, Sddl)` |
| `Set-CrComPlusPasswordAdapter -Application <COM catalog object> -Secret` → `@{ Success; Error }` | `Application.Value('Password') = $plainPassword` (the caller calls `SaveChanges`) |

## Journal.ps1 (run journal, PLAN §7.10)

Stored as `<log root>\journal.clixml` (`Export-Clixml -Path` / `Import-Clixml -Path`), rewritten after every step.
`@{ Runs = @( @{ RunId; Started; Finished = $bool; Accounts = @{ <SID> = @(<step names>) } } ) }`. Step names: `PreSteps`, `CcpCleared`, `CcpRestored`, `Unlocked`, `Secret`, `Dependents`, `Grants`, `Verified`, `AutoLogon`, and (v10) `Created`, `Enabled`, `Disabled`, `DependentsMoved`.

| Function | Returns |
|---|---|
| `Open-CrJournal -Root -Trusted <bool>` | journal hashtable; empty when the file is missing, unreadable or `-Trusted:$false` (Log.ps1 `JournalTrusted`) |
| `Start-CrJournalRun -Journal -RunId` / `Add-CrJournalStep -Journal -RunId -Sid -Step` / `Complete-CrJournalRun -Journal -RunId` | saves after each call |
| `Test-CrJournalStepInUnfinishedRun -Journal -Sid -Step [-ExceptRunId]` → bool | true if any *unfinished* run other than the current one recorded the step |

## Secrets.ps1 (prompting and probe, PLAN §6 steps 6–7)

| Function | Returns |
|---|---|
| `Read-CrSecureHost -Prompt` → SecureString | `Read-Host -AsSecureString` (separate for mocking) |
| `Get-CrNameTokens -Names <string[]>` → string[] | split on `, . - _ #`, space, tab; tokens of 3+ chars (D15) |
| `Test-CrSiteRules -Secret -Config -Names <string[]>` → `@{ Ok; Reasons = @() }` | `SitePasswordRules` (MinLength, RequireComplexity) via `Test-CrSecretComplexity` |
| `Read-CrSlotSecrets -Config -Resolved -State -Only` → hashtable slot → `@{ Slot; Skipped; NewSecret; Accounts = @(@{ Sid; Name; OldSecret; Reapply }) }` | new password twice (`Test-CrSecretEqual`), checks (site rules, local policy per account, slot `MaxLength`), old password per account with "same as previous? (Y/N)", empty new password → confirm skip; `Reapply` = new equals old (D20). Rotate-mode Windows slots only, in `Order`, honouring `-Only` and blocked slots. |
| `Invoke-CrCredentialProbe -State -Account <resolved account> -OldSecret -NewSecret -Journal -RunId` → `@{ Sid; Name; Outcome; LogonType; Fallback; Win32Error; Attempts }` | Outcome: `Old`, `New`, `Reapply`, `BothFailed`, `Unverifiable`, `Locked` (no attempt), `BudgetExceeded`, `Disabled`. D12: before each attempt re-read `Get-CrUserInfo`; attempt only if threshold is 0 or `BadPasswordCount + 2 < threshold` (`Test-CrProbeBudget`; strict rule, v10.4). D16 type via `Select-CrProbeLogonType`. Error 1385 (logon type not granted) proves nothing about the password: outcome `Unverifiable`; the apply then uses the change path, where `NetUserChangePassword` itself validates the old password (one more budgeted attempt). Further mappings: 1327 (account restriction) → `Unverifiable`; 1330/1907 (expired / must change) → the password is valid; 1909 → `Locked`; 1331 → `Disabled`; `Get-CrUserInfo` failing → `Unverifiable` without an attempt; an unknown lockout threshold counts as 3. `Read-CrSlotSecrets` takes `-BlockedSlots` (Preflight's map) and returns per slot also `Label`, `Reason`, `Findings`. Order: new first if `Test-CrJournalStepInUnfinishedRun … -Step Secret`, else old first; the second test only if the first failed. |
| `Confirm-CrYes -Prompt` → bool | exact `YES` (case-sensitive) |

## Write side of existing modules

| Module | Function | Contract |
|---|---|---|
| Accounts.ps1 | `Invoke-CrPasswordRotation -User -OldSecret -NewSecret -Path <'Change'\|'Reset'> -Journal -RunId` → `@{ Success; Win32Error; Message }` | pre-steps: unlock if locked (journal `Unlocked`), clear CCP if set (journal `CcpCleared`); then `Invoke-CrNetPasswordChange` or `-Reset`; then restore CCP (journal `CcpRestored`) even on failure; journal `Secret` on success |
| Accounts.ps1 | `Set-CrAccountFlags -User -Role` → `@{ Changed; Success; Win32Error }` | reads `Get-CrUserInfo`, sets 0x10000 (PNE) / 0x40 (CCP) as the role asks, clears 0x20 when `PasswordRequired`; writes only when different |
| Accounts.ps1 | `Unlock-CrAccount -UserName` | clears 0x10 via `Set-CrUserFlags` |
| Groups.ps1 | `Invoke-CrGroupMembershipChange -State -MemberSid -AddGroupSids -RemoveGroupSids` → array of `@{ GroupSid; GroupName; Action; Success; Win32Error }` | group name from `$State.Groups` by SID |
| Rights.ps1 | `Grant-CrDependentRights -Sid -Rights <string[]>` → array of results | only `SeServiceLogonRight` / `SeBatchLogonRight` |
| Services.ps1 | `Update-CrServiceCredentials -State -Sid -Secret` → array of `@{ Name; Success; Win32Error }` | every service whose `StartNameSid` = Sid; keeps the existing StartName text; never starts/stops (D17) |
| Tasks.ps1 | `Update-CrTaskCredentials -State -Sid -Secret` → array of `@{ Path; Success; Error }` | password-stored tasks (LogonType 1/6) of the Sid; keeps UserId, LogonType and the task SDDL (`GetSecurityDescriptor(0xF)`); calls the adapter |
| ComPlus.ps1 | `Update-CrComPlusCredentials -State -Sid -Secret` → array of `@{ Name; Success; Error }` | server applications with `IdentitySid` = Sid; adapter + `SaveChanges`; no shutdown/start (D17) |
| AutoLogon.ps1 | `Invoke-CrAutoLogonAction -Decision -State -Secret` → `@{ Success; Steps = @(); Error }` | PLAN §7.5 "Actions" in the crash-safe order; registry through mockable `Set-CrWinlogonValue -Name -Value -Kind` / `Remove-CrWinlogonValue -Name`; LSA through `Set-CrLsaSecret` / `Remove-CrLsaSecret`; `-Secret` is the target account's (new) secret, `$null` for TurnOff |

## Apply.ps1 and the entry point

- `Invoke-CrApply -State -Config -Resolved -Preflight -Plan -SlotSecrets -Probes -Journal -RunId -Only -RunningSid` → `@{ Findings = ArrayList; Slots = @(@{ Slot; Status ('Done'|'Failed'|'Skipped'|'Blocked'|'NotApplicable'); Pending = @(); Errors = @() }); ExitCode }`.
  Slots in ascending `Order`; per slot the steps of PLAN §8 (pre-steps, secret — skipped for `New`/`Reapply`, dependents, grants incl. flags and adds, verify with `Invoke-CrLogonTest` using the probe's logon type). Then the enforcement phase: removals (with rails), the auto-logon step (`Get-CrAutoLogonDecision` with the accounts actually verified, then `Invoke-CrAutoLogonAction`), check-mode fixes. A failing slot stops at that step and is reported with what is done/pending; other slots continue. Exit code: 1 if any slot failed, 4 if follow-ups (LOGINS for accounts whose password changed, IIS), else 0.
- Entry point with `-Apply`: audit as before → stop with 2 if `MachineBlocked` → `Read-CrSlotSecrets` → probes → print the plan, the probe outcomes and the high-impact items → `Confirm-CrYes` (else exit 3) → `Invoke-CrApply` → report + CSV → re-audit summary (drift left) → exit code. All secrets are disposed (`.Dispose()`) at the end.

# v10: account model (D18, D21–D25; PLAN v10.4) — supersedes the M2 parts above where they conflict

PLAN v10.4: §1, §1.1, D9, D18, D20–D25, §5 config example, §6 steps 6–7, §7.5, §8 slot order and enforcement phase. History: v10 introduced `SOP-Admin`/`PUB-User` as created target accounts; v10.1 returned the auto-logon accounts to the v9 model; v10.2 dropped `SOP-Admin` and kept `BiCA Admin`/`BiCA Remote`; v10.3 creates missing BiCA accounts; v10.4 records the decisions on review round 12 (always move dependents to `ApplicationUser`, no move to a created account, strict budget, no `-LogPath`).

## Config (Config.ps1, config/CredentialRotation.psd1)

- Roles: `Admin`, `AdminRemote` (Administrators + `Name:Offer Remote Assistance Helpers?`; Remote Desktop Users allowed, never added), `User`, `WinUser`, `Ftp`. `RotateOnly` and `Operator` are gone.
- Slots, in `Order`: `BiCAAdmin` 10, `AppUser` 20, `AutoLogon` 30, the 3 SQL slots 40–60, `BiCARemote` 90 (last, D25).
- Account keys of managed (Rotate) Windows entries:
  - `Create` (bool; single `Name` only; not with `AutoLogon`)
  - `Replaces` (string[]: names or `RID-500`)
  - `PasswordMode` (`'Set'` default | `'Change'`)
  - `Operator` (bool; single `Name`; at most one entry: the operator's account, D25)
  - `EnableIfDisabled` (bool: an existing disabled account is enabled; in the default config only `AppUser`)
- `Mode` values: `'Check'` | `'Disable'` (a `Disable` entry has `Name`/`Names`, no Role/Credential). `Candidates` stays supported but the default config doesn't use it.
- Top-level `OtherEnabledAccounts = 'Ask'` (only value).
- The `AutoLogon` entry: `Names = @('PUB-User','WinAutoUser')`, `AutoLogonUser = @( @{ Name = 'PUB-User' }, @{ Name = 'WinAutoUser' } )` (only key: `Name`), the `AutoLogon` block, `Services`/`ScheduledTasks`/`ComPlus = 'Auto'`.
- Validation:
  - `Replaces` entries are names or `RID-500`; a name may be replaced by one entry only.
  - A `Disable` entry has no Role/Credential.
  - `PasswordMode` only on Windows entries with a Credential.
  - `AutoLogonUser` must list exactly the entry's `Name`/`Names`.
  - An auto-logon account must not be in any `Replaces` or `Disable` entry.
- `Get-CrConfigSlotNames -Config` → slot names; `Get-CrUnknownOnlySlots -Config -Only` → the `-Only` names that are no slot (case-insensitive). The entry point exits 2 when there are any.

## Resolution (Principals.ps1)

Resolved entries gain:
- `Create` = `$true` when the entry has `Create` and its account doesn't exist (then `Accounts` holds one placeholder `@{ Name; Sid = $null; User = $null; ToCreate = $true }`, `NotApplicable = $false`, `Missing` empty)
- `PasswordMode`, `Operator`, `EnableIfDisabled` (bools from the entry; `$false` for non-Rotate entries)
- `Replaced = @(@{ Name; Sid; User; Enabled })` — existing accounts named in `Replaces` (RID-500 via the machine SID); a replaced account that is already disabled is listed with `Enabled = $false`
- For `Mode = 'Disable'` entries: `Mode = 'Disable'`, `Accounts` = the existing ones
- `Get-CrOtherEnabledAccounts -State -Resolved` → array of State users that are enabled and not selected by any entry (managed, replaced, disable, check). Built-in disabled accounts never appear (they're disabled).

Helpers (Plan.ps1, used by Apply.ps1 too): `Get-CrOperatorAccountName -Resolved -Fallback` (the `Operator` entry's account), `Test-CrAppUserEntry -Entry` (`$true` for the entry with `Replaces`: the application account, target of the dependents of retired and operator-disabled accounts, D24), `Test-CrEntryCreated -Entry` (`$true` if the entry has a `ToCreate` placeholder), `Get-CrMovableDependentCount -State -Sid`.

## Audit findings (Plan.ps1)

`New-CrPlan` adds:
- `Drift` "Create <name>" for `Create`, plus `Info` "no Windows login in SQL Server" when SQL Server is installed
- for a disabled managed account: `Drift` "Enable the account" only with `EnableIfDisabled`; otherwise `Info` "stays disabled", and it doesn't count as verified for the auto-logon decision
- `Drift` "Disable <name> (replaced by X)" per enabled replaced account and per enabled `Disable` account
- `HighImpact` "Move <service/task/COM+> from <old> to <target>" per dependent of an account to be disabled (D24): the replacement, or `ApplicationUser` for retired and other accounts (v10.4)
- `HighImpact` "Not disabled: <target> is created in this run …; migrate them manually (D24)" instead of the disable and move findings, when the target account is created in this run and the account has movable dependents
- `Ambiguous` "Operator decides: disable or keep <name>" per other enabled account (D23); the detail lists its dependents, which move to `ApplicationUser` if it is disabled
- `HighImpact` "the running account <name> is disabled at the end; log on as <operator> next time" when the running account is to be disabled (D25)
- `HighImpact` for an unreadable task folder (dependents there unknown)
- no probe-type finding for set accounts
- dependents are managed per kind by `Services` / `ScheduledTasks` / `ComPlus = 'Auto'`

## Preflight.ps1

- `Get-CrDependentDiscoveryErrors -State` → `'Section: message'` per failed `Services`/`Tasks`/`ComPlus` discovery section.
- If there are any, `Invoke-CrPreflight` blocks every Windows slot and adds a `Blocked` finding "no account is disabled in this run". `Get-CrApplyDisablePlan` then plans no disabling.

## Native.ps1

- `New-CrLocalUser -UserName -Secret -Comment` → `@{ Success; Win32Error }`: `NetUserAdd` level 1 (`USER_PRIV_USER`, flags `UF_SCRIPT | UF_DONT_EXPIRE_PASSWD | UF_PASSWD_CANT_CHANGE`), password as BSTR. 2224 (exists) = failure with that code.
- Disable/enable = `Set-CrUserFlags` with `0x2` (`UF_ACCOUNTDISABLE`) set/cleared.

## Accounts.ps1

- `New-CrManagedAccount -Name -Secret -Comment` → result (calls `New-CrLocalUser`; journal step `Created` for the new SID).
- `Invoke-CrPasswordSet -User -NewSecret -Journal -RunId` → `@{ Success; Win32Error; Message }`: unlock if locked, `Invoke-CrNetPasswordReset`, journal `Secret`. (`Invoke-CrPasswordRotation` remains for `PasswordMode = 'Change'`.)
- `Disable-CrAccount -User -Journal -RunId` / `Enable-CrAccount -User` → result (flags `0x2`; journal `Disabled`). Only an existing disabled account of an entry with `EnableIfDisabled` is enabled, after its password step.

## Dependents (Services.ps1, Tasks.ps1, ComPlus.ps1, Adapters.ps1)

- `Move-CrServiceAccount -State -FromSid -ToAccount '.\<name>' -Secret` → per-service results (`ChangeServiceConfigW` with the new account and password; never start/stop).
- `Move-CrTaskAccount -State -FromSid -ToUserId '<COMPUTER>\<name>' -Secret` → per-task results (LogonType and SDDL kept; adapter with the new UserId).
- `Move-CrComPlusIdentity -State -FromSid -ToIdentity '<name>' -Secret` → per-app results. `Set-CrComPlusPasswordAdapter` gains an optional `-Identity` (sets `Identity` before `Password`).
- Tasks: if `RegisterTaskDefinition` fails with an SDDL that contains a SACL, retry once with the `0x7` SDDL (owner, group, DACL) and report the dropped SACL.

## Secrets.ps1

- `Read-CrSlotSecrets`:
  - new password twice per slot; one prompt for all accounts of a slot (the auto-logon slot: every existing `PUB-User`/`WinAutoUser`)
  - old password **only** for accounts with `PasswordMode = 'Change'` that exist; created and set accounts get no old-password prompt
  - `Reapply` only for Change accounts (Set accounts: setting the same value is harmless)
  - a failing `Test-CrLocalPasswordPolicy` call (no `Status`, or an exception) is a warning, not a rejection (`Get-CrNewSecretProblems`, v10.4); only a policy verdict rejects
  - the checks apply to a re-apply too (confirmed v10.4)
  - the names for the D15 tokens are every configured name of the slot: existing accounts, accounts to be created, and the entries' `Missing` names (`Read-CrOneSlotSecret -ExtraTokenNames`, `Get-CrNewSecretProblems -ExtraNames`)
  - disabled accounts are listed as "disabled, stays disabled" or, with `EnableIfDisabled`, "will be enabled"
- `New-CrSlotAccount` returns also `Disabled` and `Enable`.
- `Read-CrOtherAccountDecisions -Accounts` → hashtable SID → `'Disable'|'Keep'` (D23; asked before the password prompts).
- `Invoke-CrCredentialProbe` is only called for Change accounts.

## AutoLogon.ps1

- `Get-CrAutoLogonDecision -State -Resolved -Config -VerifiedSids -RemovedAdminSids` (no `-CreatedTargetNames`; `TargetCreated` is gone):
  - The managed auto-logon accounts are the `AutoLogonUser` list (`PUB-User`, `WinAutoUser`).
  - An active auto-logon as one of them is **kept** on every machine: `Standardize` if usable and verified, `NoChange` if usable but not on a new secret, `Ambiguous` if not usable.
  - Any other account → `TurnOff` (SM) or `Switch` to the first usable account of the list (other machines; `Ambiguous` if none, or if the target isn't verified).
  - `OperatorOptions` are `TurnOff` and `LeaveUnchanged` only (`StandardizeCurrent` is gone).
- `Test-CrAutoLogonUsable -State -User -RemovedAdminSids` (no `-VerifiedSids`): a disabled account is never usable, because the auto-logon accounts are never enabled (D21).
- `Invoke-CrAutoLogonAction` has no `StandardizeCurrent` action. `Switch` starts with step `AutoAdminLogonOff` (v10.4), then the Standardize steps (with `RemoveAutoLogonSID`) and `AutoAdminLogonOn` last.

## Apply.ps1 / entry point

- Entry `-Apply` order: audit → print the enabled local accounts (D21) with what happens to each → `Read-CrOtherAccountDecisions` → `Read-CrSlotSecrets` → probe (Change accounts only) → summary → YES → `Invoke-CrApply`. There is no operator decision on dependents any more (`Read-CrDependentDecisions` and `-DependentDecisions` are gone, v10.4).
- Per slot:
  1. create (if `Create`; the group memberships are re-read afterwards)
  2. set or change
  3. enable if disabled and `EnableIfDisabled`
  4. grants (flags, groups, rights)
  5. dependents (own)
  6. verify (`Invoke-CrLogonTest`, D16 type), within the D12 budget: `Invoke-CrApplyLogonTest` calls `Test-CrApplyBudget` (same rule as `Test-CrProbeBudget`) first and returns `Skipped`, `Budget = $true` when it forbids the logon (`HighImpact` "Not verified (lockout budget)")
  
  A disabled account is not logon-tested (reported "cannot be verified"). When a slot stops after step 2, the accounts already on the new password are still logon-tested (`Invoke-CrApplyVerifyOnNew`).
- Enforcement per PLAN §8:
  1. removals
  2. dependent moves (D24; only to a verified replacement, or to `ApplicationUser` for retired and operator-disabled accounts; never to an account created in this run or in an earlier unfinished run per the journal step `Created` — the account then stays enabled)
  3. auto-logon step (a kept account that got a new password but couldn't be verified → `HighImpact` "auto-logon broken until re-run")
  4. disabling: replaced + `Disable` entries + operator-chosen others. Never the running account. An account stays enabled if one of its dependents couldn't be moved or it is still the auto-logon account. Nothing is disabled while dependents are unknown.
  5. check-mode fixes
  6. **running account last (D25)**, only if it is itself to be disabled, and the `Operator` entry's account (`Get-CrApplyOperatorEntry -Resolved`) is not the running account and is enabled, in Administrators, verified and holds an effective `RemoteInteractive` right (`Get-CrEffectiveLogonRights`).
- `Get-CrApplyAppUserEntry -Resolved`: the managed entry with `Replaces` (`Test-CrAppUserEntry`).
- `Find-CrApplyUserByName` ignores a `X\` prefix (e.g. `.\Bica Admin` in `DefaultUserName`).
- Follow-ups: LOGINS for accounts whose password changed or was created; `RDP` "Update the saved RDP credentials" for the `Operator` entry's account after its set (v10.4); IIS as before; "log on as <operator> next time" after D25.
- `Get-CrApplyDisablePlan -State -Resolved -Preview -RunningSid -Only -OtherDecisions` (no `-DependentDecisions`): items without `NeedsDecision`/`Decision`; `MoveEntry` = the replacement entry, or the application entry for `Disable` and `Other` items with dependents; `Planned = $false` with a reason when the move target is created in this run (`Test-CrApplyEntryCreated -Preview -Entry`).
- Exit code (v10.4): 1 also when a selected slot ends `Skipped` or `Blocked`, except the SQL slots of this version (`Unsupported = $true`); `Invoke-CrApply` returns `NotAppliedSlots`. Exit 1 also when a verification was skipped by the D12 budget (`VerifyIncomplete`). An account kept enabled because its move target is created in this run (`MigrateManually` on the disable item) gets a `FollowUp` "Migrate ... manually, then disable it (D24)". The entry point completes the journal run only when the exit code is not 1, so a partial run stays unfinished for the re-run (D11).

- **ForceGuest (D16):** when `State.Policy.ForceGuest` is `True`, `Select-CrProbeLogonType` must not choose `Network` (Windows may map a local network logon to Guest, which would accept any password); it uses the next allowed type, or `Unverifiable` if none.
