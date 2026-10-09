# Module contracts

Developer reference for `src/` at version 0.4.0 (PLAN v10.4). The design is in `docs/PLAN.md` (decisions D1–D25); this file fixes module ownership, the shared data model and the function contracts. Change a contract only together with every caller and its tests.

Notation: `→` gives the return value. *Comma-returned* means the function ends with `return , $array` (§3). A *result* is a hashtable with `Success` and error codes, never secret material.

## 1. Layout and ownership

```
src/Start-CredentialRotation.cmd   launcher (PLAN §3)
src/CredentialRotation.ps1         entry point: parameters, lib loading, audit and apply flow, exit codes
src/lib/Compat.ps1                 shared helpers (SID/name, registry, findings, arrays)
src/lib/Log.ps1                    log folder and its ACL, log file, CSV, console report
src/lib/Config.ps1                 load and validate the .psd1
src/lib/Native.ps1                 Add-Type C# 2.0 (LSA, netapi32, LogonUserW, SCM) + PowerShell wrappers
src/lib/Adapters.ps1               the only plaintext boundary (D4): Task Scheduler and COM+ password setters
src/lib/Journal.ps1                run journal (PLAN §7.10)
src/lib/Secrets.ps1                prompts, password checks (D15), D23 decisions, credential probe
src/lib/Accounts.ps1               local users: read; create, set/change, enable/disable, flags
src/lib/Groups.ps1                 local groups: read; membership changes by SID
src/lib/Rights.ps1                 token model, effective logon rights, D16 logon type, grants
src/lib/Principals.ps1             selection rules, resolution, SID overlap, other enabled accounts, group references
src/lib/Services.ps1               services: read; password update and account move
src/lib/Tasks.ps1                  scheduled tasks: read; re-registration and account move
src/lib/ComPlus.ps1                COM+ applications and DCOM RunAs: read; COM+ password update and identity move
src/lib/IisReport.ps1              IIS identities (report only)
src/lib/Sql.ps1                    SQL Server default instance (read only)
src/lib/AutoLogon.ps1              Winlogon read, D18 decision, auto-logon actions
src/lib/Preflight.ps1              computer, policy, write filter (D19), preflight checks
src/lib/Plan.ps1                   desired vs actual -> findings
src/lib/Apply.ps1                  -Apply: preview, slots, enforcement phase, exit code, summaries
config/CredentialRotation.psd1     default config (PLAN §5)
build/Build.ps1                    bundle into dist\
build/Test-Ps2Syntax.ps1           PS 2.0 syntax and D4 lint
tests/Invoke-Tests.ps1, tests/Fixtures.ps1, tests/<Module>.Tests.ps1
```

The entry point dot-sources the lib files in this order: Compat, Log, Config, Native, Adapters, Journal, Secrets, Accounts, Groups, Rights, Principals, Services, Tasks, ComPlus, IisReport, Sql, AutoLogon, Preflight, Plan, Apply. A lib file only defines functions and script variables; it runs nothing at load time (Native compiles its C# only in `Initialize-CrNative`). Calls between lib files resolve at run time, so a file may call functions of a later one.

`build/Build.ps1` replaces the block from the line `# <CR-LIB-IMPORT>` to the line `# </CR-LIB-IMPORT>` with the lib files in the same order (its own copy of the list), each wrapped in `#region lib\<file>`. A lib file must not contain the marker.

## 2. Secret handling (D4)

- A secret is a `[System.Security.SecureString]`. Parameters holding one are named `-Secret`, `-OldSecret` or `-NewSecret` (`-A`/`-B` in `Test-CrSecretEqual`).
- `Native.ps1` turns a SecureString into a BSTR (`ConvertTo-CrBstr`), passes the `IntPtr` to C# and zero-frees it in `finally` (`Clear-CrBstr` = `ZeroFreeBSTR`). The C# takes `IntPtr` (a BSTR is a valid null-terminated `LPWSTR`), never builds a managed string from it and never puts secret material into exception messages.
- Only `src/lib/Adapters.ps1` turns a secret into a managed string (Task Scheduler and COM+ accept nothing else). Variables holding it are named `$plain*` and set to `$null` right after use.
- Never print, log, export or compare secrets in PowerShell; never put them into hashtables that are logged; never pass them on a command line or to an external program; no `Invoke-Expression`. Comparison, length and complexity checks run in C# over BSTRs.
- Results carry success flags and Win32, NET_API or HRESULT codes only. A complexity result says *that* a name token occurs, never *which* one.
- Slot secrets (`Read-CrSlotSecrets`) and apply preview items hold SecureString references and are never logged. The entry point disposes every secret at the end (`Clear-CrSlotSecrets`, also after Ctrl+C or an error).
- Lint rules (`build/Test-Ps2Syntax.ps1`): `D4-PlainVariable` (`$plain*` outside Adapters.ps1), `D4-PlainArgument` (`$plain*` as a command argument), `D4-SecretOutput` (a variable named `*password*`, `*secret*` or `plain*` reaching `Write-Host`, `Write-CrLog`, `Export-Csv` and similar), `D4-SecretExternal` (such a variable on an external command line), `D4-InvokeExpression`.

## 3. Conventions and shared helpers

- Data is plain hashtables and arrays (D1). A function that returns an array ends with `return , $array`: assign the result or use it in parentheses (`(ConvertTo-CrArray $x) -contains $y`); never wrap the call in `@()` or pipe it, which nests the array (lint rule `Cr-ArrayHelper` for `ConvertTo-CrArray`).
- Discovery functions return their part even when an expected item is absent. A part that throws becomes `@{ Error = '<message>' }` in `$State` (§4.1).
- Write functions return a result and throw only on invalid arguments or when the native helpers are unavailable.
- Principals are compared by SID. Names are for display, and for the Windows APIs that take one (the current name from `$State.Users`).

Compat.ps1:

| Function | Returns |
|---|---|
| `ConvertTo-CrSidString -Bytes <byte[]>` | SID string or `$null` |
| `Resolve-CrSidToName -Sid` | `DOMAIN\Name` or `$null` |
| `Resolve-CrNameToSid -Name` | SID string or `$null`. A SID string is returned as is; `LocalSystem` → S-1-5-18; `.\x` → `<COMPUTER>\x`; a name without `\` is tried as `<COMPUTER>\name` first, then as given (`NT AUTHORITY\…`, built-in groups) |
| `Get-CrRegistryValue -Path -Name` | `@{ Exists; Value; Kind }`; `Kind` = the `RegistryValueKind` name (`String`, `DWord`, `ExpandString`, …) or `$null` |
| `Test-CrBuiltinServiceSid -Sid` | `$true` for S-1-5-18/19/20, S-1-5-80-*, S-1-5-82-* |
| `New-CrFinding -Severity -Area -Message [-Slot] [-Account] [-Detail]` | finding (§4.4); `Severity` is validated |
| `Get-CrInnermostMessage -ErrorRecord` | message of the innermost exception |
| `ConvertTo-CrArray -Value` | always an array; `$null` → empty (comma-returned) |

## 4. Data model

### 4.1 The machine state (`$State`)

`Get-CrMachineState -Config` (entry point) builds it one section at a time; it is built again for the re-audit after `-Apply`. A section that throws becomes `@{ Error = '<message>' }` and is added to `Errors`.

```powershell
$State = @{
  Computer    = Get-CrComputerInfo -Config $Config   # Preflight.ps1
  Policy      = Get-CrPasswordPolicy                 # Preflight.ps1 (Native + secedit + registry)
  WriteFilter = Get-CrWriteFilterState               # Preflight.ps1
  Users       = Get-CrLocalUsers                     # Accounts.ps1   array
  Groups      = Get-CrLocalGroups                    # Groups.ps1     array
  Rights      = Get-CrLsaRightsMap                   # Native.ps1     hashtable
  Services    = Get-CrServices                       # Services.ps1   array
  Tasks       = Get-CrScheduledTasks                 # Tasks.ps1      array
  ComPlus     = Get-CrComPlusApplications            # ComPlus.ps1    array
  Dcom        = Get-CrDcomRunAs                      # ComPlus.ps1    array
  Iis         = Get-CrIisIdentities                  # IisReport.ps1
  Sql         = Get-CrSqlState                       # Sql.ps1
  AutoLogon   = Get-CrAutoLogonState                 # AutoLogon.ps1
  Errors      = ArrayList of @{ Section; Message }   # failed sections
}
```

A failed `Users`, `Groups`, `Rights` or `Computer` section stops the run with exit 2 (`Get-CrCriticalDiscoveryError`). A failed `Services`, `Tasks` or `ComPlus` section blocks every Windows slot and every disable (§5.15). `Invoke-CrApply` updates `Users` and `Groups` in place as it works.

Shapes (every key is present; `Error` is `$null` unless something failed):

- **Computer**: `@{ Name; IsSm; OsVersion ('6.1.7601'); OsCaption; Is64BitOs; Is64BitProcess; PSVersion ('2.0'); ClrVersion; LanguageMode; IsElevated; PartOfDomain; MachineSid; SystemDrive ('C:'); Error }`. `IsSm` = `Name` matches the auto-logon block's `RestrictedComputerPattern` (case-insensitive; `'^SM'` without such a block). `MachineSid` is `$null` when it can't be read.
- **Policy**: `@{ MinPasswordLength; MaxPasswordAgeSeconds; MinPasswordAgeSeconds; PasswordHistoryLength; LockoutThreshold; LockoutDurationSeconds; LockoutObservationSeconds; ComplexityEnabled; ForceGuest; ComplexityError; Error }`. Numbers are `[int]`/`[long]`; `-1` = never (maximum age) or until an administrator unlocks (duration). `ComplexityEnabled` (from `secedit /export`) and `ForceGuest` (`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\forceguest`; absent = `$false`) are `$true`, `$false` or `$null` (unknown). `Error` = `NetUserModalsGet` failed.
- **Users** (array): `@{ Name; Sid; Rid ([int]); FullName; Flags (raw UserFlags); Disabled; LockedOut; PasswordNeverExpires; CannotChangePassword; PasswordNotRequired; PasswordAgeSeconds; BadPasswordCount; Error }`. A user that can't be read keeps only `Name` and `Error`. `LockedOut` comes from `IsAccountLocked`, else from `UF_LOCKOUT`.
- **Groups** (array): `@{ Name; Sid; MemberSids = @(<sid>); Error }`. Members come from `NetLocalGroupGetMembers` level 0 (D5), never from ADSI. `Error` is set when the members or the group SID can't be read.
- **Rights**: hashtable right name → array of SIDs (possibly empty) for exactly `SeNetworkLogonRight`, `SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeBatchLogonRight`, `SeServiceLogonRight` and the five matching `SeDeny…LogonRight` rights.
- **Services** (array, services with a StartName): `@{ Name; DisplayName; StartName; StartNameSid; StartMode; State; PathExecutable; DependentServices = @(); DependsOn = @() }`. `PathExecutable` is the executable only, never its arguments.
- **Tasks** (array, every folder, hidden tasks included): `@{ Path; UserId; UserSid; LogonType ([int]); Enabled; Error }`. Only tasks whose principal has a `UserId`, isn't a group (LogonType 4) and isn't a built-in service SID. An unreadable task or folder is an entry with `Path` and `Error` only.
- **ComPlus** (array): `@{ Name; Id; Activation ('Library'|'Server'); Identity; IdentitySid; IsEnabled; IsSystem }`. Built-in identities are compared as strings, never resolved; their `IdentitySid` is `$null`, as for names that don't resolve.
- **Dcom** (array, both registry views): `@{ View; AppId; Name; RunAs; RunAsSid }`, without `Interactive User` and built-ins.
- **Iis**: `@{ Installed; Version; Error; AppPools = @(@{ Name; IdentityType; UserName; UserSid }); VirtualDirectories = @(@{ Site; Application; Path; PhysicalPath; UserName; UserSid; Protocols }) }`. Not installed = `Installed = $false` without an error. A pool's `UserSid` is resolved only for `SpecificUser`. `Protocols` = the site's binding protocols (e.g. `ftp`).
- **Sql** (default instance only): `@{ DefaultInstancePresent; ServiceName; ServiceState; ServiceAccount; ServiceAccountSid; OtherInstances = @(); Connected; Error; MajorVersion ([int]); ProductVersion; Edition; IsExpress; IsIntegratedSecurityOnly; ConnectedAs; ConnectedAsSysadmin; Logins = @(); MasterFiles = @(<path>); AgentJobs = @(@{ Name; Owner; Enabled }); Credentials = @(@{ Name; Identity }); Proxies = @(@{ Name; CredentialName; CredentialIdentity; Enabled }); LinkedLogins = @(@{ Server; LocalLogin; UsesSelfCredential; RemoteName }) }`.
  Login: `@{ Name; Type ('SQL_LOGIN'|'WINDOWS_LOGIN'|'WINDOWS_GROUP'); Sid (SID string for Windows principals, hex '0x…' otherwise); IsDisabled; IsPolicyChecked; IsExpirationChecked; IsLocked; BadPasswordCount; PasswordLastSetTime; IsSysadmin }`. A missing instance or a stopped service is no error; `Error` joins the connection error and the failed queries (`'Query: message; …'`).
- **AutoLogon**: `@{ AutoAdminLogon (string or $null); AutoAdminLogonKind ('String'|'DWord'|$null); DefaultUserName; DefaultDomainName; DefaultPasswordPresent; AutoLogonCountPresent; ForceAutoLogon; AutoLogonSidValue; OtherMechanisms = @(<text>); LegalNoticeCaptionSet; LegalNoticeTextSet; DevicePasswordLessBuildVersion; Error }`. `OtherMechanisms`: a `Shell` other than explorer.exe, extra `Userinit` programs (executables only), Sysinternals Autologon settings in a loaded user hive. The `DefaultPassword` value and the LSA secret are never read; only the presence of the value is recorded.
- **WriteFilter**: `@{ Filters = @(@{ Type ('EWF'|'FBWF'|'UWF'); DriverInstalled; StateKnown; CurrentEnabled; NextEnabled; CommitPending; ProtectedVolumes = @('C:'); Detail }); Error }`. EWF gives one entry per volume `ewfmgr` reports on, or one summary entry.

### 4.2 Configuration

`Import-CrConfig` loads the `.psd1` (PLAN §5); `Test-CrConfig` reports every key or value not listed here (`Get-CrConfigSchema`).

| Level | Keys |
|---|---|
| Top | `SchemaVersion` (= 1), `SitePasswordRules`, `Roles`, `Credentials`, `Accounts` (required); `OtherEnabledAccounts` (optional, only `'Ask'`, D23) |
| `SitePasswordRules` | `MinLength` (positive int), `RequireComplexity` (bool) (D15) |
| Role | `Groups`, `AllowedExtraGroups` (group references), `ExclusiveGroups` (needs `Groups`), `PasswordNeverExpires`, `CannotChangePassword`, `PasswordRequired` (bools), `IfGroupMissing` (`'ReportKeepGroups'`) |
| Credential (slot) | `Slot` (unique), `Order` (unique int), `Label`, `MaxLength` (positive int) |
| Account entry | `Id` (unique), `Kind` (`Windows`\|`SqlLogin`), exactly one of `Name`, `Names`, `NamePattern`, `Candidates`; `Role`, `Credential`, `Mode`, `LoginsEntry` (bool), `Services`/`ScheduledTasks`/`ComPlus`/`IisReport` (`'Auto'`), `AutoLogon`, `AutoLogonUser`, `ServerRoles` (SqlLogin only), `Create`, `Replaces`, `PasswordMode`, `Operator`, `EnableIfDisabled` |
| `Candidates` item | `Name` or `Sid` (`S-1-…` or `RID-<n>`), `Role`, `Credential` |
| `AutoLogon` block | `Mode` (`'IfAlreadyOn'`), `RestrictedComputerPattern` (regex) |
| `AutoLogonUser` item | `Name` |

Group references: `S-1-…`, `RID-<n>` (machine SID + RID), `Name:<group>` (must exist), `Name:<group>?` (optional), `Pattern:<regex>` (only in `AllowedExtraGroups`). Every regex must compile (case-insensitive). SqlLogin entries can't use the Windows-only keys.

Entry modes: without `Mode` the entry is managed (rotated) and needs `Role` (Windows) and `Credential`. `Mode = 'Check'`: flags and groups are enforced, the password is untouched, no `Credential`. `Mode = 'Disable'`: retired accounts selected by `Name`/`Names` only; no `Role`, `Credential`, `LoginsEntry`, dependent or auto-logon keys (D22).

Account-model rules (D9, D18, D21–D25):
- `Create`, `Replaces`, `PasswordMode`, `Operator` and `EnableIfDisabled` are valid on managed Windows entries only.
- `Create` (bool) needs a single `Name` and is not valid with `AutoLogon` (the auto-logon accounts are never created, D21).
- `Replaces` needs a single `Name`. Its items are account names or `RID-500`, never SIDs or other RIDs; a name is replaced by one entry at most (case-insensitive). The entry with `Replaces` is the application account (`Test-CrAppUserEntry`, D24).
- `PasswordMode` is `'Set'` (default) or `'Change'` and needs a `Credential`.
- `Operator` (bool) needs a single `Name`; one entry at most: the operator's account (D25).
- `EnableIfDisabled` (bool): an existing disabled account of the entry is enabled after its password step.
- `AutoLogon` and `AutoLogonUser` come together, on one entry at most, and `AutoLogonUser` lists exactly the entry's `Name`/`Names`.
- An auto-logon account must not be named in a `Replaces` list or a `Disable` entry.

`IfGroupMissing` and `IisReport` are validated but change nothing: a missing required group always leaves the account's groups unchanged (reported), and IIS identities are always reported.

Default config: roles `Admin`, `AdminRemote` (Administrators + `Name:Offer Remote Assistance Helpers?`; Remote Desktop Users allowed, never added), `User`, `WinUser`, `Ftp`. Slots `BiCAAdmin` 10, `AppUser` 20, `AutoLogon` 30, `SQLApplication`/`SQLScript`/`SQLService` 40–60, `BiCARemote` 90 (last, D25). Entries: `BiCA Admin` and `BiCA Remote` (`Create`; `BiCA Remote` is the `Operator`), `ApplicationUser` (`Create`, `EnableIfDisabled`, `PasswordMode = 'Change'`, `Replaces = @('RID-500')`), the auto-logon entry (`Names = PUB-User, WinAutoUser`, both in `AutoLogonUser`, `AutoLogon = @{ Mode = 'IfAlreadyOn'; RestrictedComputerPattern = '^SM' }`), the retired accounts (`Mode = 'Disable'`), `WinUser1–3` and the FTP users (`NamePattern`) in check mode, three SQL logins, `OtherEnabledAccounts = 'Ask'`. Every managed Windows entry has `Services`/`ScheduledTasks`/`ComPlus = 'Auto'`.

### 4.3 Resolved entries

`Resolve-CrAccounts -Config -State` → one entry per config entry, in config order (comma-returned):

```powershell
@{ Id; Kind ('Windows'|'SqlLogin'); Mode ('Rotate'|'Check'|'Disable'); RoleName; Role; Slot; LoginsEntry (bool)
   Accounts = @(@{ Name; Sid; User }); Missing = @(<name>); Candidate (index or $null); NotApplicable
   Create; PasswordMode ('Set'|'Change'; $null unless a Rotate Windows entry); Operator; EnableIfDisabled
   Replaced = @(@{ Name; Sid; User; Enabled }); AutoLogon; AutoLogonUser; Config (the config entry); Error }
```

- `User` is the `$State.Users` entry. For a SQL login it is the `$State.Sql.Logins` entry (only `SQL_LOGIN` logins match) and `Sid` its hex SID.
- `Slot` = the entry's or the matched candidate's `Credential`. `NotApplicable` = no account resolved.
- `Create = $true` when a Rotate entry with `Create` has missing names and the user list was read. `Accounts` then holds placeholders `@{ Name; Sid = $null; User = $null; ToCreate = $true }`, `Missing` is empty and `NotApplicable` is `$false`.
- `Operator` and `EnableIfDisabled` are `$false` on Check and Disable entries. `Replaced` (Rotate Windows entries only) lists the existing accounts named in `Replaces` (`RID-500` via the machine SID); one that is already disabled has `Enabled = $false`.
- `Error` = the `Users` section error (Windows) or the SQL error or "not connected" (SqlLogin); `Missing` then means nothing.
- `NamePattern` entries resolve last and skip every account that another Windows entry names (`Name`, `Names`, `Replaces`, candidate and `AutoLogonUser` names) or resolves without a pattern (including `Replaced`).

### 4.4 Findings

`@{ Severity; Area; Slot; Account; Message; Detail }` (`New-CrFinding`). The CSV files carry exactly these columns. Severities, in report order:

| Severity | Meaning |
|---|---|
| `Blocked` | machine, slot or step blocked or failed (reason in `Message`) |
| `Ambiguous` | needs an operator decision (D13, D23) |
| `HighImpact` | shown before `YES` (PLAN §6 steps 5 and 8) |
| `Drift` | desired ≠ actual and `-Apply` would change it (audit exit 10) |
| `FollowUp` | work outside the tool: LOGINS, IIS, saved RDP credentials, manual migration (apply exit 4) |
| `Info` | everything else worth reporting |

## 5. Modules (import order)

### 5.1 Log.ps1 (PLAN §7.10)

| Function | Contract |
|---|---|
| `Initialize-CrLog -RunId` → `@{ Root; Directory; File; JournalTrusted; Corrected }` | `Root` is always `%ProgramData%\CredentialRotation`; the log is `<Root>\logs\CredentialRotation_<COMPUTER>_<RunId>.log`. The root gets a protected DACL (owner Administrators; Administrators and SYSTEM full control), through `takeown` if needed. `JournalTrusted = $false` and `Corrected = $true` when an existing root had another owner or write access for anyone but Administrators, SYSTEM and CREATOR OWNER |
| `Write-CrLog -Message [-Level]` | appends a timestamped UTF-8 line; also `Write-Verbose` |
| `Export-CrFindingsCsv -Findings -Path` | CSV with the finding columns; nothing is written without findings |
| `Write-CrFindingsReport -Findings` | console report grouped by severity (§4.4) |

There is no log-path parameter (removed in v10.4): logs always go to `%ProgramData%\CredentialRotation`.

### 5.2 Config.ps1 (PLAN §5)

| Function | Contract |
|---|---|
| `Import-CrConfig -Path` → hashtable | `Import-LocalizedData -BindingVariable … -UICulture en-US` (PS 2.0 needs `-BindingVariable`). Throws on a missing file, a syntax error, a non-hashtable, or a copy of the file in an `en-US\` or `en\` subfolder (it would be loaded instead of the hashed file) |
| `Test-CrConfig -Config` → error strings | writes the errors to the pipeline (none = valid); callers wrap it: `$e = @(Test-CrConfig -Config $c)`. Rules in §4.2 |
| `Get-CrConfigSlotNames -Config` → string[] | slot names in file order (comma-returned) |
| `Get-CrUnknownOnlySlots -Config -Only` → string[] | the `-Only` names that are no slot, case-insensitive (comma-returned); the entry point exits 2 when there are any |
| `Get-CrRole -Config -Name` → role | throws on an unknown role. Used by the tests; resolution reads `Roles` directly |

### 5.3 Native.ps1

C# 2.0 static classes prefixed `Cr`, without a namespace: `CrNativeLsa`, `CrNativeSecret`, `CrNativeAcct`, `CrNativeSvc`, `CrNativeNet`. `Initialize-CrNative` compiles them once (`Add-Type`, skipped when the types exist), never throws and sets `$script:CrNativeReady` / `$script:CrNativeError`; the entry point calls it after the config check, before discovery. `Test-CrNativeReady` → bool. Every wrapper first calls `Assert-CrNativeReady`, which compiles on first use and throws with the compile error if that fails. Each C# method is reached through a one-line call-layer function (`Invoke-CrNative…`, `Get-CrNative…`, `Set-CrNative…`, `Add-CrNative…`, `Remove-CrNative…`) that the tests mock.

Read side:

| Wrapper | Native |
|---|---|
| `Get-CrMachineSid` → SID | `LsaQueryInformationPolicy(PolicyAccountDomainInformation)` |
| `Get-CrLsaRightsMap` → hashtable | `LsaEnumerateAccountsWithUserRight` per right of §4.1 Rights; `STATUS_NO_MORE_ENTRIES` / `STATUS_OBJECT_NAME_NOT_FOUND` = empty; other errors throw |
| `Get-CrUserModals` → `@{ MinPasswordLength; MaxPasswordAgeSeconds; MinPasswordAgeSeconds; PasswordHistoryLength; LockoutDurationSeconds; LockoutObservationSeconds; LockoutThreshold }` | `NetUserModalsGet` levels 0 and 3; `TIMEQ_FOREVER` → `-1` |
| `Get-CrLocalGroupNames` → string[] | `NetLocalGroupEnum` level 0 |
| `Get-CrLocalGroupMemberSids -GroupName` → string[] | `NetLocalGroupGetMembers` level 0 |

Secret operations and write side. The result is `@{ Success; Win32Error }` unless noted:

| Wrapper | Native |
|---|---|
| `Test-CrSecretEqual -A -B` → bool | BSTR compare in C#: length first, then every byte without an early exit |
| `Get-CrSecretLength -Secret` → int | `SysStringLen` |
| `Test-CrSecretComplexity -Secret [-MinLength 0] [-RequireComplexity $true] [-Tokens]` → `@{ Ok; TooShort; Categories ([int]); MissingCategories (names); ContainsNameToken }` | D15 emulation over the BSTR: 5 categories (upper, lower, digit, non-alphanumeric, other letters = `char.IsLetter` without case); `ContainsNameToken` = a token of 3+ characters occurs case-insensitively (`char.ToUpperInvariant`). `Ok` = long enough and, with `RequireComplexity`, 3+ categories and no token. Tokens come from `Get-CrNameTokens` |
| `Test-CrLocalPasswordPolicy -UserName -Secret` → `@{ Ok; Status; Win32Error }` | `NetValidatePasswordPolicy(NULL, NULL, NetValidatePasswordChange, { ClearPassword = BSTR, UserAccountName, PasswordMatch = TRUE })`, then `NetValidatePasswordPolicyFree`. `Status` = ValidationStatus (0 = accepted, e.g. 2245 = rejected), `$null` when the call itself failed (`Win32Error`). Without persisted fields only length, complexity and password filters are checked, not the history |
| `Invoke-CrLogonTest -UserName -Secret [-LogonType Network\|Interactive\|Batch\|Service]` | `LogonUserW(user, ".", BSTR, 3\|2\|4\|5, LOGON32_PROVIDER_DEFAULT)`; the token is closed at once. `Win32Error` = `GetLastError`: 1326 wrong password, 1327 account restriction, 1330 expired, 1331 disabled, 1385 logon type not granted, 1909 locked |
| `Get-CrUserInfo -UserName` → `@{ Success; Win32Error; Flags; BadPasswordCount; PasswordAgeSeconds }` | `NetUserGetInfo` level 3; values `$null` on failure; never reads a password |
| `Set-CrUserFlags -UserName -Flags` | `NetUserSetInfo` level 1008 (`UF_SCRIPT` always kept); also disables and enables (`0x2`) |
| `Invoke-CrNetPasswordChange -UserName -OldSecret -NewSecret` | `NetUserChangePassword(<computer name>, user, old, new)`: a change, keeps DPAPI (D9); 86 = wrong old password, 2245 = policy, history or minimum age |
| `Invoke-CrNetPasswordReset -UserName -NewSecret` | `NetUserSetInfo` level 1003 (administrative set) |
| `New-CrLocalUser -UserName -Secret [-Comment]` | `NetUserAdd` level 1: `USER_PRIV_USER`, flags `UF_SCRIPT \| UF_NORMAL_ACCOUNT \| UF_DONT_EXPIRE_PASSWD \| UF_PASSWD_CANT_CHANGE`, password = the BSTR. 2224 (exists) and 2245 (policy) are failures |
| `Add-CrLocalGroupMemberSid` / `Remove-CrLocalGroupMemberSid -GroupName -MemberSid` | `NetLocalGroupAddMembers` / `NetLocalGroupDelMembers` level 0 by SID; 1378 (already a member) / 1377 (not a member) count as success |
| `Grant-CrAccountRight -Sid -Right` | `LsaAddAccountRights`; no function of the tool removes rights (PLAN §7.3) |
| `Set-CrLsaSecret -Name -Secret` / `Remove-CrLsaSecret -Name` | `LsaStorePrivateData` with the BSTR as `Buffer` (Length = chars × 2) / with `NULL`; deleting a missing secret (2) counts as success. Never `LsaRetrievePrivateData` |
| `Set-CrServiceLogonPassword -ServiceName -Account -Secret` | `OpenSCManagerW` + `OpenServiceW(SERVICE_CHANGE_CONFIG)` + `ChangeServiceConfigW(SERVICE_NO_CHANGE ×3, NULL…, Account, BSTR, NULL)`; never starts or stops the service |

### 5.4 Adapters.ps1 (the plaintext boundary)

| Function | Does |
|---|---|
| `Invoke-CrTaskRegistrationAdapter -Folder <ITaskFolder> -TaskName -Definition -UserId -Secret -LogonType <int> -Sddl` → `@{ Success; Error; HResult }` | `Folder.RegisterTaskDefinition(TaskName, Definition, 4 = TASK_UPDATE, UserId, $plainPassword, LogonType, Sddl)`. `HResult` is `$null` on success and when COM wasn't called |
| `Set-CrComPlusPasswordAdapter -Application <catalog object> -Secret [-Identity]` → `@{ Success; Error; IdentitySet }` | with `-Identity`, `Value('Identity') = Identity` first; then `Value('Password') = $plainPassword`. The caller calls `SaveChanges`, and must not after a failure with `IdentitySet = $true` |

Both return a failed result without calling COM when the secret or the COM object is missing. `Error` holds the operation, the exception type, the HRESULT and, for Win32 HRESULTs, the system message, never the exception message (it may quote arguments); the error records of the call are removed from `$Error`.

### 5.5 Journal.ps1 (PLAN §7.10)

Stored as `<log root>\journal.clixml` (`Export-Clixml -Depth 8` to a `.tmp` file, then `File.Replace` keeping a `.bak`), rewritten after every change. It holds no secrets.
- File: `@{ Runs = @(@{ RunId; Started; Finished; Accounts = @{ <SID> = @(<step>) } }) }`. In memory: `@{ Runs = ArrayList; Path; LastSaveError }`.
- Steps: `PreSteps`, `CcpCleared`, `CcpRestored`, `Unlocked`, `Secret`, `Dependents`, `Grants`, `Verified`, `AutoLogon`, `Created`, `Enabled`, `Disabled`, `DependentsMoved`.

| Function | Contract |
|---|---|
| `Open-CrJournal -Root -Trusted <bool>` → journal | empty, but with its path, when the file is missing, unreadable or malformed or `-Trusted:$false` (`Initialize-CrLog`'s `JournalTrusted`); malformed runs and unknown steps are dropped |
| `Start-CrJournalRun -Journal -RunId` | adds the run with `Finished = $false` |
| `Add-CrJournalStep -Journal -RunId -Sid -Step` | records the step; throws on an unknown step or an empty SID |
| `Complete-CrJournalRun -Journal -RunId` | `Finished = $true` |
| `Test-CrJournalStepInUnfinishedRun -Journal -Sid -Step [-ExceptRunId]` → bool | `$true` if an unfinished run other than `-ExceptRunId` recorded the step for the SID |

Saving never throws: a failure is logged and kept in `LastSaveError`.

### 5.6 Secrets.ps1 (PLAN §6 steps 6–7)

| Function | Contract |
|---|---|
| `Read-CrSecureHost -Prompt` → SecureString; `Read-CrHostLine -Prompt` → string | `Read-Host`, separate for mocking; `Read-CrHostLine` never for secrets |
| `Confirm-CrYes -Prompt` → bool | exact `YES` (case-sensitive) |
| `Confirm-CrYesNo -Prompt` → bool | `Y`/`YES` or `N`/`NO`; three unclear answers count as No |
| `Get-CrNameTokens -Names` → string[] | split on `, . - _ #`, space and tab; tokens of 3+ characters, de-duplicated case-insensitively (D15; comma-returned) |
| `Test-CrSiteRules -Secret -Config -Names` → `@{ Ok; Reasons }` | `SitePasswordRules` through `Test-CrSecretComplexity`; the reasons never name a token |
| `Get-CrNewSecretProblems -NewSecret -Config -Accounts -SlotDefinition -ExtraNames` → string[] | site rules (tokens from every account name, full name and `-ExtraNames`), `Test-CrLocalPasswordPolicy` per account, the slot's `MaxLength`. Only a policy verdict rejects; a failed policy call (no `Status`, or a throw) is a printed and logged warning |
| `Read-CrOtherAccountDecisions -Accounts` → hashtable SID → `'Disable'\|'Keep'` | D23: one Y/N per account; anything but a clear yes keeps it |
| `Read-CrSlotSecrets -Config -Resolved -State -Only -BlockedSlots` → hashtable slot → slot secret | below |
| `Invoke-CrCredentialProbe -State -Account -OldSecret -NewSecret -Journal -RunId` → probe | below |
| `Test-CrProbeBudget -Threshold -BadPasswordCount` → bool | D12, strict rule: threshold 0 = no lockout; otherwise `BadPasswordCount + 2 < Threshold`; an unknown threshold (`< 0`) counts as 3 |

`Read-CrSlotSecrets` walks the slots in ascending `Order`. It skips slots outside `-Only` and slots without a Rotate entry that resolved an account or a placeholder.
- A SQL slot is returned skipped ("SQL rotation not available in this version", an `Info` finding) without a prompt; a slot in `-BlockedSlots` is returned skipped with `Reason = 'Blocked: …'`.
- One prompt per slot for all its accounts (the auto-logon slot: every existing `PUB-User` and `WinAutoUser`, enabled or disabled). The new password is entered twice (`Test-CrSecretEqual`) and checked by `Get-CrNewSecretProblems`, with the entries' `Missing` names as extra token names. Three tries; an empty entry asks whether to skip the slot.
- The old password is asked only for existing accounts with `PasswordMode = 'Change'`, with "same as the one entered for X? (Y/N)"; `Reapply` (D20) is set only for them. Created and set accounts get no old-password prompt.
- The account list shows "(will be created)", "(disabled, will be enabled)" with `EnableIfDisabled`, or "(disabled, stays disabled)".
- Slot secret: `@{ Slot; Label; Skipped; Reason; NewSecret; Findings; Accounts = @(@{ Sid ($null for an account created in this run); Name; OldSecret ($null unless Change); Reapply; PasswordMode; Create }) }`.

`Invoke-CrCredentialProbe` is called only for existing Change accounts (`Invoke-CrSlotProbes`). Probe: `@{ Sid; Name; Outcome; LogonType; Fallback; Win32Error; Attempts; Message }`; `Resolve-CrProbeDecisions` may add `Path = 'Set'|'Skip'`.
- Outcomes: `Old`, `New`, `Reapply`, `BothFailed`, `Unverifiable`, `Locked`, `BudgetExceeded`, `Disabled`.
- The logon type comes from `Select-CrProbeLogonType` (D16). No SID, or no usable type (ForceGuest), gives `Unverifiable` without an attempt.
- Old equal to new (D20): one test decides `Reapply` or `BothFailed`. Otherwise the new password first if `Test-CrJournalStepInUnfinishedRun … -Step Secret`, else the old one first; the second test runs only if the first failed.
- `Get-CrUserInfo` is re-read before every attempt: unreadable → `Unverifiable`; locked → `Locked`; disabled → `Disabled`; `Test-CrProbeBudget` false → `BudgetExceeded`.
- Error mapping: 1330 and 1907 (expired, must change) = that password is valid; 1385 and 1327 → `Unverifiable` (the change path validates the old password itself); 1909 → `Locked`; 1331 → `Disabled`; any other error moves on to the next password, then `BothFailed`.

### 5.7 Accounts.ps1 (PLAN §7.1)

`Get-CrLocalUsers` → Users (ADSI `WinNT://`, §4.1). The write side uses the Native wrappers; UF bits: `0x2` disabled, `0x10` locked, `0x20` password not required, `0x40` user cannot change password (CCP), `0x10000` password never expires (PNE). `Steps` lists the journal steps done; a journal failure becomes one of the `Warnings`, never an exception.

| Function | Contract |
|---|---|
| `New-CrManagedAccount -Name -Secret [-Comment] [-Journal -RunId]` → `@{ Success; Win32Error; Message; Name; Sid; Steps; Warnings }` | `New-CrLocalUser`, then the SID by name; journal `Created` (D21) |
| `Invoke-CrPasswordSet -User -NewSecret -Journal -RunId` → `@{ Success; Win32Error; Message; Steps; Warnings }` | set path (D9): unlock if locked (journal `Unlocked`; a relock right afterwards stops with 1909), `Invoke-CrNetPasswordReset`, journal `Secret` on success |
| `Invoke-CrPasswordRotation -User -OldSecret -NewSecret -Path 'Change'\|'Reset' -Journal -RunId` → `@{ Success; Win32Error; Message; Steps; CcpRestoreFailed; Warnings }` | change path (`PasswordMode = 'Change'`): unlock as above; for `Change`, clear CCP if set (journal `CcpCleared`); change or reset; CCP restored in `finally`, also after a failure (journal `CcpRestored`); journal `Secret` on success. `PreSteps` is journaled by the caller |
| `Set-CrAccountFlags -User -Role` → `@{ Changed; Success; Win32Error }` | re-reads the flags; sets PNE and CCP and clears NOTREQD as the role asks; writes only when they differ; never touches `0x2` or `0x10` |
| `Unlock-CrAccount -UserName` → `@{ Success; Changed; Win32Error }` | clears `0x10` when set |
| `Disable-CrAccount -User -Journal -RunId` → `@{ Success; Changed; Win32Error; Message; Steps; Warnings }` | sets `0x2`; groups, password and other flags stay (D22); journal `Disabled` when it changed |
| `Enable-CrAccount -User` → `@{ Success; Changed; Win32Error; Message }` | clears `0x2`; not journaled (Apply journals `Enabled`) |

### 5.8 Groups.ps1 (PLAN §7.2)

| Function | Contract |
|---|---|
| `Get-CrLocalGroups` → Groups | §4.1; throws only if the groups can't be enumerated |
| `Invoke-CrGroupMembershipChange -State -MemberSid -AddGroupSids -RemoveGroupSids` → `@(@{ GroupSid; GroupName; Action ('Add'\|'Remove'); Success; Win32Error; Message })` | adds, then removes, by SID; group names from `$State.Groups` by SID; one failure doesn't stop the others. Rails and allow-lists are the caller's job; `$State` is not updated |

### 5.9 Rights.ps1 (PLAN §7.3, D16)

| Function | Contract |
|---|---|
| `Get-CrTokenSids -UserSid -State -LogonType 'Network'\|'Interactive'\|'RemoteInteractive'\|'Batch'\|'Service'` → string[] | the account, S-1-1-0, S-1-5-11, S-1-5-113, the logon-type SIDs (Network S-1-5-2; Interactive S-1-5-4, S-1-2-0, S-1-2-1; RemoteInteractive S-1-5-14, S-1-5-4, S-1-2-0; Batch S-1-5-3; Service S-1-5-6), every local group whose members contain a token SID (repeated until stable), and S-1-5-114 if Administrators is in the token |
| `Get-CrEffectiveLogonRights -UserSid -State` → `@{ Network; Interactive; RemoteInteractive; Batch; Service }` | granted to a token SID and denied to none; a failed Rights section counts as empty |
| `Select-CrProbeLogonType -UserSid -State` → `@{ LogonType; Fallback }` | the first effective type of Network → Interactive → Batch → Service; none → `Network` with `Fallback = $true` |
| `Test-CrIsAdmin -UserSid -State` → bool | direct member of S-1-5-32-544 |
| `Grant-CrDependentRights -Sid -Rights` → `@(@{ Right; Success; Win32Error; Message })` | only `SeServiceLogonRight` and `SeBatchLogonRight` (asking for another right throws before anything is granted); deny rights are never touched |

**ForceGuest (D16):** when `State.Policy.ForceGuest` is `$true`, `Select-CrProbeLogonType` never chooses `Network`, because Windows may map a local network logon to Guest, which accepts any password. It uses the next effective type; if there is none it returns `LogonType = $null`, `Fallback = $true`, which every caller treats as unverifiable (no logon attempt).

### 5.10 Principals.ps1 (PLAN §1.1, §5, D5, D13, D21–D23)

| Function | Contract |
|---|---|
| `Resolve-CrAccounts -Config -State` → resolved entries | §4.3 |
| `Find-CrSidOverlap -Resolved` → findings | `Ambiguous` per SID claimed by two entries (D13); the accounts of every entry and its `Replaced` accounts (claimed as `<Id> (replaces)`) count |
| `Get-CrOtherEnabledAccounts -State -Resolved` → Users entries | enabled users that no Windows entry selects as an account or a replaced account (D23); disabled built-in accounts never appear |
| `Resolve-CrGroupReference -Reference -State` → `@{ Sids; Optional; Missing; Error }` | the forms of §4.2; `Missing` only for a required group that doesn't exist; `Pattern:` is optional and may match several groups; throws on an unknown form |

### 5.11 Services.ps1, Tasks.ps1, ComPlus.ps1 (dependents; PLAN §7.4, §7.7, D17, D24)

Read side: `Get-CrServices`, `Get-CrScheduledTasks`, `Get-CrComPlusApplications`, `Get-CrDcomRunAs` (§4.1). The update functions keep the account and set its new password; the move functions switch the dependent to the target account with that account's new password (D24). None starts, stops, runs or shuts down anything (D17). Each returns one result per item and goes on after a failure; if the `$State` section failed, the only result has `Name`/`Path = $null` and `Success = $false`.

| Function | Contract |
|---|---|
| `Update-CrServiceCredentials -State -Sid -Secret` → `@(@{ Name; Success; Win32Error; Error; FromAccount; ToAccount })` | every service with `StartNameSid = Sid`: `Set-CrServiceLogonPassword` with its existing StartName text |
| `Move-CrServiceAccount -State -FromSid -ToAccount '.\<name>' -Secret` → same | the new StartName and password; the caller grants `SeServiceLogonRight` |
| `Update-CrTaskCredentials -State -Sid -Secret` → `@(@{ Path; Success; Error; SaclDropped; Warning; FromUserId; ToUserId })` | every task of the SID with LogonType 1 (password) or 6 (interactive or password): reads the live task, checks that its principal still is the SID with LogonType 1 or 6, and re-registers it through the adapter with the same UserId, LogonType, definition and SDDL |
| `Move-CrTaskAccount -State -FromSid -ToUserId '<COMPUTER>\<name>' -Secret` → same | as above with the new UserId |
| `Update-CrComPlusCredentials -State -Sid -Secret` → `@(@{ Name; Success; Error; FromIdentity; ToIdentity })` | every server application with `IdentitySid = Sid`: re-checks the live activation and identity, sets the password through the adapter, then one `SaveChanges`; success only when both worked |
| `Move-CrComPlusIdentity -State -FromSid -ToIdentity '<name>' -Secret` → same | identity and password through the adapter; if one adapter call failed after setting an identity, nothing is saved and every application of the call fails |

Task SDDL: `GetSecurityDescriptor(0xF)` (owner, group, DACL, SACL), or `0x7` (without the SACL) when the SACL can't be read. If the registration with the `0xF` SDDL fails for a reason other than the credentials (`Test-CrTaskCredentialError`: 1326–1332, 1385, 1793, 1907, 1909), it is retried once with the `0x7` SDDL; a successful retry returns `SaclDropped = $true` and a `Warning`.

### 5.12 IisReport.ps1 (PLAN §7.6)

`Get-CrIisIdentities` (§4.1) reads `Microsoft.Web.Administration` and never calls `CommitChanges`. IIS identities are reported as `FollowUp`, never changed.

### 5.13 Sql.ps1 (PLAN §7.9)

`Get-CrSqlState` (§4.1): default instance only, a non-pooled integrated connection, constant read-only `SELECT`s (`Get-CrSqlQueryText`); without `LOGINPROPERTY` (SQL Server 2005 before SP2) a basic login query is used. SQL rotation is not part of this version: SQL slots are never prompted and are reported as "SQL rotation not available in this version".

### 5.14 AutoLogon.ps1 (PLAN §7.5, D18)

| Function | Contract |
|---|---|
| `Get-CrAutoLogonState` | §4.1 |
| `Test-CrAutoLogonUsable -State -User -RemovedAdminSids` → `@{ Usable; Reasons; AdminPending; AdminRemoved }` | exists, enabled, not locked, effective interactive logon, and no admin unless this run removes it from Administrators. A disabled account is never usable, because the auto-logon accounts are never enabled (D21) |
| `Get-CrAutoLogonDecision -State -Resolved -Config -VerifiedSids -RemovedAdminSids` → `@{ Action; CurrentSid; CurrentName; TargetSid; TargetName; Reasons; OperatorOptions; HighImpact }` | read only; below |
| `Test-CrAutoLogonStandardized -State -TargetSid` → bool | `AutoAdminLogon` = REG_SZ `"1"`, `DefaultUserName` = the target without a prefix, `DefaultDomainName` = the computer name, no plain-text `DefaultPassword`, no `AutoLogonCount` (PLAN §7.5 "Audit") |
| `Invoke-CrAutoLogonAction -Decision -State -Secret` → `@{ Success; Action; Written; Steps; FailedStep; Pending; Error }` | carries out `Standardize`, `Switch` or `TurnOff` and stops at the first failing step; `LeaveOff`, `NoChange`, `Ambiguous` and `LeaveUnchanged` write nothing. `-Secret` = the target's new secret, `$null` for `TurnOff` |
| `Set-CrWinlogonValue -Name -Value -Kind 'String'\|'DWord'` / `Remove-CrWinlogonValue -Name` | the only registry writes (the Winlogon key); both throw on failure; `Set-CrWinlogonValue` refuses `DefaultPassword`; removing a missing value counts as success |

Decision (`Action` = `LeaveOff`, `Standardize`, `Switch`, `TurnOff`, `NoChange` or `Ambiguous`):
- The managed auto-logon accounts are the `AutoLogonUser` list of the entry with the `AutoLogon` block (`PUB-User`, `WinAutoUser`). `DefaultUserName` is matched against the local users, ignoring an `X\` prefix.
- Off (`AutoAdminLogon` empty or `0`) and nothing ambiguous → `LeaveOff`.
- On as a managed account → kept on every machine: `Standardize` if usable and in `VerifiedSids`, `NoChange` if usable but not on a verified new secret, `Ambiguous` if not usable.
- On as any other account → `TurnOff` on SM machines (`Computer.IsSm`); elsewhere `Switch` to the first usable account of the list, or `Ambiguous` if none is usable or the target isn't verified.
- Also `Ambiguous`: another auto-logon mechanism, an unexpected `AutoAdminLogon` value, `AutoLogonCount`, a current account that doesn't resolve. `OperatorOptions` is `@('TurnOff', 'LeaveUnchanged')` for `Ambiguous`, empty otherwise.
- `VerifiedSids` = accounts on a verified new secret (the audit passes the accounts the plan would set or change); `RemovedAdminSids` = accounts this run removes from Administrators.

Action steps, in crash-safe order:
- `Standardize`: LSA secret `DefaultPassword` → delete the plain-text `DefaultPassword` and `AutoLogonCount` → `DefaultUserName` = target, `DefaultDomainName` = computer name → `AutoAdminLogon` = REG_SZ `"1"`.
- `Switch`: `AutoAdminLogon` = `"0"` first (v10.4), then the `Standardize` steps, with `AutoLogonSID` deleted before `AutoAdminLogon` = `"1"` (PLAN §12, M0 spike item 11 is open).
- `TurnOff`: `AutoAdminLogon` = `"0"` → delete the plain-text `DefaultPassword`, the LSA secret and `AutoLogonCount`; `DefaultUserName` stays.

### 5.15 Preflight.ps1 (PLAN §6 step 2, D19)

| Function | Contract |
|---|---|
| `Get-CrComputerInfo -Config` | §4.1 Computer |
| `Get-CrPasswordPolicy` | §4.1 Policy: `Get-CrUserModals`, complexity from `secedit /export /areas SECURITYPOLICY`, `forceguest` from the registry |
| `Get-CrWriteFilterState` | §4.1 WriteFilter: EWF (`ewfmgr` per fixed drive, only when the driver isn't disabled and a protected volume is configured), FBWF (`fbwfmgr /displayconfig`), UWF (WMI `root\standardcimv2\embedded`; `uwfmgr get-config` for the detail) |
| `Get-CrWriteFilterDecision -WriteFilter -SystemDrive -SqlMasterFiles` → `@{ BlockApply; BlockSql; Reasons }` | D19: a volume is protected if a filter protects it in the current session, unless a whole-volume commit is pending; an installed filter with unknown state, or a protected volume without a drive letter, protects every volume. Protected system volume → `BlockApply`; protected volume of a SQL master file → `BlockSql` |
| `Get-CrDependentDiscoveryErrors -State` → string[] | `'Section: message'` per failed `Services`, `Tasks` or `ComPlus` section (comma-returned) |
| `Invoke-CrPreflight -State -Config` → `@{ MachineBlocked; BlockedSlots = @{ <slot> = <reason> }; Findings }` | below |

`Invoke-CrPreflight`:
- Machine blocked (`Blocked` finding; `-Apply` refused with exit 2): Computer unreadable; OS other than 6.1 build 7601+ or 10.0; no 64-bit OS; 32-bit process; not FullLanguage; not elevated; native helpers not ready; protected system volume (D19).
- Every Windows slot blocked: the Policy section failed (the D12 budget is unknown), or a dependent discovery section failed; the latter adds the `Blocked` finding "No account is disabled in this run", and `Get-CrApplyDisablePlan` plans no disable.
- SQL slots blocked: no default instance, not running, not connected, major version outside 9–14, operator not sysadmin, mixed mode off or unknown, or `BlockSql`.
- `Info`: OS and PowerShell summary, domain-joined warning, policy summary, unreadable complexity, ForceGuest, installed write-filter drivers, other SQL instances.
- The slots of a kind are the `Credential` values (entry and candidates) of the config entries of that `Kind`.

### 5.16 Plan.ps1 (PLAN §6 step 5, §7, §8)

`New-CrPlan -State -Config -Resolved -Preflight [-Only] [-RunningSid]` → `@{ Findings (ArrayList); Drift (bool); HighImpact; FollowUps }`. `RunningSid` defaults to the current identity; `Drift` is `$true` when any finding is `Drift`. The findings start with the preflight findings, the SID overlaps (`Find-CrSidOverlap`) and an `Info` per failed discovery section. Then:
- **Selection**: managed entries only for slots in `-Only`; Check entries, Disable entries and the D23 question only without `-Only`. An entry with `Error` gives one `Blocked` finding instead of claims about missing accounts. Missing accounts and not-applicable entries are `Info`.
- **Created accounts**: `Drift` "Create <name>", `Info` "no Windows login in SQL Server" when the default SQL instance exists, and the role's group additions.
- **Existing managed accounts**: a disabled account gets `Drift` "Enable the account" with `EnableIfDisabled`, otherwise `Info` "stays disabled" and it doesn't count as verified for the auto-logon decision. Set accounts get `Info` "Password set (D9: no old password)" and no probe finding. Change accounts get the change finding, `HighImpact` when disabled (set instead of change) or when the minimum age isn't reached, and the probe logon type (`Info`; with ForceGuest and no other type: "cannot be verified by a test logon").
- **Flags and groups** (Check entries too): `Drift` per missing PNE or CCP and per set NOTREQD; from `Get-CrGroupPlan`, `Drift` per addition and per removal ("enforcement phase"); a missing required group is `Info` and leaves the groups unchanged; rail: the running account stays in Administrators. Leaving Users runs the FTP checks (`HighImpact` if the network logon right is lost or an FTP folder is reachable only through Users).
- **Own dependents**, per kind managed by `Services`/`ScheduledTasks`/`ComPlus = 'Auto'`: `Info` per service, password-stored task and COM+ server application (`HighImpact` if the kind isn't managed, or if SQL Server runs as the account); `Drift` "Grant SeServiceLogonRight / SeBatchLogonRight", or `HighImpact` when denied; DCOM `Info` (report only); IIS `FollowUp`.
- **LOGINS**: `FollowUp` per account of an entry with `LoginsEntry` (not Check).
- **Disabling** (D22): `Drift` "Disable <name> (replaced by X)" per enabled replaced account (`Info` if already disabled) and "Disable <name> (no replacement)" per enabled account of a Disable entry.
- **Dependents of an account to be disabled** (D24): `HighImpact` "Move <service/task/COM+> from <old> to <target> (D24)"; the target is the replacement, or the application account for retired and other accounts. Tasks without a stored password: `HighImpact` (not moved, they stop running). DCOM `Info`, IIS `FollowUp`.
- When the move target is created in this run and the account has movable dependents, one `HighImpact` "Not disabled: <target> is created in this run …; migrate them manually (D24)" replaces the disable and move findings.
- **Running account** to be disabled: `HighImpact` "The running account <name> is disabled at the end; log on as <operator> next time (D25)".
- **Other enabled accounts**: `Ambiguous` "Operator decides: disable or keep <name> (D23)"; the detail lists the groups and the dependents and where they would move.
- `HighImpact` per unreadable task or task folder (dependents there unknown); `Info` for failed SQL queries.
- **Auto-logon** (if selected, same rule as §6.4 step 3): `Get-CrAutoLogonDecision` with the accounts the plan sets or changes (not in blocked slots, not staying disabled) and its Administrators removals → `Drift` for `Standardize` (unless `Test-CrAutoLogonStandardized`), `Switch` and `TurnOff`; `Ambiguous` with the options; the decision's `HighImpact` texts; `Ambiguous` when the Winlogon settings can't be read.
- **SQL logins**: `Info` per login (rotation, locked, disabled, policy settings) and `Drift` "Add to sysadmin (D14)".

Helpers (Apply.ps1 uses `Get-CrGroupPlan` and `Test-CrAppUserEntry`):

| Function | Returns |
|---|---|
| `Get-CrGroupPlan -State -Role -Sid -RunningSid` → `@{ Add; Remove; Notes; Skip; Rail }` | target groups from `Role.Groups`; removals only with `ExclusiveGroups`, without targets and `AllowedExtraGroups`, never the running account from Administrators; `Skip` when a required group is missing |
| `Get-CrAccountDependents -State -Sid` → `@{ Services; Tasks; OtherTasks; ComPlus; Dcom; AppPools; VirtualDirectories }` | everything that runs as the SID; `Tasks` = LogonType 1/6, `ComPlus` = server applications |
| `Get-CrMovableDependentCount -State -Sid` → int | services + password-stored tasks + COM+ server applications |
| `Get-CrOperatorAccountName -Resolved -Fallback` | the account name of the `Operator` entry |
| `Test-CrAppUserEntry -Entry` → bool | the entry has `Replaces`: the application account, target of the dependents of retired and operator-disabled accounts (D24) |
| `Test-CrEntryCreated -Entry` → bool | the entry has a `ToCreate` placeholder |

### 5.17 Apply.ps1 (PLAN §6 steps 6–11, §8)

The flow is in §6.3 and §6.4.

| Function | Contract |
|---|---|
| `Get-CrApplyAccountFates -State -Resolved -RunningSid -Only -Others` → `@(@{ Name; Sid; Fate; Detail })`; `Write-CrApplyAccountOverview -Fates` | every enabled local account with `keep`, `set`, `change`, `disable` or `ask` (D21), then the accounts to `create` |
| `Invoke-CrSlotProbes -State -Config -Resolved -Preflight -SlotSecrets -Journal -RunId -Only` → hashtable SID → probe | probes the existing Change accounts of the slots to be applied |
| `Get-CrApplyPreview -Config -Resolved -Preflight -SlotSecrets -Probes -Only` → preview | below |
| `Get-CrApplyDisablePlan -State -Resolved -Preview -RunningSid -Only -OtherDecisions` → disable items | below |
| `Get-CrApplyAutoLogonPreview -State -Config -Resolved -Preview -RunningSid -Only` → decision or `$null` | the auto-logon decision the run is expected to reach; `$null` when the step doesn't run |
| `Write-CrApplySummary -Preview -DisablePlan -Plan -AutoLogonDecision -Only` | the plan before the decisions and `YES`; names and outcomes only |
| `Resolve-CrProbeDecisions -State -Config -Resolved -Preflight -SlotSecrets -Probes -Journal -RunId -Only` | operator choices for Change accounts (D9, D13), default skip: `BothFailed` → enter the old password again, set, or skip; `BudgetExceeded` → wait and probe again, set, or skip; `Disabled` → set (and enable), or skip; minimum age not reached → set or skip. Stores `Path` on the probe or probes again |
| `Read-CrAutoLogonChoice -Decision` → `'TurnOff'\|'LeaveUnchanged'` | default `LeaveUnchanged` |
| `Invoke-CrApply …` → result | §6.4 |
| `Write-CrApplyResult -Result` | slot results, disables, check fixes, auto-logon step, FOLLOW-UP REQUIRED |
| `Clear-CrSlotSecrets -SlotSecrets` | disposes every SecureString of the slot secrets |

Internal helpers named elsewhere: `Get-CrApplyAppUserEntry -Resolved` (the managed entry with `Replaces`), `Get-CrApplyOperatorEntry -Resolved` (the managed `Operator` entry), `Find-CrApplyUserByName` (ignores an `X\` prefix, e.g. `.\BiCA Admin` in `DefaultUserName`), `Test-CrApplyBudget`, `Invoke-CrApplyLogonTest`, `Test-CrApplyEntryCreated -Preview -Entry`.

**Preview**: one item per selected slot in ascending `Order`: `@{ Slot; Order; Label; Status ('Apply'|'Blocked'|'NotApplicable'|'Skipped'); Unsupported; Reason; Accounts = @(@{ Name; Sid; UserName; User; Entry; PasswordMode; Probe; Outcome; SecretAccount; Path; Unlock; Enable; StaysDisabled; Reason }) }`. It holds SecureString references (`SecretAccount`): never log it.
- Status, first match: SQL slot → `Skipped` with `Unsupported = $true`; preflight-blocked → `Blocked`; an entry with `Error` → `Blocked`; nothing to apply → `NotApplicable`; no new password → `Skipped`; every account skipped → `Skipped`; else `Apply`.
- `Path`: `Create` (placeholder); `Set` (set accounts, D9); `Skip` (missing and not created); for Change accounts from the probe: `Old` → `Change` (`Reapply` if old equals new), `Reapply`, `New` (D11), `Unverifiable` → `Change` (the API validates the old password; a re-apply is skipped), `Locked` → `Unlock` + `Change` or `Reapply`, operator `Set` → `Set` (DPAPI data lost), anything else → `Skip` with a reason.
- `Enable` = an existing disabled account of an `EnableIfDisabled` entry; other disabled accounts are `StaysDisabled` (D21).

**Disable item**: `@{ Sid; Name; User; Kind ('Replaced'|'Disable'|'Other'); IsRunning; ReplacementEntry; ReplacementName; ReplacementSlot; Services; Tasks; ComPlus; OtherTasks; HasDependents; MoveEntry; Planned; Reason; MigrateManually }`; `Invoke-CrApply` adds `Blocked`, `MoveFailed`, `MovedTo` and `Status` (`Disabled`|`KeptEnabled`|`Failed`).
- Candidates: the enabled replaced accounts of selected slots; without `-Only` also the accounts of Disable entries and the D23 accounts with the operator's choice.
- `MoveEntry` = the replacement entry for `Replaced`; the application entry for `Disable` and chosen `Other` accounts with dependents.
- `Planned = $false`, with a reason, when the replacement's slot isn't `Apply` or its account is skipped; an `Other` account is kept; there is no application account for the dependents; the move target is created in this run (`MigrateManually = $true`); or the dependents are unknown (`Get-CrDependentDiscoveryErrors`).

## 6. Entry point and apply flow (`src/CredentialRotation.ps1`)

### 6.1 Parameters and start-up

- `-Apply` (switch); `-Only <string[]>` (slot names; `"A,B"` is split, because `powershell.exe -File` passes it as one string); `-ConfigPath` (default: `CredentialRotation.psd1` next to the script, else `..\config\CredentialRotation.psd1` when unbundled). Parameters are named only; stray positional words give exit 2. Secrets are only typed at the prompts. There is no log-path parameter (§5.1).
- `$script:CrToolVersion = '0.4.0'`; `$ErrorActionPreference = 'Stop'`.
- Start-up, each failure → exit 2: elevated; FullLanguage; one instance (mutex `Global\CredentialRotation`). Then `Initialize-CrLog` (RunId `yyyyMMdd-HHmmss`); the SHA-256 of the script, the launcher and the config, printed and logged; `Import-CrConfig` + `Test-CrConfig`; `Get-CrUnknownOnlySlots`; `Initialize-CrNative` (a failure is logged, and preflight then blocks the machine); `Get-CrMachineState`; `Get-CrCriticalDiscoveryError`.
- The audit runs in both modes: `Invoke-CrPreflight` → `Resolve-CrAccounts` → `New-CrPlan -Only -RunningSid` → console report, `CredentialRotation_<COMPUTER>_<RunId>.csv` in the log folder, findings in the log.

### 6.2 Audit result

Exit 2 if `MachineBlocked`, else 10 if `Drift`, else 0.

### 6.3 Apply flow (`Invoke-CrApplyFlow`)

Nothing changes before `YES`.
1. Exit 2 if `MachineBlocked` or the native helpers aren't ready. `Open-CrJournal -Root -Trusted` with the log root and `JournalTrusted`.
2. Without `-Only`, `Get-CrOtherEnabledAccounts`. Print the enabled local accounts and their fate (`Get-CrApplyAccountFates`, D21), then `Read-CrOtherAccountDecisions` if there are other accounts (D23).
3. `Read-CrSlotSecrets` with the preflight `BlockedSlots`; `Start-CrJournalRun`.
4. `Invoke-CrSlotProbes`: Change accounts only (D9, D12, D16).
5. Prompt findings, preview, disable plan and auto-logon preview → `Write-CrApplySummary`.
6. `Resolve-CrProbeDecisions`; the preview, disable plan and auto-logon preview are computed again; an `Ambiguous` auto-logon preview → `Read-CrAutoLogonChoice`. The final plan is printed.
7. `Confirm-CrYes`; anything else → exit 3.
8. `Invoke-CrApply` (§6.4) with `-OtherDecisions`, `-AutoLogonChoice` and `-AutoLogonPrompt` (for an ambiguity that only appears at run time).
9. Report: findings, `Write-CrApplyResult`, `CredentialRotation_<COMPUTER>_<RunId>_apply.csv`, slot and disable lines in the log. `Complete-CrJournalRun` unless the exit code is 1. A message when the running account was disabled.
10. Re-audit (`Get-CrMachineState` → `Invoke-CrPreflight` → `Resolve-CrAccounts` → `New-CrPlan`): the remaining `Drift` items are printed; a failure is only reported.
11. Exit with `Invoke-CrApply`'s exit code.

In `finally`: a journal run that was started but never reached `Invoke-CrApply` is completed, and `Clear-CrSlotSecrets` disposes every secret.

### 6.4 `Invoke-CrApply`

`Invoke-CrApply -State -Config -Resolved -Preflight -Plan -SlotSecrets -Probes -Journal -RunId -Only -RunningSid -OtherDecisions -AutoLogonChoice -AutoLogonPrompt <scriptblock>` →
`@{ Findings (ArrayList); Slots; Disables = @(@{ Sid; Name; Kind; Replacement; MovedTo; IsRunning; Status; Reason }); CheckFixes = @(@{ Id; Status; Errors }); AutoLogon = @{ Ran; Action; Success; Decision; FailedStep; Pending }; RunningAccount = @{ Disabled; Reason }; NotAppliedSlots; ChangedSids; CreatedSids; VerifiedSids; RemovedAdminSids; ExitCode }`.
Slot result: `@{ Slot; Status ('Done'|'Failed'|'Skipped'|'Blocked'|'NotApplicable'); Unsupported; FailedStep; Reason; Done; Pending; Errors; Notes; Members }`.

With `MachineBlocked` nothing is done (exit 2). Otherwise it builds the preview and the disable plan from the audit state, runs every `Apply` slot, reports the other slots, and runs the enforcement phase. It keeps `$State.Users` and `$State.Groups` current (created users, group changes, enabled and disabled accounts), so later steps judge the changed machine. It tracks the SIDs that are verified (a logon with the new password in this run, including the probe's `New`/`Reapply`), on the new password, changed (created, set or changed: LOGINS follow-up), created, and removed from Administrators.

**Slots**, in ascending `Order` (PLAN §8). The first failing step stops the slot; the other slots continue. The slot result lists done and pending steps per account, with a `Blocked` finding.
0. **Create** (`Path = 'Create'`): `New-CrManagedAccount` with the slot password (journal `Created` and `Secret`); the group memberships are read again, because `NetUserAdd` adds groups of its own.
1. **Pre-steps** (Change or Reapply accounts with `Unlock`): `Unlock-CrAccount` (journal `Unlocked`), the budget checked again, a re-apply validated with one logon; journal `PreSteps`.
2. **Secret**: none for `Create`, `New` and `Reapply` (D11, D20; they count as verified). `Change`: `Test-CrApplyBudget`, then `Invoke-CrPasswordRotation -Path Change`. `Set`: `Invoke-CrPasswordSet` (`HighImpact` "DPAPI data lost" for a Change account set by the operator's choice).
3. **Enable**: `Enable-CrAccount` for `Enable` accounts (journal `Enabled`); other disabled accounts stay disabled (D21).
4. **Grants**: `Set-CrAccountFlags`, group additions (`Get-CrGroupPlan`), and `SeServiceLogonRight`/`SeBatchLogonRight` for its own managed dependents (a denied right is `HighImpact` and never granted). Journal `Grants`.
5. **Dependents**: services → tasks → COM+ through the `Update-Cr…Credentials` functions, only for kinds managed by `'Auto'` (others `HighImpact`); nothing is restarted (D17). Journal `Dependents`.
6. **Verify**: `Invoke-CrApplyLogonTest` with the D16 type on the current state. No attempt for a disabled account, without a clearly allowed type (fallback or ForceGuest), or when `Test-CrApplyBudget` refuses (D12: `HighImpact` "Not verified (lockout budget)", which makes the run partial). 1385, 1327 and 1331 mean "not verified" (`Info`); any other error fails the slot. Journal `Verified`.

When a slot stops after step 2, its accounts already on the new password are still logon-tested (`Invoke-CrApplyVerifyOnNew`). A slot with skipped accounts ends `Failed`, or `Skipped` if no account was processed. Follow-ups per account whose password was created, set or changed: LOGINS (`LoginsEntry`), RDP "Update the saved RDP credentials" for the `Operator` entry's account, and the audit's IIS follow-ups.

`Test-CrApplyBudget -State -UserName` → `@{ Ok; Locked; Reason }`: re-reads the account and refuses when it can't be read, is locked, or `Test-CrProbeBudget` refuses (threshold 0 = no limit; unknown = 3).

**Enforcement phase** (PLAN §8):
1. **Removals**: exclusive-group removals for the accounts of `Done` slots. Rails: the running account never leaves Administrators, and Administrators keeps an enabled member that is the running account or verified in this run (`Get-CrApplyAdminRailReason`).
2. **Dependent moves** (D24), for planned disable items with dependents. The target must be verified, enabled, have its new password in memory, and not have been created by the tool in this run or in an earlier unfinished run (journal `Created`); otherwise the item is `Blocked` and stays enabled (`HighImpact`). The rights the dependents need are granted first, then `Move-CrServiceAccount` (`.\<name>`), `Move-CrTaskAccount` (`<COMPUTER>\<name>`) and `Move-CrComPlusIdentity` (`<name>`). Any failure → `MoveFailed` with a `Blocked` finding; success → journal `DependentsMoved`.
3. **Auto-logon step**, when selected: always without `-Only`; under `-Only` when the auto-logon slot is selected or the current auto-logon account is an account or a replaced account of a selected slot. `Get-CrAutoLogonDecision` with the verified SIDs and the Administrators removals. `Ambiguous` → the choice made before `YES`, else `-AutoLogonPrompt`, default `LeaveUnchanged`; `TurnOff` is carried out. `Standardize` and `Switch` need a verified target; the secret is its slot's `NewSecret`. A kept account that got a new password but wasn't verified, or was left unchanged, → `HighImpact` "auto-logon broken until re-run". Journal `AutoLogon`.
4. **Disabling** (D22, D23) of every planned item except the running account. It stays enabled (`HighImpact`) when its moves were blocked or failed, it is still the auto-logon account after step 3, the slot of its replacement isn't `Done` or the replacement isn't verified and enabled, or the Administrators rail refuses. Unplanned items get an `Info`, and with `MigrateManually` a `FollowUp` "Migrate … manually, then disable it (D24)".
5. **Check-mode fixes** (without `-Only`): flags and exclusive groups of Check entries, never the password.
6. **Running account last** (D25), only if it is a planned disable item and the `Operator` entry's account exists, isn't the running account, is enabled, in Administrators, verified in this run, and holds an effective `RemoteInteractive` right (`Get-CrEffectiveLogonRights`). The blockers of step 4 apply too, without counting the running account for the rail. When disabled: `FollowUp` "log on as <operator> next time".

Last, an `Info` "Locked: yes/no" per processed account (PLAN §6 step 11).

### 6.5 Exit codes (PLAN §6 step 11)

| Code | Meaning |
|---|---|
| 0 | audit: no drift; apply: done, nothing outstanding |
| 10 | audit: drift |
| 4 | apply: done, with `FollowUp` findings (the normal result of a full rotation) |
| 1 | apply, partial: a slot `Failed`; a selected slot `Skipped` or `Blocked`, except the SQL slots of this version (listed in `NotAppliedSlots`); a move or a disable failed; a verification skipped by the D12 budget; a check fix failed; the auto-logon step failed or could not run |
| 2 | preflight failed: not elevated, not FullLanguage, another instance running, unexpected arguments, invalid config, unknown `-Only` slot, critical discovery failure, `MachineBlocked`, native helpers unavailable (apply) |
| 3 | aborted: not confirmed with `YES`, or an unhandled error |

### 6.6 Journal use (PLAN §7.10, D11)

- The run starts after the password prompts. It is completed when the apply ends with an exit code other than 1, or when the run ends before `Invoke-CrApply`; a partial run stays unfinished for the re-run.
- The probe tests the new password first when an unfinished earlier run recorded `Secret` for the account.
- Dependents never move to an account with `Created` in an unfinished earlier run.
- An untrusted log folder (§5.1) gives an empty journal.

## 7. Verification on the dev machine

AppLocker blocks the repository's `.ps1` files on the dev machine, and the user decided: **write code and tests, but don't run them here**. Do not work around AppLocker (no `Invoke-Expression` or `[scriptblock]::Create` of repo files, no copying them to allowed folders). Allowed: reading, parsing with `[System.Management.Automation.Language.Parser]::ParseFile` in an inline `powershell.exe -Command`, the static lint `build\Test-Ps2Syntax.ps1`, and compiling C# snippets with `Add-Type` inline. The tool and the tests run on the test machines.
