# Credential Rotation configuration (docs/PLAN.md section 5). Holds no secrets.
@{
    SchemaVersion = 1

    # D15: enforced on every machine in addition to the local OS policy
    SitePasswordRules = @{ MinLength = 8; RequireComplexity = $true }

    Roles = @{
        Admin       = @{ Groups = @('S-1-5-32-544'); ExclusiveGroups = $true; PasswordNeverExpires = $true; CannotChangePassword = $true
                         PasswordRequired = $true }
        AdminRemote = @{ Groups = @('S-1-5-32-544', 'Name:Offer Remote Assistance Helpers?'); ExclusiveGroups = $true
                         AllowedExtraGroups = @('S-1-5-32-555')                               # kept if present, never added
                         PasswordNeverExpires = $true; CannotChangePassword = $true; PasswordRequired = $true }
        User        = @{ Groups = @('S-1-5-32-545'); ExclusiveGroups = $true; PasswordNeverExpires = $true; CannotChangePassword = $true
                         PasswordRequired = $true }
        WinUser     = @{ Groups = @('S-1-5-32-545'); ExclusiveGroups = $true; PasswordNeverExpires = $true; CannotChangePassword = $true
                         AllowedExtraGroups = @('S-1-5-32-555', 'Pattern:^hw_fn_') }   # kept if present, never added
        Ftp         = @{ Groups = @('Name:CardCenters'); ExclusiveGroups = $true; PasswordNeverExpires = $true; CannotChangePassword = $true
                         IfGroupMissing = 'ReportKeepGroups' }
    }

    # One prompt per slot (new password twice), applied in ascending Order (D9: set; ApplicationUser: change).
    Credentials = @(
        @{ Slot = 'BiCAAdmin';      Order = 10; Label = 'BiCA Admin' }
        @{ Slot = 'AppUser';        Order = 20; Label = 'ApplicationUser' }
        @{ Slot = 'AutoLogon';      Order = 30; Label = 'Auto-logon users (PUB-User / WinAutoUser)' }
        @{ Slot = 'SQLApplication'; Order = 40; Label = 'SQL login SQLApplication'; MaxLength = 128 }
        @{ Slot = 'SQLScript';      Order = 50; Label = 'SQL login SQLScript';      MaxLength = 128 }
        @{ Slot = 'SQLService';     Order = 60; Label = 'SQL login SQLService';     MaxLength = 128 }
        @{ Slot = 'BiCARemote';     Order = 90; Label = 'BiCA Remote (your own logon account)' }   # last (D25)
    )

    Accounts = @(
        # Managed admin accounts (D21): created if missing. Every Windows slot updates its own dependents: a set breaks
        # stored credentials (D8). No restarts (D17).
        @{ Id = 'BiCAAdmin';  Kind = 'Windows'; Name = 'BiCA Admin';  Role = 'Admin';       Credential = 'BiCAAdmin';  Create = $true
           LoginsEntry = $true; Services = 'Auto'; ScheduledTasks = 'Auto'; ComPlus = 'Auto' }
        @{ Id = 'BiCARemote'; Kind = 'Windows'; Name = 'BiCA Remote'; Role = 'AdminRemote'; Credential = 'BiCARemote'; Create = $true
           Operator = $true                                                      # the operator's account (D25)
           LoginsEntry = $true; Services = 'Auto'; ScheduledTasks = 'Auto'; ComPlus = 'Auto' }
        # Replaces = accounts disabled once this one is verified (D22), their dependents move here (D24).
        @{ Id = 'AppUser';  Kind = 'Windows'; Name = 'ApplicationUser'; Role = 'Admin'; Credential = 'AppUser'; Create = $true
           EnableIfDisabled = $true                                              # it runs the application
           PasswordMode = 'Change'                                               # D9: keep DPAPI data
           Replaces = @('RID-500'); LoginsEntry = $true
           Services = 'Auto'; ScheduledTasks = 'Auto'; ComPlus = 'Auto'; IisReport = 'Auto' }
        # Auto-logon accounts (D18, D21): every existing one, enabled or disabled, gets the slot password;
        # never created, never enabled or disabled.
        @{ Id = 'AutoLogon'; Kind = 'Windows'; Names = @('PUB-User', 'WinAutoUser'); Role = 'User'; Credential = 'AutoLogon'
           AutoLogonUser = @( @{ Name = 'PUB-User' }, @{ Name = 'WinAutoUser' } )   # kept if active; switch target: first usable
           AutoLogon = @{ Mode = 'IfAlreadyOn'; RestrictedComputerPattern = '^SM' }
           Services = 'Auto'; ScheduledTasks = 'Auto'; ComPlus = 'Auto' }
        # Retired without replacement (D22); their dependents move to ApplicationUser (D24, v10.4).
        @{ Id = 'Retired';  Kind = 'Windows'; Names = @('SP Admin', 'SYS Admin', 'SOP-Admin'); Mode = 'Disable' }
        # Kept and checked (no password change)
        @{ Id = 'WinUsers'; Kind = 'Windows'; Names = @('WinUser1', 'WinUser2', 'WinUser3'); Role = 'WinUser'; Mode = 'Check' }
        @{ Id = 'FtpUsers'; Kind = 'Windows'; NamePattern = '^ftp|ftp$'; Role = 'Ftp'; Mode = 'Check' }
        @{ Id = 'SqlApp';     Kind = 'SqlLogin'; Name = 'SQLApplication'; ServerRoles = @('sysadmin'); Credential = 'SQLApplication'; LoginsEntry = $true }
        @{ Id = 'SqlScript';  Kind = 'SqlLogin'; Name = 'SQLScript';      ServerRoles = @('sysadmin'); Credential = 'SQLScript';      LoginsEntry = $true }
        @{ Id = 'SqlService'; Kind = 'SqlLogin'; Name = 'SQLService';     ServerRoles = @('sysadmin'); Credential = 'SQLService';     LoginsEntry = $true }
    )

    # D23: every other enabled local account is put to the operator (disable / keep).
    OtherEnabledAccounts = 'Ask'
}
