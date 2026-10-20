# Credential Rotation configuration (docs/PLAN.md section 5). Holds no secrets.
@{
    SchemaVersion = 1

    # D15: enforced on every machine in addition to the local OS policy
    SitePasswordRules = @{ MinLength = 8; RequireComplexity = $true }

    Roles = @{
        Admin       = @{ Groups = @('S-1-5-32-544'); ExclusiveGroups = $true; PasswordNeverExpires = $true; CannotChangePassword = $true
                         PasswordRequired = $true }
        # SOP-Admin (D28, v10.6): Administrators + Remote Desktop Users + Offer Remote Assistance Helpers (if it exists)
        AdminRemote = @{ Groups = @('S-1-5-32-544', 'S-1-5-32-555', 'Name:Offer Remote Assistance Helpers?'); ExclusiveGroups = $true
                         PasswordNeverExpires = $true; CannotChangePassword = $true; PasswordRequired = $true }
        User        = @{ Groups = @('S-1-5-32-545'); ExclusiveGroups = $true; PasswordNeverExpires = $true; CannotChangePassword = $true
                         PasswordRequired = $true }
        WinUser     = @{ Groups = @('S-1-5-32-545'); ExclusiveGroups = $true; PasswordNeverExpires = $true; CannotChangePassword = $true
                         AllowedExtraGroups = @('S-1-5-32-555', 'Pattern:^hw_fn_') }   # kept if present, never added
        Ftp         = @{ Groups = @('Name:CardCenters'); ExclusiveGroups = $true; PasswordNeverExpires = $true; CannotChangePassword = $true
                         IfGroupMissing = 'ReportKeepGroups' }
    }

    # One prompt per slot (new password twice), applied in ascending Order (D9: set; ApplicationUser: change).
    # No SQL login slots: SQL credentials are not updated (D27, v10.5).
    Credentials = @(
        @{ Slot = 'AppUser';        Order = 20; Label = 'ApplicationUser' }
        @{ Slot = 'AutoLogon';      Order = 30; Label = 'Auto-logon users (PUB-User / WinAutoUser)' }
        @{ Slot = 'SOPAdmin';       Order = 90; Label = 'SOP-Admin (your logon account from now on)' }   # last (D25)
    )

    Accounts = @(
        # Managed admin accounts (D21): created if missing. Every Windows slot updates its own dependents: a set breaks
        # stored credentials (D8). No restarts (D17).
        # Replaces = accounts disabled once this one is verified (D22), their dependents move here (D24).
        # SOP-Admin replaces BiCA Admin and BiCA Remote (D28, v10.6); an existing one is taken over and enabled. It gets
        # the SQL Server access of their Windows logins before they are disabled (D29).
        @{ Id = 'SOPAdmin'; Kind = 'Windows'; Name = 'SOP-Admin'; Role = 'AdminRemote'; Credential = 'SOPAdmin'; Create = $true
           EnableIfDisabled = $true
           Operator = $true                                                      # the operator's account (D25)
           Replaces = @('BiCA Admin', 'BiCA Remote'); SqlAccess = 'FromReplaced'; LoginsEntry = $true
           Services = 'Auto'; ScheduledTasks = 'Auto'; ComPlus = 'Auto' }
        @{ Id = 'AppUser';  Kind = 'Windows'; Name = 'ApplicationUser'; Role = 'Admin'; Credential = 'AppUser'; Create = $true
           EnableIfDisabled = $true                                              # it runs the application
           Application = $true                                                   # dependents of retired accounts move here (D24)
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
        # 'SYS-Admin' is the same account as 'SYS Admin', spelled with a hyphen on some machines (v10.5).
        @{ Id = 'Retired';  Kind = 'Windows'; Names = @('SYS Admin', 'SYS-Admin'); Mode = 'Disable' }
        # Never changed and not put to the operator (D26, v10.5; SOP-Admin is managed since v10.6)
        @{ Id = 'Untouched'; Kind = 'Windows'; Names = @('SP Admin'); Mode = 'Keep' }
        # Kept and checked (no password change)
        @{ Id = 'WinUsers'; Kind = 'Windows'; Names = @('WinUser1', 'WinUser2', 'WinUser3'); Role = 'WinUser'; Mode = 'Check' }
        @{ Id = 'FtpUsers'; Kind = 'Windows'; NamePattern = '^ftp|ftp$'; Role = 'Ftp'; Mode = 'Check' }
    )

    # D23: every other enabled local account is put to the operator (disable / keep).
    OtherEnabledAccounts = 'Ask'
}
