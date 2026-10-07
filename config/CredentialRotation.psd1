# Credential Rotation configuration (docs/PLAN.md section 5). Holds no secrets.
@{
    SchemaVersion = 1

    # D15: enforced on every machine in addition to the local OS policy
    SitePasswordRules = @{ MinLength = 8; RequireComplexity = $true }

    Roles = @{
        Admin    = @{ Groups = @('S-1-5-32-544'); ExclusiveGroups = $true; PasswordNeverExpires = $true; CannotChangePassword = $true
                      PasswordRequired = $true }
        Operator = @{ Groups = @('S-1-5-32-544', 'S-1-5-32-555', 'Name:Offer Remote Assistance Helpers?'); ExclusiveGroups = $true
                      PasswordNeverExpires = $true; CannotChangePassword = $true; PasswordRequired = $true }
        User     = @{ Groups = @('S-1-5-32-545'); ExclusiveGroups = $true; PasswordNeverExpires = $true; CannotChangePassword = $true
                      PasswordRequired = $true }
        WinUser  = @{ Groups = @('S-1-5-32-545'); ExclusiveGroups = $true; PasswordNeverExpires = $true; CannotChangePassword = $true
                      AllowedExtraGroups = @('S-1-5-32-555', 'Pattern:^hw_fn_') }      # kept if present, never added
        Ftp      = @{ Groups = @('Name:CardCenters'); ExclusiveGroups = $true; PasswordNeverExpires = $true; CannotChangePassword = $true
                      IfGroupMissing = 'ReportKeepGroups' }
    }

    # One prompt per slot (new password twice), applied in ascending Order (D9: set; ApplicationUser: change).
    Credentials = @(
        @{ Slot = 'SOPAdmin';       Order = 10; Label = 'SOP-Admin (operator account)' }
        @{ Slot = 'AppUser';        Order = 20; Label = 'ApplicationUser' }
        @{ Slot = 'PubUser';        Order = 30; Label = 'PUB-User (auto-logon)' }
        @{ Slot = 'SQLApplication'; Order = 40; Label = 'SQL login SQLApplication'; MaxLength = 128 }
        @{ Slot = 'SQLScript';      Order = 50; Label = 'SQL login SQLScript';      MaxLength = 128 }
        @{ Slot = 'SQLService';     Order = 60; Label = 'SQL login SQLService';     MaxLength = 128 }
    )

    Accounts = @(
        # Managed accounts (D21): created if missing; Replaces = accounts disabled once this one is verified (D22),
        # their dependents move here (D24).
        @{ Id = 'SOPAdmin'; Kind = 'Windows'; Name = 'SOP-Admin'; Role = 'Operator'; Credential = 'SOPAdmin'; Create = $true
           Replaces = @('BiCA Admin', 'BiCA Remote'); LoginsEntry = $true; SqlSysadminLogin = $true }
        @{ Id = 'AppUser';  Kind = 'Windows'; Name = 'ApplicationUser'; Role = 'Admin'; Credential = 'AppUser'; Create = $true
           PasswordMode = 'Change'                                               # D9: keep DPAPI data
           Replaces = @('RID-500'); LoginsEntry = $true
           Services = 'Auto'; ScheduledTasks = 'Auto'; ComPlus = 'Auto'; IisReport = 'Auto' }   # no restarts (D17)
        @{ Id = 'PubUser';  Kind = 'Windows'; Name = 'PUB-User'; Role = 'User'; Credential = 'PubUser'; Create = $true
           Replaces = @('WinAutoUser')
           AutoLogonUser = @( @{ Name = 'PUB-User'; RequireEnabled = $true } )
           AutoLogon = @{ Mode = 'IfAlreadyOn'; RestrictedComputerPattern = '^SM' } }          # D18
        # Retired without replacement (D22); a dependent running as them is an operator decision (D24).
        @{ Id = 'Retired';  Kind = 'Windows'; Names = @('SP Admin', 'SYS Admin'); Mode = 'Disable' }
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
