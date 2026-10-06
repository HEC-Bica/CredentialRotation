# Credential Rotation configuration (docs/PLAN.md section 5). Holds no secrets.
@{
    SchemaVersion = 1

    # D15: enforced on every machine in addition to the local OS policy
    SitePasswordRules = @{ MinLength = 8; RequireComplexity = $true }

    Roles = @{
        Admin       = @{ Groups = @('S-1-5-32-544'); ExclusiveGroups = $true; PasswordNeverExpires = $true; CannotChangePassword = $true
                         PasswordRequired = $true }
        AdminRemote = @{ Groups = @('S-1-5-32-544', 'Name:Offer Remote Assistance Helpers?'); ExclusiveGroups = $true
                         AllowedExtraGroups = @('S-1-5-32-555')
                         PasswordNeverExpires = $true; CannotChangePassword = $true; PasswordRequired = $true }
        User        = @{ Groups = @('S-1-5-32-545'); ExclusiveGroups = $true; PasswordNeverExpires = $true; CannotChangePassword = $true
                         PasswordRequired = $true }
        WinUser     = @{ Groups = @('S-1-5-32-545'); ExclusiveGroups = $true; PasswordNeverExpires = $true; CannotChangePassword = $true
                         AllowedExtraGroups = @('S-1-5-32-555', 'Pattern:^hw_fn_') }
        Ftp         = @{ Groups = @('Name:CardCenters'); ExclusiveGroups = $true; PasswordNeverExpires = $true; CannotChangePassword = $true
                         IfGroupMissing = 'ReportKeepGroups' }
        RotateOnly  = @{ }
    }

    # One prompt per slot, applied in ascending Order. Windows slots also ask for the old password (D9).
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
                           @{ Sid  = 'RID-500';         Role = 'RotateOnly'; Credential = 'AppUserBuiltinAdmin' } )
           Services = 'Auto'; ScheduledTasks = 'Auto'; ComPlus = 'Auto'; IisReport = 'Auto' }
        @{ Id = 'AutoLogon';  Kind = 'Windows'; Role = 'User'; Credential = 'AutoLogon'
           Names = @('PUB-User', 'WinAutoUser')
           AutoLogonUser = @( @{ Name = 'PUB-User'; RequireEnabled = $true }, @{ Name = 'WinAutoUser' } )
           AutoLogon = @{ Mode = 'IfAlreadyOn'; RestrictedComputerPattern = '^SM' } }
        @{ Id = 'WinUsers';   Kind = 'Windows'; Names = @('WinUser1', 'WinUser2', 'WinUser3'); Role = 'WinUser'; Mode = 'Check' }
        @{ Id = 'FtpUsers';   Kind = 'Windows'; NamePattern = '^ftp|ftp$'; Role = 'Ftp'; Mode = 'Check' }
        @{ Id = 'SqlApp';     Kind = 'SqlLogin'; Name = 'SQLApplication'; ServerRoles = @('sysadmin'); Credential = 'SQLApplication'; LoginsEntry = $true }
        @{ Id = 'SqlScript';  Kind = 'SqlLogin'; Name = 'SQLScript';      ServerRoles = @('sysadmin'); Credential = 'SQLScript';      LoginsEntry = $true }
        @{ Id = 'SqlService'; Kind = 'SqlLogin'; Name = 'SQLService';     ServerRoles = @('sysadmin'); Credential = 'SQLService';     LoginsEntry = $true }
    )
}
