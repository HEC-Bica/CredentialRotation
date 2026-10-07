# Adapters.ps1 - the only plaintext boundary (docs/PLAN.md D4 and section 9, docs/dev/CONTRACTS.md "Adapters.ps1")
# Task Scheduler and the COM+ catalog accept a password only as a managed string. This file is the
# only place where a SecureString becomes one: BSTR -> $plain* -> COM method call / property setter ->
# $plain* = $null, ZeroFreeBSTR in finally. Nothing here logs or prints, and results never contain
# exception messages (PowerShell argument-conversion errors can quote argument values); they carry the
# exception type, the HRESULT and, for Win32 HRESULTs, the system message text only.

# --- internal: BSTR handling (separate functions so tests can mock them) ---

function ConvertTo-CrSecretBstr {
    param([System.Security.SecureString]$Secret)
    return [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)
}

function Clear-CrSecretBstr {
    param([IntPtr]$Bstr)
    if ($Bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr) }
}

# --- internal: error text without secret material ---

# Text from the operation name, the exception type name and the HRESULT. For FACILITY_WIN32 HRESULTs
# (0x8007xxxx) the system message of the Win32 code is added (FormatMessage, no inserts).
function Get-CrAdapterErrorText {
    param([string]$Operation, [string]$TypeName, [int]$HResult)
    $text = '{0} failed ({1}, 0x{2})' -f $Operation, $TypeName, $HResult.ToString('X8')
    if (($HResult -band 0xFFFF0000) -eq 0x80070000) {
        $code = $HResult -band 0xFFFF
        try {
            $msg = (New-Object System.ComponentModel.Win32Exception($code)).Message
            if ($msg) { $text = $text + ': ' + $msg }
        } catch { }
    }
    return $text
}

# Removes the error records added to $Error after Marker (the record that was $Error[0] before the
# call, $null if $Error was empty): a caught COM or conversion error may quote a method argument.
function Clear-CrNewErrorRecords {
    param($Marker)
    $n = $Error.Count
    for ($i = 0; $i -lt $n; $i++) {
        if ($Error.Count -eq 0) { break }
        if (($null -ne $Marker) -and [object]::ReferenceEquals($Error[0], $Marker)) { break }
        $Error.RemoveAt(0)
    }
}

# --- public ---

# Re-registers a task definition with its principal and the new password:
# Folder.RegisterTaskDefinition(TaskName, Definition, 4 = TASK_UPDATE, UserId, password, LogonType, Sddl).
# UserId is the task's own one (password update) or the replacement account (move, D24).
# Returns @{ Success; Error; HResult } (HResult = $null on success or when COM wasn't called, so the
# caller can tell credential errors from others without parsing text).
function Invoke-CrTaskRegistrationAdapter {
    param(
        $Folder,
        [string]$TaskName,
        $Definition,
        [string]$UserId,
        [System.Security.SecureString]$Secret,
        [int]$LogonType,
        [string]$Sddl
    )
    if ($null -eq $Secret) { return @{ Success = $false; Error = 'RegisterTaskDefinition not called: no new password given'; HResult = $null } }
    if ($null -eq $Folder -or $null -eq $Definition) { return @{ Success = $false; Error = 'RegisterTaskDefinition not called: task folder or definition missing'; HResult = $null } }
    $result = $null
    $errorMarker = $null
    if ($Error.Count -gt 0) { $errorMarker = $Error[0] }
    $bstr = [IntPtr]::Zero
    $plainPassword = $null
    try {
        $bstr = ConvertTo-CrSecretBstr -Secret $Secret
        $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        [void]$Folder.RegisterTaskDefinition($TaskName, $Definition, 4, $UserId, $plainPassword, $LogonType, $Sddl)
        $plainPassword = $null
        $result = @{ Success = $true; Error = $null; HResult = $null }
    } catch {
        $plainPassword = $null
        # Only the type and HRESULT leave this block; the message may quote arguments.
        $ex = $_.Exception
        while ($null -ne $ex.InnerException) { $ex = $ex.InnerException }
        $typeName = $ex.GetType().Name
        $hr = 0
        try { $hr = [Runtime.InteropServices.Marshal]::GetHRForException($ex) } catch { }
        $ex = $null
        Clear-CrNewErrorRecords -Marker $errorMarker
        $result = @{ Success = $false; Error = (Get-CrAdapterErrorText -Operation 'RegisterTaskDefinition' -TypeName $typeName -HResult $hr); HResult = $hr }
    } finally {
        $plainPassword = $null
        if ($bstr -ne [IntPtr]::Zero) { Clear-CrSecretBstr -Bstr $bstr }
        $bstr = [IntPtr]::Zero
    }
    return $result
}

# Sets the password of a COM+ application catalog object: Application.Value('Password') = password.
# With Identity (move to the replacement account, D24) Application.Value('Identity') = Identity is
# set first, then the password. The caller calls SaveChanges on the collection; when this fails with
# IdentitySet = $true the object holds the new identity without its password, so the caller must
# not call SaveChanges (unsaved changes are discarded with the collection).
# Returns @{ Success; Error; IdentitySet }.
function Set-CrComPlusPasswordAdapter {
    param(
        $Application,
        [System.Security.SecureString]$Secret,
        [string]$Identity
    )
    if ($null -eq $Secret) { return @{ Success = $false; Error = 'COM+ password not set: no new password given'; IdentitySet = $false } }
    if ($null -eq $Application) { return @{ Success = $false; Error = 'COM+ password not set: application object missing'; IdentitySet = $false } }
    $result = $null
    $errorMarker = $null
    if ($Error.Count -gt 0) { $errorMarker = $Error[0] }
    $bstr = [IntPtr]::Zero
    $plainPassword = $null
    $identitySet = $false
    $operation = 'Setting the COM+ password'
    try {
        if ($Identity) {
            $operation = 'Setting the COM+ identity'
            $Application.Value('Identity') = $Identity
            $identitySet = $true
            $operation = 'Setting the COM+ password'
        }
        $bstr = ConvertTo-CrSecretBstr -Secret $Secret
        $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        $Application.Value('Password') = $plainPassword
        $plainPassword = $null
        $result = @{ Success = $true; Error = $null; IdentitySet = $identitySet }
    } catch {
        $plainPassword = $null
        $ex = $_.Exception
        while ($null -ne $ex.InnerException) { $ex = $ex.InnerException }
        $typeName = $ex.GetType().Name
        $hr = 0
        try { $hr = [Runtime.InteropServices.Marshal]::GetHRForException($ex) } catch { }
        $ex = $null
        Clear-CrNewErrorRecords -Marker $errorMarker
        $result = @{ Success = $false; Error = (Get-CrAdapterErrorText -Operation $operation -TypeName $typeName -HResult $hr); IdentitySet = $identitySet }
    } finally {
        $plainPassword = $null
        if ($bstr -ne [IntPtr]::Zero) { Clear-CrSecretBstr -Bstr $bstr }
        $bstr = [IntPtr]::Zero
    }
    return $result
}
