# Native.ps1 - Add-Type C# 2.0 helpers (advapi32 LSA, netapi32) and thin PowerShell wrappers (docs/dev/CONTRACTS.md).
# M1 is read-only: no write APIs here yet. The C# compiles once, in Initialize-CrNative.

# The C# source. C# 2.0 only (no var, lambdas, LINQ, auto-properties); static classes prefixed Cr, no namespace.
function Get-CrNativeSource {
    param()
    return @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

public static class CrNativeLsa
{
    private const uint POLICY_VIEW_LOCAL_INFORMATION = 0x00000001;
    private const uint POLICY_LOOKUP_NAMES = 0x00000800;
    private const int PolicyAccountDomainInformation = 5;
    private const uint STATUS_NO_MORE_ENTRIES = 0x8000001A;
    private const uint STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034;

    [StructLayout(LayoutKind.Sequential)]
    private struct LSA_UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LSA_OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public int Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct POLICY_ACCOUNT_DOMAIN_INFO
    {
        public LSA_UNICODE_STRING DomainName;
        public IntPtr DomainSid;
    }

    [DllImport("advapi32.dll")]
    private static extern uint LsaOpenPolicy(IntPtr systemName, ref LSA_OBJECT_ATTRIBUTES objectAttributes,
        uint desiredAccess, out IntPtr policyHandle);

    [DllImport("advapi32.dll")]
    private static extern uint LsaQueryInformationPolicy(IntPtr policyHandle, int informationClass, out IntPtr buffer);

    [DllImport("advapi32.dll")]
    private static extern uint LsaEnumerateAccountsWithUserRight(IntPtr policyHandle, ref LSA_UNICODE_STRING userRight,
        out IntPtr buffer, out uint countReturned);

    [DllImport("advapi32.dll")]
    private static extern uint LsaFreeMemory(IntPtr buffer);

    [DllImport("advapi32.dll")]
    private static extern uint LsaClose(IntPtr policyHandle);

    [DllImport("advapi32.dll")]
    private static extern int LsaNtStatusToWinError(uint status);

    private static Exception NtError(string function, uint status)
    {
        int code = LsaNtStatusToWinError(status);
        string text = new Win32Exception(code).Message;
        return new Win32Exception(code, function + " failed: " + text + " (NTSTATUS 0x" + status.ToString("X8") +
            ", error " + code + ")");
    }

    private static IntPtr OpenPolicy(uint access)
    {
        LSA_OBJECT_ATTRIBUTES attributes = new LSA_OBJECT_ATTRIBUTES();
        attributes.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
        IntPtr handle = IntPtr.Zero;
        uint status = LsaOpenPolicy(IntPtr.Zero, ref attributes, access, out handle);
        if (status != 0) { throw NtError("LsaOpenPolicy", status); }
        return handle;
    }

    // SID of the local account domain (the machine SID).
    public static string GetMachineSid()
    {
        IntPtr handle = OpenPolicy(POLICY_VIEW_LOCAL_INFORMATION);
        try
        {
            IntPtr buffer = IntPtr.Zero;
            try
            {
                uint status = LsaQueryInformationPolicy(handle, PolicyAccountDomainInformation, out buffer);
                if (status != 0) { throw NtError("LsaQueryInformationPolicy", status); }
                POLICY_ACCOUNT_DOMAIN_INFO info = (POLICY_ACCOUNT_DOMAIN_INFO)Marshal.PtrToStructure(buffer,
                    typeof(POLICY_ACCOUNT_DOMAIN_INFO));
                if (info.DomainSid == IntPtr.Zero)
                {
                    throw new InvalidOperationException("LsaQueryInformationPolicy returned no account domain SID");
                }
                return new SecurityIdentifier(info.DomainSid).Value;
            }
            finally
            {
                if (buffer != IntPtr.Zero) { LsaFreeMemory(buffer); }
            }
        }
        finally
        {
            LsaClose(handle);
        }
    }

    // SIDs holding the given user right; an empty array when nobody holds it.
    public static string[] GetAccountsWithRight(string right)
    {
        if (right == null || right.Length == 0) { throw new ArgumentException("right is empty"); }
        IntPtr handle = OpenPolicy(POLICY_VIEW_LOCAL_INFORMATION | POLICY_LOOKUP_NAMES);
        try
        {
            LSA_UNICODE_STRING name = new LSA_UNICODE_STRING();
            name.Length = (ushort)(right.Length * 2);
            name.MaximumLength = (ushort)((right.Length + 1) * 2);
            name.Buffer = Marshal.StringToHGlobalUni(right);
            IntPtr buffer = IntPtr.Zero;
            try
            {
                uint count = 0;
                uint status = LsaEnumerateAccountsWithUserRight(handle, ref name, out buffer, out count);
                if (status == STATUS_NO_MORE_ENTRIES || status == STATUS_OBJECT_NAME_NOT_FOUND) { return new string[0]; }
                if (status != 0) { throw NtError("LsaEnumerateAccountsWithUserRight(" + right + ")", status); }
                string[] sids = new string[count];
                for (int i = 0; i < count; i++)
                {
                    IntPtr pSid = Marshal.ReadIntPtr(buffer, i * IntPtr.Size);
                    sids[i] = new SecurityIdentifier(pSid).Value;
                }
                return sids;
            }
            finally
            {
                if (buffer != IntPtr.Zero) { LsaFreeMemory(buffer); }
                Marshal.FreeHGlobal(name.Buffer);
            }
        }
        finally
        {
            LsaClose(handle);
        }
    }
}

public static class CrNativeNet
{
    private const int ERROR_MORE_DATA = 234;
    private const int MAX_PREFERRED_LENGTH = -1;

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserModalsGet(string serverName, int level, out IntPtr bufPtr);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetLocalGroupEnum(string serverName, int level, out IntPtr bufPtr, int prefMaxLen,
        out int entriesRead, out int totalEntries, ref IntPtr resumeHandle);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetLocalGroupGetMembers(string serverName, string localGroupName, int level,
        out IntPtr bufPtr, int prefMaxLen, out int entriesRead, out int totalEntries, ref IntPtr resumeHandle);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buffer);

    private static Exception NetError(string function, int code)
    {
        string text;
        switch (code)
        {
            case 2220: text = "The group name could not be found (NERR_GroupNotFound)"; break;
            case 2221: text = "The user name could not be found (NERR_UserNotFound)"; break;
            case 2351: text = "The computer name is invalid (NERR_InvalidComputer)"; break;
            default: text = new Win32Exception(code).Message; break;
        }
        return new Win32Exception(code, function + " failed: " + text + " (error " + code + ")");
    }

    private static long ReadDword(IntPtr buffer, int offset)
    {
        return (long)unchecked((uint)Marshal.ReadInt32(buffer, offset));
    }

    // Raw DWORDs: [0] min_passwd_len, [1] max_passwd_age, [2] min_passwd_age, [3] password_hist_len (level 0),
    // [4] lockout_duration, [5] lockout_observation_window, [6] lockout_threshold (level 3).
    // TIMEQ_FOREVER stays 4294967295 here; the PowerShell wrapper maps it.
    public static long[] GetUserModals()
    {
        long[] result = new long[7];
        IntPtr buffer = IntPtr.Zero;
        try
        {
            int rc = NetUserModalsGet(null, 0, out buffer);
            if (rc != 0) { throw NetError("NetUserModalsGet(level 0)", rc); }
            result[0] = ReadDword(buffer, 0);
            result[1] = ReadDword(buffer, 4);
            result[2] = ReadDword(buffer, 8);
            result[3] = ReadDword(buffer, 16);
        }
        finally
        {
            if (buffer != IntPtr.Zero) { NetApiBufferFree(buffer); }
        }
        buffer = IntPtr.Zero;
        try
        {
            int rc = NetUserModalsGet(null, 3, out buffer);
            if (rc != 0) { throw NetError("NetUserModalsGet(level 3)", rc); }
            result[4] = ReadDword(buffer, 0);
            result[5] = ReadDword(buffer, 4);
            result[6] = ReadDword(buffer, 8);
        }
        finally
        {
            if (buffer != IntPtr.Zero) { NetApiBufferFree(buffer); }
        }
        return result;
    }

    public static string[] GetLocalGroupNames()
    {
        List<string> names = new List<string>();
        IntPtr resume = IntPtr.Zero;
        int rc;
        do
        {
            IntPtr buffer = IntPtr.Zero;
            int read = 0;
            int total = 0;
            rc = NetLocalGroupEnum(null, 0, out buffer, MAX_PREFERRED_LENGTH, out read, out total, ref resume);
            try
            {
                if (rc != 0 && rc != ERROR_MORE_DATA) { throw NetError("NetLocalGroupEnum", rc); }
                if (rc == ERROR_MORE_DATA && read == 0) { throw NetError("NetLocalGroupEnum (no progress)", rc); }
                for (int i = 0; i < read; i++)
                {
                    IntPtr pName = Marshal.ReadIntPtr(buffer, i * IntPtr.Size);
                    names.Add(Marshal.PtrToStringUni(pName));
                }
            }
            finally
            {
                if (buffer != IntPtr.Zero) { NetApiBufferFree(buffer); }
            }
        } while (rc == ERROR_MORE_DATA);
        return names.ToArray();
    }

    public static string[] GetLocalGroupMemberSids(string groupName)
    {
        if (groupName == null || groupName.Length == 0) { throw new ArgumentException("groupName is empty"); }
        List<string> sids = new List<string>();
        IntPtr resume = IntPtr.Zero;
        int rc;
        do
        {
            IntPtr buffer = IntPtr.Zero;
            int read = 0;
            int total = 0;
            rc = NetLocalGroupGetMembers(null, groupName, 0, out buffer, MAX_PREFERRED_LENGTH, out read, out total,
                ref resume);
            try
            {
                if (rc != 0 && rc != ERROR_MORE_DATA) { throw NetError("NetLocalGroupGetMembers(" + groupName + ")", rc); }
                if (rc == ERROR_MORE_DATA && read == 0)
                {
                    throw NetError("NetLocalGroupGetMembers(" + groupName + ") (no progress)", rc);
                }
                for (int i = 0; i < read; i++)
                {
                    IntPtr pSid = Marshal.ReadIntPtr(buffer, i * IntPtr.Size);
                    sids.Add(new SecurityIdentifier(pSid).Value);
                }
            }
            finally
            {
                if (buffer != IntPtr.Zero) { NetApiBufferFree(buffer); }
            }
        } while (rc == ERROR_MORE_DATA);
        return sids.ToArray();
    }
}
'@
}

# The innermost exception message (method calls wrap the C# exception in MethodInvocationException).
function Get-CrNativeErrorText {
    param($ErrorRecord)
    $ex = $ErrorRecord.Exception
    while ($ex.InnerException) { $ex = $ex.InnerException }
    return $ex.Message
}

function Test-CrNativeTypeLoaded {
    param()
    return [bool](('CrNativeLsa' -as [type]) -and ('CrNativeNet' -as [type]))
}

# Compiles the C# once. Never throws; sets $script:CrNativeReady and $script:CrNativeError.
function Initialize-CrNative {
    param()
    try {
        if (-not (Test-CrNativeTypeLoaded)) {
            Add-Type -TypeDefinition (Get-CrNativeSource) -ErrorAction Stop
        }
        $script:CrNativeReady = $true
        $script:CrNativeError = $null
    } catch {
        $script:CrNativeReady = $false
        $script:CrNativeError = Get-CrNativeErrorText $_
    }
}

function Test-CrNativeReady {
    param()
    $ready = Get-Variable -Name CrNativeReady -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    return ($ready -eq $true)
}

# Compiles on first use; throws with the compile error when the types are unavailable.
function Assert-CrNativeReady {
    param()
    if (Test-CrNativeReady) { return }
    Initialize-CrNative
    if (-not (Test-CrNativeReady)) {
        $err = Get-Variable -Name CrNativeError -Scope Script -ValueOnly -ErrorAction SilentlyContinue
        throw ('Native helpers are not available: ' + $err)
    }
}

# The logon rights and deny rights read into $State.Rights (CONTRACTS "Rights").
function Get-CrLsaRightNames {
    param()
    return , @(
        'SeNetworkLogonRight', 'SeInteractiveLogonRight', 'SeRemoteInteractiveLogonRight',
        'SeBatchLogonRight', 'SeServiceLogonRight',
        'SeDenyNetworkLogonRight', 'SeDenyInteractiveLogonRight', 'SeDenyRemoteInteractiveLogonRight',
        'SeDenyBatchLogonRight', 'SeDenyServiceLogonRight'
    )
}

function Get-CrMachineSid {
    param()
    Assert-CrNativeReady
    try {
        return [CrNativeLsa]::GetMachineSid()
    } catch {
        throw (Get-CrNativeErrorText $_)
    }
}

# Internal: SIDs holding one right (empty array when none).
function Get-CrLsaAccountsWithRight {
    param([string]$Right)
    Assert-CrNativeReady
    try {
        return , ([CrNativeLsa]::GetAccountsWithRight($Right))
    } catch {
        throw (Get-CrNativeErrorText $_)
    }
}

# Hashtable right name -> array of SID strings (possibly empty) for exactly the rights of Get-CrLsaRightNames.
# Throws if any right can't be read (e.g. not elevated).
function Get-CrLsaRightsMap {
    param()
    $map = @{}
    foreach ($right in (Get-CrLsaRightNames)) {
        $map[$right] = ConvertTo-CrArray (Get-CrLsaAccountsWithRight -Right $right)
    }
    return $map
}

# Internal: the seven raw DWORDs of NetUserModalsGet levels 0 and 3 (see CrNativeNet.GetUserModals).
function Get-CrUserModalsRaw {
    param()
    Assert-CrNativeReady
    try {
        return , ([CrNativeNet]::GetUserModals())
    } catch {
        throw (Get-CrNativeErrorText $_)
    }
}

# TIMEQ_FOREVER (0xFFFFFFFF) becomes -1 ("never" / "until an administrator unlocks").
function ConvertFrom-CrTimeq {
    param($Value)
    $v = [long]$Value
    if ($v -eq 4294967295) { return [long]-1 }
    return $v
}

function Get-CrUserModals {
    param()
    $raw = ConvertTo-CrArray (Get-CrUserModalsRaw)
    if ($raw.Count -ne 7) { throw ('NetUserModalsGet returned {0} values instead of 7' -f $raw.Count) }
    return @{
        MinPasswordLength         = [int]$raw[0]
        MaxPasswordAgeSeconds     = ConvertFrom-CrTimeq $raw[1]
        MinPasswordAgeSeconds     = [long]$raw[2]
        PasswordHistoryLength     = [int]$raw[3]
        LockoutDurationSeconds    = ConvertFrom-CrTimeq $raw[4]
        LockoutObservationSeconds = [long]$raw[5]
        LockoutThreshold          = [int]$raw[6]
    }
}

# Local group names (NetLocalGroupEnum level 0); returns an array.
function Get-CrLocalGroupNames {
    param()
    Assert-CrNativeReady
    try {
        return , ([CrNativeNet]::GetLocalGroupNames())
    } catch {
        throw (Get-CrNativeErrorText $_)
    }
}

# Member SIDs of one local group (NetLocalGroupGetMembers level 0, D5); returns an array.
function Get-CrLocalGroupMemberSids {
    param([string]$GroupName)
    Assert-CrNativeReady
    try {
        return , ([CrNativeNet]::GetLocalGroupMemberSids($GroupName))
    } catch {
        throw (Get-CrNativeErrorText $_)
    }
}
