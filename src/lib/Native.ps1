# Native.ps1 - Add-Type C# 2.0 helpers (advapi32 LSA, netapi32, SCM) and thin PowerShell wrappers (docs/dev/CONTRACTS.md).
# M1 read side + M2/M3 write side. The C# compiles once, in Initialize-CrNative.
# D4: secrets arrive as SecureStrings, become BSTRs only here (ConvertTo-CrBstr), reach C# as IntPtr and are
# zero-freed in finally (Clear-CrBstr). The C# never turns them into managed strings, never logs them and never
# puts them into exception messages.

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
    private const uint POLICY_CREATE_ACCOUNT = 0x00000010;
    private const uint POLICY_CREATE_SECRET = 0x00000020;
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

    [DllImport("advapi32.dll")]
    private static extern uint LsaAddAccountRights(IntPtr policyHandle, IntPtr accountSid,
        ref LSA_UNICODE_STRING userRights, uint countOfRights);

    [DllImport("advapi32.dll", EntryPoint = "LsaStorePrivateData")]
    private static extern uint LsaStorePrivateDataValue(IntPtr policyHandle, ref LSA_UNICODE_STRING keyName,
        ref LSA_UNICODE_STRING privateData);

    [DllImport("advapi32.dll", EntryPoint = "LsaStorePrivateData")]
    private static extern uint LsaStorePrivateDataNull(IntPtr policyHandle, ref LSA_UNICODE_STRING keyName,
        IntPtr privateData);

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

    // ---- write side (M2/M3): Win32 error codes instead of exceptions --------------------------------------

    private static int ToWin32(uint status)
    {
        if (status == 0) { return 0; }
        return LsaNtStatusToWinError(status);
    }

    // LSA_UNICODE_STRING over a copy of a (non-secret) managed string; free Buffer with Marshal.FreeHGlobal.
    private static LSA_UNICODE_STRING NewLsaString(string text)
    {
        if (text.Length > 32766) { throw new ArgumentException("string is too long for LSA_UNICODE_STRING"); }
        LSA_UNICODE_STRING value = new LSA_UNICODE_STRING();
        value.Length = (ushort)(text.Length * 2);
        value.MaximumLength = (ushort)((text.Length + 1) * 2);
        value.Buffer = Marshal.StringToHGlobalUni(text);
        return value;
    }

    // LsaAddAccountRights for one right. Adds only; this tool never removes rights (PLAN 7.3).
    public static int AddAccountRight(string sid, string right)
    {
        if (right == null || right.Length == 0) { throw new ArgumentException("right is empty"); }
        IntPtr pSid = CrNativeSid.ToHGlobal(sid);
        try
        {
            LSA_OBJECT_ATTRIBUTES attributes = new LSA_OBJECT_ATTRIBUTES();
            attributes.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
            IntPtr handle = IntPtr.Zero;
            uint status = LsaOpenPolicy(IntPtr.Zero, ref attributes, POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT,
                out handle);
            if (status != 0) { return ToWin32(status); }
            try
            {
                LSA_UNICODE_STRING name = NewLsaString(right);
                try
                {
                    status = LsaAddAccountRights(handle, pSid, ref name, 1);
                }
                finally
                {
                    Marshal.FreeHGlobal(name.Buffer);
                }
                return ToWin32(status);
            }
            finally
            {
                LsaClose(handle);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(pSid);
        }
    }

    // LsaStorePrivateData(keyName, value) with the caller's BSTR as the buffer (never copied).
    // A null bstr would delete the secret, so it is refused here; DeletePrivateData does that explicitly.
    public static int StorePrivateData(string keyName, IntPtr bstr)
    {
        if (bstr == IntPtr.Zero) { throw new ArgumentNullException("bstr"); }
        int chars = CrNativeSecret.Length(bstr);
        if (chars > 32766) { throw new ArgumentException("the value is too long for LSA_UNICODE_STRING"); }
        LSA_UNICODE_STRING value = new LSA_UNICODE_STRING();
        value.Length = (ushort)(chars * 2);
        value.MaximumLength = (ushort)((chars + 1) * 2);
        value.Buffer = bstr;
        try
        {
            return StorePrivateDataCore(keyName, true, ref value);
        }
        finally
        {
            value.Buffer = IntPtr.Zero;
        }
    }

    // LsaStorePrivateData(keyName, NULL): deletes the secret. STATUS_OBJECT_NAME_NOT_FOUND is returned as
    // ERROR_FILE_NOT_FOUND (2); the PowerShell wrapper counts it as success. Never LsaRetrieve*.
    public static int DeletePrivateData(string keyName)
    {
        LSA_UNICODE_STRING unused = new LSA_UNICODE_STRING();
        return StorePrivateDataCore(keyName, false, ref unused);
    }

    private static int StorePrivateDataCore(string keyName, bool store, ref LSA_UNICODE_STRING value)
    {
        if (keyName == null || keyName.Length == 0) { throw new ArgumentException("keyName is empty"); }
        LSA_OBJECT_ATTRIBUTES attributes = new LSA_OBJECT_ATTRIBUTES();
        attributes.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
        IntPtr handle = IntPtr.Zero;
        uint status = LsaOpenPolicy(IntPtr.Zero, ref attributes, POLICY_CREATE_SECRET, out handle);
        if (status != 0) { return ToWin32(status); }
        try
        {
            LSA_UNICODE_STRING key = NewLsaString(keyName);
            try
            {
                if (store) { status = LsaStorePrivateDataValue(handle, ref key, ref value); }
                else { status = LsaStorePrivateDataNull(handle, ref key, IntPtr.Zero); }
            }
            finally
            {
                Marshal.FreeHGlobal(key.Buffer);
            }
            return ToWin32(status);
        }
        finally
        {
            LsaClose(handle);
        }
    }
}

internal static class CrNativeSid
{
    // Binary SID in HGlobal memory; the caller frees it with Marshal.FreeHGlobal.
    public static IntPtr ToHGlobal(string sid)
    {
        if (sid == null || sid.Length == 0) { throw new ArgumentException("sid is empty"); }
        SecurityIdentifier id = new SecurityIdentifier(sid);
        byte[] bytes = new byte[id.BinaryLength];
        id.GetBinaryForm(bytes, 0);
        IntPtr p = Marshal.AllocHGlobal(bytes.Length);
        Marshal.Copy(bytes, 0, p, bytes.Length);
        return p;
    }
}

// Operations over secrets given as BSTR pointers (D4, D15). Nothing here creates a managed string from a secret,
// and no exception message contains secret material.
public static class CrNativeSecret
{
    public const int CategoryUpper = 1;
    public const int CategoryLower = 2;
    public const int CategoryDigit = 4;
    public const int CategoryNonAlphanumeric = 8;
    public const int CategoryOtherLetter = 16;

    [DllImport("oleaut32.dll")]
    private static extern uint SysStringLen(IntPtr bstr);

    // Length in characters (IntPtr.Zero = empty).
    public static int Length(IntPtr bstr)
    {
        if (bstr == IntPtr.Zero) { return 0; }
        return (int)SysStringLen(bstr);
    }

    private static char CharAt(IntPtr bstr, int index)
    {
        return (char)Marshal.ReadInt16(bstr, index * 2);
    }

    // Length first, then every byte (no early exit inside equal-length strings).
    public static bool Equal(IntPtr a, IntPtr b)
    {
        int lengthA = Length(a);
        int lengthB = Length(b);
        if (lengthA != lengthB) { return false; }
        int diff = 0;
        int bytes = lengthA * 2;
        for (int i = 0; i < bytes; i++)
        {
            diff |= Marshal.ReadByte(a, i) ^ Marshal.ReadByte(b, i);
        }
        return diff == 0;
    }

    // D15 emulation. Returns [0] length in characters, [1] category bits (Category* constants),
    // [2] 1 if any token of 3+ characters occurs case-insensitively, else 0. Never says which token.
    public static int[] Complexity(IntPtr bstr, string[] tokens)
    {
        int length = Length(bstr);
        int mask = 0;
        for (int i = 0; i < length; i++)
        {
            char c = CharAt(bstr, i);
            if (char.IsUpper(c)) { mask |= CategoryUpper; }
            else if (char.IsLower(c)) { mask |= CategoryLower; }
            else if (char.IsDigit(c)) { mask |= CategoryDigit; }
            else if (char.IsLetter(c)) { mask |= CategoryOtherLetter; }
            else { mask |= CategoryNonAlphanumeric; }
        }
        int found = 0;
        if (tokens != null)
        {
            for (int t = 0; t < tokens.Length && found == 0; t++)
            {
                string token = tokens[t];
                if (token == null || token.Length < 3 || token.Length > length) { continue; }
                if (ContainsToken(bstr, length, token)) { found = 1; }
            }
        }
        return new int[] { length, mask, found };
    }

    private static bool ContainsToken(IntPtr bstr, int length, string token)
    {
        for (int start = 0; start + token.Length <= length; start++)
        {
            bool match = true;
            for (int j = 0; j < token.Length; j++)
            {
                if (char.ToUpperInvariant(CharAt(bstr, start + j)) != char.ToUpperInvariant(token[j]))
                {
                    match = false;
                    break;
                }
            }
            if (match) { return true; }
        }
        return false;
    }
}

// Local accounts (netapi32, LogonUserW). Write methods return Win32 / NET_API_STATUS codes; they throw only on
// invalid arguments. Secrets are BSTR pointers passed straight to the API.
public static class CrNativeAcct
{
    private const uint UF_SCRIPT = 0x0001;
    private const uint UF_PASSWD_CANT_CHANGE = 0x0040;
    private const uint UF_NORMAL_ACCOUNT = 0x0200;
    private const uint UF_DONT_EXPIRE_PASSWD = 0x10000;
    private const uint USER_PRIV_USER = 1;
    private const int NetValidatePasswordChange = 2;

    // USER_INFO_1 (lmaccess.h). Sequential layout with IntPtr pointers gives the native layout on both
    // architectures: x86 32 bytes (all fields 4 bytes), x64 56 bytes (flags at 40, 4 bytes padding before
    // usri1_script_path at 48).
    [StructLayout(LayoutKind.Sequential)]
    private struct USER_INFO_1
    {
        public IntPtr usri1_name;
        public IntPtr usri1_password;
        public uint usri1_password_age;
        public uint usri1_priv;
        public IntPtr usri1_home_dir;
        public IntPtr usri1_comment;
        public uint usri1_flags;
        public IntPtr usri1_script_path;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct USER_INFO_3
    {
        public IntPtr usri3_name;
        public IntPtr usri3_password;
        public uint usri3_password_age;
        public uint usri3_priv;
        public IntPtr usri3_home_dir;
        public IntPtr usri3_comment;
        public uint usri3_flags;
        public IntPtr usri3_script_path;
        public uint usri3_auth_flags;
        public IntPtr usri3_full_name;
        public IntPtr usri3_usr_comment;
        public IntPtr usri3_parms;
        public IntPtr usri3_workstations;
        public uint usri3_last_logon;
        public uint usri3_last_logoff;
        public uint usri3_acct_expires;
        public uint usri3_max_storage;
        public uint usri3_units_per_week;
        public IntPtr usri3_logon_hours;
        public uint usri3_bad_pw_count;
        public uint usri3_num_logons;
        public IntPtr usri3_logon_server;
        public uint usri3_country_code;
        public uint usri3_code_page;
        public uint usri3_user_id;
        public uint usri3_primary_group_id;
        public IntPtr usri3_profile;
        public IntPtr usri3_home_dir_drive;
        public uint usri3_password_expired;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NET_FILETIME
    {
        public uint LowDateTime;
        public uint HighDateTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NET_VALIDATE_PERSISTED_FIELDS
    {
        public uint PresentFields;
        public NET_FILETIME PasswordLastSet;
        public NET_FILETIME BadPasswordTime;
        public NET_FILETIME LockoutTime;
        public uint BadPasswordCount;
        public uint PasswordHistoryLength;
        public IntPtr PasswordHistory;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NET_VALIDATE_PASSWORD_HASH
    {
        public uint Length;
        public IntPtr Hash;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NET_VALIDATE_PASSWORD_CHANGE_INPUT_ARG
    {
        public NET_VALIDATE_PERSISTED_FIELDS InputPersistedFields;
        public IntPtr ClearPassword;
        public IntPtr UserAccountName;
        public NET_VALIDATE_PASSWORD_HASH HashedPassword;
        public byte PasswordMatch;
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserGetInfo(string serverName, string userName, int level, out IntPtr bufPtr);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "NetUserSetInfo")]
    private static extern int NetUserSetInfoFlags(string serverName, string userName, int level, ref uint flags,
        out int parmErr);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "NetUserSetInfo")]
    private static extern int NetUserSetInfoPassword(string serverName, string userName, int level,
        ref IntPtr password, out int parmErr);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserAdd(string serverName, int level, ref USER_INFO_1 buf, out int parmErr);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserChangePassword(string domainName, string userName, IntPtr oldPassword,
        IntPtr newPassword);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetLocalGroupAddMembers(string serverName, string groupName, int level, ref IntPtr buf,
        int totalEntries);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetLocalGroupDelMembers(string serverName, string groupName, int level, ref IntPtr buf,
        int totalEntries);

    [DllImport("netapi32.dll")]
    private static extern int NetValidatePasswordPolicy(IntPtr serverName, IntPtr qualifier, int validationType,
        ref NET_VALIDATE_PASSWORD_CHANGE_INPUT_ARG inputArg, out IntPtr outputArg);

    [DllImport("netapi32.dll")]
    private static extern int NetValidatePasswordPolicyFree(ref IntPtr outputArg);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buffer);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "LogonUserW",
        ExactSpelling = true)]
    private static extern bool LogonUserW(string userName, string domain, IntPtr password, int logonType,
        int logonProvider, out IntPtr token);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    private static void RequireName(string value, string name)
    {
        if (value == null || value.Length == 0) { throw new ArgumentException(name + " is empty"); }
    }

    private static void RequirePointer(IntPtr value, string name)
    {
        if (value == IntPtr.Zero) { throw new ArgumentNullException(name); }
    }

    // NetUserGetInfo level 3: [0] NET_API_STATUS, [1] usri3_flags, [2] usri3_bad_pw_count, [3] usri3_password_age.
    // The API never returns a password (usri3_password is always NULL).
    public static long[] GetUserInfo(string userName)
    {
        RequireName(userName, "userName");
        IntPtr buffer = IntPtr.Zero;
        try
        {
            int rc = NetUserGetInfo(null, userName, 3, out buffer);
            if (rc != 0) { return new long[] { rc, 0, 0, 0 }; }
            USER_INFO_3 info = (USER_INFO_3)Marshal.PtrToStructure(buffer, typeof(USER_INFO_3));
            return new long[] { 0, info.usri3_flags, info.usri3_bad_pw_count, info.usri3_password_age };
        }
        finally
        {
            if (buffer != IntPtr.Zero) { NetApiBufferFree(buffer); }
        }
    }

    // NetUserSetInfo level 1008 (USER_INFO_1008 = one DWORD). UF_SCRIPT is required by the API and always set.
    public static int SetUserFlags(string userName, int flags)
    {
        RequireName(userName, "userName");
        uint value = unchecked((uint)flags) | UF_SCRIPT;
        int parmErr = 0;
        return NetUserSetInfoFlags(null, userName, 1008, ref value, out parmErr);
    }

    // NetUserChangePassword(<this computer>, user, old, new): a change, which keeps the DPAPI master keys (D9).
    // The computer name is passed explicitly: NULL would mean the caller's logon domain, which is only
    // this computer when the operator is logged on with a local account.
    public static int ChangePassword(string userName, IntPtr oldBstr, IntPtr newBstr)
    {
        RequireName(userName, "userName");
        RequirePointer(oldBstr, "oldBstr");
        RequirePointer(newBstr, "newBstr");
        return NetUserChangePassword(Environment.MachineName, userName, oldBstr, newBstr);
    }

    // NetUserSetInfo level 1003 (USER_INFO_1003 = one LPWSTR): an administrative reset.
    public static int ResetPassword(string userName, IntPtr newBstr)
    {
        RequireName(userName, "userName");
        RequirePointer(newBstr, "newBstr");
        IntPtr value = newBstr;
        int parmErr = 0;
        try
        {
            return NetUserSetInfoPassword(null, userName, 1003, ref value, out parmErr);
        }
        finally
        {
            value = IntPtr.Zero;
        }
    }

    // NetUserAdd level 1 (D21): a normal local user with USER_PRIV_USER (groups are the caller's job), password =
    // the caller's BSTR (never copied), flags UF_SCRIPT | UF_DONT_EXPIRE_PASSWD | UF_PASSWD_CANT_CHANGE
    // (+ UF_NORMAL_ACCOUNT, the account type NetUserAdd uses by default). 2224 = the account already exists,
    // 2245 = the password does not meet the policy. The comment may be null or empty.
    public static int AddUser(string userName, IntPtr bstr, string comment)
    {
        RequireName(userName, "userName");
        RequirePointer(bstr, "bstr");
        USER_INFO_1 info = new USER_INFO_1();
        IntPtr name = IntPtr.Zero;
        IntPtr text = IntPtr.Zero;
        try
        {
            name = Marshal.StringToHGlobalUni(userName);
            if (comment != null && comment.Length > 0) { text = Marshal.StringToHGlobalUni(comment); }
            info.usri1_name = name;
            info.usri1_password = bstr;
            info.usri1_password_age = 0;
            info.usri1_priv = USER_PRIV_USER;
            info.usri1_home_dir = IntPtr.Zero;
            info.usri1_comment = text;
            info.usri1_flags = UF_SCRIPT | UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWD | UF_PASSWD_CANT_CHANGE;
            info.usri1_script_path = IntPtr.Zero;
            int parmErr = 0;
            return NetUserAdd(null, 1, ref info, out parmErr);
        }
        finally
        {
            info.usri1_password = IntPtr.Zero;
            if (text != IntPtr.Zero) { Marshal.FreeHGlobal(text); }
            if (name != IntPtr.Zero) { Marshal.FreeHGlobal(name); }
        }
    }

    // NetLocalGroupAddMembers / DelMembers level 0 (LOCALGROUP_MEMBERS_INFO_0 = one PSID).
    // 1378 (already a member) / 1377 (not a member) are returned as-is; the wrapper counts them as success.
    public static int AddGroupMember(string groupName, string memberSid)
    {
        return ChangeGroupMember(groupName, memberSid, true);
    }

    public static int RemoveGroupMember(string groupName, string memberSid)
    {
        return ChangeGroupMember(groupName, memberSid, false);
    }

    private static int ChangeGroupMember(string groupName, string memberSid, bool add)
    {
        RequireName(groupName, "groupName");
        IntPtr pSid = CrNativeSid.ToHGlobal(memberSid);
        try
        {
            IntPtr entry = pSid;
            if (add) { return NetLocalGroupAddMembers(null, groupName, 0, ref entry, 1); }
            return NetLocalGroupDelMembers(null, groupName, 0, ref entry, 1);
        }
        finally
        {
            Marshal.FreeHGlobal(pSid);
        }
    }

    // LogonUserW(user, ".", password, type, LOGON32_PROVIDER_DEFAULT); the token is closed immediately.
    // Returns 0 or GetLastError (-1 if the API failed without setting one).
    public static int LogonTest(string userName, IntPtr bstr, int logonType)
    {
        RequireName(userName, "userName");
        RequirePointer(bstr, "bstr");
        if (logonType != 2 && logonType != 3 && logonType != 4 && logonType != 5)
        {
            throw new ArgumentOutOfRangeException("logonType");
        }
        IntPtr token = IntPtr.Zero;
        try
        {
            if (LogonUserW(userName, ".", bstr, logonType, 0, out token)) { return 0; }
            int error = Marshal.GetLastWin32Error();
            if (error == 0) { return -1; }
            return error;
        }
        finally
        {
            if (token != IntPtr.Zero) { CloseHandle(token); }
        }
    }

    // NetValidatePasswordPolicy(NULL, NULL, NetValidatePasswordChange, {ClearPassword = BSTR, UserAccountName,
    // PasswordMatch = TRUE}): [0] NET_API_STATUS of the call, [1] ValidationStatus (-1 if the call failed).
    // No persisted fields are passed, so only length, complexity and password filters are checked.
    public static int[] ValidatePasswordChange(string userName, IntPtr bstr)
    {
        RequireName(userName, "userName");
        RequirePointer(bstr, "bstr");
        NET_VALIDATE_PASSWORD_CHANGE_INPUT_ARG input = new NET_VALIDATE_PASSWORD_CHANGE_INPUT_ARG();
        IntPtr name = IntPtr.Zero;
        IntPtr output = IntPtr.Zero;
        try
        {
            name = Marshal.StringToHGlobalUni(userName);
            input.ClearPassword = bstr;
            input.UserAccountName = name;
            input.PasswordMatch = 1;
            int rc = NetValidatePasswordPolicy(IntPtr.Zero, IntPtr.Zero, NetValidatePasswordChange, ref input,
                out output);
            int status = -1;
            if (rc == 0 && output != IntPtr.Zero)
            {
                // NET_VALIDATE_OUTPUT_ARG { NET_VALIDATE_PERSISTED_FIELDS ChangedPersistedFields; NET_API_STATUS ValidationStatus; }
                status = Marshal.ReadInt32(output, Marshal.SizeOf(typeof(NET_VALIDATE_PERSISTED_FIELDS)));
            }
            return new int[] { rc, status };
        }
        finally
        {
            input.ClearPassword = IntPtr.Zero;
            if (output != IntPtr.Zero) { NetValidatePasswordPolicyFree(ref output); }
            if (name != IntPtr.Zero) { Marshal.FreeHGlobal(name); }
        }
    }
}

// Service logon credentials (SCM). Never starts or stops a service (D17).
public static class CrNativeSvc
{
    private const uint SC_MANAGER_CONNECT = 0x0001;
    private const uint SERVICE_CHANGE_CONFIG = 0x0002;
    private const uint SERVICE_NO_CHANGE = 0xFFFFFFFF;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "OpenSCManagerW",
        ExactSpelling = true)]
    private static extern IntPtr OpenSCManagerW(string machineName, string databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "OpenServiceW",
        ExactSpelling = true)]
    private static extern IntPtr OpenServiceW(IntPtr scManager, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "ChangeServiceConfigW",
        ExactSpelling = true)]
    private static extern bool ChangeServiceConfigW(IntPtr service, uint serviceType, uint startType,
        uint errorControl, string binaryPathName, string loadOrderGroup, IntPtr tagId, string dependencies,
        string serviceStartName, IntPtr password, string displayName);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    private static int LastError()
    {
        int error = Marshal.GetLastWin32Error();
        if (error == 0) { return -1; }
        return error;
    }

    // ChangeServiceConfigW(SERVICE_NO_CHANGE x3, NULL..., account, password, NULL): only the logon credentials.
    public static int SetLogon(string serviceName, string account, IntPtr bstr)
    {
        if (serviceName == null || serviceName.Length == 0) { throw new ArgumentException("serviceName is empty"); }
        if (account == null || account.Length == 0) { throw new ArgumentException("account is empty"); }
        if (bstr == IntPtr.Zero) { throw new ArgumentNullException("bstr"); }
        IntPtr scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
        if (scm == IntPtr.Zero) { return LastError(); }
        try
        {
            IntPtr service = OpenServiceW(scm, serviceName, SERVICE_CHANGE_CONFIG);
            if (service == IntPtr.Zero) { return LastError(); }
            try
            {
                if (ChangeServiceConfigW(service, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, null, null,
                    IntPtr.Zero, null, account, bstr, null))
                {
                    return 0;
                }
                return LastError();
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(scm);
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
    return [bool](('CrNativeLsa' -as [type]) -and ('CrNativeNet' -as [type]) -and ('CrNativeSecret' -as [type]) -and
        ('CrNativeAcct' -as [type]) -and ('CrNativeSvc' -as [type]))
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

# The logon rights and deny rights read into $State.Rights (CONTRACTS 4.1).
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

# =====================================================================================================================
# M2/M3 write side (CONTRACTS 5.3 and 2)
#
# Every public wrapper: Assert-CrNativeReady first (throws when the C# isn't available), then the arguments, then
# ConvertTo-CrBstr / the call layer / Clear-CrBstr in finally. The call layer (Invoke-CrNative* / Get-CrNative* /
# Set-CrNative* ...) is one thin function per C# method, so unit tests can mock it without touching the system.
# Results carry success and Win32 codes only, never secret material.
# =====================================================================================================================

# Internal: SecureString -> BSTR (unmanaged plaintext). The caller passes the pointer to Clear-CrBstr in finally.
function ConvertTo-CrBstr {
    param([System.Security.SecureString]$Secret)
    if ($null -eq $Secret) { throw 'ConvertTo-CrBstr: no SecureString given' }
    return [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)
}

# Internal: zeroes and frees a BSTR from ConvertTo-CrBstr; IntPtr.Zero is ignored.
function Clear-CrBstr {
    param([IntPtr]$Pointer)
    if ($Pointer -ne [IntPtr]::Zero) {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Pointer)
    }
}

# Internal: argument checks (messages name the parameter, never a value).
function Assert-CrSecretArgument {
    param($Value, [string]$Name)
    if (-not ($Value -is [System.Security.SecureString])) { throw ('-{0} must be a SecureString' -f $Name) }
}

function Assert-CrTextArgument {
    param($Value, [string]$Name)
    if (($null -eq $Value) -or (([string]$Value).Length -eq 0)) { throw ('-{0} is empty' -f $Name) }
}

# Internal: the contract result @{ Success; Win32Error }. -SuccessCodes lists non-zero codes that count as success.
function New-CrNativeResult {
    param([int]$Code, [int[]]$SuccessCodes)
    $ok = ($Code -eq 0)
    if ((-not $ok) -and $SuccessCodes) { $ok = ($SuccessCodes -contains $Code) }
    return @{ Success = [bool]$ok; Win32Error = $Code }
}

# --- call layer (mocked in unit tests) -------------------------------------------------------------------------------

function Invoke-CrNativeSecretEqual {
    param([IntPtr]$PointerA, [IntPtr]$PointerB)
    try { return [CrNativeSecret]::Equal($PointerA, $PointerB) } catch { throw (Get-CrNativeErrorText $_) }
}

function Get-CrNativeSecretLength {
    param([IntPtr]$Pointer)
    try { return [CrNativeSecret]::Length($Pointer) } catch { throw (Get-CrNativeErrorText $_) }
}

# Returns [0] length, [1] category bits, [2] 1 if a token occurs (CrNativeSecret.Complexity).
function Invoke-CrNativeSecretComplexity {
    param([IntPtr]$Pointer, [string[]]$Tokens)
    try { return , ([CrNativeSecret]::Complexity($Pointer, $Tokens)) } catch { throw (Get-CrNativeErrorText $_) }
}

# Returns [0] NET_API_STATUS, [1] ValidationStatus (CrNativeAcct.ValidatePasswordChange).
function Invoke-CrNativeValidatePassword {
    param([string]$UserName, [IntPtr]$Pointer)
    try { return , ([CrNativeAcct]::ValidatePasswordChange($UserName, $Pointer)) } catch { throw (Get-CrNativeErrorText $_) }
}

function Invoke-CrNativeLogonUser {
    param([string]$UserName, [IntPtr]$Pointer, [int]$LogonType)
    try { return [CrNativeAcct]::LogonTest($UserName, $Pointer, $LogonType) } catch { throw (Get-CrNativeErrorText $_) }
}

# Returns [0] NET_API_STATUS, [1] flags, [2] bad password count, [3] password age (CrNativeAcct.GetUserInfo).
function Get-CrNativeUserInfo {
    param([string]$UserName)
    try { return , ([CrNativeAcct]::GetUserInfo($UserName)) } catch { throw (Get-CrNativeErrorText $_) }
}

function Set-CrNativeUserFlags {
    param([string]$UserName, [int]$Flags)
    try { return [CrNativeAcct]::SetUserFlags($UserName, $Flags) } catch { throw (Get-CrNativeErrorText $_) }
}

function Invoke-CrNativeChangePassword {
    param([string]$UserName, [IntPtr]$OldPointer, [IntPtr]$NewPointer)
    try { return [CrNativeAcct]::ChangePassword($UserName, $OldPointer, $NewPointer) } catch { throw (Get-CrNativeErrorText $_) }
}

function Invoke-CrNativeResetPassword {
    param([string]$UserName, [IntPtr]$Pointer)
    try { return [CrNativeAcct]::ResetPassword($UserName, $Pointer) } catch { throw (Get-CrNativeErrorText $_) }
}

function Add-CrNativeUser {
    param([string]$UserName, [IntPtr]$Pointer, [string]$Comment)
    try { return [CrNativeAcct]::AddUser($UserName, $Pointer, $Comment) } catch { throw (Get-CrNativeErrorText $_) }
}

function Add-CrNativeGroupMember {
    param([string]$GroupName, [string]$MemberSid)
    try { return [CrNativeAcct]::AddGroupMember($GroupName, $MemberSid) } catch { throw (Get-CrNativeErrorText $_) }
}

function Remove-CrNativeGroupMember {
    param([string]$GroupName, [string]$MemberSid)
    try { return [CrNativeAcct]::RemoveGroupMember($GroupName, $MemberSid) } catch { throw (Get-CrNativeErrorText $_) }
}

function Add-CrNativeAccountRight {
    param([string]$Sid, [string]$Right)
    try { return [CrNativeLsa]::AddAccountRight($Sid, $Right) } catch { throw (Get-CrNativeErrorText $_) }
}

function Set-CrNativeLsaPrivateData {
    param([string]$Name, [IntPtr]$Pointer)
    try { return [CrNativeLsa]::StorePrivateData($Name, $Pointer) } catch { throw (Get-CrNativeErrorText $_) }
}

function Remove-CrNativeLsaPrivateData {
    param([string]$Name)
    try { return [CrNativeLsa]::DeletePrivateData($Name) } catch { throw (Get-CrNativeErrorText $_) }
}

function Set-CrNativeServiceLogon {
    param([string]$ServiceName, [string]$Account, [IntPtr]$Pointer)
    try { return [CrNativeSvc]::SetLogon($ServiceName, $Account, $Pointer) } catch { throw (Get-CrNativeErrorText $_) }
}

# --- public wrappers -------------------------------------------------------------------------------------------------

# True if both secrets are equal (compared on BSTRs in C#, length first).
function Test-CrSecretEqual {
    param([System.Security.SecureString]$A, [System.Security.SecureString]$B)
    Assert-CrNativeReady
    Assert-CrSecretArgument -Value $A -Name 'A'
    Assert-CrSecretArgument -Value $B -Name 'B'
    $ptrA = [IntPtr]::Zero
    $ptrB = [IntPtr]::Zero
    try {
        $ptrA = ConvertTo-CrBstr -Secret $A
        $ptrB = ConvertTo-CrBstr -Secret $B
        $equal = [bool](Invoke-CrNativeSecretEqual -PointerA $ptrA -PointerB $ptrB)
    } finally {
        Clear-CrBstr -Pointer $ptrA
        Clear-CrBstr -Pointer $ptrB
    }
    return $equal
}

# Length of a secret in characters.
function Get-CrSecretLength {
    param([System.Security.SecureString]$Secret)
    Assert-CrNativeReady
    Assert-CrSecretArgument -Value $Secret -Name 'Secret'
    $ptr = [IntPtr]::Zero
    try {
        $ptr = ConvertTo-CrBstr -Secret $Secret
        $length = [int](Get-CrNativeSecretLength -Pointer $ptr)
    } finally {
        Clear-CrBstr -Pointer $ptr
    }
    return $length
}

# The five D15 character categories (bits of CrNativeSecret.Complexity), in report order.
function Get-CrComplexityCategories {
    param()
    return , @(
        @{ Bit = 1; Name = 'Uppercase' },
        @{ Bit = 2; Name = 'Lowercase' },
        @{ Bit = 4; Name = 'Digit' },
        @{ Bit = 8; Name = 'NonAlphanumeric' },
        @{ Bit = 16; Name = 'OtherLetter' }
    )
}

# D15 emulation over the BSTR. Returns @{ Ok; TooShort; Categories ([int] number of categories present);
# MissingCategories (names of the categories not present); ContainsNameToken ($true if any token of 3+ characters
# occurs case-insensitively; never which one) }. Ok = long enough and, with -RequireComplexity, 3+ categories and
# no name token. -Tokens come from Get-CrNameTokens (Secrets.ps1).
function Test-CrSecretComplexity {
    param(
        [System.Security.SecureString]$Secret,
        [int]$MinLength = 0,
        [bool]$RequireComplexity = $true,
        [string[]]$Tokens = @()
    )
    Assert-CrNativeReady
    Assert-CrSecretArgument -Value $Secret -Name 'Secret'
    $ptr = [IntPtr]::Zero
    try {
        $ptr = ConvertTo-CrBstr -Secret $Secret
        $raw = ConvertTo-CrArray (Invoke-CrNativeSecretComplexity -Pointer $ptr -Tokens $Tokens)
    } finally {
        Clear-CrBstr -Pointer $ptr
    }
    if ($raw.Count -ne 3) { throw ('CrNativeSecret.Complexity returned {0} values instead of 3' -f $raw.Count) }
    $length = [int]$raw[0]
    $mask = [int]$raw[1]
    $hasToken = ([int]$raw[2] -ne 0)
    $count = 0
    $missing = New-Object System.Collections.ArrayList
    foreach ($category in (Get-CrComplexityCategories)) {
        if (($mask -band $category['Bit']) -ne 0) { $count++ } else { [void]$missing.Add($category['Name']) }
    }
    $tooShort = ($length -lt $MinLength)
    $ok = -not $tooShort
    if ($RequireComplexity -and (($count -lt 3) -or $hasToken)) { $ok = $false }
    return @{
        Ok                = [bool]$ok
        TooShort          = [bool]$tooShort
        Categories        = $count
        MissingCategories = $missing.ToArray()
        ContainsNameToken = [bool]$hasToken
    }
}

# Local OS policy check for a password change (NetValidatePasswordPolicy). Returns @{ Ok; Status; Win32Error }:
# Status = ValidationStatus (0 = accepted, e.g. 2245 too short) or $null when the call itself failed;
# Win32Error = the NET_API_STATUS of the call.
function Test-CrLocalPasswordPolicy {
    param([string]$UserName, [System.Security.SecureString]$Secret)
    Assert-CrNativeReady
    Assert-CrTextArgument -Value $UserName -Name 'UserName'
    Assert-CrSecretArgument -Value $Secret -Name 'Secret'
    $ptr = [IntPtr]::Zero
    try {
        $ptr = ConvertTo-CrBstr -Secret $Secret
        $raw = ConvertTo-CrArray (Invoke-CrNativeValidatePassword -UserName $UserName -Pointer $ptr)
    } finally {
        Clear-CrBstr -Pointer $ptr
    }
    if ($raw.Count -ne 2) { throw ('CrNativeAcct.ValidatePasswordChange returned {0} values instead of 2' -f $raw.Count) }
    $rc = [int]$raw[0]
    $status = $null
    if ($rc -eq 0) { $status = [int]$raw[1] }
    return @{ Ok = [bool](($rc -eq 0) -and ($status -eq 0)); Status = $status; Win32Error = $rc }
}

# LogonUserW against the local SAM with the given logon type; the token is closed at once.
# Win32Error: 1326 wrong password, 1385 logon type not granted, 1909 locked, 1331 disabled, 1330 expired.
function Invoke-CrLogonTest {
    param(
        [string]$UserName,
        [System.Security.SecureString]$Secret,
        [ValidateSet('Network', 'Interactive', 'Batch', 'Service')]
        [string]$LogonType = 'Network'
    )
    Assert-CrNativeReady
    Assert-CrTextArgument -Value $UserName -Name 'UserName'
    Assert-CrSecretArgument -Value $Secret -Name 'Secret'
    $types = @{ Interactive = 2; Network = 3; Batch = 4; Service = 5 }
    $type = [int]$types[$LogonType]
    $ptr = [IntPtr]::Zero
    try {
        $ptr = ConvertTo-CrBstr -Secret $Secret
        $rc = [int](Invoke-CrNativeLogonUser -UserName $UserName -Pointer $ptr -LogonType $type)
    } finally {
        Clear-CrBstr -Pointer $ptr
    }
    return New-CrNativeResult -Code $rc
}

# NetUserGetInfo level 3 -> @{ Success; Win32Error; Flags; BadPasswordCount; PasswordAgeSeconds } (values $null on
# failure). Never reads a password.
function Get-CrUserInfo {
    param([string]$UserName)
    Assert-CrNativeReady
    Assert-CrTextArgument -Value $UserName -Name 'UserName'
    $raw = ConvertTo-CrArray (Get-CrNativeUserInfo -UserName $UserName)
    if ($raw.Count -ne 4) { throw ('CrNativeAcct.GetUserInfo returned {0} values instead of 4' -f $raw.Count) }
    $rc = [int]$raw[0]
    $result = @{ Success = ($rc -eq 0); Win32Error = $rc; Flags = $null; BadPasswordCount = $null; PasswordAgeSeconds = $null }
    if ($rc -eq 0) {
        $result['Flags'] = [int]$raw[1]
        $result['BadPasswordCount'] = [int]$raw[2]
        $result['PasswordAgeSeconds'] = [long]$raw[3]
    }
    return $result
}

# NetUserSetInfo level 1008 (the full flags word; UF_SCRIPT is always kept). Also disables / enables an account
# (UF_ACCOUNTDISABLE 0x2 set / cleared, CONTRACTS v10; the flag math is in Accounts.ps1).
function Set-CrUserFlags {
    param([string]$UserName, [int]$Flags)
    Assert-CrNativeReady
    Assert-CrTextArgument -Value $UserName -Name 'UserName'
    $rc = [int](Set-CrNativeUserFlags -UserName $UserName -Flags $Flags)
    return New-CrNativeResult -Code $rc
}

# NetUserChangePassword: a change with the old password (keeps DPAPI, D9). 86 = wrong old password,
# 2245 = policy / history / minimum age.
function Invoke-CrNetPasswordChange {
    param([string]$UserName, [System.Security.SecureString]$OldSecret, [System.Security.SecureString]$NewSecret)
    Assert-CrNativeReady
    Assert-CrTextArgument -Value $UserName -Name 'UserName'
    Assert-CrSecretArgument -Value $OldSecret -Name 'OldSecret'
    Assert-CrSecretArgument -Value $NewSecret -Name 'NewSecret'
    $oldPtr = [IntPtr]::Zero
    $newPtr = [IntPtr]::Zero
    try {
        $oldPtr = ConvertTo-CrBstr -Secret $OldSecret
        $newPtr = ConvertTo-CrBstr -Secret $NewSecret
        $rc = [int](Invoke-CrNativeChangePassword -UserName $UserName -OldPointer $oldPtr -NewPointer $newPtr)
    } finally {
        Clear-CrBstr -Pointer $oldPtr
        Clear-CrBstr -Pointer $newPtr
    }
    return New-CrNativeResult -Code $rc
}

# NetUserSetInfo level 1003: an administrative reset (the DPAPI warning is the caller's job).
function Invoke-CrNetPasswordReset {
    param([string]$UserName, [System.Security.SecureString]$NewSecret)
    Assert-CrNativeReady
    Assert-CrTextArgument -Value $UserName -Name 'UserName'
    Assert-CrSecretArgument -Value $NewSecret -Name 'NewSecret'
    $ptr = [IntPtr]::Zero
    try {
        $ptr = ConvertTo-CrBstr -Secret $NewSecret
        $rc = [int](Invoke-CrNativeResetPassword -UserName $UserName -Pointer $ptr)
    } finally {
        Clear-CrBstr -Pointer $ptr
    }
    return New-CrNativeResult -Code $rc
}

# NetUserAdd level 1 (D21, CONTRACTS v10): creates a local user (USER_PRIV_USER, PNE + CCP) with the secret as
# its password. 2224 (the account exists) is a failure with that code; 2245 = the password policy rejected it.
function New-CrLocalUser {
    param([string]$UserName, [System.Security.SecureString]$Secret, [string]$Comment = '')
    Assert-CrNativeReady
    Assert-CrTextArgument -Value $UserName -Name 'UserName'
    Assert-CrSecretArgument -Value $Secret -Name 'Secret'
    $ptr = [IntPtr]::Zero
    try {
        $ptr = ConvertTo-CrBstr -Secret $Secret
        $rc = [int](Add-CrNativeUser -UserName $UserName -Pointer $ptr -Comment $Comment)
    } finally {
        Clear-CrBstr -Pointer $ptr
    }
    return New-CrNativeResult -Code $rc
}

# NetLocalGroupAddMembers level 0 by SID; 1378 (already a member) counts as success.
function Add-CrLocalGroupMemberSid {
    param([string]$GroupName, [string]$MemberSid)
    Assert-CrNativeReady
    Assert-CrTextArgument -Value $GroupName -Name 'GroupName'
    Assert-CrTextArgument -Value $MemberSid -Name 'MemberSid'
    $rc = [int](Add-CrNativeGroupMember -GroupName $GroupName -MemberSid $MemberSid)
    return New-CrNativeResult -Code $rc -SuccessCodes @(1378)
}

# NetLocalGroupDelMembers level 0 by SID; 1377 (not a member) counts as success.
function Remove-CrLocalGroupMemberSid {
    param([string]$GroupName, [string]$MemberSid)
    Assert-CrNativeReady
    Assert-CrTextArgument -Value $GroupName -Name 'GroupName'
    Assert-CrTextArgument -Value $MemberSid -Name 'MemberSid'
    $rc = [int](Remove-CrNativeGroupMember -GroupName $GroupName -MemberSid $MemberSid)
    return New-CrNativeResult -Code $rc -SuccessCodes @(1377)
}

# LsaAddAccountRights for one right (adds only, PLAN 7.3).
function Grant-CrAccountRight {
    param([string]$Sid, [string]$Right)
    Assert-CrNativeReady
    Assert-CrTextArgument -Value $Sid -Name 'Sid'
    Assert-CrTextArgument -Value $Right -Name 'Right'
    $rc = [int](Add-CrNativeAccountRight -Sid $Sid -Right $Right)
    return New-CrNativeResult -Code $rc
}

# LsaStorePrivateData(Name, BSTR), e.g. the auto-logon DefaultPassword secret. Never reads LSA secrets.
function Set-CrLsaSecret {
    param([string]$Name, [System.Security.SecureString]$Secret)
    Assert-CrNativeReady
    Assert-CrTextArgument -Value $Name -Name 'Name'
    Assert-CrSecretArgument -Value $Secret -Name 'Secret'
    $ptr = [IntPtr]::Zero
    try {
        $ptr = ConvertTo-CrBstr -Secret $Secret
        $rc = [int](Set-CrNativeLsaPrivateData -Name $Name -Pointer $ptr)
    } finally {
        Clear-CrBstr -Pointer $ptr
    }
    return New-CrNativeResult -Code $rc
}

# LsaStorePrivateData(Name, NULL); a missing secret (STATUS_OBJECT_NAME_NOT_FOUND -> 2) counts as success.
function Remove-CrLsaSecret {
    param([string]$Name)
    Assert-CrNativeReady
    Assert-CrTextArgument -Value $Name -Name 'Name'
    $rc = [int](Remove-CrNativeLsaPrivateData -Name $Name)
    return New-CrNativeResult -Code $rc -SuccessCodes @(2)
}

# ChangeServiceConfigW: logon account text and password only; never starts or stops the service (D17).
function Set-CrServiceLogonPassword {
    param([string]$ServiceName, [string]$Account, [System.Security.SecureString]$Secret)
    Assert-CrNativeReady
    Assert-CrTextArgument -Value $ServiceName -Name 'ServiceName'
    Assert-CrTextArgument -Value $Account -Name 'Account'
    Assert-CrSecretArgument -Value $Secret -Name 'Secret'
    $ptr = [IntPtr]::Zero
    try {
        $ptr = ConvertTo-CrBstr -Secret $Secret
        $rc = [int](Set-CrNativeServiceLogon -ServiceName $ServiceName -Account $Account -Pointer $ptr)
    } finally {
        Clear-CrBstr -Pointer $ptr
    }
    return New-CrNativeResult -Code $rc
}
