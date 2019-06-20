using System;
using System.Collections;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Management.Automation;
using System.Net;
using System.Security;

namespace MG.Encryption.PowerShell
{
    public class SecurableString : StringSecurer, ISecurable
    {
        private SecurableString(byte[] bytes)
            : base(bytes) { }

        private SecurableString(string plainStr)
            : base(plainStr) { }

        private SecurableString(SecureString ss)
            : base(ss) { }

        public static string UrlEncode(string strToEncode) => WebUtility.UrlDecode(strToEncode);
        public static string UrlDecode(string encodedStr) => WebUtility.UrlDecode(encodedStr);

        public static implicit operator SecurableString(byte[] bytes) => new SecurableString(bytes);
        public static implicit operator SecurableString(int integer) => new SecurableString(Convert.ToString(integer));
        public static implicit operator SecurableString(string plainStr) => new SecurableString(plainStr);
        public static implicit operator SecurableString(NetworkCredential netCreds) => new SecurableString(netCreds.SecurePassword.Copy());
        public static implicit operator SecurableString(PSCredential psCreds) => new SecurableString(psCreds.Password.Copy());
        public static implicit operator SecurableString(SqlCredential sqlCreds) => new SecurableString(sqlCreds.Password.Copy());
        public static implicit operator SecurableString(SecureString ss) => new SecurableString(ss.Copy());
    }
}
