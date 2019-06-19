using System;
using System.Collections;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Management.Automation;
using System.Net;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace MG.Encryption
{
    public class SecurableString : StringDesecurer
    {
        private SecurableString(byte[] bytes)
            : base(bytes) { }

        private SecurableString(string plainStr)
            : base(plainStr) { }

        private SecurableString(SecureString ss)
            : base(ss) { }

        //public string AsString() => base.Desecure();
        internal SecureString AsSecureString()
        {
            var ss = new SecureString();
            string plain = base.Desecure();
            for (int i = 0; i < plain.Length; i++)
            {
                ss.AppendChar(plain[i]);
            }
            return ss;
        }
        internal PSCredential AsPSCredential(string userName)
        {
            return new PSCredential(userName, this.AsSecureString());
        }
        internal NetworkCredential AsNetworkCredential(string userName, string domain = null)
        {
            return new NetworkCredential(userName, this.AsSecureString(), domain);
        }

        //public string UrlEncode() => WebUtility.UrlEncode(this.AsString());
        public static string UrlEncode(string strToEncode) => WebUtility.UrlDecode(strToEncode);
        public static string UrlDecode(string encodedStr) => WebUtility.UrlDecode(encodedStr);

        public static implicit operator SecurableString(byte[] bytes) => new SecurableString(bytes);
        public static implicit operator SecurableString(string plainStr) => new SecurableString(plainStr);
        public static implicit operator SecurableString(NetworkCredential netCreds) => new SecurableString(netCreds.SecurePassword.Copy());
        public static implicit operator SecurableString(PSCredential psCreds) => new SecurableString(psCreds.Password.Copy());
        public static implicit operator SecurableString(SqlCredential sqlCreds) => new SecurableString(sqlCreds.Password.Copy());
        public static implicit operator SecurableString(SecureString ss) => new SecurableString(ss.Copy());
    }
}
