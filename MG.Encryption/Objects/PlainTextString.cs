using System;
using System.Management.Automation;
using System.Net;
using System.Text;

namespace MG.Encryption
{
    public class PlainTextString : SecurableString
    {
        private readonly string _val;
        internal override string Value => _val;

        private protected PlainTextString(string str) => _val = str;

        public static implicit operator PlainTextString(string inStr) => new PlainTextString(inStr);
        public static implicit operator string(PlainTextString pts) => pts.ToString();

        public PSCredential AsCredential(PlainTextString userName) =>
            new PSCredential(userName, AsSecure());

        internal protected byte[] ToPlainBytes() => Encoding.UTF8.GetBytes(this.Value);
    }
}