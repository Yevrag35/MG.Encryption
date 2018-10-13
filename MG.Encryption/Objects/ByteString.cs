using System;
using System.Text;

namespace MG.Encryption
{
    public class ProtectedString : MGString		// Used when pulling the encrypted string value from the registry
    {
        private readonly string _val;
        internal override string Value => _val;

        private protected ProtectedString(byte[] encBytes) => _val = Encoding.UTF8.GetString(encBytes);
    }
}
