using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace MG.Encryption
{
    public interface ISecurable
    {
        int Length { get; }

        SecureString AsSecureString();
        byte[] GetBytes();
        void Protect(byte[] bytes);
        void Protect(string str);
        void StoreString(SecureString secureString);
    }
}
