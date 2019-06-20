using Microsoft.Win32;
using CERTENROLLLib;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace MG.Encryption
{
    public partial class SecurityManager
    {
        public void WriteToRegistry(string registryPath, ISecurable value, RegKind regAs)
        {
            RegistryValueKind kind;
            object writeThis = null;
            if (regAs == RegKind.String)
            {
                writeThis = Encoding.UTF8.GetString(value.GetBytes());
                kind = RegistryValueKind.String;
            }
            else
            {
                writeThis = value.GetBytes();
                kind = RegistryValueKind.Binary;
            }

            Registry.SetValue(registryPath, )
        }
    }
}