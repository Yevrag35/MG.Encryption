using Microsoft.Win32;
using CERTENROLLLib;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace MG.Encryption
{
    public sealed partial class CertificateSecurity
    {
        public static ISecurable ReadFromRegistry(string registryKey, string valueName)    
        {
            object regData = Registry.GetValue(registryKey, valueName, null);
            ISecurable isec = null;
            if (regData is byte[] bytes)
            {
                isec = StringSecurer.FromBase64Bytes(bytes);
            }
            else if (regData is string strData)
            {
                isec = StringSecurer.FromBase64String(strData);
            }
            else
                throw new InvalidCastException("The resulting registry data cannot be converted to a Securable object.");

            return isec; // the output is still encrypted...
        }
        public static void WriteToRegistry(string registryKey, string valueName, ISecurable value, RegKind regAs)
        {
            // the value should already be encrypted...
            RegistryValueKind kind;
            object writeThis = null;
            if (regAs == RegKind.String)
            {
                writeThis = Encoding.ASCII.GetString(value.GetBytes());
                kind = RegistryValueKind.String;
            }
            else
            {
                writeThis = value.GetBytes();
                kind = RegistryValueKind.Binary;
            }

            Registry.SetValue(registryKey, valueName, writeThis, kind);
        } 
    }
}