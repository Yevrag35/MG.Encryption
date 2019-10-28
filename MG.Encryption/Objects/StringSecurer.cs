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
    public class StringSecurer : ISecurable
    {
        #region FIELDS/CONSTANTS
        //private const int BYTE_BASE = 16;
        private const int ZERO = 0;

        private int _origLength = ZERO;
        //private int _numOfBlanks;
        private byte[] _backingBytes;

        #endregion

        #region PROPERTIES
        int ISecurable.Length => _origLength;

        #endregion

        #region CONSTRUCTORS
        public StringSecurer(byte[] plainBytes) => ((ISecurable)this).Protect(plainBytes);
        public StringSecurer(string str) => ((ISecurable)this).Protect(str);
        public StringSecurer(SecureString ss) => ((ISecurable)this).StoreString(ss);

        #endregion

        #region METHODS
        SecureString ISecurable.AsSecureString()
        {
            var ss = new SecureString();
            string plain = this.Desecure();
            for (int i = 0; i < plain.Length; i++)
            {
                ss.AppendChar(plain[i]);
            }
            return ss;
        }

        protected internal string Desecure() => Encoding.ASCII.GetString(((ISecurable)this).GetBytes());
        byte[] ISecurable.GetBytes()
        {
            return ProtectedData.Unprotect(_backingBytes, null, DataProtectionScope.CurrentUser);
            //byte[] newBytes = new byte[_backingBytes.Length];
            //ProtectedMemory.Unprotect(_backingBytes, MemoryProtectionScope.SameProcess);
            //_backingBytes.ToList().CopyTo(ZERO, newBytes, ZERO, _backingBytes.Length);
            //ProtectedMemory.Protect(_backingBytes, MemoryProtectionScope.SameProcess);
            //return newBytes;
        }
        void ISecurable.Protect(byte[] realBytes)
        {
            //_backingBytes = new byte[realBytes.Length];
            //realBytes.CopyTo(_backingBytes, ZERO);
            //ProtectedMemory.Protect(_backingBytes, MemoryProtectionScope.SameProcess);
            _backingBytes = ProtectedData.Protect(realBytes, null, DataProtectionScope.CurrentUser);
        }
        void ISecurable.Protect(string str)
        {
            byte[] realBytes = Encoding.ASCII.GetBytes(str);
            ((ISecurable)this).Protect(realBytes);
        }
        void ISecurable.StoreString(SecureString ss)
        {
            IntPtr pointer = Marshal.SecureStringToBSTR(ss);
            ((ISecurable)this).Protect(Marshal.PtrToStringAuto(pointer));
            Marshal.ZeroFreeBSTR(pointer);
        }

        internal static ISecurable ToBase64Securable(byte[] bytes)
        {
            string str = Convert.ToBase64String(bytes);
            return new StringSecurer(str);
        }

        internal static byte[] FromBase64BytesToBytes(byte[] baseBytes) => Convert.FromBase64String(Encoding.ASCII.GetString(baseBytes));

        internal static ISecurable FromBase64Bytes(byte[] bytes)
        {
            string str = Encoding.UTF8.GetString(bytes);
            return new StringSecurer(str);
        }

        internal static ISecurable FromBase64String(string base64) => new StringSecurer(base64);

        #endregion
    }
}