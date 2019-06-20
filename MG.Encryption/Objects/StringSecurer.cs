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
        private const double BYTE_BASE = 16;
        private const int ZERO = 0;

        private int _origLength = ZERO;
        private int _numOfBlanks;
        private byte[] _backingBytes;

        #endregion

        #region PROPERTIES
        public virtual int Length => _origLength;

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

        protected internal virtual string Desecure() => Encoding.UTF8.GetString(((ISecurable)this).GetBytes());
        byte[] ISecurable.GetBytes()
        {
            byte[] newBytes = new byte[_origLength];
            ProtectedMemory.Unprotect(_backingBytes, MemoryProtectionScope.SameProcess);
            _backingBytes.ToList().CopyTo(ZERO, newBytes, ZERO, _origLength);
            ProtectedMemory.Protect(_backingBytes, MemoryProtectionScope.SameProcess);
            return newBytes;
        }
        void ISecurable.Protect(byte[] realBytes)
        {
            _origLength = realBytes.Length;
            double round = Math.Round(_origLength / BYTE_BASE, ZERO, MidpointRounding.AwayFromZero);
            if (round.Equals(ZERO))
                round++;

            int newLength = Convert.ToInt32(round * BYTE_BASE);

            _numOfBlanks = newLength - _origLength;

            _backingBytes = new byte[newLength];
            for (int i = 0; i < _origLength; i++)
            {
                _backingBytes[i] = realBytes[i];
            }
            ProtectedMemory.Protect(_backingBytes, MemoryProtectionScope.SameProcess);
        }
        void ISecurable.Protect(string str)
        {
            byte[] realBytes = Encoding.UTF8.GetBytes(str);
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

        internal static byte[] FromBase64BytesToBytes(byte[] baseBytes) => Convert.FromBase64String(Encoding.UTF8.GetString(baseBytes));

        internal static ISecurable FromBase64Bytes(byte[] bytes)
        {
            string str = Encoding.UTF8.GetString(bytes);
            return new StringSecurer(str);
        }

        internal static ISecurable FromBase64String(string base64) => new StringSecurer(base64);

        #endregion
    }
}