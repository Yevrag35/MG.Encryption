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
    public abstract class StringDesecurer
    {
        #region FIELDS/CONSTANTS
        private const double BYTE_BASE = 16;
        private const int ZERO = 0;

        private int _origLength = ZERO;
        private int _numOfBlanks;
        private byte[] _backingBytes;

        #endregion

        #region PROPERTIES
        public int Length => _origLength;

        #endregion

        #region CONSTRUCTORS
        internal StringDesecurer(byte[] plainBytes) => this.Protect(plainBytes);
        internal StringDesecurer(string str) => this.Protect(str);
        internal StringDesecurer(SecureString ss) => this.StoreString(ss);

        #endregion

        #region METHODS
        protected virtual string Desecure() => Encoding.UTF8.GetString(this.GetBytes());
        internal byte[] GetBytes()
        {
            byte[] newBytes = new byte[_origLength];
            ProtectedMemory.Unprotect(_backingBytes, MemoryProtectionScope.SameProcess);
            _backingBytes.ToList().CopyTo(ZERO, newBytes, ZERO, _origLength);
            ProtectedMemory.Protect(_backingBytes, MemoryProtectionScope.SameProcess);
            return newBytes;
        }
        private void Protect(byte[] realBytes)
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
        private void Protect(string str)
        {
            byte[] realBytes = Encoding.UTF8.GetBytes(str);
            this.Protect(realBytes);
        }

        private void StoreString(SecureString ss)
        {
            IntPtr pointer = Marshal.SecureStringToBSTR(ss);
            this.Protect(Marshal.PtrToStringAuto(pointer));
            Marshal.ZeroFreeBSTR(pointer);
        }

        #endregion
    }
}