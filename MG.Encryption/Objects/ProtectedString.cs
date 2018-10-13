using MG.Encryption.Exceptions;
using System;
using System.Text;
using System.Text.RegularExpressions;

namespace MG.Encryption
{
    public class ProtectedString : SecurableString		// Used when pulling the encrypted string value from the registry
    {
        #region Properties/Fields/Constants

        private protected const string exp = @"^MII[A-Z](?=.*\+)(?=.*\/).*$";   // Not perfect; I know.  But at least it filters out stupid strings.
        private readonly string _val;
        internal override string Value => _val;

        #endregion

        #region Constructors

        private protected ProtectedString(byte[] encBytes)
        {
            var test = Encoding.UTF8.GetString(encBytes);
            if (Passes(test))
                _val = test;
            else
                throw new InvalidProtectedStringException(test);
        }

        private protected ProtectedString(string inStr)
        {
            if (Passes(inStr))
                _val = inStr;
            else
                throw new InvalidProtectedStringException(inStr);
        }

        #endregion

        #region Operators/Casts

        public static implicit operator ProtectedString(byte[] encBytes) => 
            new ProtectedString(encBytes);

        public static implicit operator ProtectedString(string inStr) =>
            new ProtectedString(inStr);

        #endregion

        #region Public Methods

        public byte[] ToBytes() => Encoding.UTF8.GetBytes(this.Value);

        #endregion

        #region Private Methods

        private protected bool Passes(string inStr) => 
            inStr.Length >= 500 && Regex.IsMatch(inStr, exp) ? true : false;

        #endregion
    }
}
