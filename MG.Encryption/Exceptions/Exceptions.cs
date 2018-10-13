using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace MG.Encryption.Exceptions
{
    public class InvalidProtectedStringException : ArgumentException
    {
        private protected const string defMsg = "{0} is not a valid protected string.";

        public readonly string InvalidString;

        public InvalidProtectedStringException(string attempt)
            : base(string.Format(defMsg, attempt)) => InvalidString = attempt;
    }

    public class ThumbprintNotFoundException : CryptographicException
    {
        private protected const string defMsg = "{0} was not found in the {1} store.";

        public readonly string InvalidThumbprint;
        public readonly StoreLocation LocationSearched;

        public ThumbprintNotFoundException(string thumb, StoreLocation location)
            : this(thumb, location, null)
        {
        }
        public ThumbprintNotFoundException(string thumb, StoreLocation location, CryptographicException inner)
            : base(string.Format(defMsg, thumb, location.ToString()), inner)
        {
            InvalidThumbprint = thumb;
            LocationSearched = location;
        }
    }

    public class ProtectedStringDecryptionException : CryptographicException
    {
        private protected const string defMsg = "{0} was unable to be decrypted.  {1}";

        public readonly ProtectedString ProtectedString;

        public ProtectedStringDecryptionException(ProtectedString pStr, Exception innerException)
            : base(string.Format(defMsg, pStr.ToString(), innerException.Message), innerException) => ProtectedString = pStr;
    }
}
