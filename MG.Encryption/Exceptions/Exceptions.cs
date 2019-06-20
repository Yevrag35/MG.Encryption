using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace MG.Encryption
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
        private protected const string defMsg = "The string was unable to be decrypted.  {0}";

        public ProtectedStringDecryptionException(Exception innerException)
            : base(string.Format(defMsg, GetInnerException(innerException).Message), GetInnerException(innerException)) { }

        private static Exception GetInnerException(Exception e)
        {
            while (e.InnerException != null)
            {
                e = e.InnerException;
            }
            return e;
        }
    }
}
