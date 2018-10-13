using System;

namespace MG.Encryption.Exceptions
{
    public class InvalidProtectedStringException : ArgumentException
    {
        private protected const string defMsg = "{0} is not a valid protected string.";

        public readonly string InvalidString;

        public InvalidProtectedStringException(string attempt)
            : base(string.Format(defMsg, attempt)) => InvalidString = attempt;
    }
}
