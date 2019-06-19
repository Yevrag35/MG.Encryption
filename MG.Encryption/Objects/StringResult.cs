using System;

namespace MG.Encryption
{
    public sealed class StringResult
    {
        public readonly SecurableString String;
        public readonly string UrlEncodedString;

        private StringResult(SecurableString pts)
        {
            String = pts;
            UrlEncodedString = pts.UrlEncode();
        }
        private StringResult(string plainStr)
        {
            PlainTextString pts = plainStr;
            String = pts;
            UrlEncodedString = pts.UrlEncode();
        }

        public override string ToString() => this.String.ToString();

        public static explicit operator StringResult(SecurableString pts) =>
            new StringResult(pts);

        public static explicit operator string(StringResult sr) => sr.ToString();
    }
}
