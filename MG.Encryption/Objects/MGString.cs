using System;
using System.Collections;
using System.Collections.Generic;
using System.Security;

namespace MG.Encryption
{
    public abstract class MGString : IEnumerable<string>
    {
        internal abstract string Value { get; }

        public SecureString AsSecure()
        {
            var ss = new SecureString();
            for (int i = 0; i < this.Value.Length; i++)
            {
                char c = this.Value[i];
                ss.AppendChar(c);
            }
            return ss;
        }

        public override string ToString() => this.Value;

        public IEnumerator<string> GetEnumerator() =>
            new List<string>(1) { this.Value }.GetEnumerator();
        IEnumerator IEnumerable.GetEnumerator() =>
            new List<string>(1) { this.Value }.GetEnumerator();
    }
}
