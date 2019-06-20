using System;

namespace MG.Encryption
{
    public enum OutputAs
    {
        String,
        PSCredential,
        SecureString,
        NetworkCredential,
        SqlCredential
    }

    public enum RegKind
    {
        String,
        Binary
    }
}
