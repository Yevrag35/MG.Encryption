using MG.Attributes;
using System;

namespace MG.Encryption.Certificates
{
    public enum Provider
    {
        [MGName("Microsoft Enhanced RSA and AES Cryptographic Provider")]
        AESRSA = 0,

        [MGName("Microsoft Base Cryptographic Provider")]
        Base = 1,

        [MGName("Microsoft Strong Cryptographic Provider")]
        Strong = 2,

        [MGName("Microsoft Enhanced Cryptographic Provider")]
        Enhanced = 3
    }

    public enum Algorithms
    {
        SHA256 = 0,
        SHA384 = 1,
        SHA512 = 2,
        SHA1 = 3
    }

    public enum EnhancedUsages
    {
        [MGName("Client Authentication")]
        ClientAuth = 0,

        [MGName("Server Authentication")]
        ServerAuth = 1,

        [MGName("Code Signing")]
        CodeSigning = 2,

        [MGName("Secure Email")]
        SecureEmail = 3,

        [MGName("Encrypting File System")]
        EFS = 4,

        [MGName("Smart Card Logon")]
        SmartCard = 5,

        [MGName("Key Recovery")]
        KeyRecovery = 6,

        [MGName("Document Signing")]
        DocSigning = 7
    }
}
