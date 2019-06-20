using CERTENROLLLib;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace MG.Encryption
{
    public partial class SecurityManager : IDisposable
    {
        private bool _isDisp = false;
        public X509Certificate2 Certificate { get; private set; }

        #region Constructors

        public SecurityManager() { }

        public SecurityManager(string sha1Thumbprint, StoreLocation location)
        {
            using (var store = new X509Store(location))
            {
                store.Open(OpenFlags.OpenExistingOnly);
                X509Certificate2Collection certs = null;
                try
                {
                    certs = store.Certificates.Find(X509FindType.FindByThumbprint, sha1Thumbprint, false);
                }
                catch (CryptographicException ex)
                {
                    throw new ThumbprintNotFoundException(sha1Thumbprint, location, ex);
                }
                if (certs == null || certs.Count == 0)
                    throw new ThumbprintNotFoundException(sha1Thumbprint, location);
                else
                    this.Certificate = certs[0];
            }
        }
        public SecurityManager(string sha1Thumbprint) 
            : this(sha1Thumbprint, StoreLocation.CurrentUser) { }
        public SecurityManager(X509Certificate2 certificate) => this.SetCertificate(certificate);

        #endregion

        public virtual void Dispose()
        {
            if (!_isDisp)
            {
                if (this.Certificate != null)
                    this.Certificate.Dispose();

                GC.SuppressFinalize(this.Certificate);
                GC.SuppressFinalize(this);

                _isDisp = true;
            }
        }

        #region Add Certificate Method

        public void SetCertificate(X509Certificate2 certificate)
        {
            if (_isDisp)
                throw new ObjectDisposedException("SecurityManager");

            this.Certificate = certificate;
        }

        #endregion

        #region Encrypt/Decrypt

        public ISecurable EncryptString(ISecurable pts)
        {
            if (_isDisp)
                throw new ObjectDisposedException("SecurityManager");

            if (this.Certificate == null)
                throw new InvalidOperationException("The encryption certificate is still not set!  Use the 'SetCertificate' method first.");

            var cinfo = new ContentInfo(pts.GetBytes());
            var cms = new EnvelopedCms(cinfo);
            var recipient = new CmsRecipient(this.Certificate);
            cms.Encrypt(recipient);
            var base64 = StringSecurer.ToBase64Securable(cms.Encode());
            return base64;
        }

        public ISecurable DecryptContent(ISecurable pStr)
        {
            byte[] sBytes = pStr.GetBytes();
            byte[] content = StringSecurer.FromBase64BytesToBytes(sBytes);
            var cms = new EnvelopedCms();
            cms.Decode(content);
            try
            {
                cms.Decrypt();
            }
            catch (Exception ex)
            {
                throw new ProtectedStringDecryptionException(ex);
            }
            var pts = StringSecurer.FromBase64Bytes(cms.ContentInfo.Content);
            return pts;
        }

        #endregion

        #region New Certificate Generation
        private protected const string provName = "Microsoft Enhanced RSA and AES Cryptographic Provider";
        private readonly string[] EnhancedUsages = new string[2] { "Server Authentication", "Client Authentication" };
        private protected List<CX509Extension> ExtensionsToAdd;

        private protected void SetEnhancedUsages()
        {
            var oids = new CObjectIds();
            for (int i = 0; i < EnhancedUsages.Length; i++)
            {
                var s = EnhancedUsages[i];
                var oid = new CObjectId();
                var eu = Oid.FromFriendlyName(s, OidGroup.EnhancedKeyUsage);
                oid.InitializeFromValue(eu.Value);
            }
            var eku = new CX509ExtensionEnhancedKeyUsage();
            eku.InitializeEncode(oids);
            ExtensionsToAdd.Add((CX509Extension)eku);
        }

        public enum Algorithm : int
        {
            SHA256 = 0,
            SHA384 = 1,
            SHA512 = 2
        }

        #endregion
    }
}
