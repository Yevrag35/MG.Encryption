﻿using MG.Encryption.Exceptions;
using System;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace MG.Encryption
{
    public class Methods
    {
        private X509Certificate2 _cert = null;
        public X509Certificate2 Certificate => _cert;

        #region Constructors

        public Methods() { }

        public Methods(string sha1Thumbprint, StoreLocation location)
        {
            _cert = new X509Certificate2();
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
                    _cert = certs[0];
            }
        }
        public Methods(string sha1Thumbprint) : this(sha1Thumbprint, StoreLocation.CurrentUser)
        {
        }
        public Methods(X509Certificate2 certificate) => SetCertificate(certificate);

        #endregion

        #region Add Certificate Method

        public void SetCertificate(X509Certificate2 certificate) => _cert = certificate;

        #endregion

        public ProtectedString EncryptString(PlainTextString pts)
        {
            if (_cert == null)
                throw new InvalidOperationException("The encryption certificate is still not set!  Use the 'SetCertificate' method first.");

            var cinfo = new ContentInfo(pts.ToPlainBytes());
            var cms = new EnvelopedCms(cinfo);
            var recipient = new CmsRecipient(_cert);
            cms.Encrypt(recipient);
            ProtectedString base64 = Convert.ToBase64String(cms.Encode());
            return base64;
        }

        public StringResult DecryptContent(ProtectedString pStr)
        {
            byte[] content = Convert.FromBase64String(pStr.ToString());
            var cms = new EnvelopedCms();
            cms.Decode(content);
            try
            {
                cms.Decrypt();
            }
            catch (Exception ex)
            {
                throw new ProtectedStringDecryptionException(pStr, ex);
            }
            PlainTextString pts = Encoding.UTF8.GetString(cms.ContentInfo.Content);
            return (StringResult)pts;
        }
    }
}
