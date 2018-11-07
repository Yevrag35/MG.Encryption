using CERTENROLLLib;
using MG.Attributes;
using MG.Encryption.Certificates;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace MG.Encryption
{
    public class CertificateGenerator
    {
        #region Private Fields/Properties


        #endregion

        #region Public Properties
        public Enrollment Enrollment { get; internal set; }

        #endregion

        #region Constructors
        public CertificateGenerator() { }
        public CertificateGenerator(Enrollment enrollment) =>
            Enrollment = enrollment;
        
        public CertificateGenerator(object template, Enrollment enrollment)
            : this(enrollment)
        {
        }

        #endregion

        #region CA Template Methods

        #endregion

        #region Self-Sign Methods
        public void SetBasicConstraints(bool isCA, int pathLength, bool isCritical)
        {
            var bc = new CX509ExtensionBasicConstraints()
            {
                Critical = isCritical
            };
            bc.InitializeEncode(isCA, pathLength);
            Enrollment.AddExtension(bc);
        }

        public void SetKeyUsage(CERTENROLLLib.X509KeyUsageFlags flags, bool isCritical)
        {
            var ku = new CX509ExtensionKeyUsage()
            {
                Critical = isCritical
            };
            ku.InitializeEncode(flags);
            Enrollment.AddExtension(ku);
        }

        public void SetEnhancedUsage(EnhancedUsages[] usages, bool isCritical)
        {
            var oids = new CObjectIds();
            for (int i = 0; i < usages.Length; i++)
            {
                var usage = usages[i];
                string usageName = Enrollment.GetNameAttribute(usage);
                var oid = new CObjectId();
                var eu = Oid.FromFriendlyName(usageName, OidGroup.EnhancedKeyUsage);
                oid.InitializeFromValue(eu.Value);
                oids.Add(oid);
            }
            var eku = new CX509ExtensionEnhancedKeyUsage()
            {
                Critical = isCritical
            };
            eku.InitializeEncode(oids);
            Enrollment.AddExtension(eku);
        }

        #endregion

        #region Private Backend Methods

        private protected CX509PrivateKey NewPrivateKey(Provider provider, bool allowExport)
        {
            string provName = Enrollment.GetNameAttribute(provider);
            var pk = new CX509PrivateKey()
            {
                ProviderName = provName
            };
            var algId = new CObjectId();
            var algVal = Oid.FromFriendlyName("RSA", OidGroup.PublicKeyAlgorithm);
            algId.InitializeFromValue(algVal.Value);

            pk.Algorithm = algId;
            pk.KeySpec = X509KeySpec.XCN_AT_KEYEXCHANGE;
            pk.Length = Enrollment.KeyLength;
            pk.MachineContext = Enrollment.Context.MachineContext;
            pk.ExportPolicy = (X509PrivateKeyExportFlags)Convert.ToInt32(allowExport);
            pk.Create();
            return pk;
        }

        #endregion
    }
}
