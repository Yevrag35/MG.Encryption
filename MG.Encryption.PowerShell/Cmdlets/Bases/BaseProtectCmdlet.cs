using System;
using System.Management.Automation;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace MG.Encryption.PowerShell
{
    public class BaseProtectCmdlet : BaseCmdlet
    {
        #region PARAMETERS
        [Parameter(Mandatory = true, Position = 0)]
        [Alias("Credential", "String", "inStr")]
        public SecurableString Securable { get; set; }

        [Parameter(Mandatory = true, ValueFromPipeline = true, ParameterSetName = "WithX509CertificateAsString")]
        //[Parameter(Mandatory = true, ValueFromPipeline = true, ParameterSetName = "WithX509CertificateAsBytes")]
        [Alias("cert", "c")]
        public X509Certificate2 Certificate { get; set; }

        [Parameter(Mandatory = true, ParameterSetName = "FindCertificateAsString", Position = 1)]
        //[Parameter(Mandatory = true, ParameterSetName = "FindCertificateAsBytes", Position = 1)]
        [Alias("sha1")]
        public string SHA1Thumbprint { get; set; }

        [Parameter(Mandatory = false, ParameterSetName = "FindCertificateAsString")]
        //[Parameter(Mandatory = false, ParameterSetName = "FindCertificateAsBytes")]
        [Alias("store")]
        public StoreLocation Location = StoreLocation.CurrentUser;

        [Parameter(Mandatory = false)]
        [ValidateSet("String", "ByteArray")]
        public string OutputAs = "String";

        #endregion

        #region CMDLET PROCESSING
        protected override void BeginProcessing() => base.BeginProcessing();

        protected override void ProcessRecord()
        {
            enc = this.Certificate != null
                ? new CertificateSecurity(this.Certificate)
                : new CertificateSecurity(this.SHA1Thumbprint, this.Location);

            outStr = enc.EncryptString(Securable);
            if (outStr == null)
                NoEnd = true;
        }

        protected override void EndProcessing()
        {
            if (!NoEnd)
            {
                object outObj = OutputAs.Equals("String", StringComparison.CurrentCultureIgnoreCase)
                    ? Encoding.ASCII.GetString(outStr.GetBytes())
                    : (object)outStr.GetBytes();

                base.WriteObject(outObj, false);
            }
        }

        #endregion

        #region METHODS


        #endregion
    }
}