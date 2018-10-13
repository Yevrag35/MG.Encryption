using System;
using System.Management.Automation;
using System.Security.Cryptography.X509Certificates;

namespace MG.Encryption
{
    [Cmdlet(VerbsSecurity.Protect, "String", ConfirmImpact = ConfirmImpact.None,
        DefaultParameterSetName = "WithX509Certificate")]
    [CmdletBinding(PositionalBinding = false)]
    [OutputType(typeof(ProtectedString))]
    public class ProtectString : PSCmdlet
    {
        [Parameter(Mandatory = true, Position = 0)]
        [Alias("inStr", "s")]
        public PlainTextString String { get; set; }

        [Parameter(Mandatory = true, 
            ParameterSetName = "WithX509Certificate", ValueFromPipeline = true)]
        [Alias("cert", "c")]
        public X509Certificate2 Certificate { get; set; }

        [Parameter(Mandatory = true, ParameterSetName = "FindCertificate", Position = 1)]
        [Alias("sha1")]
        public string SHA1Thumbprint { get; set; }

        [Parameter(Mandatory = false, ParameterSetName = "FindCertificate")]
        [Alias("store")]
        public StoreLocation Location = StoreLocation.CurrentUser;


        private protected Methods enc;

        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            enc = ParameterSetName == "WithX509Certificate" ? 
                new Methods(Certificate) : new Methods(SHA1Thumbprint, Location);

            ProtectedString pStr = enc.EncryptString(String);
            WriteObject(pStr);
        }

    }
}
