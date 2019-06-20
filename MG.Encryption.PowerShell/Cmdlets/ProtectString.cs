using System;
using System.Management.Automation;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace MG.Encryption.PowerShell
{
    [Cmdlet(VerbsSecurity.Protect, "String", ConfirmImpact = ConfirmImpact.None,
        DefaultParameterSetName = "WithX509CertificateAsString")]
    [CmdletBinding(PositionalBinding = false)]
    [OutputType(typeof(SecurableString))]
    public class ProtectString : BaseProtectCmdlet
    {
        protected override void BeginProcessing()
        {
        }

        protected override void ProcessRecord()
        {
            base.ProcessRecord();
        }
    }
}
