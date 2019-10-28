using MG.Dynamic;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Data.SqlClient;
using System.Management.Automation;
using System.Net;
using System.Security;
using System.Text;

namespace MG.Encryption.PowerShell
{
    [Cmdlet(VerbsSecurity.Unprotect, "String")]
    [CmdletBinding(PositionalBinding = false)]
    public class UnprotectString : BaseUnprotectCmdlet, IDynamicParameters
    {
        #region PARAMETERS

        [Parameter(Mandatory = true, ValueFromPipeline = true, Position = 0, ParameterSetName = "FromSecurableString")]
        [Alias("string", "s")]
        public SecurableString SecurableString { get; set; }

        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "FromSecuredByteArray")]
        public byte[] SecuredBytes { get; set; }

        #endregion

        protected override void BeginProcessing()
        {
            base.BeginProcessing();
            if (this.ParameterSetName == "FromSecuredByteArray")
                this.SecurableString = this.SecuredBytes;
        }

        protected override void ProcessRecord() => outStr = enc.DecryptContent(this.SecurableString);

        protected override void EndProcessing() => base.EndProcessing();
    }
}
