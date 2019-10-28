using Microsoft.Win32;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Reflection;
using System.Security;
using System.Text;

namespace MG.Encryption.PowerShell
{
    [Cmdlet(VerbsSecurity.Protect, "StringToRegistry", ConfirmImpact = ConfirmImpact.Low, SupportsShouldProcess = true, DefaultParameterSetName = "WithX509CertificateAsString")]
    [CmdletBinding(PositionalBinding = false)]
    public class ProtectStringToRegistry : BaseProtectCmdlet
    {
        #region FIELDS/CONSTANTS


        #endregion

        #region PARAMETERS
        [Parameter(Mandatory = true, Position = 2)]
        [Alias("RegistryKey")]
        public string Path { get; set; }

        [Parameter(Mandatory = true, Position = 3)]
        public string Name { get; set; }

        #endregion

        #region CMDLET PROCESSING
        protected override void BeginProcessing()
        {
        }

        protected override void ProcessRecord() => base.ProcessRecord();

        protected override void EndProcessing()
        {
            if (!NoEnd)
            {
                RegistryValueKind kind;
                object writeThis = null;

                if (this.OutputAs.Equals("String", StringComparison.CurrentCultureIgnoreCase))
                {
                    kind = RegistryValueKind.String;
                    writeThis = Encoding.ASCII.GetString(outStr.GetBytes());
                }
                else
                {
                    kind = RegistryValueKind.Binary;
                    writeThis = outStr.GetBytes();
                }

                string resolvedPath = this.SessionState.Path.GetResolvedProviderPathFromPSPath(this.Path, out ProviderInfo pi).FirstOrDefault();
                Registry.SetValue(resolvedPath, this.Name, writeThis, kind);
            }
        }

        #endregion
    }
}