using Microsoft.Win32;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Reflection;
using System.Security;

namespace MG.Encryption.Cmdlets
{
    [Cmdlet(VerbsSecurity.Unprotect, "StringFromRegistry", ConfirmImpact = ConfirmImpact.Low, SupportsShouldProcess = true)]
    [CmdletBinding(PositionalBinding = false)]
    [Alias("getencbyt")]
    public class UnprotectStringFromRegistry : BaseUnprotectCmdlet
    {
        #region FIELDS/CONSTANTS


        #endregion

        #region PARAMETERS
        [Parameter(Mandatory = true, Position = 0)]
        [Alias("RegistryKey")]
        public string Path { get; set; }

        [Parameter(Mandatory = true, Position = 1)]
        public string Name { get; set; }

        #endregion

        #region CMDLET PROCESSING
        protected override void BeginProcessing()
        {
            base.BeginProcessing();
        }

        protected override void ProcessRecord()
        {
            var resolvedPath = this.SessionState.Path.GetResolvedProviderPathFromPSPath(this.Path, out ProviderInfo pi).FirstOrDefault();
            object regValue = Registry.GetValue(resolvedPath, this.Name, null);

            SecurableString secStr = null;
            if (regValue is byte[] bytes)
                secStr = bytes;

            else if (regValue is string str)
                secStr = str;

            if (secStr == null)
                throw new ArgumentException("No valid registry value could be parsed.");

            if (base.ShouldProcess(this.Name, "Read sensitive information"))
                outStr = enc.DecryptContent(secStr);

            else
                base.NoEnd = true;
        }

        protected override void EndProcessing()
        {
            base.EndProcessing();
        }

        #endregion

        #region METHODS


        #endregion
    }
}