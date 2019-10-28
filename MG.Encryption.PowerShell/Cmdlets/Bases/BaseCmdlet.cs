using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Reflection;
using System.Security;

namespace MG.Encryption.PowerShell
{
    public abstract class BaseCmdlet : PSCmdlet
    {
        #region FIELDS/CONSTANTS
        protected private CertificateSecurity enc;
        protected private bool NoEnd = false;
        protected private ISecurable outStr;

        #endregion

        #region CMDLET PROCESSING
        protected override void BeginProcessing() => enc = new CertificateSecurity();

        #endregion

        #region METHODS


        #endregion
    }
}