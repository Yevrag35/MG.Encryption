using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Reflection;
using System.Security;

namespace MG.Encryption.Cmdlets
{
    public abstract class BaseCmdlet : PSCmdlet
    {
        #region FIELDS/CONSTANTS
        protected private Methods enc;
        protected private bool NoEnd = false;
        protected private SecurableString outStr;

        #endregion

        #region CMDLET PROCESSING
        protected override void BeginProcessing() => enc = new Methods();

        #endregion

        #region METHODS


        #endregion
    }
}