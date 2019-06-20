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
    public abstract class BaseUnprotectCmdlet : BaseCmdlet, IDynamicParameters
    {
        #region FIELDS/CONSTANTS
        protected private const string DOMAIN = "Domain";
        protected private const string USERNAME = "UserName";
        protected private DynamicLibrary _dynLib;

        #endregion

        #region PARAMETERS

        [Parameter(Mandatory = false)]
        [Alias("Output", "out", "as")]
        public OutputAs OutputAs = OutputAs.String;

        #endregion

        #region DYNAMIC PARAMETERS
        public virtual object GetDynamicParameters()
        {
            if (this.OutputAs != OutputAs.String && this.OutputAs != OutputAs.SecureString)
            {
                _dynLib = new DynamicLibrary();
                var dp = new RuntimeDefinedParameter(USERNAME, typeof(string), new Collection<Attribute>
                {
                    new ParameterAttribute
                    {
                        Mandatory = true,
                        HelpMessage = "Provide a username for the PSCredential that will be outputted."
                    },
                    new ValidateNotNullOrEmptyAttribute()
                });
                _dynLib.Add(dp);

                if (this.OutputAs == OutputAs.NetworkCredential)
                {
                    var domParam = new RuntimeDefinedParameter(DOMAIN, typeof(string), new Collection<Attribute>
                    {
                        new ParameterAttribute
                        {
                            Mandatory = false
                        }
                    });
                    _dynLib.Add(domParam);
                }

                return _dynLib;
            }
            else
                return null;
        }

        #endregion

        #region CMDLET PROCESSING
        protected override void BeginProcessing() => base.BeginProcessing();

        protected override void EndProcessing()
        {
            if (!NoEnd)
            {
                switch (this.OutputAs)
                {
                    case OutputAs.String:
                    {
                        byte[] bytes = outStr.GetBytes();
                        base.WriteObject(Encoding.UTF8.GetString(bytes));
                        break;
                    }
                    case OutputAs.PSCredential:
                    {
                        var userName = _dynLib.GetParameterValue<string>(USERNAME);
                        var psCreds = new PSCredential(userName, outStr.AsSecureString());
                        base.WriteObject(psCreds);
                        break;
                    }
                    case OutputAs.SecureString:
                        base.WriteObject(outStr.AsSecureString());
                        break;

                    case OutputAs.NetworkCredential:
                    {
                        NetworkCredential netCreds = null;
                        string un = _dynLib.GetParameterValue<string>(USERNAME);
                        SecureString ss = outStr.AsSecureString();

                        netCreds = _dynLib.ParameterHasValue(DOMAIN)
                            ? new NetworkCredential(un, ss, _dynLib.GetParameterValue<string>(DOMAIN))
                            : new NetworkCredential(un, ss);

                        base.WriteObject(netCreds);
                        break;
                    }
                    case OutputAs.SqlCredential:
                    {
                        var sqlCreds = new SqlCredential(_dynLib.GetParameterValue<string>(USERNAME), outStr.AsSecureString());
                        base.WriteObject(sqlCreds);
                        break;
                    }
                }
            }
        }

        #endregion
    }
}