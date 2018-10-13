using System;
using System.Management.Automation;

namespace MG.Encryption.Cmdlets
{
    [Cmdlet(VerbsSecurity.Unprotect, "String", DefaultParameterSetName = "ByBase64String")]
    [CmdletBinding(PositionalBinding = false)]
    [OutputType(typeof(StringResult))]
    public class UnprotectString : PSCmdlet, IDynamicParameters
    {
        [Parameter(Mandatory = true, ValueFromPipeline = true, 
            ParameterSetName = "ByEncryptedBytes")]
        [Alias("bytes", "b")]
        public byte[] EncryptedBytes { get; set; }

        [Parameter(Mandatory = true, ValueFromPipeline = true, Position = 0,
            ParameterSetName = "ByBase64String")]
        [Alias("string", "s")]
        public ProtectedString ProtectedString { get; set; }

        [Parameter(Mandatory = false)]
        [Alias("out", "as")]
        public OutputAs Output = OutputAs.StringResult;

        private protected Methods enc;
        private protected UserNameParameter unp = new UserNameParameter();
        private protected RuntimeDefinedParameterDictionary pLib;

        public object GetDynamicParameters()
        {
            if (Output == OutputAs.PSCredential)
            {
                pLib = new RuntimeDefinedParameterDictionary()
                {
                    { unp.Name, unp }
                };
                return pLib;
            }
            return null;
        }

        protected override void ProcessRecord()
        {
            base.ProcessRecord();

            //if (EncryptedBytes != null && ProtectedString != null)
            //    throw new ArgumentException("Specify only bytes or a string!");
            //else if (EncryptedBytes == null && ProtectedString == null)
            //    throw new ArgumentNullException("Specify either bytes or a string!");

            enc = new Methods();
            ProtectedString pStr = EncryptedBytes == null ? ProtectedString : EncryptedBytes;
            StringResult res = enc.DecryptContent(pStr);

            switch (Output)
            {
                case OutputAs.PSCredential:
                    var pts = (PlainTextString)res.String;
                    var username = pLib[unp.Name].Value as string;

                    WriteObject(pts.AsCredential(username));
                    break;
                case OutputAs.SecureString:
                    var ss = (PlainTextString)res.String;
                    WriteObject(ss.AsSecure());
                    break;
                default:
                    WriteObject(res);
                    break;
            }
        }
    }

    public enum OutputAs
    {
        StringResult = 0,
        PSCredential = 1,
        SecureString = 2
    }
}
