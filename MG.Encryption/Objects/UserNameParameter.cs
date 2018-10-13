using System;
using System.Collections;
using System.Collections.Generic;
using System.Management.Automation;
using System.Linq;

namespace MG.Encryption
{
    internal class UserNameParameter : RuntimeDefinedParameter
    {
        private protected const string pName = "UserName";
        private static readonly Type pType = typeof(string);

        public UserNameParameter()
        {
            this.Attributes.Add(new AliasAttribute("user"));
            this.ParameterType = pType;
            this.Name = pName;
            this.Attributes.Add(new ParameterAttribute()
            {
                Mandatory = true
            });
        }
    }
}
