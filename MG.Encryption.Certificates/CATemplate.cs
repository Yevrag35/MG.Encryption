using System;
using System.DirectoryServices;
using System.Linq;

namespace MG.Encryption
{
    public class CATemplate
    {
        private protected const string TEMPLATES_CONTAINER = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{0}";

        public string Name { get; internal set; }
        public object TemplateOid { get; internal set; }

        public CATemplate(string templateName) =>
            TemplateFromName(templateName);

        private protected void TemplateFromName(string templateName)
        {
            string rootDN;
            using (var dn = new DirectoryEntry())
            {
                rootDN = dn.Path;
            }
            var fullDN = string.Format(TEMPLATES_CONTAINER, rootDN);
            using (var allEntries = new DirectoryEntry(fullDN))
            {
                foreach (DirectoryEntry entry in allEntries.Children)
                {
                    if (string.Equals(entry.Name, templateName, StringComparison.InvariantCultureIgnoreCase))
                    {
                        Name = entry.Name;
                        TemplateOid = entry.Properties["msPKI-Cert-Template-OID"].Value;
                        entry.Dispose();
                        break;
                    }
                    entry.Dispose();
                }
            }
        }
    }
}
