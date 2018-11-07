using CERTENROLLLib;
using MG.Attributes;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace MG.Encryption.Certificates
{
    public abstract class Enrollment : AttributeResolver
    {
        #region Private Fields/Properties

        private protected List<CX509Extension> _extsToAdd;

        #endregion

        #region Public Properties

        public string Subject { get; }
        public string FriendlyName { get; }
        public DateTime Expiration { get; }
        public Algorithms HashAlgorithm { get; }
        public int KeyLength { get; }
        public EnrollmentContext Context { get; }

        #endregion

        #region Constructors

        public Enrollment(string subject, DateTime validUntil, Algorithms algorithm, int keyLength, bool machineContext)
        {
            _extsToAdd = new List<CX509Extension>();
            Subject = subject;
            Expiration = validUntil;
            HashAlgorithm = algorithm;
            KeyLength = keyLength;
            Context = new EnrollmentContext(machineContext);
        }
        public Enrollment(string subject, string friendlyName, DateTime validUntil, Algorithms algorithm, int keyLength, bool machineContext)
            : this(subject, validUntil, algorithm, keyLength, machineContext) => FriendlyName = friendlyName;

        #endregion

        #region Methods

        public void AddExtension(object ext) =>
            _extsToAdd.Add((CX509Extension)ext);

        #endregion
    }

    public class EnrollmentContext
    {
        internal StoreLocation CertStore =>
            MachineContext ? StoreLocation.LocalMachine : StoreLocation.CurrentUser;
        public bool MachineContext { get; }

        public EnrollmentContext(bool machineContext) =>
            MachineContext = machineContext;
    }
}
