using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace CertStoreVerify
{
    public class CertificateInfo
    {
        public string ExpirationDate { get; set; }
        public string EffectiveDate { get; set; }
        public string Issuer { get; set; }
        public string Subject { get; set; }
        public bool Verify { get; set; }
        public string[] StatusInformationArr { get; set; }
    }

    public class Verifier
    {
        public IList<CertificateInfo> Do()
        {
            var chain = new X509Chain
            {
                ChainPolicy = new X509ChainPolicy
                {
                    RevocationMode = X509RevocationMode.Online,

                    RevocationFlag = X509RevocationFlag.EntireChain,
                    // RevocationFlag = X509RevocationFlag.ExcludeRoot,

                    VerificationFlags = X509VerificationFlags.NoFlag,
                    // VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority,
                    // VerificationFlags = X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown
                    // VerificationFlags = X509VerificationFlags.IgnoreCtlNotTimeValid
                    // VerificationFlags = X509VerificationFlags.IgnoreCtlSignerRevocationUnknown
                    // VerificationFlags = X509VerificationFlags.IgnoreEndRevocationUnknown
                    // VerificationFlags = X509VerificationFlags.IgnoreInvalidBasicConstraints
                    // VerificationFlags = X509VerificationFlags.IgnoreInvalidName
                    // VerificationFlags = X509VerificationFlags.IgnoreInvalidPolicy
                    // VerificationFlags = X509VerificationFlags.IgnoreNotTimeNested
                    // VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid
                    // VerificationFlags = X509VerificationFlags.IgnoreRootRevocationUnknown
                    // VerificationFlags = X509VerificationFlags.IgnoreWrongUsage
                }
            };

            using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);

                return store.Certificates.Cast<X509Certificate2>()
                    .Select(cert =>
                    {
                        var info = new CertificateInfo
                        {
                            ExpirationDate = cert.GetExpirationDateString(),
                            EffectiveDate = cert.GetEffectiveDateString(),
                            Issuer = cert.Issuer,
                            Subject = cert.Subject,
                            Verify = chain.Build(cert),
                        };

                        if (!info.Verify)
                        {
                            info.StatusInformationArr = chain.ChainElements.Cast<X509ChainElement>()
                                .SelectMany(element =>
                                    element.ChainElementStatus
                                        .Select(status => status.StatusInformation))
                                .ToArray();
                        }

                        return info;
                    }).ToArray();
            }
        }
    }
}
