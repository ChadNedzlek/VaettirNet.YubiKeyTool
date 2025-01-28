using System.Security.Cryptography;

namespace yk;

public static class SupportedOids
{
    public static class KeyUsages
    {
        public static readonly Oid DocumentSigning = new("1.3.6.1.4.1.311.10.3.12");
        public static readonly Oid CodeSigning = new("1.3.6.1.5.5.7.3.3");
        public static readonly Oid EmailProtection = new("1.3.6.1.5.5.7.3.4");
    }
    
    public static class CertificatePolicy
    {
        public static readonly Oid Root = new("2.5.29.32");
        public static readonly Oid DomainValidated = new("2.23.140.1.2.1");
        public static readonly Oid OrganizationValidated = new("2.23.140.1.2.2");
        public static readonly Oid IndividualValidated = new("2.23.140.1.2.3");
    }

    public static class EcCurve
    {
        public static readonly Oid EccP256 = new("1.2.840.10045.3.1.7");
        public static readonly Oid EccP384 = new("1.3.132.0.34");
    }
}