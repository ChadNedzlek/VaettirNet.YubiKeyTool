using System;
using System.Collections.Immutable;
using System.Formats.Asn1;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace yk;

internal class SignCsr : CommandBase
{
    public string CsrFilePath { get; private set; }
    public string OutputFilePath { get; private set; }
    public byte Slot { get; private set; } = Program.CaSlot;
    public int ValidityDays { get; private set; } = 30;

    public string AuthorityAccessUrl { get; private set; }
    public string CrlDistributionUrl { get; private set; }

    private readonly IUserInteraction _ui;
    private readonly IYubikeyPivSource _pivSource;

    public SignCsr(IUserInteraction ui, IYubikeyPivSource pivSource) : base("sign", "Sign a certificate signing request")
    {
        _ui = ui;
        _pivSource = pivSource;
        Options = new()
        {
            {"csr|input|i=", "(Required) Path to CSR request file", v => CsrFilePath = v},
            {"output|o=", "(Required) Output path for generated cert", v => OutputFilePath = v},
            {"slot|s=", "Slot to create the certificate in (Default 84)", v => Slot = byte.Parse(v, NumberStyles.HexNumber)},
            {"valid-days=", "Number of days for cert validity (Default 30)", v => ValidityDays = int.Parse(v)},
            {"authority-access-uri|auth-access|a=", "(Required) URL where signing cert can be fetched", v => AuthorityAccessUrl = v},
            {"crl-distribution-uri|crl|c=", "(Required) URL where CRL will be distributed", v => CrlDistributionUrl = v},
        };
    }

    protected override int Execute()
    {
        ValidateRequiredArgument(CsrFilePath, "csr");
        ValidateRequiredArgument(OutputFilePath, "output");
        ValidateRequiredArgument(AuthorityAccessUrl, "authority-access-uri");
        ValidateRequiredArgument(CrlDistributionUrl, "crl-distribution-uri");
        
        if (!File.Exists(CsrFilePath))
        {
            CommandSet.Error.WriteLine("File not found");
            Options.WriteOptionDescriptions(CommandSet.Error);
            return 1;
        }

        var piv = _pivSource.GetPivSession();
        if (piv is null)
        {
            CommandSet.Error.WriteLine("No yubikey detected");
            return 2;
        }

        X509Certificate2 slotCert = piv.GetCertificate(Slot);
        CertificateRequest req = CertificateRequest.LoadSigningRequestPem(File.ReadAllText(CsrFilePath),
            HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions,
            RSASignaturePadding.Pss);

        ImmutableHashSet<Oid> allowedKeyUsages = [
            SupportedOids.KeyUsages.DocumentSigning,
            SupportedOids.KeyUsages.EmailProtection,
            SupportedOids.KeyUsages.CodeSigning
        ];
        
        CertificateRequest cleanRequest = new CertificateRequest(req.SubjectName, req.PublicKey, req.HashAlgorithm, RSASignaturePadding.Pss);
        if (cleanRequest.CertificateExtensions.OfType<X509KeyUsageExtension>().FirstOrDefault() is { } keyUsageEx)
        {
            cleanRequest.CertificateExtensions.Add(new X509KeyUsageExtension(keyUsageEx.KeyUsages &
                (X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyAgreement),
                true
            ));
        }
        
        if (cleanRequest.CertificateExtensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault() is { } xKeyUsageEx)
        {
            var usages = new OidCollection();
            foreach (Oid item in xKeyUsageEx.EnhancedKeyUsages)
            {
                if (allowedKeyUsages.Contains(item))
                    usages.Add(item);
            }

            if (usages.Count > 0)
            {
                cleanRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usages, xKeyUsageEx.Critical));
            }
        }

        if (slotCert.Extensions.OfType<X509SubjectKeyIdentifierExtension>().FirstOrDefault() is { } ki)
        {
            cleanRequest.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(ki));
        }
        else
        {
            cleanRequest.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(certificate: slotCert, includeKeyIdentifier: false, includeIssuerAndSerial: true));
        }

        cleanRequest.CertificateExtensions.Add(new X509AuthorityInformationAccessExtension(null, [AuthorityAccessUrl]));
        
        // Need to add:
        // * certificate policies
        // * CRL distribution points

        var sigGen = new YubikeySigGenerator(req, RSASignaturePadding.Pss, piv, Slot);
        Span<byte> serialNumber = stackalloc byte[16];
        RandomNumberGenerator.Fill(serialNumber);
        CommandSet.Out.WriteLine("Signing certificate request...");
        X509Certificate2 signedCert = cleanRequest.Create(slotCert.SubjectName, sigGen, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(ValidityDays), serialNumber);
        if (File.Exists(OutputFilePath))
        {
            if (!_ui.PromptYesNo("Target file exists, overwrite [yn]? "))
            {
                CommandSet.Error.WriteLine("Cannot overwrite file, aborting");
                return 3;
            }
        }

        CommandSet.Out.WriteLine($"Writing certificate file to {OutputFilePath}");
        File.WriteAllText(OutputFilePath, signedCert.ExportCertificatePem(), new UTF8Encoding(false));
        CommandSet.Out.WriteLine("Done.");
        return 0;
    }
}

public static class SupportedOids
{
    public static class KeyUsages
    {
        public static readonly Oid DocumentSigning = new("1.3.6.1.4.1.311.10.3.12");
        public static readonly Oid CodeSigning = new("1.3.6.1.5.5.7.3.3");
        public static readonly Oid EmailProtection = new("1.3.6.1.5.5.7.3.4");
    }

    public static class CertificatePolicies
    {
        public static readonly Oid DomainValidated = new Oid("2.23.140.1.2.1");
        public static readonly Oid OrganizationValidated = new Oid("2.23.140.1.2.2");
        public static readonly Oid IndividualValidated = new Oid("2.23.140.1.2.3");
    }
}