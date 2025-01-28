using System;
using System.Collections.Immutable;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Logging;

namespace VaettirNet.YubikeyUtils.Cli;

internal class SignCsrCommand : CommandBase
{
    public string CsrFilePath { get; private set; }
    public string OutputFilePath { get; private set; }
    public byte Slot { get; private set; } = Program.CaSlot;
    public int ValidityDays { get; private set; } = 30;

    public string AuthorityAccessUrl { get; private set; }
    public string CrlDistributionUrl { get; private set; }

    private readonly IUserInteraction _ui;
    private readonly IYubikeyPivSource _pivSource;
    private readonly ILogger<SignCsrCommand> _logger;

    public SignCsrCommand(IUserInteraction ui, IYubikeyPivSource pivSource, ILogger<SignCsrCommand> logger) : base("sign", "Sign a certificate signing request")
    {
        _ui = ui;
        _pivSource = pivSource;
        _logger = logger;
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
        
        _logger.LogInformation("Loaded CSR with subject: {subject}", req.SubjectName);
        
        CertificateRequest cleanRequest = new CertificateRequest(req.SubjectName, req.PublicKey, req.HashAlgorithm, RSASignaturePadding.Pss);
        if (cleanRequest.CertificateExtensions.OfType<X509KeyUsageExtension>().FirstOrDefault() is { } keyUsageEx)
        {
            X509KeyUsageFlags allowedUsages = keyUsageEx.KeyUsages &
                (X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyAgreement);
            
            _logger.LogInformation("Setting requested key usages '{requestedUsage}' to '{keyUsage}'", keyUsageEx.KeyUsages, allowedUsages);
            cleanRequest.CertificateExtensions.Add(new X509KeyUsageExtension(allowedUsages,
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
                _logger.LogInformation("Setting requested extended key usages '{requestedUsage}' to '{keyUsage}'", xKeyUsageEx.EnhancedKeyUsages, usages);
                cleanRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usages, xKeyUsageEx.Critical));
            }
        }

        if (slotCert.Extensions.OfType<X509SubjectKeyIdentifierExtension>().FirstOrDefault() is { } ki)
        {
            _logger.LogInformation("Adding authority key identifier from key identifier: {authorityKeyId}", ki.SubjectKeyIdentifier);
            cleanRequest.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(ki));
        }
        else
        {
            var aki = X509AuthorityKeyIdentifierExtension.CreateFromCertificate(
                certificate: slotCert,
                includeKeyIdentifier: false,
                includeIssuerAndSerial: true
            );
            _logger.LogInformation("Adding authority key identifier from issuers and serial number: {issuer} {serialNumber}", aki.NamedIssuer, Convert.ToBase64String(aki.SerialNumber.Value.Span));
            cleanRequest.CertificateExtensions.Add(aki);
        }

        _logger.LogInformation("Adding authority information access extension: {authorityAccessUrl}", AuthorityAccessUrl);
        cleanRequest.CertificateExtensions.Add(new X509AuthorityInformationAccessExtension(null, [AuthorityAccessUrl]));
        _logger.LogInformation("Adding CRL distribution point: {crlDistributionUrl}", CrlDistributionUrl);
        cleanRequest.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension([CrlDistributionUrl]));
        //
        // var writer = new AsnWriter(AsnEncodingRules.DER);
        // Span<byte> policyBytes = stackalloc byte[256];
        // var cbPolicy = writer.Encode(policyBytes);
        // cleanRequest.CertificateExtensions.Add(new X509Extension(SupportedOids.CertificatePolicy.Root, policyBytes[..cbPolicy], false));
        
        // Need to add:
        // * certificate policies

        var sigGen = new YubikeySigGenerator(req, RSASignaturePadding.Pss, piv, Slot);
        Span<byte> serialNumber = stackalloc byte[16];
        RandomNumberGenerator.Fill(serialNumber);
        
        _logger.LogInformation("Generated serial number: {serialNumber}", Convert.ToBase64String(serialNumber));
        CommandSet.Out.WriteLine("Signing certificate request...");
        if (File.Exists(OutputFilePath))
        {
            if (!_ui.PromptYesNo("Target file exists, overwrite [yn]? "))
            {
                CommandSet.Error.WriteLine("Cannot overwrite file, aborting");
                return 3;
            }
        }

        X509Certificate2 signedCert = cleanRequest.Create(slotCert.SubjectName, sigGen, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(ValidityDays), serialNumber);
        CommandSet.Out.WriteLine($"Writing certificate file to {OutputFilePath}");
        _logger.LogInformation("Successfully signed certificate thumbprint: {thumbprint}", signedCert.Thumbprint);
        File.WriteAllText(OutputFilePath, signedCert.ExportCertificatePem(), new UTF8Encoding(false));
        CommandSet.Out.WriteLine("Done.");
        return 0;
    }
}