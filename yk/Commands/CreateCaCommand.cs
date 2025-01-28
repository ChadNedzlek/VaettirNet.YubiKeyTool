using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using VaettirNet.YubikeyUtils.Cli.Services;
using Yubico.YubiKey.Piv;

namespace VaettirNet.YubikeyUtils.Cli.Commands;

internal class CreateCaCommand : CommandBase
{
    private readonly IUserInteraction _ui;
    private readonly IYubikeyPivSource _pivSource;
    private readonly ILogger<CreateCaCommand> _logger;

    public string Subject { get; private set; }
    public int ValidityDays { get; private set; } = 365;
    public byte Slot { get; private set; } = Program.CaSlot;
    
    public CreateCaCommand(IUserInteraction ui, IYubikeyPivSource pivSource, ILogger<CreateCaCommand> logger) : base("create", "Create a new CA root certificate")
    {
        _ui = ui;
        _pivSource = pivSource;
        _logger = logger;
        Options = new()
        {
            {"subject|name|sn|n=", "Subject name for the certificate", v => Subject = v},
            {"slot|s=", "Slot to create the certificate in", v => Slot = byte.Parse(v, NumberStyles.HexNumber)},
            {"valid-days=", "Number of days for cert validity", v => ValidityDays = int.Parse(v)},
        };
    }

    protected override int Execute()
    {
        var piv = _pivSource.GetPivSession();
        if (piv is null)
        {
            CommandSet.Error.WriteLine("No yubikey detected");
            return 2;
        }

        if (string.IsNullOrEmpty(Subject))
        {
            Subject = _ui.Prompt("Cert subject: ");
        }
        
        _logger.LogWarning("Generating new CA cert in slot {slot}, valid until {notAfter} with subject: {subject}", Slot.ToString("x2"), DateTimeOffset.UtcNow.AddDays(ValidityDays), Subject);

        PivPublicKey publicKey;
        try
        {
            PivMetadata metadata = piv.GetMetadata(Slot);
            publicKey = PivPublicKey.Create(metadata.PublicKey.PivEncodedPublicKey);
            _logger.LogInformation("Loaded exising public key from slot");
        }
        catch (InvalidOperationException)
        {
            CommandSet.Out.WriteLine($"No private key found in slot {Slot:x2}, creating new key...");
            _logger.LogInformation("Generating new EccP384 private key into slow");
            publicKey = piv.GenerateKeyPair(Slot, PivAlgorithm.EccP384, PivPinPolicy.Always, PivTouchPolicy.Cached);
        }
        
        CommandSet.Out.WriteLine("Building certificate request...");
        
        CertificateRequest req;
        AsymmetricAlgorithm publicKeyObj;
        switch (publicKey)
        {
            case PivEccPublicKey ecc:
                var curveOid = publicKey.Algorithm switch
                {
                    PivAlgorithm.EccP256 => SupportedOids.EcCurve.EccP256,
                    PivAlgorithm.EccP384 => SupportedOids.EcCurve.EccP384,
                    _ => throw new ArgumentException("Unsupported ECC curve")
                };
                _logger.LogDebug("Found ECC key with algorithm: {oid}", curveOid);
                var curve = ECCurve.CreateFromOid(curveOid);
                int coordLength = (ecc.PublicPoint.Length - 1) / 2;
                var eccParams = new ECParameters{Curve = curve, Q = new ECPoint()
                {
                    X = ecc.PublicPoint.Slice(1, coordLength).ToArray(),
                    Y = ecc.PublicPoint.Slice(1 + coordLength, coordLength).ToArray(),
                }};
                var ecdsa  = ECDsa.Create(eccParams);
                publicKeyObj = ecdsa;
                req = new CertificateRequest(Subject, ecdsa, HashAlgorithmName.SHA256);
                break;
            case PivRsaPublicKey rsa:
                _logger.LogDebug("Found RSA key");
                var rsaKey = RSA.Create(new RSAParameters { Exponent = rsa.PublicExponent.ToArray(), Modulus = rsa.Modulus.ToArray() });
                publicKeyObj = rsaKey;
                req = new CertificateRequest(
                    Subject,
                    rsaKey,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pss
                );
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(publicKey));
        }
        _logger.LogInformation("Public key sha256 {publicKey}", new PublicHashFormatter(publicKeyObj));
        X509KeyUsageFlags keyUsage = X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.DigitalSignature;
        _logger.LogInformation("Key usage: {keyUsage}", keyUsage);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(keyUsage, true));
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, X509SubjectKeyIdentifierHashAlgorithm.Sha256, false));
        
        var sigGen = new YubikeySigGenerator(req, RSASignaturePadding.Pss, piv, Slot);
        Span<byte> serialNumber = stackalloc byte[16];
        RandomNumberGenerator.Fill(serialNumber);
        _logger.LogInformation("Serial number: {serialNumber}", Convert.ToBase64String(serialNumber));
        
        CommandSet.Out.WriteLine("Signing certificate request...");
        var selfSignedCert = req.Create(new X500DistinguishedName(Subject), sigGen, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(ValidityDays), serialNumber);
        CommandSet.Out.WriteLine("Saving certificate...");
        piv.ImportCertificate(Slot, selfSignedCert);
        _logger.LogInformation("Successfully generated key with thumbprint: {thumbprint}", selfSignedCert.Thumbprint);
        CommandSet.Out.WriteLine($"Generated thumbprint: {selfSignedCert.Thumbprint}");
        CommandSet.Out.WriteLine("Done.");
        return 0;
    }
}