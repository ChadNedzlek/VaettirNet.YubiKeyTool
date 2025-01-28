using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Yubico.YubiKey.Cryptography;
using Yubico.YubiKey.Piv;

namespace yk;

internal class CreateCaCommand : CommandBase
{
    private readonly IUserInteraction _ui;
    private readonly IYubikeyPivSource _pivSource;

    public string Subject { get; private set; }
    public int ValidityDays { get; private set; } = 365;
    public byte Slot { get; private set; } = Program.CaSlot;
    
    public CreateCaCommand(IUserInteraction ui, IYubikeyPivSource pivSource) : base("create", "Create a new CA root certificate")
    {
        _ui = ui;
        _pivSource = pivSource;
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

        PivPublicKey publicKey;
        try
        {
            PivMetadata metadata = piv.GetMetadata(Slot);
            publicKey = PivPublicKey.Create(metadata.PublicKey.PivEncodedPublicKey);
        }
        catch (InvalidOperationException)
        {
            CommandSet.Out.WriteLine($"No private key found in slot {Slot:x2}, creating new key...");
            publicKey = piv.GenerateKeyPair(Slot, PivAlgorithm.EccP384, PivPinPolicy.Always, PivTouchPolicy.Cached);
        }
        
        CommandSet.Out.WriteLine("Building certificate request...");
        
        CertificateRequest req;
        switch (publicKey)
        {
            case PivEccPublicKey ecc:
                string oidString = publicKey.Algorithm switch
                {
                    PivAlgorithm.EccP256 => "1.2.840.10045.3.1.7",
                    PivAlgorithm.EccP384 => "1.3.132.0.34",
                    _ => throw new ArgumentException("Unsupported ECC curve")
                };
                var curve = ECCurve.CreateFromValue(oidString);
                int coordLength = (ecc.PublicPoint.Length - 1) / 2;
                var eccParams = new ECParameters{Curve = curve, Q = new ECPoint()
                {
                    X = ecc.PublicPoint.Slice(1, coordLength).ToArray(),
                    Y = ecc.PublicPoint.Slice(1 + coordLength, coordLength).ToArray(),
                }};
                req = new CertificateRequest(Subject, ECDsa.Create(eccParams), HashAlgorithmName.SHA256);
                break;
            case PivRsaPublicKey rsa:
                req = new CertificateRequest(
                    Subject,
                    RSA.Create(new RSAParameters { Exponent = rsa.PublicExponent.ToArray(), Modulus = rsa.Modulus.ToArray() }),
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pss
                );
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(publicKey));
        }
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.DigitalSignature, true));
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, X509SubjectKeyIdentifierHashAlgorithm.Sha256, false));
        
        var sigGen = new YubikeySigGenerator(req, RSASignaturePadding.Pss, piv, Slot);
        Span<byte> serialNumber = stackalloc byte[16];
        RandomNumberGenerator.Fill(serialNumber);
        
        CommandSet.Out.WriteLine("Signing certificate request...");
        var selfSignedCert = req.Create(new X500DistinguishedName(Subject), sigGen, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(ValidityDays), serialNumber);
        CommandSet.Out.WriteLine("Saving certificate...");
        piv.ImportCertificate(Slot, selfSignedCert);
        CommandSet.Out.WriteLine($"Generated thumbprint: {selfSignedCert.Thumbprint}");
        CommandSet.Out.WriteLine("Done.");
        return 0;
    }
}

internal class YubikeySigGenerator : X509SignatureGenerator
{
    private readonly RSASignaturePadding _padding;
    private readonly PivSession _pivSession;
    private readonly byte _slotNumber;
    private readonly X509SignatureGenerator _base;
    private readonly int _keySizeBits;
    private readonly bool _isRsa;

    public YubikeySigGenerator(CertificateRequest req, RSASignaturePadding padding, PivSession pivSession, byte slotNumber)
    {
        _padding = padding;
        _pivSession = pivSession;
        _slotNumber = slotNumber;

        if (req.PublicKey.GetRSAPublicKey() is {} rsa)
        {
            _base = CreateForRSA(rsa, padding);
            _keySizeBits = rsa.KeySize;
            _isRsa = true;
        }
        else if (req.PublicKey.GetECDsaPublicKey() is {} ecc)
        {
            _base = CreateForECDsa(ecc);
            _keySizeBits = ecc.KeySize;
            _isRsa = false;
        }
        else throw new ArgumentException($"Unsupported public key algorithm: {req.PublicKey.Oid}");
    }

    protected override PublicKey BuildPublicKey() => _base.PublicKey;

    public override byte[] GetSignatureAlgorithmIdentifier(HashAlgorithmName hashAlgorithm) => _base.GetSignatureAlgorithmIdentifier(hashAlgorithm);


    public override byte[] SignData(byte[] data, HashAlgorithmName hashAlgorithm)
    {
        byte[] dataToSign = DigestData(data, hashAlgorithm);
        if (_isRsa)
        {
            dataToSign = PadRsa(dataToSign, hashAlgorithm);
        }

        return _pivSession.Sign(_slotNumber, dataToSign);
    }

    private byte[] DigestData(byte[] data, HashAlgorithmName hashAlgorithm)
    {
        using HashAlgorithm digester = hashAlgorithm.Name switch
        {
            "SHA1" => CryptographyProviders.Sha1Creator(),
            "SHA256" => CryptographyProviders.Sha256Creator(),
            "SHA384" => CryptographyProviders.Sha384Creator(),
            "SHA512" => CryptographyProviders.Sha512Creator(),
            _ => throw new ArgumentException(),
        };

        int hashSize = digester.HashSize / 8;
        int digestSize = _isRsa ? hashSize : _keySizeBits / 8;
        byte[] digest = new byte[digestSize];

        digester.ComputeHash(data).CopyTo(digest.AsSpan(digestSize - hashSize));

        return digest;
    }

    private byte[] PadRsa(byte[] digest, HashAlgorithmName hashAlgorithm)
    {
        int digestAlgorithm = hashAlgorithm.Name switch
        {
            "SHA1" => RsaFormat.Sha1,
            "SHA256" => RsaFormat.Sha256,
            "SHA384" => RsaFormat.Sha384,
            "SHA512" => RsaFormat.Sha512,
            _ => 0,
        };
        
        return _padding.Mode switch
        {
            RSASignaturePaddingMode.Pkcs1 => RsaFormat.FormatPkcs1Sign(digest, digestAlgorithm, _keySizeBits),
            RSASignaturePaddingMode.Pss => RsaFormat.FormatPkcs1Pss(digest, digestAlgorithm, _keySizeBits),
        };
    }
}