using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Logging;

namespace VaettirNet.YubikeyUtils.Cli;

public class CreateCsrCommand : CommandBase
{
    private readonly ILogger<CreateCsrCommand> _logger;

    public enum CsrType
    {
        Unspecified = 0,
        CodeSign,
        DocSign,
    }
    
    public CsrType Type { get; private set; }
    public string Subject { get; private set; }
    public string KeyFile { get; private set; }
    public string Output { get; private set; }
    public string OutKeyFile { get; private set; }
    
    public CreateCsrCommand(ILogger<CreateCsrCommand> logger) : base("csr create", "Create a new certificate signing request")
    {
        _logger = logger;
        Options = new()
        {
            {"type|t=", "Certificate request type ('codesign' or 'docsign')", v => Type = ParseType(v)},
            {"subject-name|subject|name|n=", "Certificate subject name", v => Subject = v},
            {"output|cert|o=", "Output file for created CSR (in PEM format)", v => Output = v},
            {"private-key|k=", "Input public key file (in PEM format), if null, a new key will be generated", v => KeyFile = v},
            {"output-key|ok=", "Output private key file for generated key (in PEM format)", v => OutKeyFile = v},
        };
    }

    private static CsrType ParseType(string input)
        => input.ToLowerInvariant().Replace("-", "") switch
        {
            "code" or "codesign" => CsrType.CodeSign,
            "doc" or "docsign" => CsrType.DocSign,
            _ => throw new CommandFailedException($"Unknown cert type: '{input}'")
        };

    protected override int Execute()
    {
        ValidateRequiredArgument(Type, "type");
        ValidateRequiredArgument(Subject, "subject-name");
        ValidateRequiredArgument(Output, "output");
        if (string.IsNullOrEmpty(KeyFile) && string.IsNullOrEmpty(OutKeyFile))
        {
            throw new CommandFailedException("One of 'public-key' or 'output-key' required", 1);
        }
        
        _logger.LogDebug("Validated all arguments");
        
        _logger.LogInformation("Creating certificate with usage: {type}", Type);

        X509SignatureGenerator signatureGenerator;
        if (KeyFile is not null)
        {
            _logger.LogDebug("Reading private key file");
            ReadOnlySpan<char> keyString = File.ReadAllText(KeyFile);
            var field = PemEncoding.Find(keyString);
            signatureGenerator = keyString[field.Label] switch
            {
                "EC PRIVATE KEY" => ImportEcDsa(keyString[field.Base64Data], field.DecodedDataLength),
                "RSA PRIVATE KEY" => ImportRsa(keyString[field.Base64Data], field.DecodedDataLength),
                _ => throw new CommandFailedException($"private key file contains unknown key type '{keyString[field.Label]}'", 3)
            };
        }
        else
        {
            CommandSet.Out.WriteLine("Generating new ECDSA key (Curve: EccP256)...");
            _logger.LogDebug("Creating new ECDSA key (Curve: EccP256)");
            var ecdsa = ECDsa.Create(ECCurve.CreateFromOid(SupportedOids.EcCurve.EccP256));
            _logger.LogDebug("Saving key {publicKeySig} to {fileName}", new PublicHashFormatter(ecdsa), OutKeyFile);
            File.WriteAllText(OutKeyFile, ecdsa.ExportECPrivateKeyPem(), new UTF8Encoding(false));
            signatureGenerator = X509SignatureGenerator.CreateForECDsa(ecdsa);
        }

        CommandSet.Out.WriteLine("Creating certificate request...");
        CertificateRequest req = new CertificateRequest(new X500DistinguishedName(Subject), signatureGenerator.PublicKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        var keyUsageFlags = X509KeyUsageFlags.DigitalSignature;
        _logger.LogInformation("Saving key usage flags: {keyUsage}", keyUsageFlags);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(keyUsageFlags, false));
        var enhancedKeyUsages = new OidCollection();
        switch (Type)
        {
            case CsrType.CodeSign:
            {
                _logger.LogInformation("Creating code sign certificate");
                enhancedKeyUsages.Add(SupportedOids.KeyUsages.CodeSigning);
                break;
            }
            case CsrType.DocSign:
            {
                _logger.LogInformation("Creating document sign certificate");
                enhancedKeyUsages.Add(SupportedOids.KeyUsages.DocumentSigning);
                break;
            }
        }

        if (enhancedKeyUsages.Count > 0)
        {
            _logger.LogInformation("Saving extended key usage flags: {keyUsage}", enhancedKeyUsages);
            req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(enhancedKeyUsages, false));
        }

        CommandSet.Out.WriteLine("Saving certificate request...");
        File.WriteAllText(Output, req.CreateSigningRequestPem(signatureGenerator));
        CommandSet.Out.WriteLine("Done.");

        return 0;
    }

    private X509SignatureGenerator ImportEcDsa(ReadOnlySpan<char> text, int length)
    {
        _logger.LogInformation("Importing {size} bytes of ECDsa key from file", length);
        Span<byte> bytes = stackalloc byte[length];
        if (!Convert.TryFromBase64Chars(text, bytes, out int cbBytes) || cbBytes != length)
        {
            _logger.LogError("Failed to decode base 64 data");
            throw new CommandFailedException("Invalid key file", 4);
        }
        var ecdsa = ECDsa.Create();
        ecdsa.ImportECPrivateKey(bytes, out _);
        _logger.LogInformation("Loaded key with public key {publicKey}", new PublicHashFormatter(ecdsa));
        return X509SignatureGenerator.CreateForECDsa(ecdsa);
    }

    private X509SignatureGenerator ImportRsa(ReadOnlySpan<char> text, int length)
    {
        _logger.LogInformation("Importing {size} bytes of RSA key from file", length);
        Span<byte> bytes = stackalloc byte[length];
        if (!Convert.TryFromBase64Chars(text, bytes, out int cbBytes) || cbBytes != length)
        {
            _logger.LogError("Failed to decode base 64 data");
            throw new CommandFailedException("Invalid key file", 4);
        }

        var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(bytes, out _);
        _logger.LogInformation("Loaded key with public key {publicKey}", new PublicHashFormatter(rsa));
        return X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pss);
    }
}