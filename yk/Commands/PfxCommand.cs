using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;

namespace VaettirNet.YubikeyUtils.Cli.Commands;

internal class PfxCommand : CommandBase
{
    private readonly ILogger<PfxCommand> _logger;
    public string CertFile { get; private set; }
    public string KeyFile { get; private set; }
    public string OutputFile { get; private set; }
    public PfxCommand(ILogger<PfxCommand> logger) : base("pfx", "Merge a private key file and signed certificate to produce a PFX")
    {
        _logger = logger;
        Options = new()
        {
            {"cert|c=", "Signed certificate file", v => CertFile = v},
            {"key|k=", "Private keyfile", v => KeyFile = v},
            {"output|out|o=", "Signed certificate file", v => OutputFile = v},
        };
    }

    protected override int Execute()
    {
        ValidateRequiredArgument(CertFile, "cert");
        ValidateRequiredArgument(KeyFile, "key");
        ValidateRequiredArgument(OutputFile, "output");
        
        var cert = X509Certificate2.CreateFromPemFile(CertFile, KeyFile);
        var export = cert.Export(X509ContentType.Pfx);
        File.WriteAllBytes(OutputFile, export);
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