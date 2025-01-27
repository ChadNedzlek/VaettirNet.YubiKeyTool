using System;
using System.Globalization;
using System.IO;
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
    private readonly IUserInteraction _ui;
    private readonly IYubikeyPivSource _pivSource;

    public SignCsr(IUserInteraction ui, IYubikeyPivSource pivSource) : base("sign", "Sign a certificate signing request")
    {
        _ui = ui;
        _pivSource = pivSource;
        Options = new()
        {
            {"csr|input|i=", "Path to CSR request file", v => CsrFilePath = v},
            {"output|o=", "Output path for generated cert", v => OutputFilePath = v},
            {"slot|s=", "Slot to create the certificate in", v => Slot = byte.Parse(v, NumberStyles.HexNumber)},
            {"valid-days=", "Number of days for cert validity", v => ValidityDays = int.Parse(v)},
        };
    }

    protected override int Execute()
    {
        if (string.IsNullOrEmpty(CsrFilePath))
        {
            CommandSet.Error.WriteLine("argument 'csr' is required");
            Options.WriteOptionDescriptions(CommandSet.Error);
            return 1;
        }
        
        if (string.IsNullOrEmpty(OutputFilePath))
        {
            CommandSet.Error.WriteLine("argument 'output' is required");
            Options.WriteOptionDescriptions(CommandSet.Error);
            return 1;
        }
        
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
        CertificateRequest req = CertificateRequest.LoadSigningRequestPem(File.ReadAllText(CsrFilePath), HashAlgorithmName.SHA256, CertificateRequestLoadOptions.Default, RSASignaturePadding.Pss);
        var sigGen = new YubikeySigGenerator(req, RSASignaturePadding.Pss, piv, Slot);
        Span<byte> serialNumber = stackalloc byte[16];
        RandomNumberGenerator.Fill(serialNumber);
        CommandSet.Out.WriteLine("Signing certificate request...");
        X509Certificate2 signedCert = req.Create(slotCert.SubjectName, sigGen, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(ValidityDays), serialNumber);
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