using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Yubico.YubiKey.Cryptography;
using Yubico.YubiKey.Piv;

namespace VaettirNet.YubikeyUtils.Cli;

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

    public YubikeySigGenerator(PublicKey pubKey, RSASignaturePadding padding, PivSession pivSession, byte slotNumber)
    {
        _padding = padding;
        _pivSession = pivSession;
        _slotNumber = slotNumber;

        if (pubKey.GetRSAPublicKey() is {} rsa)
        {
            _base = CreateForRSA(rsa, padding);
            _keySizeBits = rsa.KeySize;
            _isRsa = true;
        }
        else if (pubKey.GetECDsaPublicKey() is {} ecc)
        {
            _base = CreateForECDsa(ecc);
            _keySizeBits = ecc.KeySize;
            _isRsa = false;
        }
        else throw new ArgumentException($"Unsupported public key algorithm: {pubKey.Oid}");
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