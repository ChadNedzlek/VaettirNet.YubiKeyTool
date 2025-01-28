using System;
using System.Security.Cryptography;

namespace VaettirNet.YubikeyUtils.Cli;

public readonly struct PublicHashFormatter
{
    private readonly AsymmetricAlgorithm _alg;

    public PublicHashFormatter(AsymmetricAlgorithm alg)
    {
        _alg = alg;
    }

    public override string ToString() => Convert.ToBase64String(SHA256.HashData(_alg.ExportSubjectPublicKeyInfo()));
}