using Yubico.YubiKey.Piv;

namespace VaettirNet.YubikeyUtils.Cli.Services;

public interface IYubikeyPivSource
{
    PivSession GetPivSession();
}