using Yubico.YubiKey.Piv;

namespace VaettirNet.YubikeyUtils.Cli;

public interface IYubikeyPivSource
{
    PivSession GetPivSession();
}