using Yubico.YubiKey.Piv;

namespace yk;

public interface IYubikeyPivSource
{
    PivSession GetPivSession();
}