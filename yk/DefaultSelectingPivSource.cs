using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Yubico.YubiKey;
using Yubico.YubiKey.Piv;

namespace VaettirNet.YubikeyUtils.Cli;

public class DefaultSelectingPivSource : IYubikeyPivSource
{
    private readonly IUserInteraction _ui;
    public FirmwareVersion FirmwareVersion { get; private set; }

    public DefaultSelectingPivSource(IUserInteraction ui)
    {
        _ui = ui;
    }

    public PivSession GetPivSession()
    {
        var key = YubiKeyDevice.FindAll().FirstOrDefault();
        if (key == null) return null;
        FirmwareVersion = key.FirmwareVersion;
        var session = new PivSession(key);
        session.KeyCollector = KeyCollector;
        return session;
    }

    private bool KeyCollector(KeyEntryData arg)
    {
        switch (arg.Request)
        {
            case KeyEntryRequest.Release:
                return true;
            case KeyEntryRequest.VerifyPivPin:
            {
                string msg = arg.IsRetry ? $"Entry PIV Pin ({arg.RetriesRemaining} retries remaining): " : "Entry PIV Pin: ";
                string pin = _ui.PromptHidden(msg, '*');
                if (string.IsNullOrEmpty(pin))
                    return false;
                arg.SubmitValue(Encoding.ASCII.GetBytes(pin));
                return true;
            }
            case KeyEntryRequest.TouchRequest:
            {
                Console.Error.WriteLine("Touch Yubikey now.");
                return true;
            }
            case KeyEntryRequest.ChangePivManagementKey:
            {
                var existing = _ui.Prompt("Enter current management key (or empty for default): ");
                if (string.IsNullOrEmpty(existing))
                {
                    existing = "010203040506070801020304050607080102030405060708";
                }

                Span<byte> existingBytes = stackalloc byte[64];
                Convert.FromHexString(existing, existingBytes, out _, out int cbExisting);
                
                var key = _ui.Prompt("Enter management key (blank to generate new): ");
                if (string.IsNullOrEmpty(key))
                {
                    Span<byte> rand = stackalloc byte[32];
                    RandomNumberGenerator.Fill(rand);
                    Console.WriteLine($"New Key: {Convert.ToHexString(rand)}");
                    arg.SubmitValues(existingBytes[..cbExisting], rand);
                    CryptographicOperations.ZeroMemory(existingBytes);
                    CryptographicOperations.ZeroMemory(rand);
                    return true;
                }

                var bytes = Convert.FromHexString(key);
                
                arg.SubmitValues(existingBytes[..cbExisting], bytes);
                CryptographicOperations.ZeroMemory(existingBytes);
                CryptographicOperations.ZeroMemory(bytes);
                return true;
            }
            case KeyEntryRequest.ChangePivPin:
            {
                var existing = _ui.Prompt("Enter current PIN (enter for default): ");
                if (string.IsNullOrEmpty(existing))
                {
                    existing = "123456";
                }

                Span<byte> existingBytes = stackalloc byte[64];
                int cbExisting = Encoding.ASCII.GetBytes(existing, existingBytes);
                
                var key = _ui.Prompt("Enter new PIN: ");
                var bytes = Encoding.ASCII.GetBytes(key);
                
                arg.SubmitValues(existingBytes[..cbExisting], bytes);
                CryptographicOperations.ZeroMemory(existingBytes);
                CryptographicOperations.ZeroMemory(bytes);
                return true;
            }
            case KeyEntryRequest.ChangePivPuk:
            {
                var existing = _ui.Prompt("Enter current unlock PIN (enter for default): ");
                if (string.IsNullOrEmpty(existing))
                {
                    existing = "12345678";
                }

                Span<byte> existingBytes = stackalloc byte[64];
                int cbExisting = Encoding.ASCII.GetBytes(existing, existingBytes);
                
                var key = _ui.Prompt("Enter new unlock PIN: ");
                var bytes = Encoding.ASCII.GetBytes(key);
                
                arg.SubmitValues(existingBytes[..cbExisting], bytes);
                CryptographicOperations.ZeroMemory(existingBytes);
                CryptographicOperations.ZeroMemory(bytes);
                return true;
            }
            case KeyEntryRequest.AuthenticatePivManagementKey:
            {
                var key = _ui.PromptHidden("Enter management key : ", '*');
                var bytes = Convert.FromHexString(key);
                arg.SubmitValue(bytes);
                return true;
            }
            case KeyEntryRequest.SetU2fPin:
            case KeyEntryRequest.ChangeU2fPin:
            case KeyEntryRequest.VerifyU2fPin:
            case KeyEntryRequest.SetFido2Pin:
            case KeyEntryRequest.ChangeFido2Pin:
            case KeyEntryRequest.VerifyFido2Pin:
            case KeyEntryRequest.VerifyFido2Uv:
            case KeyEntryRequest.ResetPivPinWithPuk:
            case KeyEntryRequest.VerifyOathPassword:
            case KeyEntryRequest.SetOathPassword:
            case KeyEntryRequest.ChangeYubiHsmAuthManagementKey:
            case KeyEntryRequest.AuthenticateYubiHsmAuthCredentialPassword:
            case KeyEntryRequest.AuthenticateYubiHsmAuthManagementKey:
            case KeyEntryRequest.EnrollFingerprint:
            default:
                Console.Error.WriteLine($"Unhandled key request: {arg.Request}");
                return false;
        }
    }
}