using System;
using VaettirNet.YubikeyUtils.Cli.Services;
using Yubico.YubiKey.Piv;

namespace VaettirNet.YubikeyUtils.Cli.Commands;

public class ResetYubikeyCommand : CommandBase
{
    private readonly IUserInteraction _ui;
    private readonly IYubikeyPivSource _pivSource;

    public ResetYubikeyCommand(IUserInteraction ui, IYubikeyPivSource pivSource) : base(
        "reset",
        "Reset yubikey to factory defaults, deleting all keys"
    )
    {
        _ui = ui;
        _pivSource = pivSource;
    }

    protected override int Execute()
    {
        if (!_ui.PromptYesNo("Action will reset all data in key, continue [yn]? "))
            return 2;

        var session = _pivSource.GetPivSession();
        if (session is null)
        {
            Console.Error.WriteLine("No Yubikey detected");
            return 3;
        }
        
        Console.WriteLine("Resetting PIV data...");
        session.ResetApplication();
        Console.WriteLine("Creating new management key...");
        session.ChangeManagementKey(PivTouchPolicy.Default, PivAlgorithm.Aes256);
        Console.WriteLine("Creating unlock PIN...");
        session.ChangePuk();
        Console.WriteLine("Creating PIN...");
        session.ChangePin();
        Console.WriteLine("Done.");
        return 0;
    }
}