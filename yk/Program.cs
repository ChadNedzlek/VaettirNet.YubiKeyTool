using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Mono.Options;
using Yubico.YubiKey;
using Yubico.YubiKey.Piv;

namespace yk;

internal static class Program
{
    public const byte CaSlot = 0x84;
    static int Main(string[] args)
    {
        ServiceCollection collection = new ServiceCollection();

        collection.AddSingleton<IUserInteraction, ConsoleUserInteraction>();
        collection.AddSingleton<IYubikeyPivSource, DefaultSelectingPivSource>();
        collection.AddLogging();

        using var services = collection.BuildServiceProvider();

        Yubico.Core.Logging.Log.Instance = services.GetRequiredService<ILoggerFactory>();
        
        return new CommandSet(Environment.GetCommandLineArgs()[0])
            {
                ActivatorUtilities.CreateInstance<ResetYubikeyCommand>(services),
            }
            .Run(args);
    }
}

public abstract class CommandBase : Command
{
    public bool ShowHelp { get; private set; }
    
    protected CommandBase(string name, string help = null) : base(name, help)
    {
        Options ??= new OptionSet();
    }

    public override int Invoke(IEnumerable<string> arguments)
    {
        Options.Add("help|h|?", "Show help commands", v => ShowHelp = v is not null, true);
        List<string> extra = Options.Parse(arguments);
        IList<string> handled = HandleExtraArgs(extra);
        if (handled.Count > 0)
        {
            CommandSet.Error.WriteLine($"Unknown argument '{handled[0]}'");
            Options.WriteOptionDescriptions(Console.Error);
            return 1;
        }

        if (ShowHelp)
        {
            Options.WriteOptionDescriptions(CommandSet.Error);
            return 1;
        }

        return Execute();
    }

    public virtual IList<string> HandleExtraArgs(IList<string> arguments) => arguments;

    protected abstract int Execute();
}

public interface IUserInteraction
{
    bool PromptYesNo(string prompt, StringComparer comparer);
    string Prompt(string prompt, StringComparer comparer, params string[] options);
    string PromptHidden(string prompt, char? echo = null);
}

public static class UserInteraction
{
    public static string Prompt(this IUserInteraction ui, string prompt, params string[] options) =>
        ui.Prompt(prompt, StringComparer.CurrentCultureIgnoreCase, options);
    public static bool PromptYesNo(this IUserInteraction ui, string prompt) =>
        ui.PromptYesNo(prompt, StringComparer.CurrentCultureIgnoreCase);
}

public class ConsoleUserInteraction : IUserInteraction
{
    public bool PromptYesNo(string prompt, StringComparer comparer)
    {
        while (true)
        {
            Console.Write(prompt);
            string line = Console.ReadLine();
            if (comparer.Equals(line, "yes") || comparer.Equals(line, "y"))
                return true;
            if (comparer.Equals(line, "no") || comparer.Equals(line, "n"))
                return false;
        }
    }

    public string Prompt(string prompt, StringComparer comparer, params string[] options)
    {
        while (true)
        {
            Console.Write(prompt);
            string line = Console.ReadLine();
            if (options is not { Length: > 1 })
            {
                return line;
            }

            if (options.FirstOrDefault(o => comparer.Equals(o, line)) is { } matched)
            {
                return matched;
            }
        }
    }

    public string PromptHidden(string prompt, char? echo = null)
    {
        while (true)
        {
            Console.Write(prompt);
            StringBuilder b = new StringBuilder();
            while (true)
            {
                var r = Console.ReadKey().KeyChar;
                if (r == '\n') break;
                b.Append(r);
                if (echo is { } e)
                {
                    Console.Write(e);
                }
            }

            return b.ToString();
        }
    }
}

public interface IYubikeyPivSource
{
    PivSession GetPivSession();
}

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
                string pin = _ui.Prompt(msg);
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
            case KeyEntryRequest.AuthenticateYubiHsmAuthManagementKey:
            {
                var key = _ui.Prompt("Enter management key (blank to generate new): ");
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
            case KeyEntryRequest.AuthenticatePivManagementKey:
            case KeyEntryRequest.VerifyOathPassword:
            case KeyEntryRequest.SetOathPassword:
            case KeyEntryRequest.ChangeYubiHsmAuthManagementKey:
            case KeyEntryRequest.AuthenticateYubiHsmAuthCredentialPassword:
            case KeyEntryRequest.EnrollFingerprint:
            default:
                Console.Error.WriteLine($"Unhandled key request: {arg.Request}");
                return false;
        }
    }
}

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