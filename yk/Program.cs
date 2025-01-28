using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Mono.Options;
using VaettirNet.YubikeyUtils.Cli.Commands;
using VaettirNet.YubikeyUtils.Cli.Providers;
using VaettirNet.YubikeyUtils.Cli.Services;

namespace VaettirNet.YubikeyUtils.Cli;

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

        ILogger logger = services.GetRequiredService<ILoggerFactory>().CreateLogger("Program");

        Yubico.Core.Logging.Log.Instance = services.GetRequiredService<ILoggerFactory>();

        var commands = new CommandSet(Environment.GetCommandLineArgs()[0])
        {
            ActivatorUtilities.CreateInstance<ResetYubikeyCommand>(services),
            ActivatorUtilities.CreateInstance<CertificatesCommands>(services),
        };

        try
        {
            return commands.Run(args);
        }
        catch (CommandFailedException e)
        {
            logger.LogWarning("Command failed with exit code '{exitCode}' message: {message}", e.ExitCode, e.Message);
            Console.Error.WriteLine(e);
            if (e.ExitCode is { } ex) return ex;
            return 1;
        }
        catch (Exception e)
        {
            Console.Error.WriteLine("Unexpected exception encountered. Terminating");
            logger.LogCritical(e, "Unhandled exception");
            #if DEBUG
                throw;
            #else
            return 1000;
            #endif
        }
    }
}