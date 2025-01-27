using System;
using System.ComponentModel;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Mono.Options;

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
                ActivatorUtilities.CreateInstance<CertificatesCommands>(services),
            }
            .Run(args);
    }
}