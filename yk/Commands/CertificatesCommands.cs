using System;
using System.IO;
using Microsoft.Extensions.DependencyInjection;
using Mono.Options;

namespace VaettirNet.YubikeyUtils.Cli.Commands;

internal class CertificatesCommands : CommandSet
{
    public CertificatesCommands(IServiceProvider services, Converter<string, string> localizer = null) : base("cert", localizer)
    {
        Initialize(services);
    }

    public CertificatesCommands(IServiceProvider services, TextWriter output, TextWriter error, Converter<string, string> localizer = null) : base("cert", output, error, localizer)
    {
        Initialize(services);
    }

    private void Initialize(IServiceProvider services)
    {
        Add(ActivatorUtilities.CreateInstance<AuthorityCommands>(services));
        Add(ActivatorUtilities.CreateInstance<SignCsrCommand>(services));
        Add(ActivatorUtilities.CreateInstance<CreateCsrCommand>(services));
    }
}