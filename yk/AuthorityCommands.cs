using System;
using System.IO;
using Microsoft.Extensions.DependencyInjection;
using Mono.Options;

namespace VaettirNet.YubikeyUtils.Cli;

internal class AuthorityCommands : CommandSet
{
    public AuthorityCommands(IServiceProvider services, Converter<string, string> localizer = null) : base("ca", localizer)
    {
        Initialize(services);
    }

    public AuthorityCommands(IServiceProvider services, TextWriter output, TextWriter error, Converter<string, string> localizer = null) : base("ca", output, error, localizer)
    {
        Initialize(services);
    }

    private void Initialize(IServiceProvider services)
    {
        Add(ActivatorUtilities.CreateInstance<CreateCaCommand>(services));
    }
}