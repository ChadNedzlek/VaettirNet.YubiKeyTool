using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Mono.Options;

namespace yk;

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
        Add(ActivatorUtilities.CreateInstance<SignCsr>(services));
    }
}