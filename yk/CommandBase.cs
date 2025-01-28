using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using Mono.Options;

namespace VaettirNet.YubikeyUtils.Cli;

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

    protected void ValidateRequiredArgument<T>(T value, string argumentName)
    {
        if (typeof(T) == typeof(string))
        {
            if (string.IsNullOrEmpty(Unsafe.As<string>(value)))
            {
                throw new CommandFailedException($"Missing required argument: '{argumentName}'", 1);
            }
        }

        if (typeof(T).IsEnum && Convert.ToInt32(value) == 0)
        {
            throw new CommandFailedException($"Missing required argument: '{argumentName}'", 1);
        }

        if (value is null)
        {
            throw new CommandFailedException($"Missing required argument: '{argumentName}'", 1);
        }
    }
}