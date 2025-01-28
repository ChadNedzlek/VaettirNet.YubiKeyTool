using System;

namespace VaettirNet.YubikeyUtils.Cli;

public class CommandFailedException : Exception
{
    public int? ExitCode { get; }

    public CommandFailedException(string message) : base(message)
    {
    }

    public CommandFailedException(string message, int exitCode) : this(message)
    {
        ExitCode = exitCode;
    }
}

public class MissingRequiredArgumentException : CommandFailedException
{
    public MissingRequiredArgumentException(string argumentName) : base($"Missing required parameter '{argumentName}'", 1)
    {
    }
}