using System;

namespace VaettirNet.YubikeyUtils.Cli.Services;

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