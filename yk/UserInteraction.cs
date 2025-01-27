using System;

namespace yk;

public static class UserInteraction
{
    public static string Prompt(this IUserInteraction ui, string prompt, params string[] options) =>
        ui.Prompt(prompt, StringComparer.CurrentCultureIgnoreCase, options);
    public static bool PromptYesNo(this IUserInteraction ui, string prompt) =>
        ui.PromptYesNo(prompt, StringComparer.CurrentCultureIgnoreCase);
}