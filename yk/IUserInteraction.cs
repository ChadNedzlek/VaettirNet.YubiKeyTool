using System;

namespace yk;

public interface IUserInteraction
{
    bool PromptYesNo(string prompt, StringComparer comparer);
    string Prompt(string prompt, StringComparer comparer, params string[] options);
    string PromptHidden(string prompt, char? echo = null);
}