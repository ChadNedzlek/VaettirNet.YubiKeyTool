using System;
using System.Linq;
using System.Text;

namespace VaettirNet.YubikeyUtils.Cli;

public class ConsoleUserInteraction : IUserInteraction
{
    public bool PromptYesNo(string prompt, StringComparer comparer)
    {
        while (true)
        {
            Console.Write(prompt);
            string line = Console.ReadLine();
            if (comparer.Equals(line, "yes") || comparer.Equals(line, "y"))
                return true;
            if (comparer.Equals(line, "no") || comparer.Equals(line, "n"))
                return false;
        }
    }

    public string Prompt(string prompt, StringComparer comparer, params string[] options)
    {
        while (true)
        {
            Console.Write(prompt);
            string line = Console.ReadLine();
            if (options is not { Length: > 1 })
            {
                return line;
            }

            if (options.FirstOrDefault(o => comparer.Equals((string)o, line)) is { } matched)
            {
                return matched;
            }
        }
    }

    public string PromptHidden(string prompt, char? echo = null)
    {
        while (true)
        {
            Console.Write(prompt);
            StringBuilder b = new StringBuilder();
            while (true)
            {
                var r = Console.ReadKey().KeyChar;
                if (r == '\n') break;
                b.Append(r);
                if (echo is { } e)
                {
                    Console.Write(e);
                }
            }

            return b.ToString();
        }
    }
}