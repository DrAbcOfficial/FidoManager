using System.Globalization;

namespace Fido2.Cli;

/// <summary>
/// Minimal long-option parser: <c>--name value</c>, <c>--name=value</c> and bare
/// <c>--flag</c>. Options are position-independent, so <c>fido2 --pin 1234 creds list</c>
/// and <c>fido2 creds list --pin 1234</c> mean the same thing. Unknown options are
/// rejected with <see cref="EnsureOnly"/> so a typo can never silently change behaviour.
/// </summary>
internal sealed class CommandLine
{
    /// <summary>Options that never consume a following token — this is what keeps
    /// <c>fido2 --json creds list</c> from swallowing the command name.</summary>
    private static readonly HashSet<string> Flags = new(StringComparer.Ordinal)
    {
        "help", "version", "json", "yes", "all", "force", "pin-stdin",
    };

    private readonly Dictionary<string, string?> _options = new(StringComparer.Ordinal);
    private readonly List<string> _positionals = [];

    public IReadOnlyList<string> Positionals => _positionals;

    public static CommandLine Parse(string[] args)
    {
        var line = new CommandLine();
        for (int i = 0; i < args.Length; i++)
        {
            string argument = args[i];
            if (argument == "--")
            {
                line._positionals.AddRange(args[(i + 1)..]);
                break;
            }
            if (argument is "-h")
            {
                line._options["help"] = null;
                continue;
            }
            if (argument is "-V")
            {
                line._options["version"] = null;
                continue;
            }
            if (!argument.StartsWith("--", StringComparison.Ordinal))
            {
                line._positionals.Add(argument);
                continue;
            }

            string name = argument[2..];
            string? value = null;
            int equals = name.IndexOf('=');
            if (equals >= 0)
            {
                value = name[(equals + 1)..];
                name = name[..equals];
            }
            else if (!Flags.Contains(name) && i + 1 < args.Length && !args[i + 1].StartsWith('-'))
            {
                value = args[++i];
            }

            if (name.Length == 0)
            {
                throw new UsageException("empty option name.");
            }
            line._options[name] = value;
        }
        return line;
    }

    public bool Has(string name) => _options.ContainsKey(name);

    public string? Value(string name) => _options.TryGetValue(name, out string? value) ? value : null;

    public string RequireValue(string name) =>
        Value(name) is { Length: > 0 } value ? value : throw new UsageException($"--{name} requires a value.");

    public int? IntValue(string name)
    {
        string? raw = Value(name);
        if (raw is null)
        {
            return null;
        }
        return int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out int value)
            ? value
            : throw new UsageException($"--{name} expects an integer, got '{raw}'.");
    }

    /// <summary>Rejects any option outside the command's accepted set (typo guard).</summary>
    public void EnsureOnly(params string[] allowed)
    {
        var known = new HashSet<string>(allowed, StringComparer.Ordinal);
        foreach (string name in _options.Keys)
        {
            if (!known.Contains(name))
            {
                throw new UsageException($"unknown option --{name}.");
            }
        }
    }
}
