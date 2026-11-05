using System.Globalization;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Fido2.Core.Transports;

namespace Fido2.Cli;

internal static class ExitCodes
{
    public const int Ok = 0;
    public const int Error = 1;
    public const int Usage = 2;
}

/// <summary>Bad command line — reported with a hint and exit code 2.</summary>
internal sealed class UsageException(string message) : Exception(message);

/// <summary>An expected runtime failure (no device, firmware limitation, …).</summary>
internal sealed class CliException(string message) : Exception(message);

internal static class Options
{
    public const string Device = "device";
    public const string Pin = "pin";
    public const string PinStdin = "pin-stdin";
    public const string Json = "json";

    /// <summary>Options every command accepts.</summary>
    public static readonly string[] Global = [Device, Pin, PinStdin, Json];
}

internal static class Output
{
    public static void Json<T>(T value) =>
        Console.WriteLine(JsonSerializer.Serialize(value, typeof(T), CliJsonContext.Default));

    /// <summary>Fixed-width columns; the last column is never padded (no trailing spaces).</summary>
    public static void Table(IReadOnlyList<string[]> rows)
    {
        if (rows.Count == 0)
        {
            return;
        }
        int columns = rows[0].Length;
        var widths = new int[columns];
        foreach (string[] row in rows)
        {
            for (int i = 0; i < columns; i++)
            {
                widths[i] = Math.Max(widths[i], row[i].Length);
            }
        }
        foreach (string[] row in rows)
        {
            var builder = new StringBuilder();
            for (int i = 0; i < columns; i++)
            {
                if (i > 0)
                {
                    builder.Append("  ");
                }
                builder.Append(i == columns - 1 ? row[i] : row[i].PadRight(widths[i]));
            }
            Console.WriteLine(builder.ToString().TrimEnd());
        }
    }

    public static string Truncate(string value, int maximum) =>
        value.Length <= maximum ? value : value[..(maximum - 1)] + "…";
}

internal static class Prompt
{
    /// <summary>Reads a secret from the console without echoing it.</summary>
    public static string Secret(string purpose)
    {
        if (Console.IsInputRedirected)
        {
            throw new UsageException("no PIN supplied — pass --pin, --pin-stdin, or run interactively.");
        }

        Console.Error.Write(purpose + ": ");
        var builder = new StringBuilder();
        while (true)
        {
            ConsoleKeyInfo key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.Error.WriteLine();
                return builder.ToString();
            }
            if (key.Key == ConsoleKey.Backspace)
            {
                if (builder.Length > 0)
                {
                    builder.Length--;
                }
                continue;
            }
            if (!char.IsControl(key.KeyChar))
            {
                builder.Append(key.KeyChar);
            }
        }
    }

    public static bool Confirm(string question)
    {
        if (Console.IsInputRedirected)
        {
            throw new UsageException("confirmation required — pass --yes.");
        }
        Console.Error.Write(question + " [y/N] ");
        string? answer = Console.ReadLine();
        return answer is not null
            && (answer.Equals("y", StringComparison.OrdinalIgnoreCase)
                || answer.Equals("yes", StringComparison.OrdinalIgnoreCase));
    }
}

internal static class PinSource
{
    /// <summary>Resolves the current PIN: --pin, then --pin-stdin, then an interactive prompt.</summary>
    public static string Require(CommandLine line, string purpose)
    {
        if (line.Value(Options.Pin) is { Length: > 0 } pin)
        {
            return pin;
        }
        if (line.Has(Options.PinStdin))
        {
            string? lineRead = Console.In.ReadLine();
            if (string.IsNullOrEmpty(lineRead))
            {
                throw new UsageException("--pin-stdin was given but stdin carried no PIN.");
            }
            return lineRead;
        }
        return Prompt.Secret(purpose);
    }

    /// <summary>Resolves a new PIN: --new, or two masked prompts that must match.</summary>
    public static string New(CommandLine line)
    {
        if (line.Value("new") is { } pin)
        {
            ValidateNew(pin);
            return pin;
        }

        string first = Prompt.Secret("New PIN");
        string second = Prompt.Secret("Confirm new PIN");
        if (!string.Equals(first, second, StringComparison.Ordinal))
        {
            throw new UsageException("the two PINs do not match.");
        }
        ValidateNew(first);
        return first;
    }

    private static void ValidateNew(string pin)
    {
        int bytes = Encoding.UTF8.GetByteCount(pin);
        if (bytes is < 4 or > 63)
        {
            throw new UsageException($"a PIN must be 4–63 UTF-8 bytes (got {bytes}).");
        }
    }
}

/// <summary>Prints the touch prompt once per operation, the first time the key asks for it.</summary>
internal sealed class TouchPrompt : IProgress<KeepaliveStatus>
{
    private bool _announced;

    public void Report(KeepaliveStatus value)
    {
        if (value == KeepaliveStatus.UpNeeded && !_announced)
        {
            _announced = true;
            Console.Error.WriteLine("Touch the key to confirm…");
        }
    }
}

internal static class Elevation
{
    public static bool IsElevated { get; } = Check();

    private static bool Check()
    {
        try
        {
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch (Exception)
        {
            return false;
        }
    }
}
