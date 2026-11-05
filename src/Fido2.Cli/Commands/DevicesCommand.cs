using Fido2.Core.Sessions;

namespace Fido2.Cli;

internal static class DevicesCommand
{
    public static async Task<int> RunAsync(CommandLine line, CancellationToken cancellationToken)
    {
        line.EnsureOnly(Options.Global);

        IReadOnlyList<AuthenticatorEntry> entries =
            await AuthenticatorDiscovery.EnumerateAsync(null, cancellationToken).ConfigureAwait(false);

        if (line.Has(Options.Json))
        {
            Output.Json(entries
                .Select((entry, index) => new DeviceJson(index, entry.Kind, entry.DisplayName))
                .ToArray());
            return ExitCodes.Ok;
        }

        if (entries.Count == 0)
        {
            Console.Error.WriteLine("No authenticators found.");
            return ExitCodes.Error;
        }

        for (int i = 0; i < entries.Count; i++)
        {
            Console.WriteLine($"{i}  {entries[i].DisplayName}");
        }
        Console.Error.WriteLine($"{entries.Count} authenticator(s).");
        return ExitCodes.Ok;
    }
}
