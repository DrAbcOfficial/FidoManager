using System.Globalization;
using Fido2.Core.Sessions;
using Fido2.Core.Transports;

namespace Fido2.Cli;

/// <summary>Finds, selects and opens an authenticator for one CLI invocation.</summary>
internal static class DeviceConnector
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(20);

    public static async Task<AuthenticatorSession> OpenAsync(CommandLine line, CancellationToken cancellationToken)
    {
        IReadOnlyList<AuthenticatorEntry> entries =
            await AuthenticatorDiscovery.EnumerateAsync(null, cancellationToken).ConfigureAwait(false);
        if (entries.Count == 0)
        {
            throw new CliException("No FIDO2 authenticator found. Connect a USB key or place one on the NFC reader.");
        }

        AuthenticatorEntry entry = Select(entries, line.Value(Options.Device));
        Console.Error.WriteLine($"Using {entry.DisplayName}");

        ITokenTransport transport = entry.OpenTransport();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(ConnectTimeout);
        try
        {
            return await AuthenticatorSessionFactory
                .OpenAsync(transport, timeout.Token, new TouchPrompt())
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            transport.Dispose();
            throw new CliException($"timed out opening {entry.DisplayName}.");
        }
        catch (Exception ex)
        {
            transport.Dispose();
            if (entry.Kind == "USB" && !Elevation.IsElevated)
            {
                throw new CliException(
                    $"{ex.Message}\nUSB-HID access usually needs an elevated terminal — retry from an administrator prompt.");
            }
            throw;
        }
    }

    private static AuthenticatorEntry Select(IReadOnlyList<AuthenticatorEntry> entries, string? selector)
    {
        if (selector is null)
        {
            return entries.Count == 1
                ? entries[0]
                : throw new CliException(
                    $"{entries.Count} authenticators found — choose one with --device <index> ('fido2 devices' lists them).");
        }

        if (int.TryParse(selector, NumberStyles.Integer, CultureInfo.InvariantCulture, out int index))
        {
            return index >= 0 && index < entries.Count
                ? entries[index]
                : throw new UsageException($"--device {index} is out of range (0..{entries.Count - 1}).");
        }

        var matches = entries
            .Where(entry => entry.DisplayName.Contains(selector, StringComparison.OrdinalIgnoreCase))
            .ToList();
        return matches.Count switch
        {
            1 => matches[0],
            0 => throw new CliException($"no device matches '{selector}'."),
            _ => throw new CliException($"'{selector}' matches {matches.Count} devices — use an index."),
        };
    }
}
