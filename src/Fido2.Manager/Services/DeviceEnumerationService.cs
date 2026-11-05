using Fido2.Core.Sessions;
using Fido2.Core.Transports;

namespace Fido2.Manager.Services;

/// <summary>One selectable authenticator; the transport is only opened on connect.</summary>
public sealed record DeviceEntry(string DisplayName, string Kind, Func<ITokenTransport> OpenTransport);

/// <summary>
/// Device discovery for the picker. The scan itself lives in Core
/// (<see cref="AuthenticatorDiscovery"/>); this wrapper only localizes the "no card"
/// error message.
/// </summary>
public static class DeviceEnumerationService
{
    public static async Task<IReadOnlyList<DeviceEntry>> EnumerateAsync(CancellationToken cancellationToken)
    {
        var entries = await AuthenticatorDiscovery.EnumerateAsync(
            reader => Localization.Format("NoCardOnReader", reader), cancellationToken).ConfigureAwait(false);

        return entries
            .Select(entry => new DeviceEntry(entry.DisplayName, entry.Kind, entry.OpenTransport))
            .ToArray();
    }
}
