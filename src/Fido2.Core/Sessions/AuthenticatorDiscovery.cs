using Fido2.Core.Ctap2;
using Fido2.Core.Transports;

namespace Fido2.Core.Sessions;

/// <summary>One authenticator found during a scan; the transport is only opened on connect.</summary>
public sealed record AuthenticatorEntry(string DisplayName, string Kind, Func<ITokenTransport> OpenTransport);

/// <summary>
/// Device discovery shared by the GUI and the CLI: USB keys via HID enumeration and NFC via
/// PC/SC readers. CTAP capability is discovered by probing, never assumed — a USB-CCID
/// interface looks identical to an NFC reader by name but cannot carry CTAP2, so
/// non-answering readers are silently dropped instead of offered as unusable entries.
/// </summary>
public static class AuthenticatorDiscovery
{
    /// <param name="noCardMessage">Formats the "reader has no card" error, so the GUI can
    /// localize it; the CLI falls back to a plain English message.</param>
    public static async Task<IReadOnlyList<AuthenticatorEntry>> EnumerateAsync(
        Func<string, string>? noCardMessage = null,
        CancellationToken cancellationToken = default)
    {
        var entries = new List<AuthenticatorEntry>();

        foreach (var descriptor in await Task.Run(
                     HidDeviceEnumerator.Enumerate, cancellationToken).ConfigureAwait(false))
        {
            HidDescriptor captured = descriptor;
            entries.Add(new AuthenticatorEntry(
                DisplayName: string.IsNullOrEmpty(descriptor.SerialNumber)
                    ? $"USB  {descriptor.DisplayName}  VID_{descriptor.VendorId:X4} PID_{descriptor.ProductId:X4}"
                    : $"USB  {descriptor.DisplayName}  [{descriptor.SerialNumber}]",
                Kind: "USB",
                OpenTransport: () => HidTransport.Open(captured)));
        }

        foreach (string readerName in PcscTransport.ListReaders())
        {
            if (await ProbesCtap2Async(readerName, cancellationToken).ConfigureAwait(false))
            {
                string reader = readerName;
                entries.Add(new AuthenticatorEntry(
                    DisplayName: $"NFC  {reader}",
                    Kind: "NFC",
                    OpenTransport: () => PcscTransport.TryOpen(reader)
                        ?? throw new TransportException(
                            noCardMessage?.Invoke(reader) ?? $"No card on reader {reader}")));
            }
        }

        return entries;
    }

    private static async Task<bool> ProbesCtap2Async(string readerName, CancellationToken cancellationToken)
    {
        try
        {
            var transport = PcscTransport.TryOpen(readerName);
            if (transport is null)
            {
                return false;
            }
            using (transport)
            {
                var probe = new Ctap2Connection(transport)
                {
                    CredentialManagementOpcode = CtapCommandId.CredentialManagement,
                    BioEnrollmentOpcode = CtapCommandId.BioEnrollment,
                };
                return await probe.SendAsync(CtapCommandId.GetInfo, null, cancellationToken).ConfigureAwait(false) is not null;
            }
        }
        catch
        {
            return false;
        }
    }
}
