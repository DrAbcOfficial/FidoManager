using Fido2.Core.Ctap2;
using Fido2.Core.Sessions;
using Fido2.Core.Transports;

namespace Fido2.Manager.Services;

/// <summary>One selectable authenticator; the transport is only opened on connect.</summary>
public sealed record DeviceEntry(string DisplayName, string Kind, Func<ITokenTransport> OpenTransport);

/// <summary>
/// Device discovery (design doc §3.5): USB keys via HID enumeration, NFC via PC/SC readers.
/// CTAP capability is discovered by probing, never assumed — a USB-CCID interface looks
/// identical to an NFC reader by name but cannot carry CTAP2, so non-answering readers are
/// silently dropped instead of shown as unusable entries.
/// </summary>
public static class DeviceEnumerationService
{
    public static async Task<IReadOnlyList<DeviceEntry>> EnumerateAsync(CancellationToken cancellationToken)
    {
        var entries = new List<DeviceEntry>();

        foreach (var descriptor in await Task.Run(
                     HidDeviceEnumerator.Enumerate, cancellationToken).ConfigureAwait(false))
        {
            entries.Add(new DeviceEntry(
                DisplayName: string.IsNullOrEmpty(descriptor.SerialNumber)
                    ? $"USB  {descriptor.DisplayName}  VID_{descriptor.VendorId:X4} PID_{descriptor.ProductId:X4}"
                    : $"USB  {descriptor.DisplayName}  [{descriptor.SerialNumber}]",
                Kind: "USB",
                OpenTransport: () => HidTransport.Open(descriptor)));
        }

        foreach (var readerName in PcscTransport.ListReaders())
        {
            if (await ProbesCtap2Async(readerName, cancellationToken).ConfigureAwait(false))
            {
                entries.Add(new DeviceEntry(
                    DisplayName: $"NFC  {readerName}",
                    Kind: "NFC",
                    OpenTransport: () => PcscTransport.TryOpen(readerName)
                        ?? throw new TransportException(Localization.Format("NoCardOnReader", readerName))));
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
