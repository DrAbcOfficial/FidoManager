namespace Fido2.Core.Transports;

/// <summary>
/// Unified authenticator transport (CTAPHID over USB-HID, or CTAP over PC/SC NFC).
/// Mirrors python-fido2's <c>CtapDevice.call(cmd, data, event, on_keepalive)</c>: the
/// cancellation token maps to CTAPHID_CANCEL / NFC cancel, and keepalive reports are
/// de-duplicated by the implementation so UI code only hears about status changes.
/// </summary>
public interface ITokenTransport : IDisposable
{
    /// <summary>Human-readable device label for lists and logs.</summary>
    string DisplayName { get; }

    /// <summary>
    /// Sends one CTAP2 command frame and returns the raw response
    /// (status byte followed by optional CBOR payload).
    /// </summary>
    /// <param name="request">Operation byte followed by the CBOR-encoded parameters.</param>
    /// <exception cref="CtapException">The device answered with an error status.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> fired.</exception>
    byte[] Call(ReadOnlyMemory<byte> request, CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress);
}
