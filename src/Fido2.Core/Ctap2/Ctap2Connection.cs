using Fido2.Core.Cbor;
using Fido2.Core.Transports;

namespace Fido2.Core.Ctap2;

/// <summary>
/// Single choke point for CTAP2 request/response over a transport: combines the operation
/// byte with the CBOR parameters, checks the response status and decodes the payload.
/// User-initiated cancels (0x2D KEEPALIVE_CANCEL after CTAPHID_CANCEL / NFC cancel) are
/// surfaced as <see cref="OperationCanceledException"/>, not faults.
/// The credential-management / bio-enrollment opcodes are bound at construction time from
/// the authenticator's options map, so preview-firmware keys never send final opcodes.
/// </summary>
public sealed class Ctap2Connection(ITokenTransport transport)
{
    public ITokenTransport Transport { get; } = transport;

    public required byte CredentialManagementOpcode { get; init; }
    public required byte BioEnrollmentOpcode { get; init; }

    /// <summary>Sends a command and returns its decoded CBOR map, or null when the
    /// response carries no payload (e.g. successful config/reset/setPin).</summary>
    public async Task<IReadOnlyDictionary<object, object?>?> SendAsync(
        byte opcode,
        CborMap? parameters,
        CancellationToken cancellationToken,
        IProgress<KeepaliveStatus>? progress = null)
    {
        cancellationToken.ThrowIfCancellationRequested();

        byte[] encodedParameters = parameters?.Encode() ?? [];
        var request = new byte[1 + encodedParameters.Length];
        request[0] = opcode;
        encodedParameters.CopyTo(request.AsSpan(1));

        byte[] response = await Task.Run(
            () => Transport.Call(request, cancellationToken, progress),
            cancellationToken).ConfigureAwait(false);

        if (response.Length == 0)
        {
            throw new TransportException($"{Transport.DisplayName} returned an empty CTAP response.");
        }
        if (response[0] != 0x00)
        {
            var status = (CtapStatusCode)response[0];
            if (status == CtapStatusCode.Ctap2ErrKeepaliveCancel)
            {
                // Expected unwind after a host-side cancel — not an error.
                throw new OperationCanceledException("The operation was cancelled.");
            }
            throw new CtapException(status);
        }
        if (response.Length == 1)
        {
            return null;
        }

        return CborDecoder.Decode(response.AsMemory(1)) as IReadOnlyDictionary<object, object?>
            ?? throw new TransportException("CTAP response payload is not a CBOR map.");
    }

    public async Task ResetAsync(CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress = null) =>
        await SendAsync(CtapCommandId.Reset, null, cancellationToken, progress).ConfigureAwait(false);
}
