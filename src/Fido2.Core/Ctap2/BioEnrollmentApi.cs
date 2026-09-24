using Fido2.Core.Cbor;
using Fido2.Core.Pin;
using Fido2.Core.Transports;

namespace Fido2.Core.Ctap2;

/// <summary>
/// authenticatorBioEnrollment (0x09, or preview 0x40 — the opcode is already bound on the
/// connection). pinUvAuthParam shape: authenticate(token, modality || subCommand || cbor(params)).
/// getFingerprintSensorInfo may be sent unauthenticated. The templateId returned by
/// enrollBegin must be threaded through every captureNext call — the key never resends it.
/// </summary>
public sealed class BioEnrollmentApi(Ctap2Connection connection, ClientPinApi.PinUvContext? pinUv)
{
    private const byte ModalityFingerprint = 0x01;

    private const byte SubEnrollBegin = 0x01;
    private const byte SubEnrollCaptureNext = 0x02;
    private const byte SubCancelCurrentEnrollment = 0x03;
    private const byte SubEnumerateEnrollments = 0x04;
    private const byte SubSetFriendlyName = 0x05;
    private const byte SubRemoveEnrollment = 0x06;
    private const byte SubGetFingerprintSensorInfo = 0x07;

    /// <summary>Host-side cap: remaining_samples is device-reported, and firmware that never
    /// counts down would loop forever, each pass costing the user a touch. Real sensors want 4–17.</summary>
    public const int MaxSamples = 64;

    public async Task<FingerprintSensorInfo> GetSensorInfoAsync(CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress = null)
    {
        var response = await Send(SubGetFingerprintSensorInfo, null, authenticate: false, cancellationToken, progress).ConfigureAwait(false)
            ?? throw new TransportException("Empty sensor info response.");
        return new FingerprintSensorInfo(
            Kind: (int)(response.GetInt(2) ?? 0),
            MaxCaptureSamples: (int)(response.GetInt(3) ?? 0),
            MaxFriendlyNameLength: (int)(response.GetInt(8) ?? 0));
    }

    public async Task<IReadOnlyList<FingerprintEnrollment>> EnumerateEnrollmentsAsync(CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress = null)
    {
        IReadOnlyDictionary<object, object?>? response;
        try
        {
            response = await Send(SubEnumerateEnrollments, null, authenticate: true, cancellationToken, progress).ConfigureAwait(false);
        }
        catch (CtapException e) when (e.IsNoEnrollments)
        {
            // CTAP 2.1 §6.7.6: an empty template database answers INVALID_OPTION, not [].
            return [];
        }
        if (response?.GetArray(7) is not { } templateInfos)
        {
            return [];
        }

        var enrollments = new List<FingerprintEnrollment>();
        foreach (var entry in templateInfos)
        {
            if (entry is IReadOnlyDictionary<object, object?> info
                && info.GetBytes(1) is { } templateId)
            {
                enrollments.Add(new FingerprintEnrollment(
                    Convert.ToHexString(templateId).ToLowerInvariant(),
                    info.GetText(2)));
            }
        }
        return enrollments;
    }

    public async Task<EnrollmentSample> EnrollBeginAsync(CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress = null)
    {
        var response = await Send(SubEnrollBegin, null, authenticate: true, cancellationToken, progress).ConfigureAwait(false)
            ?? throw new TransportException("enrollBegin returned nothing.");
        if (response.GetBytes(4) is not { Length: > 0 } templateId)
        {
            throw new TransportException("enrollBegin gave no template id.");
        }
        return new EnrollmentSample(response.GetInt(5) ?? -1, (int)(response.GetInt(6) ?? 0), templateId);
    }

    public async Task<EnrollmentSample> EnrollCaptureNextAsync(
        byte[] templateId, CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress = null)
    {
        var parameters = new CborMap().Add(1, templateId);
        var response = await Send(SubEnrollCaptureNext, parameters, authenticate: true, cancellationToken, progress).ConfigureAwait(false)
            ?? throw new TransportException("enrollCaptureNext returned nothing.");
        return new EnrollmentSample(response.GetInt(5) ?? -1, (int)(response.GetInt(6) ?? 0), templateId);
    }

    /// <summary>Discards the half-built template so it does not linger as a stray.</summary>
    public async Task CancelCurrentEnrollmentAsync(CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress = null)
    {
        await Send(SubCancelCurrentEnrollment, null, authenticate: false, cancellationToken, progress).ConfigureAwait(false);
    }

    public async Task SetFriendlyNameAsync(byte[] templateId, string friendlyName, CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress = null)
    {
        var parameters = new CborMap()
            .Add(1, templateId)
            .Add(2, friendlyName);
        await Send(SubSetFriendlyName, parameters, authenticate: true, cancellationToken, progress).ConfigureAwait(false);
    }

    public async Task RemoveEnrollmentAsync(byte[] templateId, CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress = null)
    {
        var parameters = new CborMap().Add(1, templateId);
        await Send(SubRemoveEnrollment, parameters, authenticate: true, cancellationToken, progress).ConfigureAwait(false);
    }

    private Task<IReadOnlyDictionary<object, object?>?> Send(
        byte subCommand, CborMap? parameters, bool authenticate, CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress)
    {
        var map = new CborMap()
            .Add(1, (int)ModalityFingerprint)
            .Add(2, (int)subCommand);
        if (parameters is not null)
        {
            map.Add(3, parameters);
        }

        if (authenticate)
        {
            if (pinUv is null)
            {
                throw new InvalidOperationException("Bio-enrollment sub command requires a pinUvAuthToken.");
            }
            byte[] authInput = [ModalityFingerprint, subCommand];
            if (parameters is not null)
            {
                authInput = [.. authInput, .. parameters.Encode()];
            }
            byte[] pinUvAuthParam = pinUv.Protocol.Authenticate(pinUv.Token, authInput);
            map.Add(4, pinUv.ProtocolVersion);
            map.Add(5, pinUvAuthParam);
        }

        return connection.SendAsync(connection.BioEnrollmentOpcode, map, cancellationToken, progress);
    }
}
