using Fido2.Core.Ctap2;
using Fido2.Core.Pin;
using Fido2.Core.Transports;
using Fido2.Core.Transports.Vendor;

namespace Fido2.Core.Sessions;

/// <summary>
/// High-level orchestrator over one opened authenticator (design doc §2, §6): composes the
/// transport, the CTAP2 connection and the per-command APIs into the operations the UI
/// needs, and owns the safety policy — a wrong PIN must never silently burn retries, and
/// destructive operations carry their guards here rather than in the views.
/// The session is stateless regarding the PIN itself: callers prompt, remember and clear
/// the PIN (single responsibility), sessions only consume it per call.
/// </summary>
public sealed class AuthenticatorSession : IDisposable
{
    /// <summary>Refuse a PIN change when fewer retries remain — the wrong old PIN would
    /// lock the key; a reset is the saner path at that point.</summary>
    public const int ChangePinMinimumRetries = 3;

    private readonly Ctap2Connection _connection;

    public ITokenTransport Transport { get; }
    public AuthenticatorInfo Info { get; private set; }

    public AuthenticatorOptions Options => Info.Options;
    public string DisplayName => Transport.DisplayName;

    /// <summary>Token2 serial via vendor CCID APDU when the transport offers one.</summary>
    public string? VendorSerial { get; private init; }

    internal AuthenticatorSession(ITokenTransport transport, Ctap2Connection connection, AuthenticatorInfo info)
    {
        Transport = transport;
        _connection = connection;
        Info = info;
        VendorSerial = transport is PcscTransport pcsc ? Token2VendorApdu.ReadSerial(pcsc) : null;
    }

    public void Dispose() => Transport.Dispose();

    public async Task<PinState> GetPinStateAsync(CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress = null)
    {
        var clientPin = new ClientPinApi(_connection, Info);
        return await clientPin.GetPinStateAsync(cancellationToken, progress).ConfigureAwait(false);
    }

    public async Task SetPinAsync(string newPin, CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress = null)
    {
        var clientPin = new ClientPinApi(_connection, Info);
        await clientPin.SetPinAsync(newPin, cancellationToken, progress).ConfigureAwait(false);
    }

    public async Task ChangePinAsync(string currentPin, string newPin, CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress = null)
    {
        var clientPin = new ClientPinApi(_connection, Info);
        PinState state = await clientPin.GetPinStateAsync(cancellationToken, progress).ConfigureAwait(false);
        if (state.RetriesRemaining is { } retries && retries < ChangePinMinimumRetries)
        {
            throw new InvalidOperationException(
                $"Only {retries} PIN retries remain — changing the PIN now risks locking the key. Reset it instead.");
        }
        await clientPin.ChangePinAsync(currentPin, newPin, cancellationToken, progress).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<ResidentCredential>> ListCredentialsAsync(
        string pin, CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress = null)
    {
        var pinUv = await GetPinUvAsync(pin, PinTokenPermissions.CredentialManagement, cancellationToken, progress).ConfigureAwait(false);
        var credMgmt = new CredentialManagementApi(_connection, pinUv);

        var credentials = new List<ResidentCredential>();
        foreach (var (rpId, rpIdHash) in await credMgmt.EnumerateRpsAsync(cancellationToken, progress).ConfigureAwait(false))
        {
            foreach (var credential in await credMgmt.EnumerateCredentialsAsync(rpIdHash, cancellationToken, progress).ConfigureAwait(false))
            {
                credentials.Add(credential with { RpId = rpId ?? "(unknown)" });
            }
        }
        return credentials;
    }

    public async Task<CredsMetadata> GetCredentialMetadataAsync(
        string pin, CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress = null)
    {
        var pinUv = await GetPinUvAsync(pin, PinTokenPermissions.CredentialManagement, cancellationToken, progress).ConfigureAwait(false);
        var credMgmt = new CredentialManagementApi(_connection, pinUv);
        return await credMgmt.GetMetadataAsync(cancellationToken, progress).ConfigureAwait(false);
    }

    public async Task DeleteCredentialAsync(
        string pin, byte[] credentialId, CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress = null)
    {
        var pinUv = await GetPinUvAsync(pin, PinTokenPermissions.CredentialManagement, cancellationToken, progress).ConfigureAwait(false);
        var credMgmt = new CredentialManagementApi(_connection, pinUv);
        await credMgmt.DeleteCredentialAsync(credentialId, cancellationToken, progress).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<FingerprintEnrollment>> ListFingerprintsAsync(
        string pin, CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress = null)
    {
        var bio = await OpenBioAsync(pin, cancellationToken, progress).ConfigureAwait(false);
        return await bio.EnumerateEnrollmentsAsync(cancellationToken, progress).ConfigureAwait(false);
    }

    public async Task<FingerprintSensorInfo?> GetFingerprintSensorInfoAsync(
        string? pin, CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress = null)
    {
        // getFingerprintSensorInfo needs no pinUvAuthToken; only pass one when a PIN was given.
        var bio = pin is null
            ? new BioEnrollmentApi(_connection, pinUv: null)
            : await OpenBioAsync(pin, cancellationToken, progress).ConfigureAwait(false);
        return await bio.GetSensorInfoAsync(cancellationToken, progress).ConfigureAwait(false);
    }

    /// <summary>Full fingerprint enrollment: begin → capture loop (touch progress + per-sample
    /// progress) → optional friendly name. Host-side sample cap and cancel-with-discard are
    /// handled here. On cancellation or fault the partial template is removed from the key.</summary>
    public async Task<FingerprintEnrollment> EnrollFingerprintAsync(
        string pin,
        string? friendlyName,
        IProgress<EnrollmentSample>? samples,
        IProgress<KeepaliveStatus>? touch,
        CancellationToken cancellationToken)
    {
        var bio = await OpenBioAsync(pin, cancellationToken, touch).ConfigureAwait(false);

        EnrollmentSample sample = await bio.EnrollBeginAsync(cancellationToken, touch).ConfigureAwait(false);
        samples?.Report(sample);
        int captured = 1;

        try
        {
            while (sample.RemainingSamples > 0)
            {
                if (captured >= BioEnrollmentApi.MaxSamples)
                {
                    throw new TransportException(
                        $"The key kept asking for samples past the host cap ({BioEnrollmentApi.MaxSamples}).");
                }
                if (sample.TemplateId is null)
                {
                    throw new TransportException("enroll loop lost the template id.");
                }
                sample = await bio.EnrollCaptureNextAsync(sample.TemplateId, cancellationToken, touch).ConfigureAwait(false);
                captured++;
                samples?.Report(sample);
            }

            byte[] templateId = sample.TemplateId ?? throw new TransportException("Enrollment finished without a template id.");
            if (!string.IsNullOrWhiteSpace(friendlyName))
            {
                await bio.SetFriendlyNameAsync(templateId, friendlyName!, cancellationToken, touch).ConfigureAwait(false);
            }
            return new FingerprintEnrollment(
                Convert.ToHexString(templateId).ToLowerInvariant(),
                string.IsNullOrWhiteSpace(friendlyName) ? null : friendlyName);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            try { await bio.CancelCurrentEnrollmentAsync(CancellationToken.None).ConfigureAwait(false); }
            catch { /* best effort — the key may already have discarded it */ }
            throw;
        }
    }

    public async Task DeleteFingerprintAsync(
        string pin, byte[] templateId, CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress = null)
    {
        var bio = await OpenBioAsync(pin, cancellationToken, progress).ConfigureAwait(false);
        await bio.RemoveEnrollmentAsync(templateId, cancellationToken, progress).ConfigureAwait(false);
    }

    public async Task RenameFingerprintAsync(
        string pin, byte[] templateId, string friendlyName, CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress = null)
    {
        var bio = await OpenBioAsync(pin, cancellationToken, progress).ConfigureAwait(false);
        await bio.SetFriendlyNameAsync(templateId, friendlyName, cancellationToken, progress).ConfigureAwait(false);
    }

    /// <summary>Toggles alwaysUv (a toggle, not a setter) and returns the state read back.</summary>
    public async Task<bool> ToggleAlwaysUvAsync(
        string pin, CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress = null)
    {
        if (Options.AlwaysUv is null)
        {
            throw new NotSupportedException("This key does not report the alwaysUv option.");
        }
        var config = new AuthenticatorConfigApi(_connection, await GetPinUvAsync(
            pin, PinTokenPermissions.AuthenticatorConfig, cancellationToken, progress).ConfigureAwait(false));
        await config.ToggleAlwaysUvAsync(cancellationToken, progress).ConfigureAwait(false);

        var refreshed = await RefreshInfoAsync(cancellationToken, progress).ConfigureAwait(false);
        return refreshed.Options.AlwaysUv == true;
    }

    public async Task SetMinPinLengthAsync(
        string pin,
        int? newMinPinLength,
        string[]? minPinLengthRpIds,
        bool forceChangePin,
        CancellationToken cancellationToken,
        IProgress<KeepaliveStatus>? progress = null)
    {
        var config = new AuthenticatorConfigApi(_connection, await GetPinUvAsync(
            pin, PinTokenPermissions.AuthenticatorConfig, cancellationToken, progress).ConfigureAwait(false));
        await config.SetMinPinLengthAsync(
            newMinPinLength, minPinLengthRpIds, forceChangePin ? true : null, cancellationToken, progress).ConfigureAwait(false);
    }

    public async Task ResetAsync(CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress = null) =>
        await _connection.ResetAsync(cancellationToken, progress).ConfigureAwait(false);

    /// <summary>Re-reads getInfo (post-toggle confirmation, policy display refresh).</summary>
    public async Task<AuthenticatorInfo> RefreshInfoAsync(CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress = null)
    {
        var response = await _connection.SendAsync(CtapCommandId.GetInfo, null, cancellationToken, progress).ConfigureAwait(false)
            ?? throw new TransportException("getInfo returned no payload.");
        Info = AuthenticatorInfo.FromCborMap(response);
        return Info;
    }

    private async Task<BioEnrollmentApi> OpenBioAsync(
        string pin, CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress)
    {
        var pinUv = await GetPinUvAsync(pin, PinTokenPermissions.BioEnrollment, cancellationToken, progress).ConfigureAwait(false);
        return new BioEnrollmentApi(_connection, pinUv);
    }

    private Task<ClientPinApi.PinUvContext> GetPinUvAsync(
        string pin, PinTokenPermissions permissions, CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress)
    {
        var clientPin = new ClientPinApi(_connection, Info);
        return clientPin.AuthenticateAsync(pin, permissions, cancellationToken, progress);
    }
}
