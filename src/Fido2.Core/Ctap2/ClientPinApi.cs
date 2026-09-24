using System.Security.Cryptography;
using System.Text;
using Fido2.Core.Cbor;
using Fido2.Core.Pin;
using Fido2.Core.Transports;

namespace Fido2.Core.Ctap2;

/// <summary>
/// authenticatorClientPIN (0x06) sub commands (design doc §4.3):
/// getPinRetries, getKeyAgreement, setPIN, changePIN, and the two token sub commands.
/// The token sub command is chosen from the key's <c>pinUvAuthToken</c> capability:
/// 0x09 (with permissions) when supported, legacy 0x05 (permissions silently dropped)
/// otherwise — capability-based selection instead of trial-and-error fallback.
/// </summary>
public sealed class ClientPinApi(Ctap2Connection connection, AuthenticatorInfo info)
{
    private const byte SubGetPinRetries = 0x01;
    private const byte SubGetKeyAgreement = 0x02;
    private const byte SubSetPin = 0x03;
    private const byte SubChangePin = 0x04;
    private const byte SubGetPinTokenLegacy = 0x05;
    private const byte SubGetPinTokenWithPermissions = 0x09;

    private readonly IPinUvAuthProtocol _protocol =
        info.SupportsPinProtocol(PinUvAuthProtocolTwo.Instance.Version) ? PinUvAuthProtocolTwo.Instance
        : info.SupportsPinProtocol(PinUvAuthProtocolOne.Instance.Version) ? PinUvAuthProtocolOne.Instance
        : throw new NotSupportedException("No compatible PIN/UV auth protocol.");

    /// <summary>The negotiated pinUvAuth context for authenticated management commands.</summary>
    public sealed record PinUvContext(IPinUvAuthProtocol Protocol, byte[] Token)
    {
        public uint ProtocolVersion => (uint)Protocol.Version;
    }

    public async Task<PinState> GetPinStateAsync(CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress = null)
    {
        bool pinSet = info.Options.ClientPin == true;
        int? retries = null;
        if (pinSet)
        {
            var response = await Send(SubGetPinRetries, null, cancellationToken, progress).ConfigureAwait(false)
                ?? throw new TransportException("Empty getPinRetries response.");
            retries = (int?)response.GetInt(3);
        }
        return new PinState(pinSet, retries);
    }

    public async Task<int> GetPinRetriesAsync(CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress = null)
    {
        var response = await Send(SubGetPinRetries, null, cancellationToken, progress).ConfigureAwait(false)
            ?? throw new TransportException("Empty getPinRetries response.");
        return (int)(response.GetInt(3) ?? 0);
    }

    public async Task SetPinAsync(string newPin, CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress = null)
    {
        byte[] sharedSecret = await NegotiateSharedSecretAsync(cancellationToken, progress).ConfigureAwait(false);

        byte[] newPinEnc = _protocol.Encrypt(sharedSecret, PinPadder.PadTo64(newPin));
        byte[] pinUvAuthParam = _protocol.Authenticate(sharedSecret, newPinEnc);

        var parameters = new CborMap()
            .Add(3, _PlatformCoseKey)
            .Add(4, pinUvAuthParam)
            .Add(5, newPinEnc);
        await Send(SubSetPin, parameters, cancellationToken, progress).ConfigureAwait(false);
    }

    public async Task ChangePinAsync(string currentPin, string newPin, CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress = null)
    {
        byte[] sharedSecret = await NegotiateSharedSecretAsync(cancellationToken, progress).ConfigureAwait(false);

        // pinHashEnc = AES(shared, LEFT(SHA-256(currentPin), 16))
        byte[] pinHashEnc = _protocol.Encrypt(
            sharedSecret, SHA256.HashData(Encoding.UTF8.GetBytes(currentPin)).AsSpan(0, 16));
        byte[] newPinEnc = _protocol.Encrypt(sharedSecret, PinPadder.PadTo64(newPin));

        byte[] authMessage = [.. newPinEnc, .. pinHashEnc];
        byte[] pinUvAuthParam = _protocol.Authenticate(sharedSecret, authMessage);

        var parameters = new CborMap()
            .Add(3, _PlatformCoseKey)
            .Add(4, pinUvAuthParam)
            .Add(5, newPinEnc)
            .Add(6, pinHashEnc);
        await Send(SubChangePin, parameters, cancellationToken, progress).ConfigureAwait(false);
    }

    /// <summary>Obtains a pinUvAuthToken with the requested permissions (permissions only
    /// sent when the key supports scoped tokens).</summary>
    public async Task<PinUvContext> AuthenticateAsync(
        string pin, PinTokenPermissions permissions, CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress = null)
    {
        byte[] sharedSecret = await NegotiateSharedSecretAsync(cancellationToken, progress).ConfigureAwait(false);
        byte[] pinHashEnc = _protocol.Encrypt(
            sharedSecret, SHA256.HashData(Encoding.UTF8.GetBytes(pin)).AsSpan(0, 16));

        bool scopedTokens = info.Options.PinUvAuthToken == true;
        byte subCommand = scopedTokens ? SubGetPinTokenWithPermissions : SubGetPinTokenLegacy;

        var parameters = new CborMap()
            .Add(3, _PlatformCoseKey)
            .Add(6, pinHashEnc);
        if (scopedTokens)
        {
            parameters.Add(9, (int)permissions);
        }

        var response = await Send(subCommand, parameters, cancellationToken, progress).ConfigureAwait(false)
            ?? throw new TransportException("No pinUvAuthToken in response.");
        byte[] encryptedToken = response.GetBytes(2) ?? throw new TransportException("pinUvAuthToken missing from response.");
        byte[] token = _protocol.ValidateToken(_protocol.Decrypt(sharedSecret, encryptedToken));
        return new PinUvContext(_protocol, token);
    }

    private CborMap? _PlatformCoseKey;

    private async Task<byte[]> NegotiateSharedSecretAsync(CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress)
    {
        var response = await Send(SubGetKeyAgreement, null, cancellationToken, progress).ConfigureAwait(false)
            ?? throw new TransportException("No keyAgreement in response.");
        var coseKey = response.GetMap(1) ?? throw new TransportException("keyAgreement missing.");
        return _protocol.GenerateSharedSecret(coseKey, out _PlatformCoseKey);
    }

    private Task<IReadOnlyDictionary<object, object?>?> Send(
        byte subCommand, CborMap? parameters, CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress)
    {
        var map = new CborMap()
            .Add(1, (int)_protocol.Version)
            .Add(2, (int)subCommand);
        if (parameters is not null)
        {
            foreach (var (key, value) in parameters)
            {
                map.Add(key, value);
            }
        }
        return connection.SendAsync(CtapCommandId.ClientPin, map, cancellationToken, progress);
    }
}

public static class PinPadder
{
    /// <summary>Pads the PIN to exactly 64 bytes for newPinEnc (CTAP 2.0/2.1: 4–63 UTF-8 bytes).</summary>
    public static byte[] PadTo64(string pin)
    {
        byte[] pinBytes = Encoding.UTF8.GetBytes(pin);
        if (pinBytes.Length < 4)
        {
            throw new ArgumentException("PIN must be at least 4 bytes.");
        }
        if (pinBytes.Length > 63)
        {
            throw new ArgumentException("PIN must be at most 63 bytes.");
        }
        var padded = new byte[64];
        pinBytes.CopyTo(padded, 0);
        return padded;
    }
}
