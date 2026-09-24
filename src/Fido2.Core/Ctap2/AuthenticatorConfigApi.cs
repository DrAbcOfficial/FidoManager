using Fido2.Core.Cbor;
using Fido2.Core.Pin;
using Fido2.Core.Transports;

namespace Fido2.Core.Ctap2;

/// <summary>
/// authenticatorConfig (0x0D). pinUvAuthParam shape (CTAP 2.1 §6.11 — different from
/// credential management): authenticate(token, 0xFF×32 || 0x0D || subCommand || cbor(params)).
/// Using the wrong shape returns 0x33 and looks exactly like a bad token.
/// Sub-command 0x02 TOGGLES alwaysUv — callers must read the current state first and
/// read it back after. setMinPINLength can only ever be raised; lowering needs a reset.
/// </summary>
public sealed class AuthenticatorConfigApi(Ctap2Connection connection, ClientPinApi.PinUvContext pinUv)
{
    private const byte SubToggleAlwaysUv = 0x02;
    private const byte SubSetMinPinLength = 0x03;

    public async Task ToggleAlwaysUvAsync(CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress = null) =>
        await Send(SubToggleAlwaysUv, null, cancellationToken, progress).ConfigureAwait(false);

    public async Task SetMinPinLengthAsync(
        int? newMinPinLength,
        string[]? minPinLengthRpIds,
        bool? forceChangePin,
        CancellationToken cancellationToken,
        IProgress<KeepaliveStatus>? progress = null)
    {
        if (newMinPinLength is null && minPinLengthRpIds is null && forceChangePin is null)
        {
            throw new ArgumentException("Nothing to set.");
        }

        var parameters = new CborMap();
        if (newMinPinLength is not null)
        {
            parameters.Add(1, newMinPinLength.Value);
        }
        if (minPinLengthRpIds is not null)
        {
            parameters.Add(2, minPinLengthRpIds);
        }
        if (forceChangePin is not null)
        {
            parameters.Add(3, forceChangePin.Value);
        }

        await Send(SubSetMinPinLength, parameters, cancellationToken, progress).ConfigureAwait(false);
    }

    private Task Send(byte subCommand, CborMap? parameters, CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress)
    {
        // 0xFF×32 || 0x0D || subCommand || cbor(subCommandParams)
        byte[] encoded = parameters?.Encode() ?? [];
        var authInput = new byte[34 + encoded.Length];
        Array.Fill(authInput, (byte)0xFF, 0, 32);
        authInput[32] = CtapCommandId.AuthenticatorConfig;
        authInput[33] = subCommand;
        encoded.CopyTo(authInput, 34);
        byte[] pinUvAuthParam = pinUv.Protocol.Authenticate(pinUv.Token, authInput);

        var map = new CborMap()
            .Add(1, (int)subCommand);
        if (parameters is not null)
        {
            map.Add(2, parameters);
        }
        map.Add(3, pinUv.ProtocolVersion);
        map.Add(4, pinUvAuthParam);

        return connection.SendAsync(CtapCommandId.AuthenticatorConfig, map, cancellationToken, progress);
    }
}
