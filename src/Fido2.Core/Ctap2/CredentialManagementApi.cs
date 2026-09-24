using System.Security.Cryptography;
using System.Text;
using Fido2.Core.Cbor;
using Fido2.Core.Pin;
using Fido2.Core.Transports;

namespace Fido2.Core.Ctap2;

/// <summary>
/// authenticatorCredentialManagement (0x0A, or preview 0x41 — the opcode is already bound
/// on the connection). pinUvAuthParam shape: authenticate(token, subCommand || cbor(params)).
/// Begin/next pairing: only the Begin commands are authenticated; the Next commands are not.
/// </summary>
public sealed class CredentialManagementApi(Ctap2Connection connection, ClientPinApi.PinUvContext pinUv)
{
    private const byte SubGetCredsMetadata = 0x01;
    private const byte SubEnumerateRpsBegin = 0x02;
    private const byte SubEnumerateRpsNext = 0x03;
    private const byte SubEnumerateCredsBegin = 0x04;
    private const byte SubEnumerateCredsNext = 0x05;
    private const byte SubDeleteCredential = 0x06;
    private const byte SubUpdateUserInformation = 0x07;

    private const int PlausibleCountCap = 4096;

    public async Task<CredsMetadata> GetMetadataAsync(CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress = null)
    {
        try
        {
            var response = await Send(SubGetCredsMetadata, null, authenticate: true, cancellationToken, progress).ConfigureAwait(false)
                ?? throw new TransportException("Empty getCredsMetadata response.");
            return new CredsMetadata(
                (int)(response.GetInt(1) ?? 0),
                (int?)response.GetInt(2));
        }
        catch (CtapException e) when (e.IsNoCredentials)
        {
            return new CredsMetadata(0, null);
        }
    }

    /// <summary>Enumerates every RP (begin + next loop). An empty store yields an empty list.</summary>
    public async Task<IReadOnlyList<(string? RpId, byte[] RpIdHash)>> EnumerateRpsAsync(CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress = null)
    {
        IReadOnlyDictionary<object, object?>? first;
        try
        {
            first = await Send(SubEnumerateRpsBegin, null, authenticate: true, cancellationToken, progress).ConfigureAwait(false);
        }
        catch (CtapException e) when (e.IsNoCredentials)
        {
            return [];
        }
        if (first is null)
        {
            return [];
        }

        int total = (int)(first.GetInt(5) ?? 1);
        if (total > PlausibleCountCap)
        {
            throw new TransportException($"Implausible RP count {total}.");
        }

        var rps = new List<(string?, byte[])> { (first.GetMap(3)?.GetText("id"), first.GetBytes(4) ?? []) };
        for (int i = 1; i < total; i++)
        {
            var next = await Send(SubEnumerateRpsNext, null, authenticate: false, cancellationToken, progress).ConfigureAwait(false);
            if (next is null)
            {
                break;
            }
            rps.Add((next.GetMap(3)?.GetText("id"), next.GetBytes(4) ?? []));
        }
        return rps;
    }

    /// <summary>Enumerates the discoverable credentials of one RP.</summary>
    public async Task<IReadOnlyList<ResidentCredential>> EnumerateCredentialsAsync(
        byte[] rpIdHash, CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress = null)
    {
        var parameters = new CborMap().Add(1, rpIdHash);
        IReadOnlyDictionary<object, object?>? first;
        try
        {
            first = await Send(SubEnumerateCredsBegin, parameters, authenticate: true, cancellationToken, progress).ConfigureAwait(false);
        }
        catch (CtapException e) when (e.IsNoCredentials)
        {
            return [];
        }
        if (first is null)
        {
            return [];
        }

        int total = (int)(first.GetInt(9) ?? 1);
        if (total > PlausibleCountCap)
        {
            throw new TransportException("Implausible credential count.");
        }

        var credentials = new List<ResidentCredential> { MapCredential(first) };
        for (int i = 1; i < total; i++)
        {
            var next = await Send(SubEnumerateCredsNext, null, authenticate: false, cancellationToken, progress).ConfigureAwait(false);
            if (next is null)
            {
                break;
            }
            credentials.Add(MapCredential(next));
        }
        return credentials;
    }

    public async Task DeleteCredentialAsync(byte[] credentialId, CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress = null)
    {
        var descriptor = new CborMap()
            .Add("id", credentialId)
            .Add("type", "public-key");
        var parameters = new CborMap().Add(2, descriptor);
        await Send(SubDeleteCredential, parameters, authenticate: true, cancellationToken, progress).ConfigureAwait(false);
    }

    public async Task UpdateUserInformationAsync(
        byte[] credentialId, string name, string? displayName, CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress = null)
    {
        // The user id must match the credential's existing user id per CTAP 2.1; the key
        // rejects the update otherwise, so callers enumerate first and pass it through.
        var user = new CborMap()
            .Add("id", Array.Empty<byte>())
            .Add("name", name);
        if (displayName is not null)
        {
            user.Add("displayName", displayName);
        }
        var descriptor = new CborMap()
            .Add("id", credentialId)
            .Add("type", "public-key");
        var parameters = new CborMap()
            .Add(2, descriptor)
            .Add(3, user);
        await Send(SubUpdateUserInformation, parameters, authenticate: true, cancellationToken, progress).ConfigureAwait(false);
    }

    private static ResidentCredential MapCredential(IReadOnlyDictionary<object, object?> response)
    {
        var user = response.GetMap(6);
        var descriptor = response.GetMap(7);
        return new ResidentCredential(
            RpId: "(unknown)",
            UserName: user?.GetText("name"),
            DisplayName: user?.GetText("displayName"),
            UserIdHex: user?.GetBytes("id") is { } id ? Convert.ToHexString(id).ToLowerInvariant() : null,
            CredentialIdHex: descriptor?.GetBytes("id") is { } cid ? Convert.ToHexString(cid).ToLowerInvariant() : "");
    }

    private Task<IReadOnlyDictionary<object, object?>?> Send(
        byte subCommand, CborMap? parameters, bool authenticate, CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress)
    {
        var map = new CborMap().Add(1, (int)subCommand);
        if (parameters is not null)
        {
            map.Add(2, parameters);
        }

        if (authenticate)
        {
            // pinUvAuthParam over subCommand || cbor(params) — no 0xff prefix, no modality.
            byte[] authInput = [(byte)subCommand];
            if (parameters is not null)
            {
                authInput = [.. authInput, .. parameters.Encode()];
            }
            byte[] pinUvAuthParam = pinUv.Protocol.Authenticate(pinUv.Token, authInput);
            map.Add(3, pinUv.ProtocolVersion);
            map.Add(4, pinUvAuthParam);
        }

        return connection.SendAsync(connection.CredentialManagementOpcode, map, cancellationToken, progress);
    }

    /// <summary>Convenience: SHA-256 of an RP id, for <see cref="EnumerateCredentialsAsync"/>.</summary>
    public static byte[] RpIdHash(string rpId) => SHA256.HashData(Encoding.UTF8.GetBytes(rpId));
}
