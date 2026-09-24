using Fido2.Core.Cbor;

namespace Fido2.Core.Ctap2;

/// <summary>Parsed authenticatorGetInfo (0x04) response, keyed per CTAP 2.3 §6.4.</summary>
public sealed class AuthenticatorInfo
{
    public IReadOnlyList<string> Versions { get; init; } = [];
    public IReadOnlyList<string> Extensions { get; init; } = [];
    public string Aaguid { get; init; } = "";
    public AuthenticatorOptions Options { get; init; } = new(new Dictionary<object, object?>());
    public int MaxMessageSize { get; init; } = 1024;
    public IReadOnlyList<int> PinUvAuthProtocols { get; init; } = [];
    public int? MaxCredentialIdLength { get; init; }
    public IReadOnlyList<string> Transports { get; init; } = [];
    public bool ForcePinChange { get; init; }
    public int MinPinLength { get; init; } = 4;
    public int FirmwareVersion { get; init; }

    public bool SupportsFido21 => Versions.Contains("FIDO_2_1");
    public bool SupportsPinProtocol(int version) => PinUvAuthProtocols.Contains(version);

    public static AuthenticatorInfo FromCborMap(IReadOnlyDictionary<object, object?> map)
    {
        var options = map.GetMap(4) ?? new Dictionary<object, object?>();

        return new AuthenticatorInfo
        {
            Versions = map.GetArray(1)?.OfType<string>().ToArray() ?? [],
            Extensions = map.GetArray(2)?.OfType<string>().ToArray() ?? [],
            Aaguid = map.GetBytes(3) is { Length: 16 } aaguid ? Convert.ToHexString(aaguid) : "",
            Options = new AuthenticatorOptions(options),
            MaxMessageSize = (int)(map.GetInt(5) ?? 1024),
            PinUvAuthProtocols = map.GetArray(6)?.OfType<long>().Select(v => (int)v).ToArray() ?? [],
            MaxCredentialIdLength = (int?)map.GetInt(8),
            Transports = map.GetArray(9)?.OfType<string>().ToArray() ?? [],
            ForcePinChange = map.GetBool(12) == true,
            MinPinLength = (int)(map.GetInt(13) ?? 4),
            FirmwareVersion = (int)(map.GetInt(14) ?? 0),
        };
    }
}
