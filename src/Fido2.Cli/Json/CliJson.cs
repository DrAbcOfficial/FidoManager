using System.Text.Json.Serialization;

namespace Fido2.Cli;

internal sealed record DeviceJson(int Index, string Kind, string Name);

internal sealed record InfoJson(
    string Device,
    string Kind,
    string? Serial,
    string[] Versions,
    string Aaguid,
    string[] Extensions,
    string[] Transports,
    int[] PinUvAuthProtocols,
    int MinPinLength,
    int FirmwareVersion,
    int MaxMessageSize,
    bool PinSet,
    int? RetriesRemaining,
    string[] Capabilities,
    string Options);

internal sealed record CredentialJson(
    string RpId,
    string? UserName,
    string? DisplayName,
    string? UserIdHex,
    string CredentialIdHex,
    bool HasPublicKey,
    string? PublicKeyAlgorithm,
    string? OpenSshKey,
    string? OpenSshFingerprint,
    string? Comment);

internal sealed record ExportJson(string? Path, int Count, CredentialJson[] Keys);

internal sealed record PinJson(bool IsSet, int? RetriesRemaining);

/// <summary>
/// Source-generated JSON metadata — required under NativeAOT, where reflection-based
/// serialization is trimmed away. camelCase keeps the output friendly to scripts.
/// </summary>
[JsonSourceGenerationOptions(
    WriteIndented = true,
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(DeviceJson))]
[JsonSerializable(typeof(DeviceJson[]))]
[JsonSerializable(typeof(InfoJson))]
[JsonSerializable(typeof(CredentialJson))]
[JsonSerializable(typeof(CredentialJson[]))]
[JsonSerializable(typeof(ExportJson))]
[JsonSerializable(typeof(PinJson))]
internal sealed partial class CliJsonContext : JsonSerializerContext;
