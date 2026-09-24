namespace Fido2.Core.Ctap2;

/// <summary>getCredsMetadata result.</summary>
public sealed record CredsMetadata(int Existing, int? MaxRemaining);

/// <summary>One discoverable credential as shown in the credentials grid.</summary>
public sealed record ResidentCredential(
    string RpId,
    string? UserName,
    string? DisplayName,
    string? UserIdHex,
    string CredentialIdHex)
{
    /// <summary>UserName and DisplayName are optional per WebAuthn; fall back in order.</summary>
    public string BestUserName => UserName ?? DisplayName ?? CoreStrings.Unnamed;
}

/// <summary>One fingerprint enrollment.</summary>
public sealed record FingerprintEnrollment(string TemplateIdHex, string? FriendlyName)
{
    public string BestName => string.IsNullOrWhiteSpace(FriendlyName) ? CoreStrings.Unnamed : FriendlyName!;
}

/// <summary>getFingerprintSensorInfo result.</summary>
public sealed record FingerprintSensorInfo(int Kind, int MaxCaptureSamples, int MaxFriendlyNameLength)
{
    public string KindText => Kind switch
    {
        1 => "touch",
        2 => "swipe",
        _ => "unknown",
    };
}

/// <summary>Per-sample enrollment feedback (lastEnrollSampleStatus / remainingSamples).</summary>
public sealed record EnrollmentSample(long LastSampleStatus, int RemainingSamples, byte[]? TemplateId = null)
{
    public string StatusText => LastSampleStatus switch
    {
        0x00 => "good sample captured",
        0x01 => "sample too high or partial — try again",
        0x02 => "sample too low or partial — try again",
        0x03 => "sample partial — center your finger on the sensor",
        0x04 => "too many samples failed — enrollment may need restarting",
        0x05 => "low quality — clean the sensor and your finger, then retry",
        0x06 => "too close to a previous sample — adjust finger position",
        0x07 => "sensor timeout — touch the sensor",
        _ => "retry the sample",
    };
}

/// <summary>PIN state snapshot for the PIN page.</summary>
public sealed record PinState(bool IsSet, int? RetriesRemaining);
