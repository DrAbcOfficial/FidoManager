namespace Fido2.Core.Ctap2;

/// <summary>
/// Strongly-typed view over the authenticatorGetInfo options map. The CTAP options map is
/// the authoritative capability source — vendor config bits are not reliable across models
/// (design doc §4.5) — and the UI enables/disables controls from these flags.
/// </summary>
public sealed class AuthenticatorOptions(IReadOnlyDictionary<object, object?> map)
{
    private bool? Get(string key) => map.TryGetValue(key, out var value) && value is bool b ? b : null;

    public bool? ClientPin => Get("clientPin");
    public bool? Uv => Get("uv");
    public bool? BioEnroll => Get("bioEnroll");
    public bool? UserVerificationMgmtPreview => Get("userVerificationMgmtPreview");
    public bool? CredentialManagement => Get("credMgmt");
    public bool? CredentialManagementPreview => Get("credentialMgmtPreview");
    public bool? AlwaysUv => Get("alwaysUv");
    public bool? AuthenticatorConfig => Get("authnrCfg");
    public bool? SetMinPinLength => Get("setMinPINLength");
    public bool? PinUvAuthToken => Get("pinUvAuthToken");
    public bool? ResidentKey => Get("rk");

    /// <summary>The credential-management API this key speaks: final, preview, or null.</summary>
    public byte CredentialManagementOpcode =>
        CredentialManagement == true ? CtapCommandId.CredentialManagement
        : CredentialManagementPreview == true ? CtapCommandId.CredentialManagementPreview
        : throw new NotSupportedException("This key does not advertise a credential-management API.");

    public bool SupportsCredentialManagement => CredentialManagement == true || CredentialManagementPreview == true;

    /// <summary>The bio-enrollment command byte this key speaks (standard 0x09 preferred).</summary>
    public byte BioEnrollmentOpcode =>
        UserVerificationMgmtPreview == true && BioEnroll != true ? CtapCommandId.BioEnrollmentPreview
        : CtapCommandId.BioEnrollment;

    public bool SupportsBioEnrollment => BioEnroll == true || UserVerificationMgmtPreview == true;

    public string Summary => string.Join(" ", map
        .Select(kv => $"{kv.Key}={kv.Value}")
        .OrderBy(value => value, StringComparer.Ordinal));
}
