using System.Text;

namespace Fido2.Core.Ctap2;

/// <summary>
/// Strongly-typed view over the authenticatorGetInfo options map. The CTAP options map is
/// the authoritative capability source — vendor config bits are not reliable across models
/// (design doc §4.5) — and the UI enables/disables controls from these flags.
///
/// Some preview firmwares (observed on Feitian 096e:0853) corrupt option names with control
/// bytes ("credentialMgmtPreview" → "credential\x01gmtPreview"). Lookups therefore normalize
/// each received key (letters/digits only) and match the known option set by subsequence,
/// which tolerates inserted or dropped characters. Exact matches always win, and the known
/// set is closed, so spec-conformant keys resolve exactly as before.
/// </summary>
public sealed class AuthenticatorOptions
{
    public AuthenticatorOptions(IReadOnlyDictionary<object, object?> map)
    {
        Raw = map;
    }

    /// <summary>The raw options map, for diagnostics.</summary>
    public IReadOnlyDictionary<object, object?> Raw { get; }

    private static readonly string[] KnownOptions =
    [
        "clientPin", "uv", "bioEnroll", "userVerificationMgmtPreview", "credMgmt",
        "credentialMgmtPreview", "alwaysUv", "authnrCfg", "setMinPINLength",
        "pinUvAuthToken", "rk", "up", "plat", "makeCredUvNotRqd", "credProtect",
        "largeBlobs", "enterpriseAttestation", "uvToken",
    ];

    private bool? Get(string key)
    {
        foreach (var (name, value) in Raw)
        {
            if (name is not string text)
            {
                continue;
            }
            if (Matches(text, key))
            {
                return value is bool b ? b : null;
            }
        }
        return null;
    }

    private static bool Matches(string received, string wanted)
    {
        if (string.Equals(received, wanted, StringComparison.Ordinal))
        {
            return true;
        }

        string a = Normalize(received);
        string b = Normalize(wanted);
        return a.Length >= b.Length - 2 && IsSubsequence(b, a);
    }

    private static string Normalize(string name)
    {
        var sb = new StringBuilder(name.Length);
        foreach (var ch in name)
        {
            if (char.IsAsciiLetterOrDigit(ch))
            {
                sb.Append(char.ToLowerInvariant(ch));
            }
        }
        return sb.ToString();
    }

    private static bool IsSubsequence(string wanted, string received)
    {
        // True when `received` can be obtained by deleting characters from `wanted`:
        // iterate wanted, consuming received greedily.
        int j = 0;
        foreach (var ch in wanted)
        {
            if (j < received.Length && received[j] == ch)
            {
                j++;
            }
        }
        return j == received.Length;
    }

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

    public string Summary => string.Join(" ", Raw
        .Select(kv => $"{kv.Key}={kv.Value}")
        .OrderBy(value => value, StringComparer.Ordinal));
}
