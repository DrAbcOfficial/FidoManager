namespace Fido2.Core.Ctap2;

/// <summary>
/// Thrown when an authenticator answers a CTAP command with a non-zero status.
/// Carries semantic classification helpers used throughout the app:
/// <list type="bullet">
///   <item>empty-result codes (0x2E NO_CREDENTIALS, 0x12 INVALID_CBOR on enumerate — some
///     firmware answers 0x12 instead of 0x2E for an empty store; 0x2C INVALID_OPTION for an
///     empty fingerprint list, per CTAP 2.1 §6.7.6) must be treated as "nothing stored"</item>
///   <item>PIN-related codes clear any cached PIN so a stale PIN cannot silently burn retries</item>
///   <item>0x2D KEEPALIVE_CANCEL is a user-initiated cancel, not a fault</item>
/// </list>
/// </summary>
public sealed class CtapException : Exception
{
    public CtapStatusCode Status { get; }

    public CtapException(CtapStatusCode status)
        : base($"{status} (0x{(byte)status:X2}): {CtapErrorText.Get(status)}")
    {
        Status = status;
    }

    /// <summary>0x2E NO_CREDENTIALS / 0x12 INVALID_CBOR — treat as "no credentials stored".</summary>
    public bool IsNoCredentials =>
        Status == CtapStatusCode.Ctap2ErrNoCredentials ||
        Status == CtapStatusCode.Ctap2ErrInvalidCbor;

    /// <summary>0x2C INVALID_OPTION — fingerprint enumeration with an empty template database.</summary>
    public bool IsNoEnrollments => Status == CtapStatusCode.Ctap2ErrInvalidOption;

    /// <summary>0x2D — expected unwind after CTAPHID_CANCEL / NFC cancel.</summary>
    public bool IsUserCancelled => Status == CtapStatusCode.Ctap2ErrKeepaliveCancel;

    /// <summary>0x31/0x32/0x33/0x34/0x35/0x36 — a remembered PIN must be dropped after any of these.</summary>
    public bool IsPinError => Status is
        CtapStatusCode.Ctap2ErrPinInvalid or
        CtapStatusCode.Ctap2ErrPinBlocked or
        CtapStatusCode.Ctap2ErrPinAuthInvalid or
        CtapStatusCode.Ctap2ErrPinAuthBlocked or
        CtapStatusCode.Ctap2ErrPinNotSet or
        CtapStatusCode.Ctap2ErrPuatRequired;
}

/// <summary>Human-readable text for CTAP status codes (manager-oriented phrasing).</summary>
public static class CtapErrorText
{
    public static string Get(CtapStatusCode status) => status switch
    {
        CtapStatusCode.Ok => "success",
        CtapStatusCode.Ctap1ErrInvalidCommand => "the key rejected the command",
        CtapStatusCode.Ctap1ErrChannelBusy => "channel busy",
        CtapStatusCode.Ctap2ErrCborUnexpectedType => "the key rejected the request shape",
        CtapStatusCode.Ctap2ErrInvalidCbor => "invalid CBOR / length (often means: nothing stored)",
        CtapStatusCode.Ctap2ErrMissingParameter => "missing parameter",
        CtapStatusCode.Ctap2ErrFpDatabaseFull => "fingerprint database full",
        CtapStatusCode.Ctap2ErrOperationDenied => "operation denied by the key",
        CtapStatusCode.Ctap2ErrInvalidOption => "invalid option for current operation",
        CtapStatusCode.Ctap2ErrKeepaliveCancel => "cancelled",
        CtapStatusCode.Ctap2ErrNoCredentials => "no credentials stored",
        CtapStatusCode.Ctap2ErrUserActionTimeout => "no touch registered in time",
        CtapStatusCode.Ctap2ErrNotAllowed => "not allowed in this state (reset needs a fresh power-up)",
        CtapStatusCode.Ctap2ErrPinInvalid => "wrong PIN (a retry was consumed)",
        CtapStatusCode.Ctap2ErrPinBlocked => "PIN blocked — power-cycle the key",
        CtapStatusCode.Ctap2ErrPinAuthInvalid => "pinUvAuthParam rejected (wrong token or missing permission)",
        CtapStatusCode.Ctap2ErrPinAuthBlocked => "PIN authentication blocked — power-cycle the key",
        CtapStatusCode.Ctap2ErrPinNotSet => "no PIN set on this key",
        CtapStatusCode.Ctap2ErrPuatRequired => "this command needs a PIN",
        CtapStatusCode.Ctap2ErrPinPolicyViolation => "PIN does not meet the key policy",
        CtapStatusCode.Ctap2ErrPinTokenExpired => "PIN token expired — fetch a fresh one",
        CtapStatusCode.Ctap2ErrActionTimeout => "the operation timed out",
        CtapStatusCode.Ctap2ErrUpRequired => "user presence required",
        CtapStatusCode.Ctap2ErrUvBlocked => "built-in user verification locked out",
        CtapStatusCode.Ctap2ErrInvalidSubcommand => "unsupported sub command",
        CtapStatusCode.Ctap2ErrUvInvalid => "built-in user verification failed — retry",
        CtapStatusCode.Ctap2ErrUnauthorizedPermission => "the pinUvAuthToken lacks the required permission",
        _ => "see the CTAP specification error table",
    };
}
