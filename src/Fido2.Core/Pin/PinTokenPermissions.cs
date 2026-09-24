namespace Fido2.Core.Pin;

/// <summary>pinUvAuthToken permission bits (CTAP 2.1 authenticatorClientPIN).</summary>
[Flags]
public enum PinTokenPermissions : int
{
    None = 0,
    MakeCredential = 0x01,
    GetAssertion = 0x02,
    CredentialManagement = 0x04,
    BioEnrollment = 0x08,
    LargeBlobWrite = 0x10,
    AuthenticatorConfig = 0x20,
    PersistentCredentialManagement = 0x40,
}
