namespace Fido2.Core.Ctap2;

/// <summary>CTAP2 authenticator command opcodes (incl. the CTAP2.0 preview commands).</summary>
public static class CtapCommandId
{
    public const byte MakeCredential = 0x01;
    public const byte GetAssertion = 0x02;
    public const byte GetInfo = 0x04;
    public const byte ClientPin = 0x06;
    public const byte Reset = 0x07;
    public const byte GetNextAssertion = 0x08;
    public const byte BioEnrollment = 0x09;
    public const byte CredentialManagement = 0x0A;
    public const byte Selection = 0x0B;
    public const byte LargeBlobs = 0x0C;
    public const byte AuthenticatorConfig = 0x0D;

    // CTAP 2.0 preview commands, paired with the legacy getPinToken (0x05) token.
    public const byte BioEnrollmentPreview = 0x40;
    public const byte CredentialManagementPreview = 0x41;
}
