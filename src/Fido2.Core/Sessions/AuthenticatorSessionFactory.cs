using Fido2.Core.Ctap2;
using Fido2.Core.Transports;

namespace Fido2.Core.Sessions;

/// <summary>
/// Opens a session: reads getInfo once (the standard capability source), binds the
/// credential-management / bio-enrollment opcodes from it (final CTAP 2.1 vs preview —
/// capability-based selection, never trial-and-error), and derives the vendor serial from
/// the transport when available (Token2 CCID).
/// </summary>
public static class AuthenticatorSessionFactory
{
    public static async Task<AuthenticatorSession> OpenAsync(
        ITokenTransport transport,
        CancellationToken cancellationToken,
        IProgress<KeepaliveStatus>? progress = null)
    {
        var probingConnection = new Ctap2Connection(transport)
        {
            CredentialManagementOpcode = CtapCommandId.CredentialManagement,
            BioEnrollmentOpcode = CtapCommandId.BioEnrollment,
        };

        var infoResponse = await probingConnection.SendAsync(
            CtapCommandId.GetInfo, null, cancellationToken, progress).ConfigureAwait(false)
            ?? throw new TransportException($"{transport.DisplayName} returned no getInfo payload.");
        var info = AuthenticatorInfo.FromCborMap(infoResponse);

        var connection = new Ctap2Connection(transport)
        {
            CredentialManagementOpcode = info.Options.SupportsCredentialManagement
                ? info.Options.CredentialManagementOpcode
                : CtapCommandId.CredentialManagement,
            BioEnrollmentOpcode = info.Options.BioEnrollmentOpcode,
        };

        return new AuthenticatorSession(transport, connection, info);
    }
}
