using Fido2.Core.Cbor;
using Fido2.Core.Credentials;
using Fido2.Core.Ctap2;
using Fido2.Core.Pin;
using Fido2.Core.Transports;

namespace Fido2.Core.Tests;

/// <summary>
/// Drives authenticatorCredentialManagement over a fake transport: the CTAP 2.1 response
/// carries the credential public key in member 0x08, which is exactly what the OpenSSH
/// export consumes. Preview firmware omits it and must degrade to "no key", not a crash.
/// </summary>
public class CredentialManagementPublicKeyTests
{
    private static readonly byte[] CredentialId = Convert.FromHexString("a1b2c3d4");
    private const string CredentialIdHex = "a1b2c3d4";
    private const string Ed25519Fingerprint = "SHA256:nX0hpi5mKbTIJ10yBq5/sLQhiI1Y0RBAqN0drDdgJWs";

    [Fact]
    public async Task EnumerateCredentialsParsesTheCosePublicKey()
    {
        ResidentCredential credential = await EnumerateSingleAsync(withPublicKey: true);

        Assert.Equal("alice", credential.UserName);
        Assert.Equal("Alice", credential.DisplayName);
        Assert.Equal("010203", credential.UserIdHex);
        Assert.Equal(CredentialIdHex, credential.CredentialIdHex);
        Assert.NotNull(credential.PublicKey);
        Assert.True(credential.HasSshPublicKey);
        Assert.Equal("Ed25519", credential.PublicKey.AlgorithmName);

        Assert.True(OpenSshPublicKey.TryGetFingerprint(credential.PublicKey, out string fingerprint));
        Assert.Equal(Ed25519Fingerprint, fingerprint);

        var sshCredential = credential with { RpId = "ssh:" };
        Assert.True(OpenSshPublicKey.TryFormat(sshCredential, out string line));
        Assert.StartsWith("sk-ssh-ed25519@openssh.com ", line);
        Assert.EndsWith(" alice@ssh", line);
    }

    [Fact]
    public async Task WithoutThePublicKeyMemberTheCredentialIsSimplyNotExportable()
    {
        ResidentCredential credential = await EnumerateSingleAsync(withPublicKey: false);

        Assert.Null(credential.PublicKey);
        Assert.False(credential.HasSshPublicKey);
        Assert.False(OpenSshPublicKey.TryFormat(credential with { RpId = "ssh:" }, out _));
    }

    private static async Task<ResidentCredential> EnumerateSingleAsync(bool withPublicKey)
    {
        var transport = new SingleResponseTransport(Response(withPublicKey));
        var connection = new Ctap2Connection(transport)
        {
            CredentialManagementOpcode = CtapCommandId.CredentialManagement,
            BioEnrollmentOpcode = CtapCommandId.BioEnrollment,
        };
        var pinUv = new ClientPinApi.PinUvContext(new FakeProtocol(), new byte[32]);
        var api = new CredentialManagementApi(connection, pinUv);

        IReadOnlyList<ResidentCredential> credentials = await api
            .EnumerateCredentialsAsync(CredentialManagementApi.RpIdHash("ssh:"), CancellationToken.None);

        return Assert.Single(credentials);
    }

    private static byte[] Response(bool withPublicKey)
    {
        var user = new CborMap()
            .Add("id", new byte[] { 0x01, 0x02, 0x03 })
            .Add("name", "alice")
            .Add("displayName", "Alice");
        var descriptor = new CborMap()
            .Add("id", CredentialId)
            .Add("type", "public-key");

        var response = new CborMap()
            .Add(6, user)
            .Add(7, descriptor);
        if (withPublicKey)
        {
            response.Add(8, new CborMap()
                .Add(1, 1)   // kty: OKP
                .Add(3, -8)  // alg: EdDSA
                .Add(-1, 6)  // crv: Ed25519
                .Add(-2, Enumerable.Range(1, 32).Select(i => (byte)i).ToArray()));
        }
        response.Add(9, 1); // totalCredentials

        return [0x00, .. response.Encode()];
    }

    private sealed class SingleResponseTransport(byte[] response) : ITokenTransport
    {
        public string DisplayName => "fake";

        public byte[] Call(ReadOnlyMemory<byte> request, CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress) =>
            response;

        public void Dispose()
        {
        }
    }

    /// <summary>Stands in for pinUvAuthProtocol 2 — the command flow, not the crypto, is under test.</summary>
    private sealed class FakeProtocol : IPinUvAuthProtocol
    {
        public int Version => 2;

        public byte[] GenerateSharedSecret(
            IReadOnlyDictionary<object, object?> authenticatorCoseKey, out CborMap platformCoseKey)
        {
            platformCoseKey = new CborMap();
            return new byte[32];
        }

        public byte[] Encrypt(byte[] key, ReadOnlySpan<byte> plaintext) => plaintext.ToArray();

        public byte[] Decrypt(byte[] key, byte[] ciphertext) => ciphertext;

        public byte[] Authenticate(byte[] key, ReadOnlySpan<byte> message) => new byte[16];

        public byte[] ValidateToken(byte[] token) => token;
    }
}
