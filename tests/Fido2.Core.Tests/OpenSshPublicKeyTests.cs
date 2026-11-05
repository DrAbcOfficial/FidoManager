using System.Text;
using Fido2.Core.Credentials;

namespace Fido2.Core.Tests;

/// <summary>
/// Golden vectors for the OpenSSH FIDO public key format. Both expected lines were checked
/// with <c>ssh-keygen -lf</c>, which reports them as (ED25519-SK) / (ECDSA-SK) and prints
/// the fingerprints asserted below — so these tests pin the exact wire format OpenSSH
/// accepts, not just this implementation's own output.
/// </summary>
public class OpenSshPublicKeyTests
{
    // Ed25519 public key 0x01..0x20.
    private const string Ed25519Line =
        "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gAAAABHNzaDo= alice@ssh";
    private const string Ed25519Fingerprint = "SHA256:nX0hpi5mKbTIJ10yBq5/sLQhiI1Y0RBAqN0drDdgJWs";

    // P-256 key generated with ssh-keygen -t ecdsa -b 256; coordinates below are its X/Y.
    private const string P256X = "dbf035ebb55020dd2c5ea1bb2be1aca6180dc20d2615f54d184423b79cb7a56c";
    private const string P256Y = "e4ee79e4c0d22355a8eca4d385b754bf5618fc862e97321a360a8113411fb1a9";
    private const string EcdsaLine =
        "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBNvwNeu1UCDdLF6huyvhrKYYDcINJhX1TRhEI7ect6Vs5O555MDSI1Wo7KTThbdUv1YY/IYulzIaNgqBE0EfsakAAAAEc3NoOg== alice@ssh";
    private const string EcdsaFingerprint = "SHA256:IhI0GhSm89CAuPrbkHd46SlqxpWdPq+A08TR9OZi9/w";

    private static CosePublicKey Ed25519Key() =>
        CosePublicKey.FromCbor(new Dictionary<object, object?>
        {
            [1] = 1L,   // kty: OKP
            [3] = -8L,  // alg: EdDSA
            [-1] = 6L,  // crv: Ed25519
            [-2] = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray(),
        })!;

    private static CosePublicKey P256Key() =>
        CosePublicKey.FromCbor(new Dictionary<object, object?>
        {
            [1] = 2L,   // kty: EC2
            [3] = -7L,  // alg: ES256
            [-1] = 1L,  // crv: P-256
            [-2] = Convert.FromHexString(P256X),
            [-3] = Convert.FromHexString(P256Y),
        })!;

    [Fact]
    public void Ed25519_RendersExactlyTheOpenSshSkLine()
    {
        Assert.True(OpenSshPublicKey.TryFormat(Ed25519Key(), "alice@ssh", out string line));
        Assert.Equal(Ed25519Line, line);
    }

    [Fact]
    public void P256_RendersExactlyTheOpenSshSkLine()
    {
        Assert.True(OpenSshPublicKey.TryFormat(P256Key(), "alice@ssh", out string line));
        Assert.Equal(EcdsaLine, line);
    }

    [Fact]
    public void FingerprintsMatchSshKeygen()
    {
        Assert.True(OpenSshPublicKey.TryGetFingerprint(Ed25519Key(), out string ed25519));
        Assert.Equal(Ed25519Fingerprint, ed25519);

        Assert.True(OpenSshPublicKey.TryGetFingerprint(P256Key(), out string p256));
        Assert.Equal(EcdsaFingerprint, p256);
    }

    [Fact]
    public void BlobIsStructuredAsTypeKeyApplication()
    {
        Assert.True(OpenSshPublicKey.TryCreateBlob(Ed25519Key(), out byte[] blob));
        var reader = new SshStringReader(blob);
        Assert.Equal(OpenSshPublicKey.Ed25519KeyType, reader.ReadText());
        Assert.Equal(32, reader.ReadBytes().Length);
        Assert.Equal(OpenSshPublicKey.SshApplication, reader.ReadText());
        Assert.True(reader.AtEnd);
    }

    [Fact]
    public void P256BlobCarriesCurveNameAndUncompressedPoint()
    {
        Assert.True(OpenSshPublicKey.TryCreateBlob(P256Key(), out byte[] blob));
        var reader = new SshStringReader(blob);
        Assert.Equal(OpenSshPublicKey.EcdsaP256KeyType, reader.ReadText());
        Assert.Equal(OpenSshPublicKey.P256CurveName, reader.ReadText());
        byte[] point = reader.ReadBytes();
        Assert.Equal(65, point.Length);
        Assert.Equal(0x04, point[0]);
        Assert.Equal(OpenSshPublicKey.SshApplication, reader.ReadText());
        Assert.True(reader.AtEnd);
    }

    [Fact]
    public void UnsupportedKeyShapesAreRefused()
    {
        // EC2 P-384: valid COSE, but neither an SSH sk key nor something we can export.
        CosePublicKey? p384 = CosePublicKey.FromCbor(new Dictionary<object, object?>
        {
            [1] = 2L,
            [3] = -35L, // ES384
            [-1] = 2L,  // P-384
            [-2] = Enumerable.Repeat((byte)0x11, 48).ToArray(),
            [-3] = Enumerable.Repeat((byte)0x22, 48).ToArray(),
        });
        Assert.NotNull(p384);
        Assert.False(p384!.SupportsOpenSsh);
        Assert.Equal("COSE kty 2 crv 2 alg -35", p384.AlgorithmName);
        Assert.False(OpenSshPublicKey.TryFormat(p384, null, out _));
        Assert.False(OpenSshPublicKey.TryGetFingerprint(p384, out _));
        Assert.Null(OpenSshPublicKey.GetKeyType(p384));
    }

    [Fact]
    public void MissingCommentLeavesNoTrailingSpace()
    {
        Assert.True(OpenSshPublicKey.TryFormat(Ed25519Key(), null, out string line));
        Assert.Equal(Ed25519Line[..Ed25519Line.LastIndexOf(' ')], line);

        Assert.True(OpenSshPublicKey.TryFormat(Ed25519Key(), "   ", out string blank));
        Assert.Equal(line, blank);
    }

    [Theory]
    [InlineData("ssh:", "alice", "alice@ssh")]
    [InlineData("example.com", null, "fido2@example.com")]
    [InlineData("ssh:", "ali ce", "ali-ce@ssh")]
    [InlineData("ssh:", "a\"b\tc", "ab-c@ssh")]
    [InlineData("ssh:", null, "fido2@ssh")]
    public void SuggestedCommentIsASafeSingleLine(string rpId, string? userName, string expected) =>
        Assert.Equal(expected, OpenSshPublicKey.SuggestComment(rpId, userName));

    [Fact]
    public void CredentialOverloadUsesTheSuggestedComment()
    {
        var credential = new Ctap2.ResidentCredential("ssh:", "alice", null, null, "00") { PublicKey = Ed25519Key() };
        Assert.True(OpenSshPublicKey.TryFormat(credential, out string line));
        Assert.Equal(Ed25519Line, line);
        Assert.True(credential.HasSshPublicKey);
    }

    [Fact]
    public void CredentialWithoutPublicKeyCannotBeExported()
    {
        var credential = new Ctap2.ResidentCredential("ssh:", "alice", null, null, "00");
        Assert.False(credential.HasSshPublicKey);
        Assert.False(OpenSshPublicKey.TryFormat(credential, out _));
    }

    /// <summary>Minimal SSH string reader — decodes the same 4-byte length prefix format.</summary>
    private sealed class SshStringReader(byte[] data)
    {
        private int _offset;

        public bool AtEnd => _offset == data.Length;

        public byte[] ReadBytes()
        {
            uint length = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(_offset, 4));
            _offset += 4;
            byte[] value = data.AsSpan(_offset, (int)length).ToArray();
            _offset += (int)length;
            return value;
        }

        public string ReadText() => Encoding.ASCII.GetString(ReadBytes());
    }
}
