using Fido2.Core.Credentials;

namespace Fido2.Core.Tests;

public class CosePublicKeyTests
{
    [Fact]
    public void ShortCoordinatesAreLeftPaddedToTheP256Width()
    {
        byte[] x = [1, 2, 3];
        CosePublicKey? key = CosePublicKey.FromCbor(new Dictionary<object, object?>
        {
            [1] = 2L,
            [3] = -7L,
            [-1] = 1L,
            [-2] = x,
            [-3] = new byte[32],
        });

        Assert.NotNull(key);
        Assert.Equal(32, key.X.Length);
        Assert.Equal(x, key.X[^3..]);
        Assert.True(key.IsP256);
    }

    [Fact]
    public void Ed25519KeysWithLeadingZeroBytesArePreserved()
    {
        byte[] x = [0x00, .. Enumerable.Repeat((byte)0xAA, 31)];
        CosePublicKey? key = CosePublicKey.FromCbor(new Dictionary<object, object?>
        {
            [1] = 1L,
            [3] = -8L,
            [-1] = 6L,
            [-2] = x,
        });

        Assert.NotNull(key);
        Assert.Equal(x, key.X);
        Assert.True(key.IsEd25519);
        Assert.Equal("Ed25519", key.AlgorithmName);
    }

    [Fact]
    public void MissingOrIncompleteMapsYieldNull()
    {
        Assert.Null(CosePublicKey.FromCbor(null));
        Assert.Null(CosePublicKey.FromCbor(new Dictionary<object, object?> { [1] = 2L }));

        // x missing
        Assert.Null(CosePublicKey.FromCbor(new Dictionary<object, object?>
        {
            [1] = 2L,
            [3] = -7L,
            [-1] = 1L,
            [-3] = new byte[32],
        }));
    }

    [Fact]
    public void OversizedCoordinatesAreRejected()
    {
        Assert.Null(CosePublicKey.FromCbor(new Dictionary<object, object?>
        {
            [1] = 2L,
            [3] = -7L,
            [-1] = 1L,
            [-2] = Enumerable.Repeat((byte)0x01, 33).ToArray(),
            [-3] = new byte[32],
        }));
    }

    [Fact]
    public void AlgorithmNameDescribesUnknownShapes()
    {
        // kty = 3 (RSA), no curve: parseable but not exportable.
        CosePublicKey? rsa = CosePublicKey.FromCbor(new Dictionary<object, object?>
        {
            [1] = 3L,
            [3] = -257L,
            [-2] = new byte[32],
        });

        Assert.NotNull(rsa);
        Assert.False(rsa.SupportsOpenSsh);
        Assert.Contains("kty 3", rsa.AlgorithmName);
    }
}
