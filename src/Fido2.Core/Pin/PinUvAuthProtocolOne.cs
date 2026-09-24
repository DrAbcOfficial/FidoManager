using System.Security.Cryptography;
using Fido2.Core.Cbor;

namespace Fido2.Core.Pin;

/// <summary>PIN/UV auth protocol v1 (CTAP 2.3 §6.5.6.4): kdf(Z) = SHA-256(Z),
/// AES-256-CBC with an all-zero IV and no padding, MAC = left16(HMAC-SHA-256).</summary>
public sealed class PinUvAuthProtocolOne : IPinUvAuthProtocol
{
    public static readonly PinUvAuthProtocolOne Instance = new();

    public int Version => 1;

    private static readonly byte[] ZeroIv = new byte[16];

    public byte[] GenerateSharedSecret(IReadOnlyDictionary<object, object?> authenticatorCoseKey, out CborMap platformCoseKey)
    {
        byte[] x = CborMapExtensions.ToCoordinate32(
            authenticatorCoseKey.GetBytes(-2) ?? throw new FormatException("keyAgreement missing x"));
        byte[] y = CborMapExtensions.ToCoordinate32(
            authenticatorCoseKey.GetBytes(-3) ?? throw new FormatException("keyAgreement missing y"));

        using var clientKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        ECPoint q = clientKey.ExportParameters(false).Q;
        platformCoseKey = CborMapExtensions.BuildP256CoseKey(q.X, q.Y);

        using var peerKey = ECDiffieHellman.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = x, Y = y },
        });
        // HASH(Z) with no prefix/append is exactly v1's kdf.
        return clientKey.DeriveKeyFromHash(peerKey.PublicKey, HashAlgorithmName.SHA256);
    }

    public byte[] Encrypt(byte[] key, ReadOnlySpan<byte> plaintext)
    {
        using Aes aes = Aes.Create();
        aes.Key = key;
        return aes.EncryptCbc(plaintext, ZeroIv, PaddingMode.None);
    }

    public byte[] Decrypt(byte[] key, byte[] ciphertext)
    {
        if (ciphertext.Length % 16 != 0)
        {
            throw new CryptographicException("Ciphertext length must be a multiple of the AES block length.");
        }
        using Aes aes = Aes.Create();
        aes.Key = key;
        return aes.DecryptCbc(ciphertext, ZeroIv, PaddingMode.None);
    }

    public byte[] Authenticate(byte[] key, ReadOnlySpan<byte> message)
    {
        Span<byte> mac = stackalloc byte[32];
        HMACSHA256.HashData(key, message, mac);
        return mac[..16].ToArray();
    }

    public byte[] ValidateToken(byte[] token)
    {
        if (token.Length is not (16 or 32))
        {
            throw new FormatException($"pinUvAuthToken decrypted to {token.Length} bytes (spec allows 16 or 32) — bad shared secret.");
        }
        return token;
    }
}
