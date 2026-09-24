using System.Security.Cryptography;
using Fido2.Core.Cbor;

namespace Fido2.Core.Pin;

/// <summary>
/// PIN/UV auth protocol v2: kdf(Z) = HKDF-SHA256 splits the raw shared point into an
/// HMAC key and an AES key; AES-256-CBC with a random IV prepended to the ciphertext;
/// MAC = full HMAC-SHA-256 with the HMAC key. Requires <see cref="ECDiffieHellman.DeriveRawSecretAgreement"/>
/// (Windows-supported; this is the same capability gate the PS 5.1 reference hit).
/// </summary>
public sealed class PinUvAuthProtocolTwo : IPinUvAuthProtocol
{
    public static readonly PinUvAuthProtocolTwo Instance = new();

    public int Version => 2;

    private const string HmacInfo = "CTAP2 HMAC key";
    private const string AesInfo = "CTAP2 AES key";

    public byte[] GenerateSharedSecret(IReadOnlyDictionary<object, object?> authenticatorCoseKey, out CborMap platformCoseKey)
    {
        byte[] x = authenticatorCoseKey.GetBytes(-2) ?? throw new FormatException("keyAgreement missing x");
        byte[] y = authenticatorCoseKey.GetBytes(-3) ?? throw new FormatException("keyAgreement missing y");

        using var clientKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        ECPoint q = clientKey.ExportParameters(false).Q;
        platformCoseKey = CborMapExtensions.BuildP256CoseKey(q.X, q.Y);

        using var peerKey = ECDiffieHellman.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = x, Y = y },
        });
        byte[] z = clientKey.DeriveRawSecretAgreement(peerKey.PublicKey);

        byte[] hmacKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, z, 32, salt: new byte[32], info: System.Text.Encoding.ASCII.GetBytes(HmacInfo));
        byte[] aesKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, z, 32, salt: new byte[32], info: System.Text.Encoding.ASCII.GetBytes(AesInfo));
        return [.. hmacKey, .. aesKey];
    }

    public byte[] Encrypt(byte[] key, ReadOnlySpan<byte> plaintext)
    {
        byte[] iv = RandomNumberGenerator.GetBytes(16);
        using Aes aes = Aes.Create();
        aes.Key = key.AsSpan(32).ToArray();
        return [.. iv, .. aes.EncryptCbc(plaintext, iv, PaddingMode.None)];
    }

    public byte[] Decrypt(byte[] key, byte[] ciphertext)
    {
        if (ciphertext.Length < 32 || (ciphertext.Length - 16) % 16 != 0)
        {
            throw new CryptographicException("Malformed v2 ciphertext.");
        }
        using Aes aes = Aes.Create();
        aes.Key = key.AsSpan(32).ToArray();
        return aes.DecryptCbc(ciphertext.AsSpan(16), ciphertext.AsSpan(0, 16), PaddingMode.None);
    }

    public byte[] Authenticate(byte[] key, ReadOnlySpan<byte> message)
    {
        return HMACSHA256.HashData(key.AsSpan(0, 32), message);
    }

    public byte[] ValidateToken(byte[] token)
    {
        if (token.Length != 32)
        {
            throw new FormatException($"pinUvAuthToken decrypted to {token.Length} bytes (v2 requires 32) — bad shared secret.");
        }
        return token;
    }
}
