using Fido2.Core.Cbor;

namespace Fido2.Core.Pin;

/// <summary>PIN/UV auth protocol (v1 or v2) — the four primitives CTAP2 §6.5.6 defines.</summary>
public interface IPinUvAuthProtocol
{
    int Version { get; }

    /// <summary>Generates a fresh platform key pair, performs ECDH against the authenticator's
    /// keyAgreement COSE key and returns (sharedSecret, platformCoseKey).</summary>
    byte[] GenerateSharedSecret(IReadOnlyDictionary<object, object?> authenticatorCoseKey, out CborMap platformCoseKey);

    byte[] Encrypt(byte[] key, ReadOnlySpan<byte> plaintext);

    byte[] Decrypt(byte[] key, byte[] ciphertext);

    /// <summary>pinUvAuthParam = MAC(key, message).</summary>
    byte[] Authenticate(byte[] key, ReadOnlySpan<byte> message);

    /// <summary>Validates the decrypted pinUvAuthToken length (v1: 16/32, v2: 32).</summary>
    byte[] ValidateToken(byte[] token);
}
