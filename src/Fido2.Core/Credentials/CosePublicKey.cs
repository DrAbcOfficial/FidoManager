using Fido2.Core.Cbor;

namespace Fido2.Core.Credentials;

/// <summary>
/// A credential public key in COSE_Key form (CTAP 2.1 §6.8.2, member 0x08 of
/// enumerateCredentialsBegin). Only the two key shapes a resident credential can carry are
/// modelled — OKP/Ed25519 (EdDSA) and EC2/P-256 (ES256) — because those are the only ones
/// OpenSSH FIDO keys accept as well.
/// </summary>
public sealed class CosePublicKey
{
    private const int KeyTypeOkp = 1;
    private const int KeyTypeEc2 = 2;
    private const int CurveP256 = 1;
    private const int CurveEd25519 = 6;

    private CosePublicKey(int keyType, int algorithm, int? curve, byte[] x, byte[]? y)
    {
        KeyType = keyType;
        Algorithm = algorithm;
        Curve = curve;
        X = x;
        Y = y;
    }

    /// <summary>COSE key type (1 = OKP, 2 = EC2).</summary>
    public int KeyType { get; }

    /// <summary>COSE algorithm (‑7 = ES256, ‑8 = EdDSA).</summary>
    public int Algorithm { get; }

    /// <summary>COSE curve (1 = P-256, 6 = Ed25519); null when the key carries none.</summary>
    public int? Curve { get; }

    /// <summary>Public key material: the Ed25519 point, or the P-256 X coordinate.</summary>
    public byte[] X { get; }

    /// <summary>The P-256 Y coordinate; null for Ed25519.</summary>
    public byte[]? Y { get; }

    public bool IsEd25519 => KeyType == KeyTypeOkp && Curve == CurveEd25519 && X.Length == 32;

    public bool IsP256 => KeyType == KeyTypeEc2 && Curve == CurveP256 && X.Length == 32 && Y is { Length: 32 };

    /// <summary>Whether this key can be rendered as an OpenSSH <c>sk-*</c> public key.</summary>
    public bool SupportsOpenSsh => IsEd25519 || IsP256;

    /// <summary>Short algorithm name for lists and messages.</summary>
    public string AlgorithmName => IsEd25519
        ? "Ed25519"
        : IsP256
            ? "ECDSA P-256"
            : $"COSE kty {KeyType} crv {Curve?.ToString() ?? "-"} alg {Algorithm}";

    /// <summary>
    /// Parses a decoded COSE_Key map. Coordinates are normalized to the 32-byte field width
    /// (some firmware strips leading zeros); null when the map is absent or unusable.
    /// </summary>
    public static CosePublicKey? FromCbor(IReadOnlyDictionary<object, object?>? map)
    {
        if (map is null)
        {
            return null;
        }

        int? keyType = (int?)map.GetInt(1);
        int? algorithm = (int?)map.GetInt(3);
        int? curve = (int?)map.GetInt(-1);
        byte[]? x = map.GetBytes(-2);
        byte[]? y = map.GetBytes(-3);
        if (keyType is null || algorithm is null || x is null)
        {
            return null;
        }

        // Normalize only the shapes this app understands. Unknown curves keep their raw
        // coordinates — they stay inspectable (AlgorithmName) but never become SSH keys.
        bool knownShape = (keyType == KeyTypeOkp && curve == CurveEd25519)
            || (keyType == KeyTypeEc2 && curve == CurveP256);
        if (knownShape)
        {
            try
            {
                x = CborMapExtensions.ToCoordinate32(x);
                if (y is not null)
                {
                    y = CborMapExtensions.ToCoordinate32(y);
                }
            }
            catch (FormatException)
            {
                return null; // wider than P-256/Ed25519 — malformed for this shape
            }
        }

        return new CosePublicKey(keyType.Value, algorithm.Value, curve, x, y);
    }
}
