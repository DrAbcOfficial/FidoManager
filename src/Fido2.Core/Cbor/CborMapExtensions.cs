using System.Buffers.Binary;

namespace Fido2.Core.Cbor;

/// <summary>
/// Typed accessors over the decoded CBOR tree. CTAP response map keys are integers
/// (documented per command), nested user/credential entities use text keys.
/// </summary>
public static class CborMapExtensions
{
    public static long? GetInt(this IReadOnlyDictionary<object, object?> map, object key)
        => map.TryGetValue(key, out var value) && value is long i ? i : null;

    public static byte[]? GetBytes(this IReadOnlyDictionary<object, object?> map, object key)
        => map.TryGetValue(key, out var value) && value is byte[] b ? b : null;

    public static string? GetText(this IReadOnlyDictionary<object, object?> map, object key)
        => map.TryGetValue(key, out var value) && value is string s ? s : null;

    public static bool? GetBool(this IReadOnlyDictionary<object, object?> map, object key)
        => map.TryGetValue(key, out var value) && value is bool b ? b : null;

    public static IReadOnlyDictionary<object, object?>? GetMap(this IReadOnlyDictionary<object, object?> map, object key)
        => map.TryGetValue(key, out var value) && value is Dictionary<object, object?> m ? m : null;

    public static IReadOnlyList<object?>? GetArray(this IReadOnlyDictionary<object, object?> map, object key)
        => map.TryGetValue(key, out var value) && value is List<object?> a ? a : null;

    public static string? GetText(this IReadOnlyList<object?> array, int index)
        => index < array.Count && array[index] is string s ? s : null;

    public static IReadOnlyDictionary<object, object?>? GetMap(this IReadOnlyList<object?> array, int index)
        => index < array.Count && array[index] is Dictionary<object, object?> m ? m : null;

    /// <summary>Builds a COSE_Key (EC2 / P-256) map from raw X/Y coordinates.</summary>
    public static CborMap BuildP256CoseKey(ReadOnlySpan<byte> x, ReadOnlySpan<byte> y)
    {
        return new CborMap()
            .Add(1, 2)      // kty: EC2
            .Add(3, -25)    // alg: ECDH-ES-HKDF-256 (per spec, "NOT the algorithm actually used")
            .Add(-1, 1)     // crv: P-256
            .Add(-2, x.ToArray())
            .Add(-3, y.ToArray());
    }

    /// <summary>Extracts raw X (index 1) and Y (index 2) coordinates from a compressed BCRYPT ECKey blob.</summary>
    public static (byte[] X, byte[] Y) FromEcKeyBlob(ReadOnlySpan<byte> blob)
    {
        // BCRYPT_ECCKEY_BLOB: magic(4) + cbKey(4) + X(cbKey) + Y(cbKey).
        if (blob.Length < 8 || BinaryPrimitives.ReadInt32LittleEndian(blob) != unchecked((int)0x314B4345))
        {
            throw new FormatException("Unexpected EC key blob magic (want BCRYPT_ECDH_PUBLIC_P256).");
        }
        int keySize = BinaryPrimitives.ReadInt32LittleEndian(blob.Slice(4));
        return (blob.Slice(8, keySize).ToArray(), blob.Slice(8 + keySize, keySize).ToArray());
    }

    /// <summary>Serializes an ECDH P-256 public key into the CNG public blob layout.</summary>
    public static byte[] ToEcKeyBlob(byte[] x, byte[] y)
    {
        var blob = new byte[8 + x.Length + y.Length];
        BinaryPrimitives.WriteInt32LittleEndian(blob, unchecked((int)0x314B4345)); // "ECK1"
        BinaryPrimitives.WriteInt32LittleEndian(blob.AsSpan(4), x.Length);
        x.CopyTo(blob, 8);
        y.CopyTo(blob, 8 + x.Length);
        return blob;
    }

    /// <summary>
    /// Normalizes a COSE EC2 coordinate to exactly 32 bytes (P-256 field width). Devices
    /// occasionally strip leading zeros (short integer encoding) or over-pad; CNG rejects
    /// both with "parameter invalid" on import. Left-pads after trimming excess zeros.
    /// </summary>
    public static byte[] ToCoordinate32(ReadOnlySpan<byte> coordinate)
    {
        int start = 0;
        while (start < coordinate.Length - 1 && coordinate[start] == 0)
        {
            start++;
        }
        int length = coordinate.Length - start;
        if (length > 32)
        {
            throw new FormatException("COSE EC2 coordinate exceeds the P-256 field width.");
        }
        var normalized = new byte[32];
        coordinate.Slice(start, length).CopyTo(normalized.AsSpan(32 - length));
        return normalized;
    }
}
