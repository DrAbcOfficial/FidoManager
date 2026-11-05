using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Fido2.Core.Ctap2;

namespace Fido2.Core.Credentials;

/// <summary>
/// Renders a discoverable credential's public key as an OpenSSH FIDO public key
/// (OpenSSH PROTOCOL.u2f, ssh-keygen 8.2+). The wire blob is
/// <c>string keyType || key material || string application</c> where the application is the
/// RP id the credential was created under — SSH always uses <c>"ssh:"</c>.
/// <list type="bullet">
///   <item>Ed25519 → <c>sk-ssh-ed25519@openssh.com</c> + the 32-byte point</item>
///   <item>P-256 → <c>sk-ecdsa-sha2-nistp256@openssh.com</c> + <c>"nistp256"</c> + the
///     uncompressed point (0x04 || X || Y)</item>
/// </list>
/// The rendered line is exactly what <c>ssh-keygen -t ed25519-sk -f …</c> writes to the
/// .pub file, so it can be appended to authorized_keys as-is.
/// </summary>
public static class OpenSshPublicKey
{
    public const string Ed25519KeyType = "sk-ssh-ed25519@openssh.com";
    public const string EcdsaP256KeyType = "sk-ecdsa-sha2-nistp256@openssh.com";
    public const string P256CurveName = "nistp256";

    /// <summary>The FIDO application (RP id) OpenSSH authenticates against.</summary>
    public const string SshApplication = "ssh:";

    /// <summary>The OpenSSH key type for a COSE key, or null when it cannot be exported.</summary>
    public static string? GetKeyType(CosePublicKey? key) =>
        key is null ? null
        : key.IsEd25519 ? Ed25519KeyType
        : key.IsP256 ? EcdsaP256KeyType
        : null;

    /// <summary>
    /// Builds the SSH wire blob (the part that is base64-encoded in a .pub file). This is
    /// also what OpenSSH hashes for the key fingerprint.
    /// </summary>
    public static bool TryCreateBlob(CosePublicKey? key, out byte[] blob)
    {
        blob = [];
        if (key is null)
        {
            return false;
        }

        using var buffer = new MemoryStream(96);
        if (key.IsEd25519)
        {
            WriteString(buffer, Encoding.ASCII.GetBytes(Ed25519KeyType));
            WriteString(buffer, key.X);
        }
        else if (key.IsP256)
        {
            WriteString(buffer, Encoding.ASCII.GetBytes(EcdsaP256KeyType));
            WriteString(buffer, Encoding.ASCII.GetBytes(P256CurveName));
            Span<byte> point = stackalloc byte[65];
            point[0] = 0x04; // uncompressed
            key.X.CopyTo(point[1..]);
            key.Y!.CopyTo(point[33..]);
            WriteString(buffer, point);
        }
        else
        {
            return false;
        }

        WriteString(buffer, Encoding.ASCII.GetBytes(SshApplication));
        blob = buffer.ToArray();
        return true;
    }

    /// <summary>
    /// Formats a full <c>.pub</c> line: <c>keyType base64(blob) [comment]</c>. The comment is
    /// optional and, like ssh-keygen's <c>-C</c>, never part of the key.
    /// </summary>
    public static bool TryFormat(CosePublicKey? key, string? comment, out string text)
    {
        text = "";
        if (!TryCreateBlob(key, out byte[] blob))
        {
            return false;
        }

        string line = $"{GetKeyType(key)} {Convert.ToBase64String(blob)}";
        if (!string.IsNullOrWhiteSpace(comment))
        {
            line += " " + comment.Trim();
        }
        text = line;
        return true;
    }

    /// <summary>Formats the credential with an automatic <c>user@rp</c>-style comment.</summary>
    public static bool TryFormat(ResidentCredential credential, out string text) =>
        TryFormat(credential.PublicKey, SuggestComment(credential.RpId, credential.BestUserName), out text);

    /// <summary>OpenSSH SHA-256 fingerprint of the key blob (<c>SHA256:…</c>, no padding).</summary>
    public static bool TryGetFingerprint(CosePublicKey? key, out string fingerprint)
    {
        fingerprint = "";
        if (!TryCreateBlob(key, out byte[] blob))
        {
            return false;
        }
        fingerprint = "SHA256:" + Convert.ToBase64String(SHA256.HashData(blob)).TrimEnd('=');
        return true;
    }

    /// <summary>
    /// Default comment for an exported credential: <c>user@rp</c>, stripped of characters
    /// that would break the single-line .pub format.
    /// </summary>
    public static string SuggestComment(string rpId, string? userName)
    {
        string user = Sanitize(userName) ?? "fido2";
        string rp = Sanitize(rpId.TrimEnd(':', '/')) ?? "key";
        return $"{user}@{rp}";
    }

    private static string? Sanitize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var builder = new StringBuilder(value.Length);
        foreach (char ch in value)
        {
            if (ch is >= '!' and <= '~' && ch is not ('"' or '\\'))
            {
                builder.Append(ch);
            }
            else if (char.IsWhiteSpace(ch))
            {
                builder.Append('-');
            }
        }
        return builder.Length == 0 ? null : builder.ToString();
    }

    private static void WriteString(Stream stream, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, (uint)value.Length);
        stream.Write(length);
        stream.Write(value);
    }
}
