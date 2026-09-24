using System.Text;

namespace Fido2.Core.Cbor;

/// <summary>
/// Decodes CBOR into a plain object tree. CTAP responses only need:
/// <list type="bullet">
///   <item>integers → <see cref="long"/></item>
///   <item>byte strings → <c>byte[]</c></item>
///   <item>text strings → <see cref="string"/></item>
///   <item>arrays → <see cref="List{T}"/> of object?</item>
///   <item>maps → <see cref="Dictionary{TKey,TValue}"/> (int or text keys)</item>
///   <item>simple values → <see cref="bool"/> / null</item>
/// </list>
/// Every multi-byte integer is assembled from widened ints — see the CTAP trap notes
/// (§4.1 of the design doc): narrowing shifts silently truncate 16-bit values.
/// </summary>
public static class CborDecoder
{
    public static object? Decode(ReadOnlyMemory<byte> data)
    {
        var reader = new Reader(data);
        var value = reader.ReadValue();
        return value;
    }

    private sealed class Reader(ReadOnlyMemory<byte> data)
    {
        private int _position;

        public object? ReadValue()
        {
            byte head = ReadByte();
            byte major = (byte)(head >> 5);
            byte info = (byte)(head & 0x1F);

            long argument = info < 24
                ? info
                : info switch
                {
                    24 => ReadByte(),
                    25 => ReadUInt16(),
                    26 => ReadUInt32(),
                    27 => unchecked((long)ReadUInt64()),
                    _ => throw new FormatException($"Invalid CBOR additional info {info}"),
                };

            return major switch
            {
                0 => argument,                       // unsigned int
                1 => -1 - argument,                  // negative int
                2 => ReadBytes((int)argument),       // byte string
                3 => ReadTextString((int)argument),  // text string
                4 => ReadArray((int)argument),
                5 => ReadMap((int)argument),
                7 => info switch
                {
                    20 => false,
                    21 => true,
                    22 => null,
                    _ => argument,                    // other simple values / floats unused by CTAP
                },
                _ => throw new FormatException($"Unsupported CBOR major type {major}"),
            };
        }

        /// <summary>
        /// Decodes a text string. Interior NULs are passed through as-is: CBOR permits
        /// them, and earlier "stray NUL" firmware quirks were traced to a CTAPHID
        /// continuation-packet reassembly bug on the host, not to the device.
        /// </summary>
        private string ReadTextString(int length)
        {
            return System.Text.Encoding.UTF8.GetString(ReadBytes(length));
        }

        private byte ReadByte()
        {
            EnsureLength(1);
            return data.Span[_position++];
        }

        private ushort ReadUInt16()
        {
            EnsureLength(2);
            ushort value = (ushort)((uint)data.Span[_position] << 8 | data.Span[_position + 1]);
            _position += 2;
            return value;
        }

        private uint ReadUInt32()
        {
            // Widen every byte before shifting (see class doc).
            uint value = (uint)data.Span[_position] << 24
                | (uint)data.Span[_position + 1] << 16
                | (uint)data.Span[_position + 2] << 8
                | data.Span[_position + 3];
            _position += 4;
            return value;
        }

        private ulong ReadUInt64()
        {
            ulong value = 0;
            for (int i = 0; i < 8; i++)
            {
                value = (value << 8) | data.Span[_position + i];
            }
            _position += 8;
            return value;
        }

        private byte[] ReadBytes(int length)
        {
            EnsureLength(length);
            var bytes = data.Span.Slice(_position, length).ToArray();
            _position += length;
            return bytes;
        }

        private List<object?> ReadArray(int count)
        {
            var items = new List<object?>(count);
            for (int i = 0; i < count; i++)
            {
                items.Add(ReadValue());
            }
            return items;
        }

        private Dictionary<object, object?> ReadMap(int count)
        {
            var map = new Dictionary<object, object?>(count);
            for (int i = 0; i < count; i++)
            {
                object key = ReadValue() ?? throw new FormatException("CBOR map key must not be null");
                // Normalize integer keys to int: decoders emit long, and lookups with
                // boxed int literals would otherwise silently miss (int 1 != long 1).
                if (key is long l and >= int.MinValue and <= int.MaxValue)
                {
                    key = (int)l;
                }
                map[key] = ReadValue();
            }
            return map;
        }

        private void EnsureLength(int required)
        {
            if (_position + required > data.Length)
            {
                throw new FormatException("Truncated CBOR payload");
            }
        }
    }
}
