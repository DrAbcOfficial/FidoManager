using System.Buffers.Binary;

namespace Fido2.Core.Cbor;

/// <summary>
/// Minimal RFC 8949 CBOR encoder for CTAP2 requests.
/// Only the subset CTAP uses is emitted: unsigned/negative integers, byte and text
/// strings, arrays, maps and simple values (true/false/null).
/// </summary>
public sealed class CborWriter
{
    private readonly List<byte> _buffer = [];

    public byte[] ToArray() => [.. _buffer];

    public void WriteUIntValue(ulong value) => WriteHead(0, value);

    public void WriteIntValue(long value)
    {
        if (value >= 0)
        {
            WriteHead(0, (ulong)value);
        }
        else
        {
            WriteHead(1, (ulong)(-1 - value));
        }
    }

    public void WriteByteString(ReadOnlySpan<byte> data)
    {
        WriteHead(2, (ulong)data.Length);
        _buffer.AddRange(data);
    }

    public void WriteTextString(string value)
    {
        var utf8 = System.Text.Encoding.UTF8.GetBytes(value);
        WriteHead(3, (ulong)utf8.Length);
        _buffer.AddRange(utf8);
    }

    public void WriteArrayHeader(int count) => WriteHead(4, (ulong)count);

    public void WriteMapHeader(int count) => WriteHead(5, (ulong)count);

    public void WriteBool(bool value) => WriteHead(7, value ? 21ul : 20ul);

    public void WriteNull() => WriteHead(7, 22);

    private void WriteHead(byte majorType, ulong argument)
    {
        byte type = (byte)(majorType << 5);
        switch (argument)
        {
            case < 24:
                _buffer.Add((byte)(type | argument));
                break;
            case <= 0xFF:
                _buffer.Add((byte)(type | 24));
                _buffer.Add((byte)argument);
                break;
            case <= 0xFFFF:
                _buffer.Add((byte)(type | 25));
                AppendBigEndian((ushort)argument);
                break;
            case <= 0xFFFFFFFF:
                _buffer.Add((byte)(type | 26));
                AppendBigEndian((uint)argument);
                break;
            default:
                _buffer.Add((byte)(type | 27));
                Span<byte> scratch = stackalloc byte[8];
                BinaryPrimitives.WriteUInt64BigEndian(scratch, argument);
                _buffer.AddRange(scratch);
                break;
        }
    }

    private void AppendBigEndian(ushort value)
    {
        Span<byte> scratch = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(scratch, value);
        _buffer.AddRange(scratch);
    }

    private void AppendBigEndian(uint value)
    {
        Span<byte> scratch = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(scratch, value);
        _buffer.AddRange(scratch);
    }
}
