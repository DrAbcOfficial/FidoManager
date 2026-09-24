namespace Fido2.Core.Cbor;

/// <summary>
/// Ordered CBOR map builder for CTAP2 request parameters.
/// CTAP parameter maps use integer keys; user/credential entities use text keys.
/// Insertion order is preserved so golden-vector tests are reproducible.
/// </summary>
public sealed class CborMap : IEnumerable<KeyValuePair<object, object?>>
{
    private readonly List<KeyValuePair<object, object?>> _entries = [];

    public int Count => _entries.Count;

    public IEnumerator<KeyValuePair<object, object?>> GetEnumerator() => _entries.GetEnumerator();

    System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => _entries.GetEnumerator();

    public CborMap Add(object key, object? value)
    {
        _entries.Add(new KeyValuePair<object, object?>(key, value));
        return this;
    }

    public CborMap AddIfNotNull(object key, object? value)
    {
        if (value is not null)
        {
            Add(key, value);
        }
        return this;
    }

    public byte[] Encode()
    {
        var writer = new CborWriter();
        writer.WriteMapHeader(_entries.Count);
        foreach (var (key, value) in _entries)
        {
            WriteValue(writer, key);
            WriteValue(writer, value);
        }
        return writer.ToArray();
    }

    internal static void WriteValue(CborWriter writer, object? value)
    {
        switch (value)
        {
            case null:
                writer.WriteNull();
                break;
            case bool b:
                writer.WriteBool(b);
                break;
            case int i:
                writer.WriteIntValue(i);
                break;
            case uint u:
                writer.WriteUIntValue(u);
                break;
            case long l:
                writer.WriteIntValue(l);
                break;
            case ulong ul:
                writer.WriteUIntValue(ul);
                break;
            case byte[] bytes:
                writer.WriteByteString(bytes);
                break;
            case ReadOnlyMemory<byte> memory:
                writer.WriteByteString(memory.Span);
                break;
            case string text:
                writer.WriteTextString(text);
                break;
            case CborMap map:
                map.WriteInto(writer);
                break;
            case IEnumerable<object?> items:
                writer.WriteArrayHeader(items.Count());
                foreach (var item in items)
                {
                    WriteValue(writer, item);
                }
                break;
            default:
                throw new NotSupportedException($"Unsupported CBOR value type: {value.GetType().Name}");
        }
    }

    private void WriteInto(CborWriter writer)
    {
        writer.WriteMapHeader(_entries.Count);
        foreach (var (key, value) in _entries)
        {
            WriteValue(writer, key);
            WriteValue(writer, value);
        }
    }
}
