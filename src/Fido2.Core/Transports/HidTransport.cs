namespace Fido2.Core.Transports;

/// <summary><see cref="ITokenTransport"/> over CTAPHID (USB). Blocking channel calls are
/// wrapped for async callers via <see cref="System.Threading.Tasks.Task.Run"/> in the session.</summary>
public sealed class HidTransport : ITokenTransport
{
    private readonly CtaphidChannel _channel;

    public HidDescriptor Descriptor { get; }

    public string DisplayName =>
        string.IsNullOrEmpty(Descriptor.SerialNumber)
            ? Descriptor.DisplayName
            : $"{Descriptor.DisplayName} [{Descriptor.SerialNumber}]";

    private HidTransport(HidDescriptor descriptor, CtaphidChannel channel)
    {
        Descriptor = descriptor;
        _channel = channel;
    }

    public static HidTransport Open(HidDescriptor descriptor) =>
        new(descriptor, CtaphidChannel.Open(descriptor));

    public byte[] Call(ReadOnlyMemory<byte> request, CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress) =>
        _channel.Call(request.ToArray(), cancellationToken, progress);

    public void Dispose() => _channel.Dispose();
}
