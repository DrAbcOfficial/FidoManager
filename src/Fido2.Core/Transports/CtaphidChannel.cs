using System.IO;
using System.Runtime.InteropServices;
using Fido2.Core.Ctap2;
using Fido2.Core.Transports.Interop;

namespace Fido2.Core.Transports;

/// <summary>
/// CTAPHID protocol over an opened USB-HID interface (design doc §3.3, §11.3):
/// INIT handshake with nonce verification, request fragmentation (init 57-byte style
/// sizing derived from the actual report size), keepalive de-duplication, host-side
/// cancellation via CTAPHID_CANCEL, and CTAP1_CHANNEL_BUSY retry.
/// All blocking I/O stays synchronous here; callers wrap calls in Task.Run.
/// </summary>
public sealed class CtaphidChannel : IDisposable
{
    private const byte TypeInit = 0x80;
    private const byte CmdPing = 0x01;
    private const byte CmdInit = 0x06;
    private const byte CmdCbor = 0x10;
    private const byte CmdCancel = 0x11;
    private const byte CmdKeepalive = 0x3B;
    private const byte CmdError = 0x3F;

    private const uint BroadcastChannelId = 0xFFFFFFFF;
    private const byte CapabilityCbor = 0x04;

    private readonly FileStream _stream;
    private uint _channelId;
    private readonly int _reportSizeIn;
    private readonly int _reportSizeOut;
    private KeepaliveStatus? _lastKeepaliveStatus;

    private CtaphidChannel(FileStream stream, uint channelId, int reportSizeIn, int reportSizeOut)
    {
        _stream = stream;
        _channelId = channelId;
        _reportSizeIn = reportSizeIn;
        _reportSizeOut = reportSizeOut;
    }

    public static CtaphidChannel Open(HidDescriptor descriptor)
    {
        // Read/write is only requested for the one device we actually talk to;
        // denial (0x5) means the process is not elevated.
        var handle = Kernel32Native.CreateFile(
            descriptor.DevicePath,
            Kernel32Native.GenericRead | Kernel32Native.GenericWrite,
            Kernel32Native.FileShareRead | Kernel32Native.FileShareWrite,
            IntPtr.Zero, Kernel32Native.OpenExisting, 0, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            throw new TransportException(error == 5
                ? $"HID open denied for '{descriptor.DisplayName}' — run the app as Administrator."
                : $"HID open failed (0x{error:X}) for '{descriptor.DisplayName}'.");
        }

        var stream = new FileStream(handle, FileAccess.ReadWrite, descriptor.ReportSizeOut + 1, isAsync: false);
        try
        {
            var channel = new CtaphidChannel(stream, BroadcastChannelId, descriptor.ReportSizeIn, descriptor.ReportSizeOut);
            channel.Initialize(descriptor);
            return channel;
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    private void Initialize(HidDescriptor descriptor)
    {
        Span<byte> nonce = stackalloc byte[8];
        System.Security.Cryptography.RandomNumberGenerator.Fill(nonce);

        // CTAPHID_INIT on the broadcast channel: CID | TYPE_INIT|INIT | BCNT(2) | nonce.
        Span<byte> packet = stackalloc byte[_reportSizeOut];
        packet.Clear();
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(packet, BroadcastChannelId);
        packet[4] = (byte)(CmdInit | TypeInit);
        packet[5] = 0;
        packet[6] = 8;
        nonce.CopyTo(packet.Slice(7));
        WritePacket(packet);

        byte[] payload = ReceiveCommand(CmdInit);
        if (payload.Length < 17 || !payload.AsSpan(0, 8).SequenceEqual(nonce))
        {
            throw new TransportException($"CTAPHID_INIT nonce mismatch on '{descriptor.DisplayName}'.");
        }

        _channelId = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(8));
        byte capabilities = payload[16];
        if ((capabilities & CapabilityCbor) == 0)
        {
            throw new TransportException($"'{descriptor.DisplayName}' reports no CBOR capability over HID.");
        }
        _lastKeepaliveStatus = null;
    }

    /// <summary>Sends one fragmented CTAPHID command and assembles the reply payload —
    /// used for the INIT handshake (CBOR-specific handling does not apply there).</summary>
    private byte[] ReceiveCommand(byte expectedCommand)
    {
        var readBuffer = new byte[_reportSizeIn + 1];
        ReadFullReport(readBuffer);

        byte command = (byte)(readBuffer[5] & 0x7F);
        if (command != expectedCommand)
        {
            throw new TransportException(command == CmdError
                ? $"CTAPHID_ERROR 0x{readBuffer[7]:X2} during INIT."
                : $"Unexpected CTAPHID command 0x{command:X2} during INIT.");
        }

        int length = (readBuffer[6] << 8) | readBuffer[7];
        var payload = new List<byte>(length);
        payload.AddRange(readBuffer.AsSpan(8, 8 + Math.Min(_reportSizeIn - 7, length)).ToArray());

        byte sequence = 0;
        while (payload.Count < length)
        {
            ReadFullReport(readBuffer);
            if ((readBuffer[5] & 0x7F) != (sequence & 0x7F) || (readBuffer[5] & TypeInit) != 0)
            {
                throw new TransportException("CTAPHID sequence mismatch during INIT.");
            }
            sequence++;
            payload.AddRange(readBuffer.AsSpan(5, 5 + Math.Min(_reportSizeIn - 5, length - payload.Count)).ToArray());
        }
        return [.. payload.Take(length)];
    }

    /// <summary>Sends one CTAP2 request (operation byte + CBOR) and returns the response payload.</summary>
    public byte[] Call(byte operation, ReadOnlyMemory<byte> parameters, CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress)
    {
        var request = new byte[1 + parameters.Length];
        request[0] = operation;
        parameters.CopyTo(request.AsMemory(1));
        return Call(request, cancellationToken, progress);
    }

    public byte[] Call(byte[] request, CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress)
    {
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return CallOnce(request, cancellationToken, progress);
            }
            catch (CtapException e) when (e.Status == CtapStatusCode.Ctap1ErrChannelBusy)
            {
                // Another client (browser, Windows Hello) is mid-command on the shared
                // device. Retry until it frees the channel or the user cancels.
                cancellationToken.WaitHandle.WaitOne(100);
                cancellationToken.ThrowIfCancellationRequested();
            }
        }
    }

    private byte[] CallOnce(byte[] request, CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress)
    {
        SendRequest(request);
        _lastKeepaliveStatus = null;

        int expectedLength = 0;
        var response = new List<byte>();
        byte sequence = 0;
        var readBuffer = new byte[_reportSizeIn + 1];
        var cancelSent = false;

        while (true)
        {
            if (cancellationToken.IsCancellationRequested && !cancelSent)
            {
                // The blocking read cannot observe the token; CTAPHID_CANCEL makes the
                // device abort the pending command and answer, unwinding the loop.
                SendCancel();
                cancelSent = true;
            }

            ReadFullReport(readBuffer);
            uint channel = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(readBuffer.AsSpan(1, 4));
            if (channel != _channelId)
            {
                throw new TransportException("CTAPHID reply on a foreign channel.");
            }

            byte commandOrSequence = readBuffer[5];
            if (response.Count == 0 || (commandOrSequence & TypeInit) != 0)
            {
                byte command = (byte)(commandOrSequence & 0x7F);
                if (command == CmdCancel && cancelSent)
                {
                    throw new CtapException(CtapStatusCode.Ctap2ErrKeepaliveCancel);
                }
                if (command == CmdKeepalive)
                {
                    ReportKeepalive(readBuffer[7], progress);
                    continue;
                }                if (command == CmdError)
                {
                    throw new CtapException((CtapStatusCode)readBuffer[7]);
                }
                if (command != CmdCbor)
                {
                    throw new TransportException($"Unexpected CTAPHID command 0x{command:X2} in reply.");
                }

                expectedLength = (readBuffer[6] << 8) | readBuffer[7];
                int initial = Math.Min(_reportSizeIn - 7, expectedLength);
                response.AddRange(readBuffer.AsSpan(8, 8 + initial).ToArray());
            }
            else
            {
                if (commandOrSequence != (sequence & 0x7F))
                {
                    throw new TransportException("CTAPHID sequence mismatch.");
                }
                sequence++;
                int remaining = expectedLength - response.Count;
                response.AddRange(readBuffer.AsSpan(5, 5 + Math.Min(_reportSizeIn - 5, remaining)).ToArray());
            }

            if (response.Count >= expectedLength)
            {
                return [.. response.Take(expectedLength)];
            }
        }
    }

    private void SendRequest(byte[] request)
    {
        if (request.Length > 7609)
        {
            throw new TransportException($"CTAP request too large: {request.Length} bytes.");
        }

        int packetSize = _reportSizeOut;
        Span<byte> packet = stackalloc byte[packetSize];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(packet, _channelId);
        packet[4] = (byte)(CmdCbor | TypeInit);
        packet[5] = (byte)(request.Length >> 8);
        packet[6] = (byte)request.Length;
        int first = Math.Min(request.Length, packetSize - 7);
        request.AsSpan(0, first).CopyTo(packet.Slice(7));
        WritePacket(packet);

        int offset = first;
        byte sequence = 0;
        while (offset < request.Length)
        {
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(packet, _channelId);
            packet[4] = (byte)(sequence & 0x7F);
            int chunk = Math.Min(request.Length - offset, packetSize - 5);
            request.AsSpan(offset, chunk).CopyTo(packet.Slice(5));
            WritePacket(packet);
            offset += chunk;
            sequence++;
        }
    }

    private void SendCancel()
    {
        Span<byte> packet = stackalloc byte[_reportSizeOut];
        packet.Clear();
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(packet, _channelId);
        packet[4] = (byte)(CmdCancel | TypeInit);
        try { WritePacket(packet); }
        catch { /* best effort — the pending read below will surface the outcome */ }
    }

    private void WritePacket(ReadOnlySpan<byte> packet)
    {
        var buffer = new byte[_reportSizeOut + 1];
        packet.CopyTo(buffer.AsSpan(1)); // buffer[0] = report id 0
        _stream.Write(buffer);
        _stream.Flush();
    }

    private void ReadFullReport(byte[] buffer)
    {
        int offset = 0;
        while (offset < buffer.Length)
        {
            int read = _stream.Read(buffer, offset, buffer.Length - offset);
            if (read <= 0)
            {
                throw new TransportException("CTAPHID read failed (device closed the connection).");
            }
            offset += read;
        }
    }

    private void ReportKeepalive(byte statusCode, IProgress<KeepaliveStatus>? progress)
    {
        if (progress is null || statusCode is 0 or > 2)
        {
            return;
        }
        // Only forward transitions; the key repeats the same status ~twice a second.
        var status = (KeepaliveStatus)statusCode;
        if (_lastKeepaliveStatus != status)
        {
            _lastKeepaliveStatus = status;
            progress.Report(status);
        }
    }

    public void Dispose() => _stream.Dispose();
}
