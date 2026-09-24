using System.Buffers.Binary;
using System.Runtime.InteropServices;
using Fido2.Core.Ctap2;
using Fido2.Core.Transports.Interop;

namespace Fido2.Core.Transports;

/// <summary>
/// CTAP over PC/SC (design doc §3.4, §11.4): FIDO applet SELECT, NFCCTAP_MSG (80 10) with
/// NFCCTAP_GETRESPONSE (80 11) polling while SW=9100, cancel via P1=0x11, short-APDU
/// chaining and T=0 GET RESPONSE continuation. Intended for NFC readers; on USB the CCID
/// interface answers vendor APDUs only, which <see cref="Vendor.Token2VendorApdu"/> uses.
/// </summary>
public sealed class PcscTransport : ITokenTransport
{
    public const string FidoAppletAid = "A0000006472F0001";
    public const string OtpAppletAid = "F00000014F747001";

    private readonly IntPtr _context;
    private readonly IntPtr _card;
    private readonly int _protocol;

    public string ReaderName { get; }

    public string DisplayName => $"NFC  {ReaderName}";

    private PcscTransport(IntPtr context, IntPtr card, int protocol, string readerName)
    {
        _context = context;
        _card = card;
        _protocol = protocol;
        ReaderName = readerName;
    }

    public static string[] ListReaders()
    {
        if (WinscardNative.SCardEstablishContext(WinscardNative.ScopeSystem, IntPtr.Zero, IntPtr.Zero, out var context)
            != WinscardNative.Success)
        {
            return [];
        }
        try
        {
            int length = 0;
            _ = WinscardNative.SCardListReaders(context, IntPtr.Zero, null, ref length);
            if (length <= 0)
            {
                return [];
            }
            var buffer = new byte[length * 2];
            if (WinscardNative.SCardListReaders(context, IntPtr.Zero, buffer, ref length) != WinscardNative.Success)
            {
                return [];
            }
            // Multi-sz: double-NUL-terminated UTF-16 strings.
            var multiString = System.Text.Encoding.Unicode.GetString(buffer, 0, length * 2);
            return multiString.Split('\0', StringSplitOptions.RemoveEmptyEntries);
        }
        finally
        {
            _ = WinscardNative.SCardReleaseContext(context);
        }
    }

    /// <summary>Connects and SELECTs the FIDO applet. Returns null when the reader has no card
    /// or the applet is absent — capability probing happens on first use, never assumed.</summary>
    public static PcscTransport? TryOpen(string readerName)
    {
        if (WinscardNative.SCardEstablishContext(WinscardNative.ScopeSystem, IntPtr.Zero, IntPtr.Zero, out var context)
            != WinscardNative.Success)
        {
            return null;
        }

        IntPtr card = IntPtr.Zero;
        int protocol = 0;
        try
        {
            // Shared first, then exclusive (mirrors the reference transports).
            if (WinscardNative.SCardConnect(context, readerName, WinscardNative.ShareShared,
                    WinscardNative.ProtocolAny, out card, out protocol) != WinscardNative.Success)
            {
                _ = WinscardNative.SCardDisconnect(card, WinscardNative.DisconnectLeave);
                card = IntPtr.Zero;
                if (WinscardNative.SCardConnect(context, readerName, WinscardNative.ShareExclusive,
                        WinscardNative.ProtocolAny, out card, out protocol) != WinscardNative.Success)
                {
                    _ = WinscardNative.SCardReleaseContext(context);
                    return null;
                }
            }

            var transport = new PcscTransport(context, card, protocol, readerName);
            var (data, sw) = transport.Exchange(BuildSelect(FidoAppletAid));
            if (sw != 0x9000)
            {
                transport.Dispose();
                return null;
            }
            return transport;
        }
        catch
        {
            if (card != IntPtr.Zero)
            {
                _ = WinscardNative.SCardDisconnect(card, WinscardNative.DisconnectLeave);
            }
            _ = WinscardNative.SCardReleaseContext(context);
            throw;
        }
    }

    public byte[] Call(ReadOnlyMemory<byte> request, CancellationToken cancellationToken, IProgress<KeepaliveStatus>? progress)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // NFCCTAP_MSG. The FIDO applet must be current — other applet reads switch it
        // behind our back, so re-SELECT before every CTAP command (SW deliberately ignored;
        // some firmware answers 6A81 yet still switches).
        _ = Exchange(BuildSelect(FidoAppletAid));
        var body = request.ToArray();
        var (data, sw) = Exchange(BuildCtapApdu(0x00, body));

        // NFCCTAP_GETRESPONSE polling while the key signals 91 00 (first response byte is
        // the keepalive status). p1 = 0x11 cancels.
        byte p1 = 0x00;
        while ((sw & 0xFF00) == 0x9100)
        {
            ReportKeepalive(data.Length > 0 ? data[0] : (byte)0, progress);
            if (cancellationToken.IsCancellationRequested)
            {
                p1 = 0x11;
            }
            (data, sw) = Exchange(BuildCtapApdu(p1, []));
        }

        if (sw != 0x9000)
        {
            throw new TransportException(sw is 0x6D00 or 0x6985
                ? "This interface does not carry CTAP2 (USB-CCID is serial/config only — use a USB-HID connection or an NFC reader)."
                : $"APDU exchange failed: SW={sw:X4}.");
        }
        if (data.Length == 0)
        {
            throw new TransportException("Empty CTAP response over NFC.");
        }
        if (data[0] != 0x00)
        {
            throw new CtapException((CtapStatusCode)data[0]);
        }
        return data;
    }

    /// <summary>Raw APDU exchange used by vendor reads (serial/config). Returns (data, SW1SW2).</summary>
    public (byte[] Data, ushort StatusWord) Exchange(byte[] apdu)
    {
        var sendPci = new WinscardNative.SCARD_IO_REQUEST
        {
            dwProtocol = _protocol,
            cbPciLength = Marshal.SizeOf<WinscardNative.SCARD_IO_REQUEST>(),
        };
        var response = new byte[4096];
        int responseLength = response.Length;
        int rc = WinscardNative.SCardTransmit(_card, in sendPci, apdu, apdu.Length, IntPtr.Zero, response, ref responseLength);
        if (rc == WinscardNative.ScardEInsufficientBuffer)
        {
            throw new TransportException("SCardTransmit refused (0x80100027) — CTAP over PC/SC needs an elevated session.");
        }
        if (rc != WinscardNative.Success || responseLength < 2)
        {
            throw new TransportException($"SCardTransmit failed: rc=0x{rc:X8}.");
        }

        var data = response.AsSpan(0, responseLength - 2).ToArray();
        ushort sw = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(responseLength - 2, 2));

        // T=0 continuation: 61 xx means xx more bytes are waiting.
        int guard = 0;
        while ((sw >> 8) == 0x61 && guard++ < 64)
        {
            int le = sw & 0xFF;
            var getResponse = new byte[] { 0x00, 0xC0, 0x00, 0x00, (byte)le };
            responseLength = response.Length;
            if (WinscardNative.SCardTransmit(_card, in sendPci, getResponse, getResponse.Length, IntPtr.Zero, response, ref responseLength) != WinscardNative.Success
                || responseLength < 2)
            {
                break;
            }
            data = [.. data, .. response.AsSpan(0, responseLength - 2).ToArray()];
            sw = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(responseLength - 2, 2));
        }

        return (data, sw);
    }

    public static byte[] BuildSelect(string aidHex)
    {
        var aid = Convert.FromHexString(aidHex);
        return [0x00, 0xA4, 0x04, 0x00, (byte)aid.Length, .. aid];
    }

    private static byte[] BuildCtapApdu(byte p1, byte[] body)
    {
        if (body.Length > 255)
        {
            throw new TransportException($"CTAP payload {body.Length} bytes exceeds short Lc.");
        }
        return [0x80, 0x10, p1, 0x00, (byte)body.Length, .. body, 0x00];
    }

    private static void ReportKeepalive(byte statusCode, IProgress<KeepaliveStatus>? progress)
    {
        if (progress is not null && statusCode is 1 or 2)
        {
            progress.Report((KeepaliveStatus)statusCode);
        }
    }

    public void Dispose()
    {
        _ = WinscardNative.SCardDisconnect(_card, WinscardNative.DisconnectLeave);
        _ = WinscardNative.SCardReleaseContext(_context);
    }
}
