using System.Runtime.InteropServices;

namespace Fido2.Core.Transports.Interop;

/// <summary>PC/SC (winscard) P/Invoke for the CCID/NFC transport.</summary>
internal static partial class WinscardNative
{
    public const int ScopeSystem = 2;
    public const int ShareShared = 2;
    public const int ShareExclusive = 1;
    public const int ProtocolAny = 3;

    public const int Success = 0x00000000;
    public const int ScardEInsufficientBuffer = unchecked((int)0x80100027);

    public const int ProtocolT0 = 0x01;
    public const int ProtocolT1 = 0x02;

    public const int DisconnectLeave = 0;

    [StructLayout(LayoutKind.Sequential)]
    public struct SCARD_IO_REQUEST
    {
        public int dwProtocol;
        public int cbPciLength;
    }

    [LibraryImport("winscard.dll")]
    internal static partial int SCardEstablishContext(int scope, IntPtr reserved1, IntPtr reserved2, out IntPtr context);

    [LibraryImport("winscard.dll")]
    internal static partial int SCardReleaseContext(IntPtr context);

    // winscard exports suffixed ANSI/wide variants for the string-taking functions;
    // name them explicitly ([LibraryImport] resolves exact names only).
    [LibraryImport("winscard.dll", EntryPoint = "SCardListReadersW", StringMarshalling = StringMarshalling.Utf16)]
    internal static partial int SCardListReaders(IntPtr context, IntPtr groups, byte[]? readers, ref int readersLength);

    [LibraryImport("winscard.dll", EntryPoint = "SCardConnectW", StringMarshalling = StringMarshalling.Utf16)]
    internal static partial int SCardConnect(
        IntPtr context,
        string readerName,
        int shareMode,
        int preferredProtocols,
        out IntPtr card,
        out int activeProtocol);

    [LibraryImport("winscard.dll")]
    internal static partial int SCardDisconnect(IntPtr card, int disposition);

    [LibraryImport("winscard.dll")]
    internal static partial int SCardTransmit(
        IntPtr card,
        in SCARD_IO_REQUEST sendPci,
        byte[] sendBuffer,
        int sendLength,
        IntPtr recvPci,
        byte[] recvBuffer,
        ref int recvLength);
}
