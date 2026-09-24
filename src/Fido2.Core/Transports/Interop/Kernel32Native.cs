using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Fido2.Core.Transports.Interop;

/// <summary>kernel32 P/Invoke for opening HID device paths. Handles are wrapped in
/// <see cref="SafeFileHandle"/> so I/O can go through <see cref="System.IO.FileStream"/>.</summary>
internal static partial class Kernel32Native
{
    public const uint GenericRead = 0x80000000;
    public const uint GenericWrite = 0x40000000;
    public const uint FileShareRead = 0x00000001;
    public const uint FileShareWrite = 0x00000002;
    public const uint OpenExisting = 3;

    [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    internal static partial SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);
}
