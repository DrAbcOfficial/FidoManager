using System.Runtime.InteropServices;

namespace Fido2.Core.Transports.Interop;

internal static partial class SetupApiNative
{
    public const uint DigcfPresent = 0x02;
    public const uint DigcfDeviceInterface = 0x10;

    [StructLayout(LayoutKind.Sequential)]
    public struct SP_DEVICE_INTERFACE_DATA
    {
        public int cbSize;
        public Guid InterfaceClassGuid;
        public int Flags;
        public IntPtr Reserved;
    }

    // setupapi.dll exports only the suffixed SetupDiGetClassDevsA/W — entry points must
    // be named explicitly ([LibraryImport] does not probe A/W variants at runtime).
    [LibraryImport("setupapi.dll", SetLastError = true, EntryPoint = "SetupDiGetClassDevsA")]
    internal static partial IntPtr SetupDiGetClassDevs(
        in Guid classGuid,
        IntPtr enumerator,
        IntPtr hwndParent,
        uint flags);

    [LibraryImport("setupapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool SetupDiEnumDeviceInterfaces(
        IntPtr deviceInfoSet,
        IntPtr deviceInfoData,
        in Guid interfaceClassGuid,
        int memberIndex,
        ref SP_DEVICE_INTERFACE_DATA deviceInterfaceData);

    // ANSI detail structure: fixed header size 8 (x64) / 6 (x86) must be written into
    // cbSize, while the device path string starts at offset 4 — see HidDeviceEnumerator.
    [LibraryImport("setupapi.dll", SetLastError = true, EntryPoint = "SetupDiGetDeviceInterfaceDetailA")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool SetupDiGetDeviceInterfaceDetail(
        IntPtr deviceInfoSet,
        ref SP_DEVICE_INTERFACE_DATA deviceInterfaceData,
        IntPtr deviceInterfaceDetailData,
        uint deviceInterfaceDetailDataSize,
        out uint requiredSize,
        IntPtr deviceInfoData);

    [LibraryImport("setupapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool SetupDiDestroyDeviceInfoList(IntPtr deviceInfoSet);
}
