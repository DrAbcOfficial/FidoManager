using System.Runtime.InteropServices;
using Fido2.Core.Transports.Interop;

namespace Fido2.Core.Transports;

/// <summary>Diagnostic verdict for one HID interface seen during a scan.</summary>
public sealed record HidInterfaceInfo(
    string Path,
    ushort UsagePage,
    ushort Usage,
    bool IsFido,
    string? OpenError);

/// <summary>
/// Enumerates FIDO HID interfaces via setupapi + hid.dll.
/// Traps encoded here (design doc §11.2):
/// <list type="bullet">
///   <item>setupapi exports only suffixed SetupDiGetClassDevsA/W and
///     SetupDiGetDeviceInterfaceDetailA/W — [LibraryImport] resolves exact entry points.</item>
///   <item>SP_DEVICE_INTERFACE_DETAIL_DATA (ANSI): cbSize is the fixed header size the OS
///     validates (8 on x64 / 6 on x86), while the device path string starts at offset 4.
///     Reading at 0 or 8 produces unusable paths.</item>
///   <item>Identification opens each candidate with dwDesiredAccess = 0 (metadata-only):
///     GetPreparsedData/GetCaps/GetAttributes all work on a zero-access handle, and this avoids
///     opening every keyboard and mouse on the bus read/write.</item>
///   <item>Filter on usage page 0xF1D0 AND usage 0x01.</item>
///   <item>Report sizes come from caps minus the report-id byte.</item>
/// </list>
/// </summary>
public static class HidDeviceEnumerator
{
    /// <summary>Walks every present HID device interface and reports its usage and FIDO verdict.
    /// Also the diagnostic view behind "no devices found" states.</summary>
    public static IReadOnlyList<HidInterfaceInfo> ScanInterfaces()
    {
        HidNative.HidD_GetHidGuid(out var hidGuid);
        var deviceInfo = SetupApiNative.SetupDiGetClassDevs(
            in hidGuid, IntPtr.Zero, IntPtr.Zero,
            SetupApiNative.DigcfPresent | SetupApiNative.DigcfDeviceInterface);
        if (deviceInfo == new IntPtr(-1))
        {
            throw new TransportException(
                $"SetupDiGetClassDevs failed (error 0x{Marshal.GetLastWin32Error():X}).");
        }

        var interfaces = new List<HidInterfaceInfo>();
        try
        {
            for (int index = 0; ; index++)
            {
                var interfaceData = new SetupApiNative.SP_DEVICE_INTERFACE_DATA
                {
                    cbSize = Marshal.SizeOf<SetupApiNative.SP_DEVICE_INTERFACE_DATA>(),
                };
                if (!SetupApiNative.SetupDiEnumDeviceInterfaces(
                        deviceInfo, IntPtr.Zero, in hidGuid, index, ref interfaceData))
                {
                    break; // no more interfaces
                }

                uint requiredSize = 0;
                _ = SetupApiNative.SetupDiGetDeviceInterfaceDetail(
                    deviceInfo, ref interfaceData, IntPtr.Zero, 0, out requiredSize, IntPtr.Zero);
                if (requiredSize == 0)
                {
                    continue;
                }

                var detailBuffer = Marshal.AllocHGlobal((int)requiredSize);
                try
                {
                    // cbSize = fixed header size the OS validates: 8 on x64, 6 on x86.
                    Marshal.WriteInt32(detailBuffer, 0, IntPtr.Size == 8 ? 8 : 6);
                    if (!SetupApiNative.SetupDiGetDeviceInterfaceDetail(
                            deviceInfo, ref interfaceData, detailBuffer, requiredSize, out _, IntPtr.Zero))
                    {
                        interfaces.Add(new HidInterfaceInfo("(detail failed)", 0, 0, false,
                            $"SetupDiGetDeviceInterfaceDetail error 0x{Marshal.GetLastWin32Error():X}"));
                        continue;
                    }

                    // The path begins right after the 4-byte cbSize field, on both
                    // architectures — reading at offset 0 yields the cbSize bytes and
                    // every subsequent CreateFile then fails. (ANSI structure → ANSI path.)
                    int maxChars = (int)(requiredSize - 4);
                    var path = Marshal.PtrToStringAnsi(detailBuffer + 4, maxChars);
                    if (string.IsNullOrEmpty(path))
                    {
                        interfaces.Add(new HidInterfaceInfo("(empty path)", 0, 0, false, null));
                        continue;
                    }

                    interfaces.Add(Probe(path.Split('\0')[0]));
                }
                finally
                {
                    Marshal.FreeHGlobal(detailBuffer);
                }
            }
        }
        finally
        {
            _ = SetupApiNative.SetupDiDestroyDeviceInfoList(deviceInfo);
        }

        return interfaces;
    }

    /// <summary>FIDO-only view used by the device picker.</summary>
    public static IReadOnlyList<HidDescriptor> Enumerate() =>
        ScanInterfaces()
            .Where(i => i.IsFido)
            .Select(i => Identify(i.Path))
            .OfType<HidDescriptor>()
            .ToList();

    private static HidInterfaceInfo Probe(string devicePath)
    {
        // Metadata-only access: some HID devices are exclusively held by the OS and
        // refuse read/write to anyone; a zero-access handle still identifies them.
        using var probe = Kernel32Native.CreateFile(
            devicePath, 0,
            Kernel32Native.FileShareRead | Kernel32Native.FileShareWrite,
            IntPtr.Zero, Kernel32Native.OpenExisting, 0, IntPtr.Zero);
        if (probe.IsInvalid)
        {
            return new HidInterfaceInfo(devicePath, 0, 0, false,
                $"CreateFile error 0x{Marshal.GetLastWin32Error():X}");
        }

        if (!HidNative.HidD_GetPreparsedData(probe, out var preparsedData))
        {
            return new HidInterfaceInfo(devicePath, 0, 0, false,
                $"HidD_GetPreparsedData error 0x{Marshal.GetLastWin32Error():X}");
        }
        try
        {
            var caps = new HidNative.HIDP_CAPS();
            if (HidNative.HidP_GetCaps(preparsedData, ref caps) != HidNative.HidpStatusSuccess)
            {
                return new HidInterfaceInfo(devicePath, 0, 0, false, "HidP_GetCaps failed");
            }

            bool isFido = caps.UsagePage == HidNative.FidoUsagePage && caps.Usage == HidNative.FidoUsage;
            if (!isFido)
            {
                return new HidInterfaceInfo(devicePath, caps.UsagePage, caps.Usage, false, null);
            }

            var attributes = new HidNative.HIDD_ATTRIBUTES { Size = Marshal.SizeOf<HidNative.HIDD_ATTRIBUTES>() };
            _ = HidNative.HidD_GetAttributes(probe, ref attributes);

            return new HidInterfaceInfo(devicePath, caps.UsagePage, caps.Usage, true, null);
        }
        finally
        {
            _ = HidNative.HidD_FreePreparsedData(preparsedData);
        }
    }

    /// <summary>Opens and fully identifies a FIDO interface (second pass, after filtering).</summary>
    private static HidDescriptor? Identify(string devicePath)
    {
        using var probe = Kernel32Native.CreateFile(
            devicePath, 0,
            Kernel32Native.FileShareRead | Kernel32Native.FileShareWrite,
            IntPtr.Zero, Kernel32Native.OpenExisting, 0, IntPtr.Zero);
        if (probe.IsInvalid)
        {
            return null;
        }

        if (!HidNative.HidD_GetPreparsedData(probe, out var preparsedData))
        {
            return null;
        }
        try
        {
            var caps = new HidNative.HIDP_CAPS();
            if (HidNative.HidP_GetCaps(preparsedData, ref caps) != HidNative.HidpStatusSuccess
                || caps.UsagePage != HidNative.FidoUsagePage || caps.Usage != HidNative.FidoUsage)
            {
                return null;
            }

            var attributes = new HidNative.HIDD_ATTRIBUTES { Size = Marshal.SizeOf<HidNative.HIDD_ATTRIBUTES>() };
            _ = HidNative.HidD_GetAttributes(probe, ref attributes);

            return new HidDescriptor(
                devicePath,
                attributes.VendorID,
                attributes.ProductID,
                caps.InputReportByteLength - 1,
                caps.OutputReportByteLength - 1,
                HidNative.GetProductString(probe),
                HidNative.GetSerialNumberString(probe));
        }
        finally
        {
            _ = HidNative.HidD_FreePreparsedData(preparsedData);
        }
    }
}
