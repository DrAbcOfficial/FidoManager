using System.Runtime.InteropServices;
using System.Text;
using Fido2.Core.Transports.Interop;

namespace Fido2.Core.Transports;

/// <summary>
/// Enumerates FIDO HID interfaces via setupapi + hid.dll.
/// Traps encoded here (design doc §11.2):
/// <list type="bullet">
///   <item>SP_DEVICE_INTERFACE_DETAIL_DATA: cbSize is the fixed header size the OS validates
///     (8 on x64 / 6 on x86), while the device path string starts at offset 4.</item>
///   <item>Identification opens each candidate with dwDesiredAccess = 0 (metadata-only):
///     GetPreparsedData/GetCaps/GetAttributes all work on a zero-access handle, and this avoids
///     opening every keyboard and mouse on the bus read/write.</item>
///   <item>Filter on usage page 0xF1D0 AND usage 0x01.</item>
///   <item>Report sizes come from caps minus the report-id byte.</item>
/// </list>
/// </summary>
public static class HidDeviceEnumerator
{
    public static IReadOnlyList<HidDescriptor> Enumerate()
    {
        HidNative.HidD_GetHidGuid(out var hidGuid);
        var deviceInfo = SetupApiNative.SetupDiGetClassDevs(
            in hidGuid, IntPtr.Zero, IntPtr.Zero,
            SetupApiNative.DigcfPresent | SetupApiNative.DigcfDeviceInterface);
        if (deviceInfo == -1)
        {
            return [];
        }

        var descriptors = new List<HidDescriptor>();
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
                        continue;
                    }

                    // The path begins right after the 4-byte cbSize field, on both architectures.
                    int maxChars = (int)(requiredSize - 4) / 2;
                    var path = Marshal.PtrToStringUni(detailBuffer, maxChars);
                    if (string.IsNullOrEmpty(path))
                    {
                        continue;
                    }

                    var descriptor = Probe(path.Split('\0')[0]);
                    if (descriptor is not null)
                    {
                        descriptors.Add(descriptor);
                    }
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

        return descriptors;
    }

    private static HidDescriptor? Probe(string devicePath)
    {
        // Metadata-only access: some HID devices are exclusively held by the OS and
        // refuse read/write to anyone; a zero-access handle still identifies them.
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
            if (HidNative.HidP_GetCaps(preparsedData, ref caps) != HidNative.HidpStatusSuccess)
            {
                return null;
            }
            if (caps.UsagePage != HidNative.FidoUsagePage || caps.Usage != HidNative.FidoUsage)
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
