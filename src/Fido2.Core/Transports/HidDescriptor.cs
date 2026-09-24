namespace Fido2.Core.Transports;

/// <summary>Identification data of a FIDO HID interface. Report sizes come from
/// HidP_GetCaps (they are not always 64 — never hard-code the classic value).</summary>
public sealed record HidDescriptor(
    string DevicePath,
    ushort VendorId,
    ushort ProductId,
    int ReportSizeIn,
    int ReportSizeOut,
    string? ProductName,
    string? SerialNumber)
{
    public string DisplayName =>
        string.IsNullOrEmpty(ProductName)
            ? $"VID_{VendorId:X4} PID_{ProductId:X4}"
            : ProductName;
}
