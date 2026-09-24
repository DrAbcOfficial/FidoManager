namespace Fido2.Core.Transports.Vendor;

/// <summary>
/// Token2 vendor APDUs (CCID-only; work unelevated, unlike CTAP). The serial is read from
/// the FIDO applet (80 33), the vendor config bits from the OTP applet (80 C5) — see
/// design doc §3.4 / the PS1 reference.
/// </summary>
public static class Token2VendorApdu
{
    /// <summary>Reads the device serial via the vendor 80 33 command. Returns null when the
    /// card does not answer (non-Token2 key or no card present).</summary>
    public static string? ReadSerial(PcscTransport transport)
    {
        var (data, sw) = transport.Exchange([0x80, 0x33, 0x00, 0x00, 0x12, 0xD1, 0x10, .. new byte[16]]);
        if (sw != 0x9000 || data.Length < 2 || data[0] != 0xD1)
        {
            return null;
        }

        int serialLength = data[1];
        if (data.Length < 2 + serialLength || serialLength % 2 != 0)
        {
            return null;
        }

        // The serial is double-encoded: ASCII-hex characters that decode to bytes.
        var ascii = System.Text.Encoding.ASCII.GetString(data, 2, serialLength);
        try
        {
            var bytes = Convert.FromHexString(ascii);
            return Convert.ToHexString(bytes);
        }
        catch (FormatException)
        {
            return null;
        }
    }
}
