using Fido2.Core.Ctap2;
using Fido2.Core.Sessions;
using Fido2.Core.Transports;

namespace Fido2.Cli;

internal static class InfoCommand
{
    public static async Task<int> RunAsync(CommandLine line, CancellationToken cancellationToken)
    {
        line.EnsureOnly(Options.Global);

        using AuthenticatorSession session =
            await DeviceConnector.OpenAsync(line, cancellationToken).ConfigureAwait(false);
        AuthenticatorInfo info = session.Info;
        PinState state = await session.GetPinStateAsync(cancellationToken, new TouchPrompt()).ConfigureAwait(false);
        string[] capabilities = DescribeCapabilities(info);
        string kind = session.Transport is PcscTransport ? "NFC" : "USB";

        if (line.Has(Options.Json))
        {
            Output.Json(new InfoJson(
                Device: session.DisplayName,
                Kind: kind,
                Serial: session.VendorSerial,
                Versions: [.. info.Versions],
                Aaguid: info.Aaguid,
                Extensions: [.. info.Extensions],
                Transports: [.. info.Transports],
                PinUvAuthProtocols: [.. info.PinUvAuthProtocols],
                MinPinLength: info.MinPinLength,
                FirmwareVersion: info.FirmwareVersion,
                MaxMessageSize: info.MaxMessageSize,
                PinSet: state.IsSet,
                RetriesRemaining: state.RetriesRemaining,
                Capabilities: capabilities,
                Options: info.Options.Summary));
            return ExitCodes.Ok;
        }

        Row("Device", session.DisplayName);
        if (session.VendorSerial is { } serial)
        {
            Row("Serial", serial);
        }
        Row("Versions", string.Join(" ", info.Versions));
        Row("AAGUID", info.Aaguid);
        Row("Extensions", string.Join(" ", info.Extensions));
        Row("Transports", string.Join(" ", info.Transports));
        Row("PIN", state.IsSet
            ? $"set · {state.RetriesRemaining?.ToString() ?? "?"} retries remaining"
            : "not set");
        Row("Capabilities", string.Join(" · ", capabilities));
        Row("Max message", $"{info.MaxMessageSize} bytes");
        Row("PIN protocols", string.Join(" ", info.PinUvAuthProtocols));
        Row("Min PIN length", info.MinPinLength.ToString());
        Row("Firmware", info.FirmwareVersion.ToString());
        Row("Options", info.Options.Summary);
        return ExitCodes.Ok;
    }

    private static void Row(string label, string? value) => Console.WriteLine($"{label,-16}{value ?? ""}");

    private static string[] DescribeCapabilities(AuthenticatorInfo info)
    {
        var capabilities = new List<string>();
        if (info.SupportsFido21)
        {
            capabilities.Add("FIDO 2.1");
        }
        if (info.Options.ClientPin == true)
        {
            capabilities.Add("PIN set");
        }
        else if (info.Options.ClientPin == false)
        {
            capabilities.Add("no PIN");
        }
        if (info.Options.SupportsBioEnrollment)
        {
            capabilities.Add("fingerprint");
        }
        if (info.Options.SupportsCredentialManagement)
        {
            capabilities.Add("credential management");
        }
        if (info.Options.AuthenticatorConfig == true)
        {
            capabilities.Add("config commands");
        }
        if (info.Options.AlwaysUv == true)
        {
            capabilities.Add("alwaysUv");
        }
        if (info.ForcePinChange)
        {
            capabilities.Add("PIN change required");
        }
        return [.. capabilities];
    }
}
