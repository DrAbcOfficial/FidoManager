using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Fido2.Core.Ctap2;
using Fido2.Manager.Services;

namespace Fido2.Manager.ViewModels;

public sealed record NameValueRow(string Name, string Value);

/// <summary>Info page: fills the property grid from the session's cached getInfo plus
/// PIN state and the vendor serial (when the transport can read one).</summary>
public partial class DeviceInfoViewModel : ObservableObject
{
    private static UiStateService UiState => AppServices.UiState;

    public DeviceInfoViewModel()
    {
        DeviceName = Localization.Get("NoDeviceSelected");
        Capabilities = "";
    }

    public ObservableCollection<NameValueRow> Rows { get; } = [];

    /// <summary>Header line: the device's display name.</summary>
    [ObservableProperty]
    public partial string DeviceName { get; set; }

    /// <summary>Header line: capabilities joined into one short line, e.g. "FIDO 2.1 · PIN · 指纹".</summary>
    [ObservableProperty]
    public partial string Capabilities { get; set; }

    [ObservableProperty]
    public partial bool HasRows { get; set; }

    /// <summary>Hides the whole property card when no device is connected.</summary>
    public Microsoft.UI.Xaml.Visibility RowsVisibility => HasRows
        ? Microsoft.UI.Xaml.Visibility.Visible
        : Microsoft.UI.Xaml.Visibility.Collapsed;

    partial void OnHasRowsChanged(bool value) => OnPropertyChanged(nameof(RowsVisibility));

    [RelayCommand]
    public async Task OnSessionOpenedAsync()
    {
        var session = AppServices.Sessions.Current;
        if (session is null)
        {
            Rows.Clear();
            HasRows = false;
            DeviceName = Localization.Get("NoDeviceSelected");
            Capabilities = "";
            return;
        }

        UiState.IsBusy = true;
        try
        {
            var info = session.Info;
            Rows.Clear();
            Rows.Add(new NameValueRow(Localization.Get("RowDevice"), session.DisplayName));
            if (session.VendorSerial is { } serial)
            {
                Rows.Add(new NameValueRow(Localization.Get("RowSerialVendor"), serial));
            }
            Rows.Add(new NameValueRow(Localization.Get("RowVersions"), string.Join(", ", info.Versions)));
            Rows.Add(new NameValueRow("AAGUID", info.Aaguid));
            Rows.Add(new NameValueRow(Localization.Get("RowExtensions"), string.Join(", ", info.Extensions)));
            Rows.Add(new NameValueRow(Localization.Get("RowMaxMessageSize"), Localization.Format("BytesValue", info.MaxMessageSize)));
            Rows.Add(new NameValueRow(Localization.Get("RowPinProtocol"), string.Join(", ", info.PinUvAuthProtocols)));
            Rows.Add(new NameValueRow(Localization.Get("RowMinPinLength"), info.MinPinLength.ToString()));
            Rows.Add(new NameValueRow(Localization.Get("RowFirmwareVersion"), info.FirmwareVersion.ToString()));
            Rows.Add(new NameValueRow(Localization.Get("RowTransport"), session.Transport.GetType().Name.Replace("Transport", "")));

            PinState state = await session.GetPinStateAsync(CancellationToken.None).ConfigureAwait(true);
            Rows.Add(new NameValueRow(Localization.Get("RowPin"), state.IsSet
                ? Localization.Format("PinSetWithRetries", state.RetriesRemaining)
                : Localization.Get("PinNotSet")));

            string capabilities = string.Join(" · ", DescribeCapabilities(info));
            Rows.Add(new NameValueRow(Localization.Get("RowCapabilities"), capabilities));
            HasRows = true;

            DeviceName = session.DisplayName;
            Capabilities = capabilities;
            UiState.SetMessage(Localization.Get("DeviceInfoLoaded"));
        }
        catch (Exception ex)
        {
            AppServices.Sessions.ClearPinOnError(ex);
            UiState.SetError(Localization.Format("DeviceInfoFailed", ex.Message));
        }
        finally
        {
            UiState.IsBusy = false;
        }
    }

    private static IEnumerable<string> DescribeCapabilities(Fido2.Core.Ctap2.AuthenticatorInfo info)
    {
        if (info.SupportsFido21)
        {
            yield return "FIDO 2.1";
        }
        if (info.Options.ClientPin == true)
        {
            yield return Localization.Get("CapPinSet");
        }
        else if (info.Options.ClientPin == false)
        {
            yield return Localization.Get("CapNoPin");
        }
        if (info.Options.SupportsBioEnrollment)
        {
            yield return Localization.Get("CapFingerprint");
        }
        if (info.Options.SupportsCredentialManagement)
        {
            yield return Localization.Get("CapCredentialMgmt");
        }
        if (info.Options.AuthenticatorConfig == true)
        {
            yield return Localization.Get("CapAuthnrConfig");
        }
        if (info.ForcePinChange)
        {
            yield return Localization.Get("CapForcePinChange");
        }
    }
}
