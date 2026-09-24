using System.Collections.ObjectModel;
using System.Security.Principal;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Fido2.Core.Sessions;
using Fido2.Core.Transports;
using Fido2.Manager.Services;

namespace Fido2.Manager.ViewModels;

/// <summary>Device picker + connection lifecycle. Owning the elevation banner too: USB-HID
/// CTAP needs admin (HID open otherwise returns 0x5), so the state is worth surfacing even
/// though the app manifest already requests elevation.</summary>
public partial class MainViewModel : ObservableObject
{
    private static UiStateService UiState => AppServices.UiState;

    public MainViewModel()
    {
        DeviceSummary = Localization.Get("NoDeviceSelected");
    }

    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(15);

    public ObservableCollection<DeviceEntry> Devices { get; } = [];

    [ObservableProperty]
    public partial DeviceEntry? SelectedDevice { get; set; }

    [ObservableProperty]
    public partial bool IsBusy { get; set; }

    [ObservableProperty]
    public partial string DeviceSummary { get; set; }

    public bool IsElevated { get; } = CheckElevated();

    public string ElevationBanner => IsElevated
        ? Localization.Get("BannerElevated")
        : Localization.Get("BannerNotElevated");

    /// <summary>Raised after a device was connected and its session is ready.</summary>
    public event Action? SessionOpened;

    [RelayCommand]
    private async Task RefreshAsync()
    {
        UiState.IsBusy = true;
        UiState.SetMessage(Localization.Get("ScanningDevices"));
        try
        {
            // A remembered PIN belongs to the key that was plugged in — a rescan may
            // reveal a different one, so drop it (design doc §6).
            AppServices.Sessions.CloseDevice();
            Devices.Clear();

            var devices = await DeviceEnumerationService.EnumerateAsync(CancellationToken.None).ConfigureAwait(true);
            foreach (var device in devices)
            {
                Devices.Add(device);
            }
            UiState.SetMessage(Localization.Format("DevicesFound", devices.Count));
            DeviceSummary = devices.Count > 0
                ? Localization.Get("SelectDevicePrompt")
                : Localization.Get("NoDevicesFound");
        }
        catch (Exception ex)
        {
            UiState.SetError(Localization.Format("ScanFailed", ex.Message));
        }
        finally
        {
            UiState.IsBusy = false;
        }
    }

    public async Task ConnectAsync(DeviceEntry entry)
    {
        if (!ReferenceEquals(SelectedDevice, entry))
        {
            SelectedDevice = entry;
            return; // OnSelectedDeviceChanged drives the connect
        }
        await ConnectCoreAsync(entry).ConfigureAwait(true);
    }

    partial void OnSelectedDeviceChanged(DeviceEntry? value)
    {
        if (value is not null)
        {
            _ = ConnectCoreAsync(value);
        }
    }

    private async Task ConnectCoreAsync(DeviceEntry entry)
    {
        UiState.IsBusy = true;
        UiState.SetMessage(Localization.Format("Connecting", entry.DisplayName));
        try
        {
            using var timeout = new CancellationTokenSource(ConnectTimeout);
            ITokenTransport transport = entry.OpenTransport();
            AuthenticatorSession session = await AuthenticatorSessionFactory
                .OpenAsync(transport, timeout.Token)
                .ConfigureAwait(true);

            AppServices.Sessions.ReplaceSession(session);

            string serial = session.VendorSerial is { } s ? Localization.Format("SerialNumberLabel", s) : "";
            DeviceSummary = $"{session.DisplayName}{serial}   |   {string.Join(", ", session.Info.Versions)}";
            UiState.SetMessage(Localization.Get("Connected"));
            SessionOpened?.Invoke();
        }
        catch (Exception ex)
        {
            AppServices.Sessions.CloseDevice();
            DeviceSummary = Localization.Get("ConnectFailed");
            UiState.SetError(Localization.Format("ConnectFailedWithReason", ex.Message));
        }
        finally
        {
            UiState.IsBusy = false;
        }
    }

    private static bool CheckElevated()
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
