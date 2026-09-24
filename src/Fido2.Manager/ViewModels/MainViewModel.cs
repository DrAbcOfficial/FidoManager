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
        DeviceSummary = "未选择设备";
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
        ? "已以管理员身份运行 — 全部功能可用。"
        : "未提权 — USB HID 无法打开(0x5),请以管理员身份重新运行。";

    /// <summary>Raised after a device was connected and its session is ready.</summary>
    public event Action? SessionOpened;

    [RelayCommand]
    private async Task RefreshAsync()
    {
        UiState.IsBusy = true;
        UiState.SetMessage("正在扫描设备…");
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
            UiState.SetMessage($"找到 {devices.Count} 台设备");
            DeviceSummary = devices.Count > 0 ? "请选择设备" : "未找到设备 — 插入钥匙或将卡片放到 NFC 读卡器上";
        }
        catch (Exception ex)
        {
            UiState.SetError($"扫描失败:{ex.Message}");
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
        UiState.SetMessage($"正在连接 {entry.DisplayName}…");
        try
        {
            using var timeout = new CancellationTokenSource(ConnectTimeout);
            ITokenTransport transport = entry.OpenTransport();
            AuthenticatorSession session = await AuthenticatorSessionFactory
                .OpenAsync(transport, timeout.Token)
                .ConfigureAwait(true);

            AppServices.Sessions.ReplaceSession(session);

            string serial = session.VendorSerial is { } s ? $"  串号 {s}" : "";
            DeviceSummary = $"{session.DisplayName}{serial}   |   {string.Join(", ", session.Info.Versions)}";
            UiState.SetMessage("已连接");
            SessionOpened?.Invoke();
        }
        catch (Exception ex)
        {
            AppServices.Sessions.CloseDevice();
            DeviceSummary = "连接失败";
            UiState.SetError($"连接失败:{ex.Message}");
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
