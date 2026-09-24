using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Fido2.Manager.Services;

namespace Fido2.Manager.ViewModels;

/// <summary>Policy page (authenticatorConfig): alwaysUv toggle (it IS a toggle — the label
/// reflects the read-back state), minimum PIN length (one-way up), force PIN change.
/// Controls are enabled from the getInfo options map only.</summary>
public partial class PolicyViewModel : ObservableObject
{
    private static UiStateService UiState => AppServices.UiState;

    public PolicyViewModel()
    {
        StateText = "选择设备后加载策略状态。";
        ToggleButtonText = "切换";
        MinPinLength = 8;
    }

    [ObservableProperty]
    public partial string StateText { get; set; }

    [ObservableProperty]
    public partial string AlwaysUvText { get; set; }

    [ObservableProperty]
    public partial string ToggleButtonText { get; set; }

    [ObservableProperty]
    public partial bool CanToggleAlwaysUv { get; set; }

    [ObservableProperty]
    public partial bool CanSetMinPin { get; set; }

    [ObservableProperty]
    public partial int MinPinLength { get; set; }

    public async Task OnSessionOpenedAsync()
    {
        var session = AppServices.Sessions.Current;
        if (session is null)
        {
            StateText = "未选择设备。";
            CanToggleAlwaysUv = CanSetMinPin = false;
            return;
        }

        var options = session.Options;
        bool authnrCfg = options.AuthenticatorConfig == true;
        bool setMinPin = options.SetMinPinLength == true;
        CanToggleAlwaysUv = authnrCfg;
        CanSetMinPin = authnrCfg && setMinPin;
        MinPinLength = Math.Max(session.Info.MinPinLength, 8);

        AlwaysUvText = options.AlwaysUv switch
        {
            true => "当前:开",
            false => "当前:关",
            null => "当前:未报告",
        };
        ToggleButtonText = options.AlwaysUv == true ? "关闭 alwaysUv" : "开启 alwaysUv";

        StateText = authnrCfg
            ? (setMinPin ? "此钥匙支持 authenticatorConfig。" : "此钥匙支持 authenticatorConfig,但不含 setMinPINLength — 长度控件不可用。")
            : "此钥匙不提供 authenticatorConfig — 策略修改不可用。";
        await Task.CompletedTask.ConfigureAwait(true);
    }

    [RelayCommand]
    private async Task ToggleAlwaysUvAsync()
    {
        var session = AppServices.Sessions.Current;
        if (session is null)
        {
            return;
        }
        string? pin = await AppServices.PinDialog.GetPinAsync("修改 alwaysUv 需要 PIN。", AppServices.Sessions).ConfigureAwait(true);
        if (pin is null)
        {
            return;
        }

        UiState.IsBusy = true;
        UiState.SetMessage("正在切换 alwaysUv…");
        try
        {
            bool after = await session.ToggleAlwaysUvAsync(pin, CancellationToken.None).ConfigureAwait(true);
            AlwaysUvText = after ? "当前:开" : "当前:关";
            ToggleButtonText = after ? "关闭 alwaysUv" : "开启 alwaysUv";
            UiState.SetMessage($"alwaysUv 现在为 {(after ? "开" : "关")}");
        }
        catch (Exception ex)
        {
            AppServices.Sessions.ClearPinOnError(ex);
            UiState.SetError(ex.Message);
        }
        finally
        {
            UiState.IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task ApplyMinPinAsync()
    {
        var session = AppServices.Sessions.Current;
        if (session is null)
        {
            return;
        }
        bool confirmed = await AppServices.PinDialog.ConfirmAsync(
            "提高最小 PIN 长度",
            $"将最小 PIN 长度提高到 {MinPinLength}?\n\n此设置只能调高 — 调回必须恢复出厂(清空所有凭据)。").ConfigureAwait(true);
        if (!confirmed)
        {
            return;
        }
        string? pin = await AppServices.PinDialog.GetPinAsync("修改最小 PIN 长度需要 PIN。", AppServices.Sessions).ConfigureAwait(true);
        if (pin is null)
        {
            return;
        }

        UiState.IsBusy = true;
        UiState.SetMessage("正在设置最小 PIN 长度…");
        try
        {
            await session.SetMinPinLengthAsync(pin, MinPinLength, null, forceChangePin: false, CancellationToken.None).ConfigureAwait(true);
            UiState.SetMessage($"最小 PIN 长度现为 {MinPinLength}");
        }
        catch (Exception ex)
        {
            AppServices.Sessions.ClearPinOnError(ex);
            UiState.SetError(ex.Message);
        }
        finally
        {
            UiState.IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task ForcePinChangeAsync()
    {
        var session = AppServices.Sessions.Current;
        if (session is null)
        {
            return;
        }
        bool confirmed = await AppServices.PinDialog.ConfirmAsync(
            "强制下次改 PIN",
            "下次使用此钥匙时必须设置新的 PIN。适合在转交钥匙前使用。").ConfigureAwait(true);
        if (!confirmed)
        {
            return;
        }
        string? pin = await AppServices.PinDialog.GetPinAsync("强制改 PIN 需要 PIN。", AppServices.Sessions).ConfigureAwait(true);
        if (pin is null)
        {
            return;
        }

        UiState.IsBusy = true;
        try
        {
            await session.SetMinPinLengthAsync(pin, null, null, forceChangePin: true, CancellationToken.None).ConfigureAwait(true);
            UiState.SetMessage("已设置:下次使用时强制改 PIN");
        }
        catch (Exception ex)
        {
            AppServices.Sessions.ClearPinOnError(ex);
            UiState.SetError(ex.Message);
        }
        finally
        {
            UiState.IsBusy = false;
        }
    }
}
