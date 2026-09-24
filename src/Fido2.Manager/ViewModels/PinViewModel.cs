using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Fido2.Manager.Services;

namespace Fido2.Manager.ViewModels;

/// <summary>PIN page: state check, first-time set, and change (with retry-count guard).
/// PIN strings live only long enough for one operation — the service clears any cached
/// value on PIN errors and rescans.</summary>
public partial class PinViewModel : ObservableObject
{
    private static UiStateService UiState => AppServices.UiState;

    public PinViewModel()
    {
        StateText = "选择设备后点击“检查”。";
    }

    [ObservableProperty]
    public partial string StateText { get; set; }

    [ObservableProperty]
    public partial string OldPin { get; set; }

    [ObservableProperty]
    public partial string NewPin { get; set; }

    [ObservableProperty]
    public partial string ConfirmPin { get; set; }

    [ObservableProperty]
    public partial bool HasPin { get; set; }

    public async Task OnSessionOpenedAsync() => await CheckAsync().ConfigureAwait(true);

    [RelayCommand]
    public async Task CheckAsync()
    {
        var session = AppServices.Sessions.Current;
        if (session is null)
        {
            await AppServices.PinDialog.NotifyAsync("提示", "请先选择设备。").ConfigureAwait(true);
            return;
        }

        UiState.IsBusy = true;
        try
        {
            var state = await session.GetPinStateAsync(CancellationToken.None).ConfigureAwait(true);
            HasPin = state.IsSet;
            StateText = state.IsSet
                ? $"已设置 PIN。剩余重试:{state.RetriesRemaining}"
                : "未设置 PIN。“当前 PIN”留空即为首次设置。";
            UiState.SetMessage("PIN 状态已检查");
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
    private async Task ApplyAsync()
    {
        var session = AppServices.Sessions.Current;
        if (session is null)
        {
            await AppServices.PinDialog.NotifyAsync("提示", "请先选择设备。").ConfigureAwait(true);
            return;
        }
        if (!string.Equals(NewPin, ConfirmPin, StringComparison.Ordinal))
        {
            await AppServices.PinDialog.NotifyAsync("PIN 不一致", "两次输入的新 PIN 不相同。").ConfigureAwait(true);
            return;
        }
        if (Encoding.UTF8.GetByteCount(NewPin) < 4)
        {
            await AppServices.PinDialog.NotifyAsync("PIN 太短", "PIN 至少需要 4 个字节。").ConfigureAwait(true);
            return;
        }
        if (HasPin && string.IsNullOrEmpty(OldPin))
        {
            await AppServices.PinDialog.NotifyAsync("缺少当前 PIN", "钥匙已设置 PIN,修改需要当前 PIN。").ConfigureAwait(true);
            return;
        }

        UiState.IsBusy = true;
        UiState.SetMessage(HasPin ? "正在修改 PIN…" : "正在设置 PIN…");
        try
        {
            if (HasPin)
            {
                await session.ChangePinAsync(OldPin, NewPin, CancellationToken.None).ConfigureAwait(true);
            }
            else
            {
                await session.SetPinAsync(NewPin, CancellationToken.None).ConfigureAwait(true);
            }
            AppServices.Sessions.ClearPin();
            OldPin = NewPin = ConfirmPin = "";
            UiState.SetMessage(HasPin ? "PIN 已修改" : "PIN 已设置");
            await CheckAsync().ConfigureAwait(true);
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
