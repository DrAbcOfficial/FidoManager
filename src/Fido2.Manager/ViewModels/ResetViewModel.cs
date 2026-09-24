using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Fido2.Manager.Services;

namespace Fido2.Manager.ViewModels;

/// <summary>Reset page. The warning must mention the ~10s power-up window — the key refuses
/// otherwise (0x30 NOT_ALLOWED).</summary>
public partial class ResetViewModel : ObservableObject
{
    private static UiStateService UiState => AppServices.UiState;

    public async Task OnSessionOpenedAsync() => await Task.CompletedTask.ConfigureAwait(true);

    [RelayCommand]
    private async Task ResetAsync()
    {
        var session = AppServices.Sessions.Current;
        if (session is null)
        {
            await AppServices.PinDialog.NotifyAsync("提示", "请先选择设备。").ConfigureAwait(true);
            return;
        }

        bool confirmed = await AppServices.PinDialog.ConfirmAsync(
            "恢复出厂设置",
            "恢复出厂会清空此钥匙上的全部 passkey 与 PIN,且不可撤销。\n\n" +
            "钥匙只在上电后约 10 秒内接受重置:请先拔下再插回(或从 NFC 感应区移开再放回),然后立即点击“确认”。\n\n确定继续?").ConfigureAwait(true);
        if (!confirmed)
        {
            return;
        }

        UiState.IsBusy = true;
        UiState.SetMessage("正在恢复出厂…");
        try
        {
            await session.ResetAsync(CancellationToken.None).ConfigureAwait(true);
            UiState.SetMessage("已恢复出厂。全部凭据与 PIN 已清除。");
        }
        catch (Exception ex)
        {
            UiState.SetError(ex.Message);
        }
        finally
        {
            UiState.IsBusy = false;
        }
    }
}
