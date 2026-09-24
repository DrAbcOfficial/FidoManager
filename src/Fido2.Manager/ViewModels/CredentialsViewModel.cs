using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Fido2.Core.Ctap2;
using Fido2.Manager.Services;

namespace Fido2.Manager.ViewModels;

/// <summary>Credentials page: enumerate discoverable credentials (PIN required) and
/// delete with confirmation. Empty-store firmware quirks (0x2E/0x12) are normalized by Core.</summary>
public partial class CredentialsViewModel : ObservableObject
{
    private static UiStateService UiState => AppServices.UiState;

    public CredentialsViewModel()
    {
        EmptyText = "尚未加载。点击“列出凭据” — 将需要 PIN。";
    }

    public ObservableCollection<ResidentCredential> Credentials { get; } = [];

    [ObservableProperty]
    public partial string MetadataText { get; set; }

    [ObservableProperty]
    public partial string EmptyText { get; set; }

    [ObservableProperty]
    public partial bool HasCredentials { get; set; }

    public async Task OnSessionOpenedAsync() => await ListAsync().ConfigureAwait(true);

    [RelayCommand]
    public async Task ListAsync()
    {
        var session = AppServices.Sessions.Current;
        if (session is null)
        {
            await AppServices.PinDialog.NotifyAsync("提示", "请先选择设备。").ConfigureAwait(true);
            return;
        }
        if (session.Options.SupportsCredentialManagement is false)
        {
            await AppServices.PinDialog.NotifyAsync("不支持", "这把钥匙没有提供凭据管理 API。").ConfigureAwait(true);
            return;
        }

        string? pin = await AppServices.PinDialog.GetPinAsync("列出凭据需要 PIN。", AppServices.Sessions).ConfigureAwait(true);
        if (pin is null)
        {
            return;
        }

        UiState.IsBusy = true;
        UiState.SetMessage("正在读取凭据…");
        try
        {
            var meta = await session.GetCredentialMetadataAsync(pin, CancellationToken.None).ConfigureAwait(true);
            MetadataText = meta.MaxRemaining is { } free
                ? $"已存 {meta.Existing}    剩余可存 {free}"
                : $"已存 {meta.Existing}";

            var credentials = await session.ListCredentialsAsync(pin, CancellationToken.None).ConfigureAwait(true);
            Credentials.Clear();
            foreach (var credential in credentials)
            {
                Credentials.Add(credential);
            }
            HasCredentials = credentials.Count > 0;
            EmptyText = HasCredentials ? "" : "这把钥匙上没有可发现( resident )凭据。";
            UiState.SetMessage($"共 {credentials.Count} 条凭据");
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
    private async Task DeleteAsync(ResidentCredential? credential)
    {
        if (credential is null)
        {
            return;
        }
        bool confirmed = await AppServices.PinDialog.ConfirmAsync(
            "删除凭据",
            $"删除这条凭据?\n\n{credential.RpId} / {credential.UserName ?? credential.DisplayName ?? "(未命名)"}\n\n此操作不可撤销。").ConfigureAwait(true);
        if (!confirmed)
        {
            return;
        }

        string? pin = await AppServices.PinDialog.GetPinAsync("删除凭据需要 PIN。", AppServices.Sessions).ConfigureAwait(true);
        if (pin is null)
        {
            return;
        }

        var session = AppServices.Sessions.Current;
        if (session is null)
        {
            return;
        }

        UiState.IsBusy = true;
        UiState.SetMessage("正在删除凭据…");
        try
        {
            await session.DeleteCredentialAsync(
                pin, Convert.FromHexString(credential.CredentialIdHex), CancellationToken.None).ConfigureAwait(true);
            Credentials.Remove(credential);
            HasCredentials = Credentials.Count > 0;
            EmptyText = HasCredentials ? "" : "这把钥匙上没有可发现( resident )凭据。";
            UiState.SetMessage("凭据已删除");
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
