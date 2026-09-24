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
            await AppServices.PinDialog.NotifyAsync(
                Localization.Get("NotifyTitleHint"), Localization.Get("PromptSelectDeviceFirst")).ConfigureAwait(true);
            return;
        }

        bool confirmed = await AppServices.PinDialog.ConfirmAsync(
            Localization.Get("ResetTitle"),
            Localization.Get("ResetConfirm")).ConfigureAwait(true);
        if (!confirmed)
        {
            return;
        }

        UiState.IsBusy = true;
        UiState.SetMessage(Localization.Get("Resetting"));
        try
        {
            await session.ResetAsync(CancellationToken.None).ConfigureAwait(true);
            UiState.SetMessage(Localization.Get("ResetDone"));
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
