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
        StateText = Localization.Get("PinInitialState");
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
            await AppServices.PinDialog.NotifyAsync(
                Localization.Get("NotifyTitleHint"), Localization.Get("PromptSelectDeviceFirst")).ConfigureAwait(true);
            return;
        }

        UiState.IsBusy = true;
        try
        {
            var state = await session.GetPinStateAsync(CancellationToken.None).ConfigureAwait(true);
            HasPin = state.IsSet;
            StateText = state.IsSet
                ? Localization.Format("PinSetWithRetries", state.RetriesRemaining)
                : Localization.Get("PinNotSetFirstTime");
            UiState.SetMessage(Localization.Get("PinStateChecked"));
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
            await AppServices.PinDialog.NotifyAsync(
                Localization.Get("NotifyTitleHint"), Localization.Get("PromptSelectDeviceFirst")).ConfigureAwait(true);
            return;
        }
        if (!string.Equals(NewPin, ConfirmPin, StringComparison.Ordinal))
        {
            await AppServices.PinDialog.NotifyAsync(
                Localization.Get("PinMismatchTitle"), Localization.Get("PinMismatchMessage")).ConfigureAwait(true);
            return;
        }
        if (Encoding.UTF8.GetByteCount(NewPin) < 4)
        {
            await AppServices.PinDialog.NotifyAsync(
                Localization.Get("PinTooShortTitle"), Localization.Get("PinTooShortMessage")).ConfigureAwait(true);
            return;
        }
        if (HasPin && string.IsNullOrEmpty(OldPin))
        {
            await AppServices.PinDialog.NotifyAsync(
                Localization.Get("PinCurrentRequiredTitle"), Localization.Get("PinCurrentRequiredMessage")).ConfigureAwait(true);
            return;
        }

        UiState.IsBusy = true;
        UiState.SetMessage(Localization.Get(HasPin ? "ChangingPin" : "SettingPin"));
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
            UiState.SetMessage(Localization.Get(HasPin ? "PinChanged" : "PinSet"));
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
