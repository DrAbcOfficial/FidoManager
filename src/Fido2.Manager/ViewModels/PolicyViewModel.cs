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
        StateText = Localization.Get("PolicyInitialState");
        ToggleButtonText = Localization.Get("ToggleButtonDefault");
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
            StateText = Localization.Get("PolicyNoDevice");
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
            true => Localization.Get("AlwaysUvCurrentlyOn"),
            false => Localization.Get("AlwaysUvCurrentlyOff"),
            null => Localization.Get("AlwaysUvUnreported"),
        };
        ToggleButtonText = options.AlwaysUv == true
            ? Localization.Get("DisableAlwaysUv")
            : Localization.Get("EnableAlwaysUv");

        StateText = authnrCfg
            ? (setMinPin
                ? Localization.Get("PolicyConfigSupported")
                : Localization.Get("PolicyConfigNoSetMinPin"))
            : Localization.Get("PolicyConfigUnsupported");
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
        string? pin = await AppServices.PinDialog.GetPinAsync(Localization.Get("AlwaysUvNeedPin"), AppServices.Sessions).ConfigureAwait(true);
        if (pin is null)
        {
            return;
        }

        UiState.IsBusy = true;
        UiState.SetMessage(Localization.Get("TogglingAlwaysUv"));
        try
        {
            bool after = await session.ToggleAlwaysUvAsync(pin, CancellationToken.None).ConfigureAwait(true);
            AlwaysUvText = after ? Localization.Get("AlwaysUvCurrentlyOn") : Localization.Get("AlwaysUvCurrentlyOff");
            ToggleButtonText = after ? Localization.Get("DisableAlwaysUv") : Localization.Get("EnableAlwaysUv");
            UiState.SetMessage(Localization.Format("AlwaysUvNow", Localization.Get(after ? "On" : "Off")));
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
            Localization.Get("RaiseMinPinTitle"),
            Localization.Format("RaiseMinPinConfirm", MinPinLength)).ConfigureAwait(true);
        if (!confirmed)
        {
            return;
        }
        string? pin = await AppServices.PinDialog.GetPinAsync(Localization.Get("MinPinNeedPin"), AppServices.Sessions).ConfigureAwait(true);
        if (pin is null)
        {
            return;
        }

        UiState.IsBusy = true;
        UiState.SetMessage(Localization.Get("SettingMinPin"));
        try
        {
            await session.SetMinPinLengthAsync(pin, MinPinLength, null, forceChangePin: false, CancellationToken.None).ConfigureAwait(true);
            UiState.SetMessage(Localization.Format("MinPinNow", MinPinLength));
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
            Localization.Get("ForcePinChangeTitle"),
            Localization.Get("ForcePinChangeConfirm")).ConfigureAwait(true);
        if (!confirmed)
        {
            return;
        }
        string? pin = await AppServices.PinDialog.GetPinAsync(Localization.Get("ForcePinChangeNeedPin"), AppServices.Sessions).ConfigureAwait(true);
        if (pin is null)
        {
            return;
        }

        UiState.IsBusy = true;
        try
        {
            await session.SetMinPinLengthAsync(pin, null, null, forceChangePin: true, CancellationToken.None).ConfigureAwait(true);
            UiState.SetMessage(Localization.Get("ForcePinChangeSet"));
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
