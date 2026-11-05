using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Fido2.Core.Credentials;
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
        EmptyText = Localization.Get("CredsNotLoaded");
    }

    public ObservableCollection<ResidentCredential> Credentials { get; } = [];

    [ObservableProperty]
    public partial string MetadataText { get; set; }

    [ObservableProperty]
    public partial string EmptyText { get; set; }

    [ObservableProperty]
    public partial bool HasCredentials { get; set; }

    /// <summary>The list itself stays empty — this drives the centered placeholder instead.</summary>
    public Microsoft.UI.Xaml.Visibility EmptyVisibility => string.IsNullOrEmpty(EmptyText)
        ? Microsoft.UI.Xaml.Visibility.Collapsed
        : Microsoft.UI.Xaml.Visibility.Visible;

    partial void OnEmptyTextChanged(string value) => OnPropertyChanged(nameof(EmptyVisibility));

    [ObservableProperty]
    public partial ResidentCredential? SelectedCredential { get; set; }

    /// <summary>Only a selected credential whose public key the key reported can be exported.</summary>
    public bool CanExportSsh => SelectedCredential?.HasSshPublicKey == true;

    partial void OnSelectedCredentialChanged(ResidentCredential? value) => OnPropertyChanged(nameof(CanExportSsh));

    public async Task OnSessionOpenedAsync() => await ListAsync().ConfigureAwait(true);

    [RelayCommand]
    public async Task ListAsync()
    {
        var session = AppServices.Sessions.Current;
        if (session is null)
        {
            await AppServices.PinDialog.NotifyAsync(
                Localization.Get("NotifyTitleHint"), Localization.Get("PromptSelectDeviceFirst")).ConfigureAwait(true);
            return;
        }
        if (session.Options.SupportsCredentialManagement is false)
        {
            await AppServices.PinDialog.NotifyAsync(
                Localization.Get("CredsUnsupportedTitle"), Localization.Get("CredsUnsupportedMessage")).ConfigureAwait(true);
            return;
        }

        string? pin = await AppServices.PinDialog.GetPinAsync(Localization.Get("CredsNeedPin"), AppServices.Sessions).ConfigureAwait(true);
        if (pin is null)
        {
            return;
        }

        UiState.IsBusy = true;
        UiState.SetMessage(Localization.Get("ReadingCredentials"));
        try
        {
            var meta = await session.GetCredentialMetadataAsync(pin, CancellationToken.None).ConfigureAwait(true);
            MetadataText = meta.MaxRemaining is { } free
                ? Localization.Format("CredsStoredFree", meta.Existing, free)
                : Localization.Format("CredsStored", meta.Existing);

            var credentials = await session.ListCredentialsAsync(pin, CancellationToken.None).ConfigureAwait(true);
            Credentials.Clear();
            foreach (var credential in credentials)
            {
                Credentials.Add(credential);
            }
            HasCredentials = credentials.Count > 0;
            EmptyText = HasCredentials ? "" : Localization.Get("NoResidentCredentials");
            UiState.SetMessage(Localization.Format("CredentialsListed", credentials.Count));
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

    /// <summary>
    /// Exports the selected credential's public key as an OpenSSH sk-* line. The public key
    /// was already returned by the enumeration that filled the list, so no new PIN prompt
    /// is needed; credentials from preview firmware (no publicKey member) stay disabled.
    /// </summary>
    [RelayCommand]
    private async Task ExportSshAsync(ResidentCredential? credential)
    {
        credential ??= SelectedCredential;
        if (credential is null)
        {
            return;
        }
        if (credential.PublicKey is null)
        {
            await AppServices.PinDialog.NotifyAsync(
                Localization.Get("ExportSshNoKeyTitle"), Localization.Get("ExportSshNoKeyMessage")).ConfigureAwait(true);
            return;
        }
        if (!OpenSshPublicKey.TryFormat(credential, out string keyLine)
            || !OpenSshPublicKey.TryGetFingerprint(credential.PublicKey, out string fingerprint))
        {
            await AppServices.PinDialog.NotifyAsync(
                Localization.Get("ExportSshUnsupportedTitle"), Localization.Get("ExportSshUnsupportedMessage")).ConfigureAwait(true);
            return;
        }

        await AppServices.Export.ShowOpenSshKeyAsync(credential, keyLine, fingerprint).ConfigureAwait(true);
    }

    [RelayCommand]
    private async Task DeleteAsync(ResidentCredential? credential)
    {
        if (credential is null)
        {
            return;
        }
        bool confirmed = await AppServices.PinDialog.ConfirmAsync(
            Localization.Get("DeleteCredentialTitle"),
            Localization.Format("DeleteCredentialConfirm", credential.RpId,
                credential.UserName ?? credential.DisplayName ?? Localization.Get("Unnamed"))).ConfigureAwait(true);
        if (!confirmed)
        {
            return;
        }

        string? pin = await AppServices.PinDialog.GetPinAsync(Localization.Get("DeleteCredentialNeedPin"), AppServices.Sessions).ConfigureAwait(true);
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
        UiState.SetMessage(Localization.Get("DeletingCredential"));
        try
        {
            await session.DeleteCredentialAsync(
                pin, Convert.FromHexString(credential.CredentialIdHex), CancellationToken.None).ConfigureAwait(true);
            Credentials.Remove(credential);
            HasCredentials = Credentials.Count > 0;
            EmptyText = HasCredentials ? "" : Localization.Get("NoResidentCredentials");
            UiState.SetMessage(Localization.Get("CredentialDeleted"));
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
