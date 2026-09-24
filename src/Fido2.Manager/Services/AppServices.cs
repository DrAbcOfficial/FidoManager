using Fido2.Manager.ViewModels;
using Microsoft.UI.Dispatching;

namespace Fido2.Manager.Services;

/// <summary>Composition root. Singletons are created eagerly — all of them are cheap and
/// stateless regarding the PIN (which lives only in <see cref="SessionService"/> memory).</summary>
public static class AppServices
{
    public static UiStateService UiState { get; } = new();
    public static SessionService Sessions { get; } = new();
    public static PinDialogService PinDialog { get; } = new();
    public static MainViewModel Main { get; } = new();
    public static DeviceInfoViewModel DeviceInfo { get; } = new();
    public static CredentialsViewModel Credentials { get; } = new();
    public static FingerprintsViewModel Fingerprints { get; } = new();
    public static PinViewModel Pin { get; } = new();
    public static PolicyViewModel Policy { get; } = new();
    public static ResetViewModel Reset { get; } = new();

    public static void Initialize(DispatcherQueue dispatcher)
    {
        UiState.Initialize(dispatcher);
        Main.SessionOpened += OnSessionOpened;
    }

    private static void OnSessionOpened()
    {
        // Only the PIN-less loads run automatically — credentials/fingerprints need a PIN
        // and must never pop the dialog just because a device was selected.
        _ = DeviceInfo.OnSessionOpenedAsync();
        _ = Policy.OnSessionOpenedAsync();
        _ = Pin.OnSessionOpenedAsync();
    }
}
