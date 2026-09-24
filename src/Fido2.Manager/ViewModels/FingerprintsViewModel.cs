using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Fido2.Core.Transports;
using Fido2.Manager.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Fido2.Manager.ViewModels;

/// <summary>Fingerprints page: list / enroll / rename / delete. Enrollment runs a modal
/// progress dialog wired to the touch keepalive; cancel discards the partial template.</summary>
public partial class FingerprintsViewModel : ObservableObject
{
    private static UiStateService UiState => AppServices.UiState;

    public FingerprintsViewModel()
    {
        EmptyText = Localization.Get("BioNotLoaded");
    }

    public ObservableCollection<Fido2.Core.Ctap2.FingerprintEnrollment> Enrollments { get; } = [];

    [ObservableProperty]
    public partial string EmptyText { get; set; }

    [ObservableProperty]
    public partial string SensorText { get; set; }

    [ObservableProperty]
    public partial bool HasEnrollments { get; set; }

    [ObservableProperty]
    public partial bool IsEnrolling { get; set; }

    /// <summary>Drives the "no sensor" InfoBar.</summary>
    [ObservableProperty]
    public partial bool ShowSensorWarning { get; set; }

    public Microsoft.UI.Xaml.Visibility EnrollProgressVisibility =>
        IsEnrolling ? Microsoft.UI.Xaml.Visibility.Visible : Microsoft.UI.Xaml.Visibility.Collapsed;

    /// <summary>The list itself stays empty — this drives the centered placeholder instead.</summary>
    public Microsoft.UI.Xaml.Visibility EmptyVisibility => string.IsNullOrEmpty(EmptyText)
        ? Microsoft.UI.Xaml.Visibility.Collapsed
        : Microsoft.UI.Xaml.Visibility.Visible;

    partial void OnIsEnrollingChanged(bool value) =>
        OnPropertyChanged(nameof(EnrollProgressVisibility));

    partial void OnEmptyTextChanged(string value) => OnPropertyChanged(nameof(EmptyVisibility));

    public async Task OnSessionOpenedAsync()
    {
        var session = AppServices.Sessions.Current;
        if (session is null)
        {
            return;
        }
        if (session.Options.SupportsBioEnrollment)
        {
            SensorText = "";
            ShowSensorWarning = false;
        }
        else
        {
            SensorText = Localization.Get("NoBioSensor");
            ShowSensorWarning = true;
        }
    }

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
        if (!session.Options.SupportsBioEnrollment)
        {
            SensorText = Localization.Get("NoBioSensor");
            ShowSensorWarning = true;
            return;
        }

        string? pin = await AppServices.PinDialog.GetPinAsync(Localization.Get("BioListNeedPin"), AppServices.Sessions).ConfigureAwait(true);
        if (pin is null)
        {
            return;
        }

        UiState.IsBusy = true;
        try
        {
            var enrollments = await session.ListFingerprintsAsync(pin, CancellationToken.None).ConfigureAwait(true);
            Enrollments.Clear();
            foreach (var enrollment in enrollments)
            {
                Enrollments.Add(enrollment);
            }
            HasEnrollments = enrollments.Count > 0;
            EmptyText = HasEnrollments ? "" : Localization.Get("NoFingerprints");
            UiState.SetMessage(Localization.Format("FingerprintsListed", enrollments.Count));
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
    private async Task EnrollAsync()
    {
        var session = AppServices.Sessions.Current;
        if (session is null || IsEnrolling)
        {
            return;
        }

        string? name = await AppServices.PinDialog.PromptTextAsync(
            Localization.Get("EnrollTitle"), Localization.Get("EnrollNamePrompt")).ConfigureAwait(true);
        if (name is null)
        {
            return;
        }
        string? pin = await AppServices.PinDialog.GetPinAsync(Localization.Get("EnrollNeedPin"), AppServices.Sessions).ConfigureAwait(true);
        if (pin is null)
        {
            return;
        }

        await RunEnrollmentWithDialogAsync(session, pin, name).ConfigureAwait(true);
    }

    private async Task RunEnrollmentWithDialogAsync(
        Fido2.Core.Sessions.AuthenticatorSession session, string pin, string? name)
    {
        XamlRoot? root = App.MainWindow?.Content?.XamlRoot;
        if (root is null)
        {
            return;
        }

        var statusBar = new TextBlock { Text = Localization.Get("EnrollWaitFirstTouch") };
        var progressBar = new ProgressBar { Minimum = 0, Maximum = 100, Value = 0 };
        var panel = new StackPanel
        {
            Spacing = 12,
            Children =
            {
                new TextBlock { Text = Localization.Get("EnrollInstruction") },
                progressBar,
                statusBar,
            },
        };
        var dialog = new ContentDialog
        {
            Title = Localization.Get("EnrollingTitle"),
            Content = panel,
            CloseButtonText = Localization.Get("CommonCancel"),
            XamlRoot = root,
        };
        var cancellationTokenSource = new CancellationTokenSource();
        dialog.Closed += (_, _) => cancellationTokenSource.Cancel();

        IsEnrolling = true;
        UiState.SetMessage(Localization.Get("Enrolling"));
        try
        {
            // Progress<T> is created on the UI thread, so callbacks arrive marshalled.
            int captured = 0;
            var samples = new Progress<Fido2.Core.Ctap2.EnrollmentSample>(sample =>
            {
                captured++;
                string status = Localization.TryGet($"BioSample{sample.LastSampleStatus:X2}")
                    ?? Localization.Get("BioSampleOther");
                statusBar.Text = Localization.Format("SampleProgress", status, sample.RemainingSamples);
                if (sample.RemainingSamples >= 0)
                {
                    double total = captured + sample.RemainingSamples;
                    if (total > 0)
                    {
                        progressBar.Maximum = total;
                        progressBar.Value = Math.Min(captured, total);
                    }
                }
            });
            var touch = new Progress<KeepaliveStatus>(status =>
            {
                if (status == KeepaliveStatus.UpNeeded)
                {
                    statusBar.Text = Localization.Get("TouchSensor");
                }
            });

            _ = dialog.ShowAsync(); // modal, but we continue to run the enrollment
            var enrollment = await session.EnrollFingerprintAsync(pin, name, samples, touch, cancellationTokenSource.Token)
                .ConfigureAwait(true);
            UiState.SetMessage(Localization.Format("Enrolled", enrollment.FriendlyName ?? enrollment.TemplateIdHex));
            await ListAsyncCoreAsync(session, pin).ConfigureAwait(true);
        }
        catch (OperationCanceledException)
        {
            UiState.SetMessage(Localization.Get("EnrollCanceled"));
        }
        catch (Exception ex)
        {
            AppServices.Sessions.ClearPinOnError(ex);
            UiState.SetError(ex.Message);
        }
        finally
        {
            IsEnrolling = false;
            cancellationTokenSource.Dispose();
            dialog.Hide();
        }
    }

    private async Task ListAsyncCoreAsync(Fido2.Core.Sessions.AuthenticatorSession session, string pin)
    {
        try
        {
            var enrollments = await session.ListFingerprintsAsync(pin, CancellationToken.None).ConfigureAwait(true);
            Enrollments.Clear();
            foreach (var enrollment in enrollments)
            {
                Enrollments.Add(enrollment);
            }
            HasEnrollments = Enrollments.Count > 0;
            EmptyText = HasEnrollments ? "" : Localization.Get("NoFingerprints");
        }
        catch
        {
            // list refresh after enrollment is best-effort; primary errors already surfaced
        }
    }

    [RelayCommand]
    private async Task RenameAsync(Fido2.Core.Ctap2.FingerprintEnrollment? enrollment)
    {
        if (enrollment is null)
        {
            return;
        }
        string? name = await AppServices.PinDialog.PromptTextAsync(
            Localization.Get("RenameTitle"), Localization.Get("RenamePrompt"), enrollment.FriendlyName).ConfigureAwait(true);
        if (string.IsNullOrWhiteSpace(name))
        {
            return;
        }
        string? pin = await AppServices.PinDialog.GetPinAsync(Localization.Get("RenameNeedPin"), AppServices.Sessions).ConfigureAwait(true);
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
        try
        {
            await session.RenameFingerprintAsync(
                pin, Convert.FromHexString(enrollment.TemplateIdHex), name, CancellationToken.None).ConfigureAwait(true);
            await ListAsyncCoreAsync(session, pin).ConfigureAwait(true);
            UiState.SetMessage(Localization.Get("Renamed"));
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
    private async Task DeleteAsync(Fido2.Core.Ctap2.FingerprintEnrollment? enrollment)
    {
        if (enrollment is null)
        {
            return;
        }
        bool confirmed = await AppServices.PinDialog.ConfirmAsync(
            Localization.Get("DeleteFingerprintTitle"),
            Localization.Format("DeleteFingerprintConfirm", enrollment.FriendlyName ?? enrollment.TemplateIdHex)).ConfigureAwait(true);
        if (!confirmed)
        {
            return;
        }
        string? pin = await AppServices.PinDialog.GetPinAsync(Localization.Get("DeleteFingerprintNeedPin"), AppServices.Sessions).ConfigureAwait(true);
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
        try
        {
            await session.DeleteFingerprintAsync(
                pin, Convert.FromHexString(enrollment.TemplateIdHex), CancellationToken.None).ConfigureAwait(true);
            Enrollments.Remove(enrollment);
            HasEnrollments = Enrollments.Count > 0;
            EmptyText = HasEnrollments ? "" : Localization.Get("NoFingerprints");
            UiState.SetMessage(Localization.Get("FingerprintDeleted"));
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
