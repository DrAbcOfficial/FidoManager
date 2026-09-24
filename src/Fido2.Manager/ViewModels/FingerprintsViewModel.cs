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
        EmptyText = "尚未加载。点击“列出” — 将需要 PIN。";
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

    public Microsoft.UI.Xaml.Visibility EnrollProgressVisibility =>
        IsEnrolling ? Microsoft.UI.Xaml.Visibility.Visible : Microsoft.UI.Xaml.Visibility.Collapsed;

    partial void OnIsEnrollingChanged(bool value) =>
        OnPropertyChanged(nameof(EnrollProgressVisibility));

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
        }
        else
        {
            SensorText = "这把钥匙没有指纹传感器(getInfo 未提供 bioEnroll)。";
        }
    }

    [RelayCommand]
    public async Task ListAsync()
    {
        var session = AppServices.Sessions.Current;
        if (session is null)
        {
            await AppServices.PinDialog.NotifyAsync("提示", "请先选择设备。").ConfigureAwait(true);
            return;
        }
        if (!session.Options.SupportsBioEnrollment)
        {
            SensorText = "这把钥匙没有指纹传感器(getInfo 未提供 bioEnroll)。";
            return;
        }

        string? pin = await AppServices.PinDialog.GetPinAsync("列出指纹需要 PIN。", AppServices.Sessions).ConfigureAwait(true);
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
            EmptyText = HasEnrollments ? "" : "这把钥匙上没有指纹。";
            UiState.SetMessage($"共 {enrollments.Count} 枚指纹");
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
            "录入指纹", "为这根手指命名(可选):").ConfigureAwait(true);
        if (name is null)
        {
            return;
        }
        string? pin = await AppServices.PinDialog.GetPinAsync("录入指纹需要 PIN。", AppServices.Sessions).ConfigureAwait(true);
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

        var statusBar = new TextBlock { Text = "等待第一次触摸…" };
        var progressBar = new ProgressBar { Minimum = 0, Maximum = 100, Value = 0 };
        var panel = new StackPanel
        {
            Spacing = 12,
            Children =
            {
                new TextBlock { Text = "反复触摸传感器,直到录入完成。" },
                progressBar,
                statusBar,
            },
        };
        var dialog = new ContentDialog
        {
            Title = "正在录入指纹",
            Content = panel,
            CloseButtonText = "取消",
            XamlRoot = root,
        };
        var cancellationTokenSource = new CancellationTokenSource();
        dialog.Closed += (_, _) => cancellationTokenSource.Cancel();

        IsEnrolling = true;
        UiState.SetMessage("正在录入指纹…");
        try
        {
            // Progress<T> is created on the UI thread, so callbacks arrive marshalled.
            int captured = 0;
            var samples = new Progress<Fido2.Core.Ctap2.EnrollmentSample>(sample =>
            {
                captured++;
                statusBar.Text = $"{sample.StatusText} — 还需 {sample.RemainingSamples} 次";
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
                    statusBar.Text = "请触摸传感器…";
                }
            });

            _ = dialog.ShowAsync(); // modal, but we continue to run the enrollment
            var enrollment = await session.EnrollFingerprintAsync(pin, name, samples, touch, cancellationTokenSource.Token)
                .ConfigureAwait(true);
            UiState.SetMessage($"指纹已录入({enrollment.FriendlyName ?? enrollment.TemplateIdHex})");
            await ListAsyncCoreAsync(session, pin).ConfigureAwait(true);
        }
        catch (OperationCanceledException)
        {
            UiState.SetMessage("录入已取消");
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
            EmptyText = HasEnrollments ? "" : "这把钥匙上没有指纹。";
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
            "重命名指纹", "新名称:", enrollment.FriendlyName).ConfigureAwait(true);
        if (string.IsNullOrWhiteSpace(name))
        {
            return;
        }
        string? pin = await AppServices.PinDialog.GetPinAsync("重命名需要 PIN。", AppServices.Sessions).ConfigureAwait(true);
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
            UiState.SetMessage("已重命名");
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
            "删除指纹",
            $"删除这枚指纹?\n\n{(enrollment.FriendlyName ?? enrollment.TemplateIdHex)}\n\n此操作不可撤销。").ConfigureAwait(true);
        if (!confirmed)
        {
            return;
        }
        string? pin = await AppServices.PinDialog.GetPinAsync("删除指纹需要 PIN。", AppServices.Sessions).ConfigureAwait(true);
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
            EmptyText = HasEnrollments ? "" : "这把钥匙上没有指纹。";
            UiState.SetMessage("指纹已删除");
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
