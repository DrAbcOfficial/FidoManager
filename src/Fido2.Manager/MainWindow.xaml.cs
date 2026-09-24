using System.Diagnostics;
using Fido2.Manager.Services;
using Fido2.Manager.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Fido2.Manager;

/// <summary>Language switcher entry: Tag is the saved preference ("" = follow the system).</summary>
public sealed record LanguageOption(string Tag, string Label);

/// <summary>Navigation shell. Pages are instantiated once in XAML and switched by
/// Visibility — deliberately avoiding Frame.Navigate, whose type resolution relies on
/// the reflection path that NativeAOT does not provide. Static texts are set from
/// Localization in code: x:Uid resource application needs package identity and crashes
/// unpackaged apps, so no x:Uid anywhere.</summary>
public sealed partial class MainWindow : Window
{
    private MainViewModel ViewModel => AppServices.Main;

    private bool _suppressLanguageSelection;

    public MainWindow()
    {
        InitializeComponent();

        Title = Localization.Get("AppTitle");
        AppServices.Initialize(DispatcherQueue);
        AppServices.PinDialog.XamlRoot = Content.XamlRoot;

        BannerText.Text = ViewModel.ElevationBanner;
        Banner.Visibility = ViewModel.IsElevated ? Visibility.Collapsed : Visibility.Visible;

        ApplyLocalizedTexts();
        InitializeLanguageCombo();

        AppServices.UiState.Changed += RefreshStatus;
        RefreshStatus();

        // Initial scan once the window is visible.
        Activated += OnActivated;
    }

    private bool _scanned;

    private void OnActivated(object sender, WindowActivatedEventArgs args)
    {
        if (_scanned || args.WindowActivationState == WindowActivationState.Deactivated)
        {
            return;
        }
        _scanned = true;
        _ = ViewModel.RefreshCommand.ExecuteAsync(null);
    }

    private void ApplyLocalizedTexts()
    {
        DeviceLabel.Text = Localization.Get("DeviceLabel");
        RefreshButton.Content = Localization.Get("RefreshButton");
        LanguageLabel.Text = Localization.Get("LanguageLabel");
        NavDeviceInfo.Content = Localization.Get("NavDeviceInfo");
        NavCredentials.Content = Localization.Get("NavCredentials");
        NavFingerprints.Content = Localization.Get("NavFingerprints");
        NavPin.Content = Localization.Get("NavPin");
        NavPolicy.Content = Localization.Get("NavPolicy");
        NavReset.Content = Localization.Get("NavReset");
    }

    private void Nav_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (args.SelectedItemContainer?.Tag is string tag && int.TryParse(tag, out int index))
        {
            FrameworkElement[] pages = [Page0, Page1, Page2, Page3, Page4, Page5];
            for (int i = 0; i < pages.Length; i++)
            {
                pages[i].Visibility = i == index ? Visibility.Visible : Visibility.Collapsed;
            }
        }
    }

    private void InitializeLanguageCombo()
    {
        // "" = follow the system language.
        string applied = Localization.LoadSavedLanguage() ?? Localization.Auto;
        List<LanguageOption> options =
        [
            new(Localization.Auto, Localization.Get("LanguageAuto")),
            new(Localization.Chinese, "中文"),
            new(Localization.English, "English"),
        ];
        _suppressLanguageSelection = true;
        LanguageCombo.ItemsSource = options;
        LanguageCombo.SelectedIndex = applied switch
        {
            Localization.Chinese => 1,
            Localization.English => 2,
            _ => 0,
        };
        _suppressLanguageSelection = false;
    }

    private async void LanguageCombo_SelectionChanged(object sender, SelectionChangedEventArgs args)
    {
        if (_suppressLanguageSelection || LanguageCombo.SelectedItem is not LanguageOption option)
        {
            return;
        }
        string applied = Localization.LoadSavedLanguage() ?? Localization.Auto;
        if (option.Tag == applied)
        {
            return;
        }

        bool restart = await AppServices.PinDialog.ConfirmAsync(
            Localization.Get("LanguageDialogTitle"),
            Localization.Get("LanguageRestartPrompt"),
            primaryText: Localization.Get("RestartNow"),
            closeText: Localization.Get("Later")).ConfigureAwait(true);
        if (!restart)
        {
            InitializeLanguageCombo(); // revert to the language actually in effect
            return;
        }

        Localization.SaveLanguage(option.Tag);
        Process.Start(new ProcessStartInfo { FileName = Environment.ProcessPath!, UseShellExecute = true });
        Application.Current.Exit();
    }

    private void RefreshStatus()
    {
        UiStateService ui = AppServices.UiState;
        BusyRing.IsActive = ui.IsBusy;
        StatusText.Text = ui.Status;
        StatusText.Foreground = ui.IsError
            ? new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.IndianRed)
            : new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.Gray);
    }
}
