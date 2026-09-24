using System.Diagnostics;
using Fido2.Manager.Services;
using Fido2.Manager.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.Graphics;

namespace Fido2.Manager;

/// <summary>Navigation shell. Pages are instantiated once in XAML and switched by
/// Visibility — deliberately avoiding Frame.Navigate, whose type resolution relies on
/// the reflection path that NativeAOT does not provide. Static texts are set from
/// Localization in code: x:Uid resource application needs package identity and crashes
/// unpackaged apps, so no x:Uid anywhere.</summary>
public sealed partial class MainWindow : Window
{
    private MainViewModel ViewModel => AppServices.Main;

    private bool _suppressLanguageSelection;
    private bool _scanned;

    public MainWindow()
    {
        InitializeComponent();

        Title = Localization.Get("AppTitle");
        AppTitleBar.Title = Title;
        // Acrylic material: everything above it must stay on the theme's layer/card
        // brushes, otherwise the backdrop is painted over and the window looks flat.
        SystemBackdrop = new DesktopAcrylicBackdrop();
        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);
        AppWindow.Resize(new SizeInt32(1020, 720));

        AppServices.Initialize(DispatcherQueue);

        ApplyLocalizedTexts();
        InitializeLanguageMenu();

        AppServices.UiState.Changed += RefreshStatus;
        RefreshStatus();

        // Initial scan once the window is visible.
        Activated += OnActivated;
    }

    private void OnActivated(object sender, WindowActivatedEventArgs args)
    {
        if (args.WindowActivationState == WindowActivationState.Deactivated)
        {
            return;
        }
        // XamlRoot only exists once the content is attached to a live window.
        AppServices.PinDialog.XamlRoot = Content.XamlRoot;
        if (_scanned)
        {
            return;
        }
        _scanned = true;
        _ = ViewModel.RefreshCommand.ExecuteAsync(null);
    }

    private void ApplyLocalizedTexts()
    {
        DeviceCombo.PlaceholderText = Localization.Get("SelectDevicePrompt");
        ToolTipService.SetToolTip(RefreshButton, Localization.Get("RefreshButton"));
        ElevationBar.Title = Localization.Get("BannerNotElevatedTitle");
        NavDeviceInfo.Content = Localization.Get("NavDeviceInfo");
        NavCredentials.Content = Localization.Get("NavCredentials");
        NavFingerprints.Content = Localization.Get("NavFingerprints");
        NavPin.Content = Localization.Get("NavPin");
        NavPolicy.Content = Localization.Get("NavPolicy");
        NavReset.Content = Localization.Get("NavReset");
    }

    private void Nav_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        // SelectedItem (the NavigationViewItem itself) rather than SelectedItemContainer:
        // the container can be a recycled element whose Tag belongs to another item.
        if (args.SelectedItem is NavigationViewItem { Tag: string tag } && int.TryParse(tag, out int index))
        {
            FrameworkElement[] pages = [Page0, Page1, Page2, Page3, Page4, Page5];
            for (int i = 0; i < pages.Length; i++)
            {
                pages[i].Visibility = i == index ? Visibility.Visible : Visibility.Collapsed;
            }
        }
    }

    private void InitializeLanguageMenu()
    {
        // "" = follow the system language.
        string applied = Localization.LoadSavedLanguage() ?? Localization.Auto;
        RadioMenuFlyoutItem[] items = [LanguageAutoItem, LanguageZhItem, LanguageEnItem];
        string[] tags = [Localization.Auto, Localization.Chinese, Localization.English];
        string[] labels =
        [
            Localization.Get("LanguageAuto"),
            Localization.Get("LanguageChinese"),
            Localization.Get("LanguageEnglish"),
        ];

        _suppressLanguageSelection = true;
        for (int i = 0; i < items.Length; i++)
        {
            items[i].Tag = tags[i];
            items[i].Text = labels[i];
            items[i].IsChecked = tags[i] == applied;
        }
        _suppressLanguageSelection = false;
    }

    private async void LanguageItem_Click(object sender, RoutedEventArgs args)
    {
        if (_suppressLanguageSelection || sender is not RadioMenuFlyoutItem item || item.Tag is not string tag)
        {
            return;
        }
        string applied = Localization.LoadSavedLanguage() ?? Localization.Auto;
        if (tag == applied)
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
            InitializeLanguageMenu(); // revert to the language actually in effect
            return;
        }

        Localization.SaveLanguage(tag);
        Process.Start(new ProcessStartInfo { FileName = Environment.ProcessPath!, UseShellExecute = true });
        Application.Current.Exit();
    }

    private void RefreshStatus()
    {
        UiStateService ui = AppServices.UiState;
        BusyRing.IsActive = ui.IsBusy;
        StatusText.Text = ui.Status;
        StatusErrorIcon.Visibility = ui.IsError ? Visibility.Visible : Visibility.Collapsed;
    }
}
