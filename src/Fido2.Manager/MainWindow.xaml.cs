using Fido2.Manager.Services;
using Fido2.Manager.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Fido2.Manager;

/// <summary>Navigation shell. Pages are instantiated once in XAML and switched by
/// Visibility — deliberately avoiding Frame.Navigate, whose type resolution relies on
/// the reflection path that NativeAOT does not provide.</summary>
public sealed partial class MainWindow : Window
{
    private MainViewModel ViewModel => AppServices.Main;

    public MainWindow()
    {
        InitializeComponent();

        Title = "FIDO2 管理工具";
        AppServices.Initialize(DispatcherQueue);
        AppServices.PinDialog.XamlRoot = Content.XamlRoot;

        BannerText.Text = ViewModel.ElevationBanner;
        Banner.Visibility = ViewModel.IsElevated ? Visibility.Collapsed : Visibility.Visible;

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
