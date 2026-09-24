using Fido2.Core;
using Fido2.Manager.Services;
using Microsoft.UI.Xaml;

namespace Fido2.Manager;

public partial class App : Application
{
    public static Window? MainWindow { get; private set; }

    public App()
    {
        InitializeComponent();
    }

    protected override void OnLaunched(Microsoft.UI.Xaml.LaunchActivatedEventArgs args)
    {
        // Localization initializes on first use (pins the language ResourceContext);
        // this only repoints the Core library's fallback display string.
        CoreStrings.Unnamed = Localization.Get("Unnamed");

        MainWindow = new MainWindow();
        MainWindow.Activate();
    }
}
