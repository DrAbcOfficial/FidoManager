using Fido2.Manager.Services;
using Fido2.Manager.ViewModels;
using Microsoft.UI.Xaml.Controls;

namespace Fido2.Manager.Views;

public sealed partial class FingerprintsPage : UserControl
{
    public FingerprintsViewModel ViewModel => AppServices.Fingerprints;

    public FingerprintsPage()
    {
        InitializeComponent();
        ListButton.Content = Localization.Get("BioListButton");
        EnrollButton.Content = Localization.Get("BioEnrollButton");
        RenameButton.Content = Localization.Get("BioRenameButton");
        DeleteButton.Content = Localization.Get("BioDeleteButton");
    }
}
