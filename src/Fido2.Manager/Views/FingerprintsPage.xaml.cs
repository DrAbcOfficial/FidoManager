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
        ListButtonText.Text = Localization.Get("BioListButton");
        EnrollButtonText.Text = Localization.Get("BioEnrollButton");
        RenameButtonText.Text = Localization.Get("BioRenameButton");
        DeleteButtonText.Text = Localization.Get("BioDeleteButton");
    }
}
