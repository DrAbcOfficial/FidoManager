using Fido2.Manager.Services;
using Fido2.Manager.ViewModels;
using Microsoft.UI.Xaml.Controls;

namespace Fido2.Manager.Views;

public sealed partial class PinPage : UserControl
{
    public PinViewModel ViewModel => AppServices.Pin;

    public PinPage()
    {
        InitializeComponent();
        CheckButton.Content = Localization.Get("PinCheckButton");
        CurrentLabel.Text = Localization.Get("PinCurrentLabel");
        NewLabel.Text = Localization.Get("PinNewLabel");
        ConfirmLabel.Text = Localization.Get("PinConfirmLabel");
        ApplyButton.Content = Localization.Get("PinApplyButton");
    }
}
