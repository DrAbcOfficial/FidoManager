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
        CheckButtonText.Text = Localization.Get("PinCheckButton");
        ApplyButtonText.Text = Localization.Get("PinApplyButton");
        OldPinBox.Header = Localization.Get("PinCurrentLabel");
        NewPinBox.Header = Localization.Get("PinNewLabel");
        NewPinBox.PlaceholderText = Localization.Get("PinNewHint");
        ConfirmPinBox.Header = Localization.Get("PinConfirmLabel");
    }
}
