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
    }
}
