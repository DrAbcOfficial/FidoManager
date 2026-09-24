using Fido2.Manager.Services;
using Fido2.Manager.ViewModels;
using Microsoft.UI.Xaml.Controls;

namespace Fido2.Manager.Views;

public sealed partial class ResetPage : UserControl
{
    public ResetViewModel ViewModel => AppServices.Reset;

    public ResetPage()
    {
        InitializeComponent();
    }
}
