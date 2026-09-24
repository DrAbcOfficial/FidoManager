using Fido2.Manager.Services;
using Fido2.Manager.ViewModels;
using Microsoft.UI.Xaml.Controls;

namespace Fido2.Manager.Views;

public sealed partial class CredentialsPage : UserControl
{
    public CredentialsViewModel ViewModel => AppServices.Credentials;

    public CredentialsPage()
    {
        InitializeComponent();
        ListButton.Content = Localization.Get("CredsListButton");
        DeleteButton.Content = Localization.Get("CredsDeleteButton");
    }
}
