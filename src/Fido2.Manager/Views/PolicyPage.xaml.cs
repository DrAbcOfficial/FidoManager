using Fido2.Manager.Services;
using Fido2.Manager.ViewModels;
using Microsoft.UI.Xaml.Controls;

namespace Fido2.Manager.Views;

public sealed partial class PolicyPage : UserControl
{
    public PolicyViewModel ViewModel => AppServices.Policy;

    public PolicyPage()
    {
        InitializeComponent();
        AlwaysUvTitle.Text = Localization.Get("PolicyAlwaysUvTitle");
        AlwaysUvDesc.Text = Localization.Get("PolicyAlwaysUvDesc");
        MinPinTitle.Text = Localization.Get("PolicyMinPinTitle");
        MinPinDesc.Text = Localization.Get("PolicyMinPinDesc");
        ApplyMinPinButton.Content = Localization.Get("PolicyApplyMinPinButton");
        ForceChangeTitle.Text = Localization.Get("PolicyForceChangeTitle");
        ForceChangeDesc.Text = Localization.Get("PolicyForceChangeDesc");
        ForceChangeButton.Content = Localization.Get("PolicyForceChangeButton");
    }
}
