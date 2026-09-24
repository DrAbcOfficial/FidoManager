using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Fido2.Manager.Services;

/// <summary>
/// PIN entry via a modal ContentDialog. A wrong PIN costs a retry, so the dialog warns
/// explicitly and offers session-only remembering (never persisted).
/// </summary>
public sealed class PinDialogService
{
    public XamlRoot? XamlRoot { get; set; }

    /// <summary>Shows the PIN prompt. Returns the entered PIN, the cached one, or null on cancel.</summary>
    public async Task<string?> GetPinAsync(string purpose, SessionService sessions)
    {
        if (sessions.CachedPin is { } cached)
        {
            return cached;
        }

        XamlRoot? root = XamlRoot ?? App.MainWindow?.Content?.XamlRoot;
        if (root is null)
        {
            return null;
        }

        var pinBox = new PasswordBox
        {
            PlaceholderText = "FIDO2 PIN",
            Margin = new Thickness(0, 4, 0, 0),
        };

        var remember = new CheckBox
        {
            Content = Localization.Get("RememberPinThisSession"),
            IsChecked = true,
            Margin = new Thickness(0, 8, 0, 0),
        };

        var panel = new StackPanel
        {
            Spacing = 4,
            Children =
            {
                new TextBlock
                {
                    Text = purpose,
                    TextWrapping = TextWrapping.Wrap,
                    Foreground = new Microsoft.UI.Xaml.Media.SolidColorBrush(
                        Microsoft.UI.Colors.SaddleBrown),
                },
                pinBox,
                remember,
            },
        };

        var dialog = new ContentDialog
        {
            Title = Localization.Get("PinDialogTitle"),
            Content = panel,
            PrimaryButtonText = Localization.Get("CommonOk"),
            CloseButtonText = Localization.Get("CommonCancel"),
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = root,
        };
        pinBox.KeyDown += (_, args) =>
        {
            if (args.Key == Windows.System.VirtualKey.Enter)
            {
                dialog.Hide();
            }
        };

        ContentDialogResult result = await dialog.ShowAsync();
        string? pin = result == ContentDialogResult.Primary ? pinBox.Password : null;
        if (pin is not null && remember.IsChecked == true)
        {
            sessions.RememberPin(pin);
        }
        return pin;
    }

    /// <summary>Simple text prompt (fingerprint names are not secret). Returns null on cancel/empty.</summary>
    public async Task<string?> PromptTextAsync(string title, string label, string? preset = null)
    {
        XamlRoot? root = XamlRoot ?? App.MainWindow?.Content?.XamlRoot;
        if (root is null)
        {
            return null;
        }

        var input = new TextBox
        {
            PlaceholderText = label,
            Text = preset ?? "",
            Margin = new Thickness(0, 4, 0, 0),
        };
        var dialog = new ContentDialog
        {
            Title = title,
            Content = input,
            PrimaryButtonText = Localization.Get("CommonOk"),
            CloseButtonText = Localization.Get("CommonCancel"),
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = root,
        };
        return await dialog.ShowAsync() == ContentDialogResult.Primary ? input.Text : null;
    }

    /// <summary>Yes/no confirmation for destructive operations. Button texts default to
    /// 确认/取消 and can be overridden (e.g. the language restart prompt).</summary>
    public async Task<bool> ConfirmAsync(string title, string message,
        string? primaryText = null, string? closeText = null)
    {
        XamlRoot? root = XamlRoot ?? App.MainWindow?.Content?.XamlRoot;
        if (root is null)
        {
            return false;
        }
        var dialog = new ContentDialog
        {
            Title = title,
            Content = message,
            PrimaryButtonText = primaryText ?? Localization.Get("CommonConfirm"),
            CloseButtonText = closeText ?? Localization.Get("CommonCancel"),
            DefaultButton = ContentDialogButton.Close,
            XamlRoot = root,
        };
        return await dialog.ShowAsync() == ContentDialogResult.Primary;
    }

    public async Task NotifyAsync(string title, string message)
    {
        XamlRoot? root = XamlRoot ?? App.MainWindow?.Content?.XamlRoot;
        if (root is null)
        {
            return;
        }
        var dialog = new ContentDialog
        {
            Title = title,
            Content = message,
            CloseButtonText = Localization.Get("CommonClose"),
            XamlRoot = root,
        };
        await dialog.ShowAsync();
    }
}
