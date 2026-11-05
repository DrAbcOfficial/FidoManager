using System.Text;
using Fido2.Core.Credentials;
using Fido2.Core.Ctap2;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.ApplicationModel.DataTransfer;
using Windows.Storage;
using Windows.Storage.Pickers;

namespace Fido2.Manager.Services;

/// <summary>
/// Shows an exported OpenSSH FIDO public key with copy/save actions. Public keys are not
/// secret, so no confirmation is needed — the line is only kept read-only so it is copied
/// verbatim. Saving writes the same single line ssh-keygen would put in a .pub file.
/// </summary>
public sealed class ExportDialogService
{
    public async Task ShowOpenSshKeyAsync(ResidentCredential credential, string keyLine, string fingerprint)
    {
        XamlRoot? root = AppServices.PinDialog.XamlRoot ?? App.MainWindow?.Content?.XamlRoot;
        if (root is null)
        {
            return;
        }

        var keyBox = new TextBox
        {
            Text = keyLine,
            IsReadOnly = true,
            TextWrapping = TextWrapping.Wrap,
            MinWidth = 460,
            MaxHeight = 120,
            FontFamily = new FontFamily("Consolas"),
        };
        var fingerprintText = new TextBlock
        {
            Text = Localization.Format("ExportSshFingerprint", fingerprint),
            FontFamily = new FontFamily("Consolas"),
            Opacity = 0.75,
            TextWrapping = TextWrapping.Wrap,
        };
        var hint = new TextBlock
        {
            Text = Localization.Get("ExportSshHint"),
            TextWrapping = TextWrapping.Wrap,
        };

        var panel = new StackPanel { Spacing = 10 };
        panel.Children.Add(keyBox);
        panel.Children.Add(fingerprintText);
        panel.Children.Add(hint);
        if (!string.Equals(credential.RpId, OpenSshPublicKey.SshApplication, StringComparison.Ordinal))
        {
            // Still a valid key line, but OpenSSH only looks credentials up under "ssh:".
            panel.Children.Add(new TextBlock
            {
                Text = Localization.Format("ExportSshWrongRp", credential.RpId),
                TextWrapping = TextWrapping.Wrap,
            });
        }

        var dialog = new ContentDialog
        {
            Title = Localization.Get("ExportSshTitle"),
            Content = panel,
            PrimaryButtonText = Localization.Get("ExportSshCopyButton"),
            SecondaryButtonText = Localization.Get("ExportSshSaveButton"),
            CloseButtonText = Localization.Get("CommonClose"),
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = root,
        };

        ContentDialogResult result = await dialog.ShowAsync();
        if (result == ContentDialogResult.Primary)
        {
            Copy(keyLine);
            AppServices.UiState.SetMessage(Localization.Get("ExportSshCopied"));
        }
        else if (result == ContentDialogResult.Secondary)
        {
            await SaveAsync(credential, keyLine);
        }
    }

    private static void Copy(string keyLine)
    {
        var package = new DataPackage();
        package.SetText(keyLine);
        Clipboard.SetContent(package);
        try
        {
            // Keeps the clipboard alive after this window closes.
            Clipboard.Flush();
        }
        catch (Exception)
        {
            // Flush is best-effort; the content is already set.
        }
    }

    private static async Task SaveAsync(ResidentCredential credential, string keyLine)
    {
        if (App.MainWindow is null)
        {
            return;
        }

        var picker = new FileSavePicker
        {
            SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
            SuggestedFileName = credential.PublicKey?.IsEd25519 == true ? "id_ed25519_sk" : "id_ecdsa_sk",
        };
        picker.FileTypeChoices.Add(Localization.Get("ExportSshFileType"), [".pub"]);
        WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(App.MainWindow));

        StorageFile? file = await picker.PickSaveFileAsync();
        if (file is null)
        {
            return;
        }

        // No BOM and a trailing newline: exactly what ssh-keygen writes for a .pub file.
        await File.WriteAllTextAsync(file.Path, keyLine + "\n", new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        AppServices.UiState.SetMessage(Localization.Format("ExportSshSaved", file.Path));
    }
}
