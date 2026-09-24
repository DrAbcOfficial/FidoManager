using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Fido2.Core.Ctap2;
using Fido2.Manager.Services;

namespace Fido2.Manager.ViewModels;

public sealed record NameValueRow(string Name, string Value);

/// <summary>Info page: fills the property grid from the session's cached getInfo plus
/// PIN state and the vendor serial (when the transport can read one).</summary>
public partial class DeviceInfoViewModel : ObservableObject
{
    private static UiStateService UiState => AppServices.UiState;

    public DeviceInfoViewModel()
    {
        Summary = "未选择设备";
    }

    public ObservableCollection<NameValueRow> Rows { get; } = [];

    [ObservableProperty]
    public partial string Summary { get; set; }

    [RelayCommand]
    public async Task OnSessionOpenedAsync()
    {
        var session = AppServices.Sessions.Current;
        if (session is null)
        {
            Rows.Clear();
            Summary = "未选择设备";
            return;
        }

        UiState.IsBusy = true;
        try
        {
            var info = session.Info;
            Rows.Clear();
            Rows.Add(new NameValueRow("设备", session.DisplayName));
            if (session.VendorSerial is { } serial)
            {
                Rows.Add(new NameValueRow("串号(厂商)", serial));
            }
            Rows.Add(new NameValueRow("版本", string.Join(", ", info.Versions)));
            Rows.Add(new NameValueRow("AAGUID", info.Aaguid));
            Rows.Add(new NameValueRow("扩展", string.Join(", ", info.Extensions)));
            Rows.Add(new NameValueRow("最大消息大小", $"{info.MaxMessageSize} 字节"));
            Rows.Add(new NameValueRow("PIN 协议", string.Join(", ", info.PinUvAuthProtocols)));
            Rows.Add(new NameValueRow("最小 PIN 长度", info.MinPinLength.ToString()));
            Rows.Add(new NameValueRow("固件版本", info.FirmwareVersion.ToString()));
            Rows.Add(new NameValueRow("传输", session.Transport.GetType().Name.Replace("Transport", "")));

            PinState state = await session.GetPinStateAsync(CancellationToken.None).ConfigureAwait(true);
            Rows.Add(new NameValueRow("PIN", state.IsSet ? $"已设置(剩余 {state.RetriesRemaining} 次重试)" : "未设置"));

            Rows.Add(new NameValueRow("能力", info.Options.Summary));

            Summary = $"{session.DisplayName} — {string.Join(" | ", DescribeCapabilities(info))}";
            UiState.SetMessage("设备信息已加载");
        }
        catch (Exception ex)
        {
            AppServices.Sessions.ClearPinOnError(ex);
            UiState.SetError($"读取设备信息失败:{ex.Message}");
        }
        finally
        {
            UiState.IsBusy = false;
        }
    }

    private static IEnumerable<string> DescribeCapabilities(Fido2.Core.Ctap2.AuthenticatorInfo info)
    {
        if (info.SupportsFido21)
        {
            yield return "FIDO 2.1";
        }
        if (info.Options.ClientPin == true)
        {
            yield return "PIN 已设置";
        }
        else if (info.Options.ClientPin == false)
        {
            yield return "无 PIN";
        }
        if (info.Options.SupportsBioEnrollment)
        {
            yield return "指纹";
        }
        if (info.Options.SupportsCredentialManagement)
        {
            yield return "凭据管理";
        }
        if (info.Options.AuthenticatorConfig == true)
        {
            yield return "策略配置";
        }
        if (info.ForcePinChange)
        {
            yield return "要求改 PIN";
        }
    }
}
