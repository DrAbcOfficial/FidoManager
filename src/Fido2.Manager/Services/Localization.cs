using System.Runtime.InteropServices;
using Microsoft.Windows.ApplicationModel.Resources;
namespace Fido2.Manager.Services;

/// <summary>UI strings from the app's Resources.resw (Strings\zh-Hans / Strings\en-US), read
/// via MRT Core — works unpackaged and under NativeAOT because PRI is resolved natively.
///
/// Language selection uses a dedicated ResourceContext whose Language qualifier is pinned
/// to the chosen language. ApplicationLanguages.PrimaryLanguageOverride is NOT an option
/// here: its setter requires package identity and crashes an unpackaged app (0x80073D54),
/// while explicit ResourceContexts are the documented MRT Core pattern for unpackaged use.
/// With no saved choice, the OS UI culture picks zh-Hans or English (en fallback).
/// Switching languages in-app asks for a restart: view models snapshot their strings and
/// the pages set their static texts once on construction. Settings live in
/// %LOCALAPPDATA%\Fido2Manager because unpackaged apps have no roaming store.</summary>
public static class Localization
{
    private static readonly ResourceManager Manager = new();
    private static readonly string SettingsFile = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Fido2Manager", "language.txt");

    public const string Auto = "";
    public const string Chinese = "zh-Hans";
    public const string English = "en-US";

    private static ResourceContext Context { get; } = CreateContext(LoadSavedLanguage() ?? Auto);

    /// <summary>Subtree generated from Resources.resw. ResourceLoader() is implicitly bound
    /// to this map; with a raw ResourceManager the keys must be resolved through it.</summary>
    private static readonly ResourceMap ResourcesMap = Manager.MainResourceMap.GetSubtree("Resources");

    /// <summary>The effective language ("zh-Hans"/"en-US") the context is pinned to.</summary>
    public static string CurrentLanguage => Context.QualifierValues.TryGetValue("Language", out string? v)
        ? v : Auto;

    private static ResourceContext CreateContext(string language)
    {
        var context = Manager.CreateResourceContext();
        context.QualifierValues["Language"] = language switch
        {
            Chinese => Chinese,
            English => English,
            _ => MatchSystemLanguage(),
        };
        return context;
    }

    // InvariantGlobalization=true makes CultureInfo.CurrentUICulture unreliable (it stops
    // tracking the OS UI language), so ask Windows directly: primary LANGID 0x0004 = Chinese.
    [DllImport("Kernel32", ExactSpelling = true)]
    private static extern ushort GetUserDefaultUILanguage();

    private static string MatchSystemLanguage()
    {
        ushort primary = (ushort)(GetUserDefaultUILanguage() & 0x03FF);
        return primary == 0x0004 ? Chinese : English;
    }

    /// <summary>Value for a key in the selected language; null when missing
    /// (PRI falls back to the default language first, so this only guards typos).</summary>
    public static string? TryGet(string key)
    {
        try
        {
            string? value = ResourcesMap.GetValue(key, Context)?.ValueAsString;
            return string.IsNullOrEmpty(value) ? null : value;
        }
        catch (COMException)
        {
            // "NamedResource not found" for unknown keys
            return null;
        }
    }

    /// <summary>Value for a key in the selected language; the key itself when missing.</summary>
    public static string Get(string key) => TryGet(key) ?? key;

    public static string Format(string key, params object?[] args) => string.Format(Get(key), args);

    /// <summary>The language saved by the in-app switcher ("zh-Hans"/"en-US"), or null for auto.</summary>
    public static string? LoadSavedLanguage()
    {
        try
        {
            return File.ReadAllText(SettingsFile).Trim() switch
            {
                Chinese => Chinese,
                English => English,
                _ => null,
            };
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
    }

    public static void SaveLanguage(string? language)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(SettingsFile)!);
            if (language is null or Auto)
            {
                File.Delete(SettingsFile);
            }
            else
            {
                File.WriteAllText(SettingsFile, language);
            }
        }
        catch (IOException)
        {
            // best-effort persistence; an unwritable profile must not break the switch
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
