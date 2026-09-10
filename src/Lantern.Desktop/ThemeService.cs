using Microsoft.Win32;
using System.Windows;
using System.Windows.Media;

namespace Lantern.Desktop;

public sealed class ThemeService : IDisposable
{
    private string mode = "System";
    public ThemeService() => SystemEvents.UserPreferenceChanged += OnChanged;
    public void Set(string value) { mode = value; Apply(); }
    private void OnChanged(object sender, UserPreferenceChangedEventArgs e) => Application.Current.Dispatcher.InvokeAsync(Apply);
    private void Apply()
    {
        bool dark = mode == "Dark";
        if (mode == "System")
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            dark = key?.GetValue("AppsUseLightTheme") is int value && value == 0;
        }
        Application.Current.ThemeMode = mode switch { "Dark" => ThemeMode.Dark, "Light" => ThemeMode.Light, _ => ThemeMode.System };
        var colors = dark ? new[] { "#111821", "#1B2533", "#EDF3FA", "#B1C0D4", "#344459", "#60B8FF" }
                          : new[] { "#F5F7FB", "#FFFFFF", "#18263B", "#51617A", "#DFE6EF", "#0078D4" };
        var keys = new[] { "PageBrush", "CardBrush", "InkBrush", "MutedBrush", "LineBrush", "AccentBrush" };
        for (int i = 0; i < keys.Length; i++) Application.Current.Resources[keys[i]] = new SolidColorBrush((Color)ColorConverter.ConvertFromString(colors[i]));
        if (SystemParameters.HighContrast)
        {
            Application.Current.Resources["PageBrush"] = SystemColors.WindowBrush;
            Application.Current.Resources["CardBrush"] = SystemColors.WindowBrush;
            Application.Current.Resources["InkBrush"] = SystemColors.WindowTextBrush;
            Application.Current.Resources["MutedBrush"] = SystemColors.WindowTextBrush;
            Application.Current.Resources["LineBrush"] = SystemColors.WindowTextBrush;
            Application.Current.Resources["AccentBrush"] = SystemColors.HighlightBrush;
        }
    }
    public void Dispose() => SystemEvents.UserPreferenceChanged -= OnChanged;
}
