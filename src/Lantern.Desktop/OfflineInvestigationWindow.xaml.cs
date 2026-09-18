using System.Diagnostics;
using System.Windows;
using Microsoft.Win32;

namespace Lantern.Desktop;

public partial class OfflineInvestigationWindow : Window
{
    public string SelectedFile => FileBox.Text;
    public OfflineInvestigationWindow() => InitializeComponent();
    private void Browse(object sender, RoutedEventArgs e)
    {
        var picker = new OpenFileDialog { Title = "Select full sign-in JSON", Filter = "Sign-in JSON (*.json)|*.json", CheckFileExists = true };
        if (picker.ShowDialog(this) != true) return;
        FileBox.Text = picker.FileName;
        AnalyzeButton.IsEnabled = true;
    }
    private void Analyze(object sender, RoutedEventArgs e) => DialogResult = true;
    private void OpenPortal(object sender, RoutedEventArgs e)
    {
        try { Process.Start(new ProcessStartInfo("https://entra.microsoft.com") { UseShellExecute = true }); }
        catch (System.ComponentModel.Win32Exception) { ErrorLabel.Text = "Open https://entra.microsoft.com in your browser."; }
    }
}
