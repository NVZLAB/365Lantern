using System.IO;
using System.Net.Http;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Identity.Client;
using Microsoft.Win32;
using Lantern.Core;

namespace Lantern.Desktop;

public partial class MainWindow : Window
{
    private readonly ThemeService themes = new();
    private readonly TenantSession session = new();
    private readonly HttpClient http = new(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false })
        { Timeout = TimeSpan.FromSeconds(60), MaxResponseContentBufferSize = 16 * 1024 * 1024 };
    private Investigation? investigation;
    private CancellationTokenSource? operation;
    private string page = "Overview";
    private bool closing;

    public MainWindow()
    {
        InitializeComponent();
        themes.Set("System");
        Loaded += async (_, _) =>
        {
            var args = Environment.GetCommandLineArgs();
            if (args.Length == 3 && args[1] == "--smoke-test") await RunSmokeTest(args[2]);
        };
        Closing += async (_, e) =>
        {
            if (closing) return;
            e.Cancel = true; closing = true;
            await Task.Yield(); // Leave the original Closing callback before issuing Close again.
            operation?.Cancel(); ClearInvestigation();
            try { await session.DisconnectAsync(); }
            finally { themes.Dispose(); http.Dispose(); Close(); }
        };
    }

    private int Days => int.Parse(((ComboBoxItem)DaysPicker.SelectedItem).Tag.ToString()!);
    private void ThemeChanged(object sender, SelectionChangedEventArgs e)
    {
        if (IsInitialized && ThemePicker.SelectedItem is ComboBoxItem item) themes.Set(item.Content.ToString()!);
    }
    private void Navigate(object sender, RoutedEventArgs e)
    {
        page = (string)((Button)sender).Tag;
        PageTitle.Text = page == "Overview" ? "Tenant overview" : page;
        ConnectionPanel.Visibility = page == "Connect tenant" ? Visibility.Visible : Visibility.Collapsed;
        ResponsePanel.Visibility = page == "Response" ? Visibility.Visible : Visibility.Collapsed;
        InvestigationPanel.Visibility = page is "Response" or "Connect tenant" ? Visibility.Collapsed : Visibility.Visible;
        RefreshFindings();
    }
    private void SetBusy(bool busy)
    {
        DemoButton.IsEnabled = ConnectButton.IsEnabled = DisconnectButton.IsEnabled = !busy;
        CollectButton.IsEnabled = !busy && session.IsConnected;
        CancelButton.IsEnabled = busy;
        ExportButton.IsEnabled = !busy && investigation is not null;
        AccountBox.IsEnabled = DaysPicker.IsEnabled = ClientIdBox.IsEnabled = TenantIdBox.IsEnabled = !busy;
    }
    private async void RunDemo(object sender, RoutedEventArgs e)
    {
        await session.DisconnectAsync();
        ClientIdBox.Clear(); TenantIdBox.Clear();
        AccountBox.Text = "alex@example.com";
        ShowInvestigation(DemoInvestigation.Run(DateTimeOffset.UtcNow, Days));
        SessionLabel.Text = "Northwind Demo · SYNTHETIC";
        SetBusy(false);
        StatusLabel.Text = "Synthetic demo complete. No network calls or tenant changes were made.";
    }
    private async void Connect(object sender, RoutedEventArgs e)
    {
        ClearInvestigation();
        operation = new CancellationTokenSource(TimeSpan.FromMinutes(5)); SetBusy(true);
        StatusLabel.Text = "Complete sign-in in your browser. You can cancel here.";
        try
        {
            await session.ConnectAsync(ClientIdBox.Text.Trim(), TenantIdBox.Text.Trim(), operation.Token);
            SessionLabel.Text = "Connected · Read-only";
            StatusLabel.Text = $"Connected to tenant {session.TenantId}. Choose an account to collect sign-ins.";
        }
        catch (OperationCanceledException) { StatusLabel.Text = "Sign-in canceled or timed out. No tenant changes made."; }
        catch (ArgumentException ex) { StatusLabel.Text = ex.Message; }
        catch (MsalException) { StatusLabel.Text = "Sign-in could not complete. Check the app registration, consent and tenant access, then retry."; }
        catch (Exception) { StatusLabel.Text = "Connection failed. No credentials or diagnostic response bodies were saved."; }
        finally
        {
            if (!session.IsConnected) SessionLabel.Text = "Not connected";
            operation.Dispose(); operation = null; SetBusy(false);
        }
    }
    private async void Collect(object sender, RoutedEventArgs e)
    {
        ClearInvestigation();
        operation = new CancellationTokenSource(); SetBusy(true);
        StatusLabel.Text = "Collecting sign-ins into memory…";
        try
        {
            var now = DateTimeOffset.UtcNow;
            var result = await new GraphCollector(http, session.GetTokenAsync)
                .CollectAsync(session.TenantId!, AccountBox.Text.Trim(), now.AddDays(-Days), now, operation.Token);
            if (!closing) { ShowInvestigation(result); StatusLabel.Text = "Collection finished. Review coverage before interpreting findings."; }
        }
        catch (OperationCanceledException) { StatusLabel.Text = "Collection canceled; in-progress results discarded."; }
        catch (ArgumentException ex) { StatusLabel.Text = ex.Message; }
        catch (MsalException) { StatusLabel.Text = "Authentication requires attention. Clear the session and reconnect."; }
        catch (Exception) { StatusLabel.Text = "Collection failed. No result was saved. Reconnect and retry."; }
        finally { operation.Dispose(); operation = null; SetBusy(false); }
    }
    private void Cancel(object sender, RoutedEventArgs e) => operation?.Cancel();
    private async void Disconnect(object sender, RoutedEventArgs e)
    {
        ClearInvestigation(); AccountBox.Clear(); ClientIdBox.Clear(); TenantIdBox.Clear();
        await session.DisconnectAsync();
        SessionLabel.Text = "Not connected"; SetBusy(false);
        StatusLabel.Text = "App session cleared. Exported files and browser sign-in are unchanged.";
    }
    private void ClearInvestigation()
    {
        investigation = null; FindingsList.ItemsSource = null; CoverageList.ItemsSource = null;
        FindingDetail.Text = ""; RawEvidence.Clear(); RawPanel.Visibility = Visibility.Collapsed;
        SummaryLabel.Text = "Ready when you are"; ScopeLabel.Text = "Run a synthetic demo or collect from your connected tenant.";
        ExportButton.IsEnabled = false;
    }
    private void ShowInvestigation(Investigation value)
    {
        investigation = value;
        SummaryLabel.Text = $"{value.Findings.Count} findings to review · {value.Coverage.Count(c => c.Status != "Complete")} collection gaps";
        ScopeLabel.Text = $"{(value.IsDemo ? "SYNTHETIC DATA" : "LIVE DATA")} · {value.Account} · {value.StartUtc:yyyy-MM-dd HH:mm} – {value.EndUtc:yyyy-MM-dd HH:mm} UTC";
        CoverageList.ItemsSource = value.Coverage; ExportButton.IsEnabled = true; RefreshFindings();
    }
    private void RefreshFindings()
    {
        if (investigation is null) return;
        FindingsList.ItemsSource = investigation.Findings.Where(f => page switch
        { "Sign-ins" => f.Source == "Entra sign-ins", "Mailbox rules" => f.Source.Contains("Exchange"), _ => true }).ToArray();
        FindingDetail.Text = "Select a finding to see its explanation. No matching indicators does not establish that an account is safe.";
        RawPanel.Visibility = page == "Evidence" ? Visibility.Visible : Visibility.Collapsed;
        RawEvidence.Text = page == "Evidence" ? JsonSerializer.Serialize(investigation.Evidence, new JsonSerializerOptions { WriteIndented = true }) : "";
    }
    private void FindingSelected(object sender, SelectionChangedEventArgs e)
    {
        if (FindingsList.SelectedItem is not Finding finding || investigation is null) return;
        FindingDetail.Text = finding.Explanation;
        RawEvidence.Text = investigation.Evidence.FirstOrDefault(x => x.Id == finding.EvidenceId)?.Data.ToString() ?? "Evidence unavailable.";
        RawPanel.Visibility = Visibility.Visible;
    }
    private void Export(object sender, RoutedEventArgs e)
    {
        if (investigation is null) return;
        var preview = $"{(investigation.IsDemo ? "SYNTHETIC DEMO" : "LIVE TENANT DATA")}\n\nAccount: {investigation.Account}\n{investigation.Evidence.Count} raw records; {investigation.Findings.Count} findings.\n\nThe ZIP contains evidence.json, summary.txt and a SHA-256 manifest. Raw evidence may include names, IP addresses and other personal data. This preview does not redact records.\n\nChoose a local file destination?";
        if (MessageBox.Show(this, preview, "Review evidence export", MessageBoxButton.OKCancel, MessageBoxImage.Information) != MessageBoxResult.OK) return;
        var dialog = new SaveFileDialog { Title = "Save evidence locally", Filter = "Evidence archive (*.zip)|*.zip", FileName = $"365Lantern-{(investigation.IsDemo ? "demo-" : "")}{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}.zip", OverwritePrompt = true };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            var bytes = EvidenceExport.Create(investigation);
            File.WriteAllBytes(dialog.FileName, bytes);
            StatusLabel.Text = "Evidence archive saved to your chosen destination. Treat it as sensitive case material.";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        { StatusLabel.Text = "Export failed. Check the destination; a partial file may exist."; }
    }
    private async Task RunSmokeTest(string directory)
    {
        // Explicit developer-only invocation; exclusively synthetic data. No auth is started.
        Directory.CreateDirectory(directory);
        RunDemo(this, new RoutedEventArgs());
        foreach (var theme in new[] { "Light", "Dark" })
        {
            themes.Set(theme); UpdateLayout(); await Task.Delay(150);
            var surface = (FrameworkElement)Content;
            var bitmap = new System.Windows.Media.Imaging.RenderTargetBitmap((int)surface.ActualWidth, (int)surface.ActualHeight, 96, 96, System.Windows.Media.PixelFormats.Pbgra32);
            bitmap.Render(surface);
            var png = new System.Windows.Media.Imaging.PngBitmapEncoder(); png.Frames.Add(System.Windows.Media.Imaging.BitmapFrame.Create(bitmap));
            using var file = File.Create(Path.Combine(directory, theme.ToLowerInvariant() + ".png")); png.Save(file);
        }
        if (investigation?.Findings.Count != 2 || !ExportButton.IsEnabled) throw new InvalidOperationException("Demo UI failed.");
        await session.DisconnectAsync(); ClearInvestigation();
        if (FindingsList.ItemsSource is not null || RawEvidence.Text.Length != 0 || ExportButton.IsEnabled) throw new InvalidOperationException("Clear UI failed.");
        File.WriteAllText(Path.Combine(directory, "smoke-result.txt"), "PASS: demo findings, light/dark renders, and clearing investigation UI.");
        Close();
    }
}
