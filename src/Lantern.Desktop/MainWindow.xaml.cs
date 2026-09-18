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
    private SignInDiagnostics? diagnostics;
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
        ShowPage((string)((Button)sender).Tag);
    }
    private void ShowPage(string name)
    {
        page = name;
        PageTitle.Text = page == "Overview" ? "Tenant overview" : page;
        ConnectionPanel.Visibility = page == "Connect tenant" ? Visibility.Visible : Visibility.Collapsed;
        ResponsePanel.Visibility = page == "Response" ? Visibility.Visible : Visibility.Collapsed;
        InvestigationPanel.Visibility = page is "Response" or "Connect tenant" ? Visibility.Collapsed : Visibility.Visible;
        RefreshFindings();
    }
    private void ShowConnected(string tenant, string? operatorUpn)
    {
        SessionLabel.Text = "Connected · Read-only";
        AccountBox.Text = operatorUpn ?? "";
        ShowPage("Overview");
        SummaryLabel.Text = "Connected. Ready to investigate.";
        ScopeLabel.Text = "Confirm the account and time range, then select Investigate account. Signing in does not collect evidence.";
        StatusLabel.Text = $"Connected to tenant {tenant}. No tenant changes made.";
        AccountBox.Focus();
    }
    private void SetBusy(bool busy)
    {
        OfflineButton.IsEnabled = ConnectButton.IsEnabled = DisconnectButton.IsEnabled = !busy;
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
            if (!closing) ShowConnected(session.TenantId!, session.Operator);
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
        StatusLabel.Text = "Collecting sign-ins and Exchange configuration into memory…";
        try
        {
            var now = DateTimeOffset.UtcNow;
            var result = await new GraphCollector(http, session.GetTokenAsync)
                .CollectAsync(session.TenantId!, AccountBox.Text.Trim(), now.AddDays(-Days), now, operation.Token);
            StatusLabel.Text = "Checking Exchange access; complete browser sign-in if prompted…";
            var exchange = await new ExchangeCollector().CollectAsync(session, AccountBox.Text.Trim(), operation.Token);
            result = result with { Evidence = result.Evidence.Concat(exchange.Evidence).ToArray(), Findings = result.Findings.Concat(exchange.Findings).ToArray(), Coverage = result.Coverage.Where(c => c.Source == "Entra sign-ins").Concat(exchange.Coverage).ToArray() };
            if (!closing) { ShowInvestigation(result); StatusLabel.Text = "Collection finished. Review coverage before interpreting findings."; }
        }
        catch (OperationCanceledException) { StatusLabel.Text = "Collection canceled; in-progress results discarded."; }
        catch (ArgumentException ex) { StatusLabel.Text = ex.Message; }
        catch (MsalException) { StatusLabel.Text = "Authentication requires attention. Clear the session and reconnect."; }
        catch (Exception) { StatusLabel.Text = "Collection failed. No result was saved. Reconnect and retry."; }
        finally { operation.Dispose(); operation = null; SetBusy(false); }
    }
    private async void ImportJson(object sender, RoutedEventArgs e)
    {
        var dialog = new OfflineInvestigationWindow { Owner = this };
        if (dialog.ShowDialog() != true) return;
        operation = new CancellationTokenSource(); SetBusy(true);
        StatusLabel.Text = "Reading local sign-in JSON into memory…";
        try
        {
            var token = operation.Token;
            var result = await Task.Run(async () =>
            {
                using var stream = new FileStream(dialog.SelectedFile, FileMode.Open, FileAccess.Read, FileShare.Read);
                if (stream.Length == 0 || stream.Length > JsonSignInImport.MaxBytes)
                    throw new InvalidDataException("Choose a nonempty JSON file no larger than 32 MiB.");
                var bytes = new byte[(int)stream.Length];
                try
                {
                    await stream.ReadExactlyAsync(bytes, token);
                    return JsonSignInImport.Read(bytes, DateTimeOffset.UtcNow, token);
                }
                finally { Array.Clear(bytes); }
            }, token);
            if (!closing)
            {
                ShowPage("Overview"); ShowInvestigation(result);
                StatusLabel.Text = "Imported all file records and dates. Live account/time filters were not applied. Nothing was saved or sent.";
            }
        }
        catch (OperationCanceledException) { StatusLabel.Text = "Import canceled. Previous investigation retained."; }
        catch (InvalidDataException ex) { StatusLabel.Text = ex.Message; }
        catch (JsonException) { StatusLabel.Text = "Invalid or excessively nested JSON. No records were imported."; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        { StatusLabel.Text = "Could not read the selected file. Previous investigation retained."; }
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
        diagnostics = null; DiagnosticGroups.ItemsSource = null; DiagnosticEvents.ItemsSource = null; DiagnosticsSummary.Text = ""; DiagnosticsPanel.Visibility = Visibility.Collapsed;
        investigation = null; FindingsList.ItemsSource = null; CoverageList.ItemsSource = null;
        FindingDetail.Text = ""; RawEvidence.Clear(); RawPanel.Visibility = Visibility.Collapsed;
        LimitsLabel.Text = ""; SummaryLabel.Text = "Ready when you are"; ScopeLabel.Text = "Connect a tenant or start an offline investigation.";
        ExportButton.IsEnabled = false;
    }
    private void ShowInvestigation(Investigation value)
    {
        investigation = value;
        diagnostics = SignInDiagnostics.Create(value.Evidence); DiagnosticsSummary.Text = diagnostics.Summary; DiagnosticsPanel.Visibility = Visibility.Visible; RefreshDiagnostics();
        SummaryLabel.Text = value.Evidence.Count == 0 && value.Coverage.Any(c => c.Status is "Failed" or "Partial")
            ? "No evidence collected · Investigation incomplete"
            : $"{value.Findings.Count} findings to review · {value.Coverage.Count(c => c.Status is "Failed" or "Partial" or "Not collected")} sources incomplete" + (value.Import is not null ? " · Import completeness unverified" : "");
        ScopeLabel.Text = $"{(value.IsDemo ? "SYNTHETIC DATA" : value.Import is not null ? "IMPORTED DATA · observed event dates" : "LIVE DATA")} · {value.Account} · {value.StartUtc:yyyy-MM-dd HH:mm} – {value.EndUtc:yyyy-MM-dd HH:mm} UTC";
        LimitsLabel.Text = InvestigationCoverage.Describe(value);
        CoverageList.ItemsSource = value.Coverage; ExportButton.IsEnabled = true; RefreshFindings();
    }
    private void DiagnosticViewChanged(object sender, SelectionChangedEventArgs e)
    {
        if (IsInitialized) RefreshDiagnostics();
    }
    private void RefreshDiagnostics()
    {
        if (diagnostics is null) return;
        DiagnosticGroups.ItemsSource = DiagnosticView.SelectedIndex switch { 1 => diagnostics.Countries, 2 => diagnostics.Regions, 3 => diagnostics.Applications, _ => diagnostics.IPs };
        DiagnosticEvents.ItemsSource = null;
    }
    private void DiagnosticGroupSelected(object sender, SelectionChangedEventArgs e)
    {
        if (diagnostics is null || DiagnosticGroups.SelectedItem is not DiagnosticGroup group) { DiagnosticEvents.ItemsSource = null; return; }
        DiagnosticEvents.ItemsSource = diagnostics.Events.Where(row => (DiagnosticView.SelectedIndex switch { 1 => row.Country, 2 => row.Region, 3 => row.Application, _ => row.IP }) == group.Value).ToArray();
    }
    private void DiagnosticEventSelected(object sender, SelectionChangedEventArgs e)
    {
        if (DiagnosticEvents.SelectedItem is not DiagnosticEvent row || investigation is null) return;
        var evidence = investigation.Evidence.FirstOrDefault(item => item.Id == row.EvidenceId);
        var detail = new Window { Owner = this, Title = "Sign-in evidence — " + row.Time + " UTC", Icon = Icon, Width = 820, Height = 600, WindowStartupLocation = WindowStartupLocation.CenterOwner, Background = Background, Content = new TextBox { Text = evidence?.Data.ToString() ?? "Evidence unavailable", IsReadOnly = true, TextWrapping = TextWrapping.Wrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Margin = new Thickness(16), Background = (System.Windows.Media.Brush)FindResource("CardBrush"), Foreground = (System.Windows.Media.Brush)FindResource("InkBrush") } };
        detail.ShowDialog();
    }
    private void RefreshFindings()
    {
        if (investigation is null) return;
        FindingsList.ItemsSource = investigation.Findings.Where(f => page switch
        { "Sign-ins" => f.Source == "Entra sign-ins", "Mailbox rules" => f.Source is "Exchange rules" or "Mailbox forwarding", _ => true }).ToArray();
        FindingDetail.Text = investigation.Evidence.Count == 0 && investigation.Coverage.Any(c => c.Status is "Failed" or "Partial")
            ? "Collection did not return evidence. This investigation cannot assess account compromise; review the sources incomplete above."
            : "Select a finding to see its explanation. No matching indicators does not establish that an account is safe.";
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
        var preview = $"{(investigation.IsDemo ? "SYNTHETIC DEMO" : investigation.Import is not null ? "IMPORTED DATA — origin and completeness unverified" : "LIVE TENANT DATA")}\n\nAccount: {investigation.Account}\n{investigation.Evidence.Count} raw records; {investigation.Findings.Count} findings.\n\nThe ZIP contains evidence.json, summary.txt and a SHA-256 manifest. Raw evidence may include names, IP addresses and other personal data. This preview does not redact records.\n\nChoose a local file destination?";
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
        var offline = new OfflineInvestigationWindow { Owner = this };
        offline.Show(); offline.UpdateLayout(); await Task.Delay(150);
        var offlineSurface = (FrameworkElement)offline.Content;
        var offlineBitmap = new System.Windows.Media.Imaging.RenderTargetBitmap((int)offlineSurface.ActualWidth, (int)offlineSurface.ActualHeight, 96, 96, System.Windows.Media.PixelFormats.Pbgra32);
        offlineBitmap.Render(offlineSurface);
        var offlinePng = new System.Windows.Media.Imaging.PngBitmapEncoder();
        offlinePng.Frames.Add(System.Windows.Media.Imaging.BitmapFrame.Create(offlineBitmap));
        using (var file = File.Create(Path.Combine(directory, "offline.png"))) offlinePng.Save(file);
        if (offline.Icon is null || Icon is null || !OfflineButton.IsEnabled) throw new InvalidOperationException("Offline dialog or icon failed.");
        offline.Close();
        if (investigation?.Findings.Count != 2 || !ExportButton.IsEnabled) throw new InvalidOperationException("Demo UI failed.");
        ShowPage("Connect tenant");
        ShowConnected("synthetic-tenant", "alex@example.com");
        if (ConnectionPanel.Visibility != Visibility.Collapsed || InvestigationPanel.Visibility != Visibility.Visible ||
            AccountBox.Text != "alex@example.com" || page != "Overview") throw new InvalidOperationException("Connected transition failed.");
        ShowInvestigation(investigation with { Findings = [], Evidence = [], Coverage = [new("Entra sign-ins", "Failed", 0, "Synthetic failure")] });
        if (!SummaryLabel.Text.Contains("Investigation incomplete") || !FindingDetail.Text.Contains("cannot assess")) throw new InvalidOperationException("Failed collection UI failed.");
        var imported = JsonSignInImport.Read(System.Text.Encoding.UTF8.GetBytes("""[{"id":"smoke","userPrincipalName":"alex@example.com","createdDateTime":"2026-09-10T10:00:00Z","riskLevelDuringSignIn":"high"}]"""), DateTimeOffset.UtcNow);
        ShowInvestigation(imported);
        if (!ScopeLabel.Text.Contains("IMPORTED DATA") || !ExportButton.IsEnabled || investigation.Findings.Count != 1)
            throw new InvalidOperationException("Import UI failed.");
        await session.DisconnectAsync(); ClearInvestigation();
        if (FindingsList.ItemsSource is not null || RawEvidence.Text.Length != 0 || ExportButton.IsEnabled) throw new InvalidOperationException("Clear UI failed.");
        File.WriteAllText(Path.Combine(directory, "smoke-result.txt"), "PASS: demo findings, light/dark renders, connected navigation, failed collection summary, and clearing investigation UI.");
        Close();
    }
}
