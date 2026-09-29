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
    private IReadOnlyList<ActivityRow> timeline = [];
    private IReadOnlyList<SuspiciousItem> suspicious = [];
    private CancellationTokenSource? operation;
    private string page = "Investigate";
    private bool closing;
    private async void CheckUpdates(object sender, RoutedEventArgs e)
    {
        UpdateButton.IsEnabled = false;
        try
        {
            var current = ReleaseVersion.Parse(BuildInfo.Version) ?? throw new InvalidOperationException();
            using var client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false }) { Timeout = TimeSpan.FromSeconds(15), MaxResponseContentBufferSize = 4 * 1024 * 1024 };
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            var latest = await ReleaseUpdates.CheckAsync(client, current.Pre.Length > 0, timeout.Token);
            if (closing) return;
            var description = latest is null ? "No eligible public releases have been published yet." : latest.CompareTo(current) > 0 ? $"A newer release is available: {latest.Text}." : $"No newer eligible release was found. Highest published version: {latest.Text}.";
            if (MessageBox.Show(this, $"Installed: {BuildInfo.Version}\n{description}\n\n" + (current.Pre.Length > 0 ? "This preview checks stable and prerelease versions." : "This build checks stable releases only.") + "\n\nOpen GitHub Releases? Download and extract updates to a new folder. Export your case before closing the current app.", "365Lantern updates", MessageBoxButton.YesNo, MessageBoxImage.Information) == MessageBoxResult.Yes)
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(ReleaseUpdates.Page) { UseShellExecute = true });
        }
        catch (Exception) { if (!closing) MessageBox.Show(this, "The update check could not complete. GitHub may be unavailable, private, or rate limited. Your current app and investigation are unchanged.\n\nRelease page: " + ReleaseUpdates.Page, "Update check unavailable", MessageBoxButton.OK, MessageBoxImage.Information); }
        finally { UpdateButton.IsEnabled = true; }
    }

    public MainWindow()
    {
        InitializeComponent();
        Title = $"365Lantern {BuildInfo.Version} — Investigation preview";
        VersionLabel.Text = "v" + BuildInfo.Version;
        VersionLabel.ToolTip = BuildInfo.InformationalVersion;
        themes.Set("System");
        ShowPage("Connect tenant");
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
        PageTitle.Text = page;
        ConnectionPanel.Visibility = page == "Connect tenant" ? Visibility.Visible : Visibility.Collapsed;
        ResponsePanel.Visibility = page == "Response" ? Visibility.Visible : Visibility.Collapsed;
        InvestigationPanel.Visibility = page == "Investigate" ? Visibility.Visible : Visibility.Collapsed;
        ResultsPanel.Visibility = page == "Findings" ? Visibility.Visible : Visibility.Collapsed;
        RefreshFindings();
    }
    private void ShowConnected(string tenant, string? operatorUpn)
    {
        SessionLabel.Text = "Connected · Read-only";
        AccountBox.Text = operatorUpn ?? "";
        ShowPage("Investigate");
        SummaryLabel.Text = "Connected. Ready to investigate.";
        ScopeLabel.Text = "Confirm the account and time range, then select Investigate account. Signing in does not collect evidence.";
        StatusLabel.Text = $"Connected to tenant {tenant}. No tenant changes made.";
        AccountBox.Focus();
    }
    private void SetBusy(bool busy)
    {
        if (!busy) CollectionAnimation.Visibility = Visibility.Collapsed;
        OfflineButton.IsEnabled = ConnectButton.IsEnabled = DisconnectButton.IsEnabled = !busy;
        CollectButton.IsEnabled = !busy && session.IsConnected;
        CancelButton.IsEnabled = busy;
        ExportFindingsButton.IsEnabled = !busy && investigation is not null;
        AdvancedAuthentication.IsEnabled = IncludeGrants.IsEnabled = TenantWide.IsEnabled = !busy;
        RelatedButton.IsEnabled = !busy && investigation is not null;
        DaysPicker.IsEnabled = ClientIdBox.IsEnabled = TenantIdBox.IsEnabled = !busy;
        AccountBox.IsEnabled = !busy && TenantWide.IsChecked != true;
    }
    private async void RunDemo(object sender, RoutedEventArgs e)
    {
        await session.DisconnectAsync();
        ClientIdBox.Clear(); TenantIdBox.Clear();
        ShowPage("Investigate");
        AccountBox.Text = "alex@example.com";
        ShowInvestigation(DemoInvestigation.Run(DateTimeOffset.UtcNow, Days));
        SessionLabel.Text = "Northwind Demo · SYNTHETIC";
        SetBusy(false);
        StatusLabel.Text = "Synthetic demo complete. No network calls or tenant changes were made.";
    }
    private void AuthenticationModeChanged(object sender, RoutedEventArgs e)
    {
        if (ClientRegistrationPanel is not null) ClientRegistrationPanel.Visibility = AdvancedAuthentication.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
    }
    private async void Connect(object sender, RoutedEventArgs e)
    {
        ClearInvestigation();
        operation = new CancellationTokenSource(TimeSpan.FromMinutes(5)); SetBusy(true);
        StatusLabel.Text = "Complete sign-in in your browser. You can cancel here.";
        try
        {
            if (AdvancedAuthentication.IsChecked == true) await session.ConnectAsync(ClientIdBox.Text.Trim(), TenantIdBox.Text.Trim(), operation.Token, IncludeGrants.IsChecked == true);
            else await session.ConnectDefaultAsync(TenantIdBox.Text.Trim(), operation.Token, IncludeGrants.IsChecked == true);
            if (!closing) ShowConnected(session.TenantId!, session.Operator);
        }
        catch (OperationCanceledException) { StatusLabel.Text = "Sign-in canceled or timed out. No tenant changes made."; }
        catch (ArgumentException ex) { StatusLabel.Text = ex.Message; }
        catch (InvalidOperationException) { StatusLabel.Text = "Microsoft module sign-in failed. Verify PowerShell 7, Graph Authentication 2.36.1+, tenant selection and consent. See the setup guide."; }
        catch (MsalException) { StatusLabel.Text = "Sign-in could not complete. Check the app registration, consent and tenant access, then retry."; }
        catch (Exception) { StatusLabel.Text = "Connection failed. No credentials or diagnostic response bodies were saved."; }
        finally
        {
            if (!session.IsConnected) SessionLabel.Text = "Not connected";
            operation.Dispose(); operation = null; SetBusy(false);
        }
    }
    private async void Collect(object sender, RoutedEventArgs e) => await RunCollection();
    private async Task RunCollection(string? relatedAccount = null)
    {
        var parent = relatedAccount is null ? null : investigation;
        if (parent is not null && parent.Evidence.Count >= 200000) { StatusLabel.Text = "Case has reached the related-investigation safety boundary. Export and start a narrower investigation."; return; }
        if (parent is null) ClearInvestigation();
        var targetAccount = relatedAccount ?? AccountBox.Text.Trim();
        bool tenantWide = relatedAccount is null && TenantWide.IsChecked == true;
        operation = new CancellationTokenSource(); SetBusy(true);
        Investigation? retained = null;
        StatusLabel.Text = "Collecting available evidence into memory; unavailable sources will be reported as gaps…";
        CollectionAnimation.Visibility = Visibility.Visible;
        try
        {
            bool resolutionFailed = false;
            if (parent is not null)
            {
                try
                {
                    var resolved = await new ExchangeCollector().ActivityAsync(session, new { action = "activity", kind = "resolveAccount", account = targetAccount }, operation.Token);
                    var upn = resolved.GetProperty("rows").EnumerateArray().FirstOrDefault().GetString();
                    if (resolved.GetProperty("status").GetString() == "ok" && !string.IsNullOrWhiteSpace(upn) && upn.Contains('@')) targetAccount = upn;
                    else resolutionFailed = true;
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception) { resolutionFailed = true; }
            }
            var now = DateTimeOffset.UtcNow;
            using var moduleHttp = session.Modules is { } module ? new HttpClient(module, false) { Timeout = TimeSpan.FromMinutes(5) } : null;
            var result = await new GraphCollector(moduleHttp ?? http, session.Modules is null ? session.GetTokenAsync : _ => Task.FromResult("module-session"))
                .CollectAsync(session.TenantId!, targetAccount, parent?.StartUtc ?? now.AddDays(-Days), parent?.EndUtc ?? now, operation.Token, tenantWide);
            retained = result;
            if (!operation.IsCancellationRequested)
            {
                StatusLabel.Text = "Reading noninteractive sign-ins (Microsoft Graph beta)…";
                var background = await new GraphCollector(moduleHttp ?? http, session.Modules is null ? session.GetTokenAsync : _ => Task.FromResult("module-session"))
                    .CollectAsync(session.TenantId!, targetAccount, result.StartUtc, result.EndUtc, operation.Token, tenantWide, true);
                result = result with { Evidence = result.Evidence.Concat(background.Evidence).ToArray(), Coverage = result.Coverage.Concat(background.Coverage.Where(c => c.Source == SignInTypes.Noninteractive)).ToArray(), Findings = result.Findings.Concat(background.Findings).ToArray() };
                retained = result;
            }
            StatusLabel.Text = "Checking Exchange access; complete browser sign-in if prompted…";
            var inventory = await new AccountInventory(moduleHttp ?? http, session.Modules is null ? session.GetTokenAsync : _ => Task.FromResult("module-session"))
                .CollectAsync(tenantWide ? null : targetAccount, operation.Token);
            var allEvidence = result.Evidence.Concat(inventory.Evidence).ToList();
            var allCoverage = result.Coverage.Where(c => c.Source is "Entra sign-ins" or SignInTypes.Noninteractive).Concat(inventory.Coverage).ToList();
            var allFindings = result.Findings.ToList();
            if (resolutionFailed) allCoverage.Add(new("Related address resolution", "Partial", 0, "Could not resolve the selected address to a mailbox UPN; searching the supplied address. It may be external or an alias and account queries may miss evidence."));
            retained = result with { Evidence = allEvidence, Coverage = allCoverage, Findings = allFindings, Accounts = inventory.Accounts };
            var targets = tenantWide
                ? inventory.Accounts.Select(a => a.Account).Concat(ActivityTimeline.Create(result).Select(r => r.Account).Where(a => a.Contains('@'))).Distinct(StringComparer.OrdinalIgnoreCase).Take(1000).ToArray()
                : [targetAccount];
            if (tenantWide && inventory.Coverage.Any(c => c.Source == "Account inventory" && c.Status != "Complete"))
                allCoverage.Add(new("Account scope fallback", "Partial", targets.Length, "Directory enumeration incomplete. Continuing with directory accounts and accounts observed in collected sign-ins, up to 1,000. Unobserved accounts may be missing."));
            StatusLabel.Text = "Reading identity audit history…";
            var audit = await new DirectoryAuditCollector(moduleHttp ?? http, session.Modules is null ? session.GetTokenAsync : _ => Task.FromResult("module-session"))
                .CollectAsync(tenantWide ? null : targetAccount, inventory.Accounts.FirstOrDefault()?.Id, result.StartUtc, result.EndUtc, operation.Token);
            allEvidence.AddRange(audit.Evidence); allCoverage.AddRange(audit.Coverage);
            StatusLabel.Text = "Reading delegated application grants…";
            var grants = await new GrantCollector(moduleHttp ?? http, session.Modules is null ? session.GetTokenAsync : _ => Task.FromResult("module-session"))
                .CollectAsync(tenantWide ? null : targetAccount, inventory.Accounts.FirstOrDefault()?.Id, inventory.Accounts, operation.Token);
            allEvidence.AddRange(grants.Evidence); allCoverage.AddRange(grants.Coverage);
            foreach (var target in targets)
            {
                if (allEvidence.Count >= 100000) { allCoverage.Add(new("Remaining accounts", "Not collected", 0, "100,000-record run budget reached. Narrow account or time scope; completed sources retained.")); break; }
                if (operation.IsCancellationRequested) { allCoverage.Add(new("Remaining accounts", "Not collected", 0, "Canceled before all account checks completed.")); break; }
                StatusLabel.Text = $"Reading Exchange configuration: {target}";
                var exchange = await new ExchangeCollector().CollectAsync(session, target, operation.Token);
                string Prefix(string id) => target + ":" + id;
                allEvidence.AddRange(exchange.Evidence.Select(e => e with { Id = Prefix(e.Id), CollectedUtc = DateTimeOffset.UtcNow }));
                allFindings.AddRange(exchange.Findings.Select(f => f with { EvidenceId = Prefix(f.EvidenceId) }));
                allCoverage.AddRange(exchange.Coverage.Select(c => c with { Detail = target + ": " + c.Detail }));
                var persistence = await new PersistenceCollector((request, ct) => new ExchangeCollector().ActivityAsync(session, request, ct)).CollectAsync(target, operation.Token);
                allEvidence.AddRange(persistence.Evidence); allCoverage.AddRange(persistence.Coverage);
                StatusLabel.Text = $"Reading mail flow and Microsoft 365 audit history: {target}";
                var activity = await new MailActivityCollector((request, ct) => new ExchangeCollector().ActivityAsync(session, request, ct))
                    .CollectAsync(target, result.StartUtc, result.EndUtc, operation.Token);
                allEvidence.AddRange(activity.Evidence); allCoverage.AddRange(activity.Coverage);
            }
            if (targets.Length == 0) allCoverage.Add(new("Exchange", "Not collected", 0, "No directory accounts available; tenant mailbox coverage is unavailable."));
            allCoverage.Add(new("Defender click evidence", "Not collected", 0, "Defender enrichment is not implemented in this milestone. Message traces cannot establish link clicks or phishing verdicts."));
            allCoverage.Add(new("Other sign-in types", "Not collected", 0, "Service-principal and managed-identity sign-ins are not collected; these differ from background user sign-ins."));
            result = result with { Evidence = allEvidence, Findings = allFindings, Coverage = allCoverage, Accounts = inventory.Accounts, CollectedUtc = DateTimeOffset.UtcNow };
            if (!closing) { ShowInvestigation(parent is null ? result : RelatedAccounts.Merge(parent, result, "Account", relatedAccount!)); StatusLabel.Text = "Collection finished. Review coverage before interpreting findings."; }
        }
        catch (OperationCanceledException) { ShowInterrupted(parent is not null && retained is not null ? RelatedAccounts.Merge(parent, retained, "Account", relatedAccount!) : retained ?? parent, "Canceled; completed sources retained. Remaining checks were not performed."); }
        catch (ArgumentException ex) { StatusLabel.Text = ex.Message; }
        catch (MsalException) { ShowInterrupted(parent is not null && retained is not null ? RelatedAccounts.Merge(parent, retained, "Account", relatedAccount!) : retained ?? parent, "Authentication interrupted collection. Completed sources retained; remaining checks were not performed."); }
        catch (Exception) { ShowInterrupted(parent is not null && retained is not null ? RelatedAccounts.Merge(parent, retained, "Account", relatedAccount!) : retained ?? parent, "Collection interrupted. Completed sources retained; remaining checks were not performed."); }
        finally { operation.Dispose(); operation = null; if (!session.IsConnected) SessionLabel.Text = "Not connected"; SetBusy(false); }
    }
    private void ShowInterrupted(Investigation? retained, string reason)
    {
        if (retained is not null && !closing) ShowInvestigation(retained with { Coverage = retained.Coverage.Append(new Coverage("Remaining checks", "Not collected", 0, reason)).ToArray(), CollectedUtc = DateTimeOffset.UtcNow });
        StatusLabel.Text = reason;
    }
    private async void Related(object sender, RoutedEventArgs e)
    {
        if (investigation is null || operation is not null) return;
        var live = session.IsConnected && investigation.Import is null && !investigation.IsDemo && string.Equals(session.TenantId, investigation.Tenant, StringComparison.OrdinalIgnoreCase);
        var window = new RelatedAccountsWindow(investigation, live, SearchRelated) { Owner = this, Icon = Icon };
        var investigate = window.ShowDialog() == true;
        ShowInvestigation(window.Investigation);
        if (investigate && window.SelectedAccount is { } account) await RunCollection(account);
    }
    private async Task<Investigation> SearchRelated(Investigation original, RelatedSeed seed, CancellationToken ct)
    {
        if (!session.IsConnected || original.Import is not null || original.IsDemo || !string.Equals(session.TenantId, original.Tenant, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException();
        var evidence = new List<Evidence>(); var coverage = new List<Coverage>(); var findings = new List<Finding>();
        if (original.Evidence.Count >= 200000) coverage.Add(new("Related search", "Not collected", 0, "Case already contains 200,000 records. Export and start a narrower investigation."));
        else if (seed.ValidMessage)
        {
            var messages = await new RelatedMessageCollector((request, token) => new ExchangeCollector().ActivityAsync(session, request, token)).CollectAsync(seed, original.StartUtc, original.EndUtc, ct);
            evidence.AddRange(messages.Evidence); coverage.AddRange(messages.Coverage);
        }
        else
        {
            using var moduleHttp = session.Modules is { } module ? new HttpClient(module, false) { Timeout = TimeSpan.FromMinutes(5) } : null;
            foreach (var background in new[] { false, true })
            {
                if (ct.IsCancellationRequested) { coverage.Add(new(background ? SignInTypes.Noninteractive : "Entra sign-ins", "Not collected", 0, "Related search canceled before this source.")); continue; }
                var result = await new GraphCollector(moduleHttp ?? http, session.Modules is null ? session.GetTokenAsync : _ => Task.FromResult("module-session"))
                    .CollectAsync(original.Tenant, "", original.StartUtc, original.EndUtc, ct, true, background, seed);
                evidence.AddRange(result.Evidence); findings.AddRange(result.Findings); coverage.AddRange(result.Coverage.Where(c => c.Source is "Entra sign-ins" or SignInTypes.Noninteractive));
            }
        }
        var added = new Investigation(original.Tenant, "Related search", original.StartUtc, original.EndUtc, DateTimeOffset.UtcNow, false, findings, coverage, evidence);
        return RelatedAccounts.Merge(original, added, seed.Kind, seed.Value);
    }
    private void PersistenceSelected(object sender, SelectionChangedEventArgs e)
    {
        if (investigation is null || PersistenceList.SelectedItem is not PersistenceRow row) return;
        var source = investigation.Evidence.FirstOrDefault(item => item.Id == row.EvidenceId);
        new Window { Owner = this, Title = "Persistence evidence — current snapshot", Icon = Icon, Width = 820, Height = 600, Background = Background, WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Content = new TextBox { Text = row.Account + " · " + row.Source + "\nCurrent snapshot, not the time access was granted.\n\n" + source?.Data.ToString(), IsReadOnly = true, TextWrapping = TextWrapping.Wrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Margin = new Thickness(16), Background = (System.Windows.Media.Brush)FindResource("CardBrush"), Foreground = (System.Windows.Media.Brush)FindResource("InkBrush") } }.ShowDialog();
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
                ShowPage("Investigate"); ShowInvestigation(result);
                StatusLabel.Text = "Imported all file records and dates. Live account/time filters were not applied. Nothing was saved or sent.";
            }
        }
        catch (OperationCanceledException) { StatusLabel.Text = "Import canceled. Previous investigation retained."; }
        catch (InvalidDataException ex) { StatusLabel.Text = ex.Message; }
        catch (JsonException) { StatusLabel.Text = "Invalid or excessively nested JSON. No records were imported."; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        { StatusLabel.Text = "Could not read the selected file. Previous investigation retained."; }
        finally { operation.Dispose(); operation = null; if (!session.IsConnected) SessionLabel.Text = "Not connected"; SetBusy(false); }
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
        suspicious = []; SuspiciousSummary.Text = ""; PersistenceList.ItemsSource = null; RelatedButton.IsEnabled = false;
        timeline = []; TimelineEvents.ItemsSource = null; TimelineAccount.ItemsSource = null; TimelineSummary.Text = "";
        diagnostics = null; ObservedIPs.ItemsSource = ObservedCountries.ItemsSource = ObservedRegions.ItemsSource = null; DiagnosticGroups.ItemsSource = null; DiagnosticEvents.ItemsSource = null; DiagnosticsSummary.Text = ""; DiagnosticsPanel.Visibility = Visibility.Collapsed;
        AccountDetails.ItemsSource = null; investigation = null; FindingsList.ItemsSource = null; CoverageList.ItemsSource = null;
        FindingDetail.Text = ""; RawEvidence.Clear(); RawPanel.Visibility = Visibility.Collapsed;
        LimitsLabel.Text = ""; SummaryLabel.Text = "Ready when you are"; ScopeLabel.Text = "Connect a tenant or start an offline investigation.";
        ExportFindingsButton.IsEnabled = false;
    }
    private void ShowInvestigation(Investigation value)
    {
        investigation = value; AccountDetails.ItemsSource = value.Accounts; PersistenceList.ItemsSource = PersistenceReview.Rows(value.Evidence); RelatedButton.IsEnabled = true;
        suspicious = SuspiciousBehavior.Analyze(value);
        SuspiciousSummary.Text = $"{suspicious.Count} indicators · {suspicious.Count(i => i.Priority == "High")} high priority · {suspicious.Count(i => i.Priority == "Medium")} medium priority. " + SuspiciousBehavior.Limitations;
        timeline = ActivityTimeline.Create(value);
        TimelineAccount.ItemsSource = new[] { "All accounts" }.Concat(timeline.Select(r => r.Account).Where(a => a.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(a => a)).ToArray();
        TimelineAccount.SelectedIndex = 0;
        RefreshTimeline();
        diagnostics = SignInDiagnostics.Create(value.Evidence); DiagnosticsSummary.Text = diagnostics.Summary; DiagnosticsPanel.Visibility = Visibility.Visible; RefreshDiagnostics();
        SummaryLabel.Text = value.Evidence.Count == 0 && value.Coverage.Any(c => c.Status is "Failed" or "Partial")
            ? "No evidence collected · Investigation incomplete"
            : $"{suspicious.Count} suspicious indicators to review · {value.Coverage.Count(c => c.Status is "Failed" or "Partial" or "Not collected")} sources incomplete" + (value.Import is not null ? " · Import completeness unverified" : "");
        ScopeLabel.Text = $"{(value.IsDemo ? "SYNTHETIC DATA" : value.Import is not null ? "IMPORTED DATA · observed event dates" : "LIVE DATA")} · {value.Account} · {value.StartUtc:yyyy-MM-dd HH:mm} – {value.EndUtc:yyyy-MM-dd HH:mm} UTC";
        if (value.Pivots.Count > 0) ScopeLabel.Text += $" · {value.Pivots.Count} related searches added (original scope retained)";
        LimitsLabel.Text = InvestigationCoverage.Describe(value);
        CoverageList.ItemsSource = value.Coverage; ExportFindingsButton.IsEnabled = true; ShowPage("Findings");
    }
    private void TimelineFilterChanged(object sender, SelectionChangedEventArgs e) { if (IsInitialized) RefreshTimeline(); }
    private void RefreshTimeline()
    {
        if (investigation is null || TimelineCategory is null) return;
        var account = TimelineAccount.SelectedItem as string;
        var category = (TimelineCategory.SelectedItem as ComboBoxItem)?.Content.ToString();
        var rows = timeline.Where(r => (account is null or "All accounts" || string.Equals(r.Account, account, StringComparison.OrdinalIgnoreCase)) && (category is null or "All activity" || r.Category == category)).ToArray();
        TimelineEvents.ItemsSource = rows;
        TimelineSummary.Text = $"{rows.Length} timeline rows · {rows.Count(r => r.Source == "Mail flow inbound")} inbound / {rows.Count(r => r.Source == "Mail flow outbound")} outbound transport records · {rows.Count(r => r.Category is "Audit" or "Identity")} audit rows. Multiple recipients can produce multiple transport records for one message. Snapshot times show collection, not change time.";
    }
    private void TimelineSelected(object sender, SelectionChangedEventArgs e)
    {
        if (TimelineEvents.SelectedItem is not ActivityRow row || investigation is null) return;
        var evidence = investigation.Evidence.FirstOrDefault(item => item.Id == row.EvidenceId);
        var related = timeline.Where(item => item.EvidenceId != row.EvidenceId && string.Equals(item.Account, row.Account, StringComparison.OrdinalIgnoreCase) && row.MessageId.Length > 0 && item.MessageId == row.MessageId).Select(item => item.Time + " · " + item.Activity).ToArray();
        var nearby = timeline.Where(item => item.EvidenceId != row.EvidenceId && item.Category != "Snapshot" && string.Equals(item.Account, row.Account, StringComparison.OrdinalIgnoreCase) && item.Timestamp.HasValue && row.Timestamp.HasValue && (item.Timestamp.Value - row.Timestamp.Value).Duration() <= TimeSpan.FromHours(1)).Take(50).Select(item => item.Time + " · " + item.Activity + " · Evidence: " + item.EvidenceId);
        var text = row.Source + " · " + row.Time + "\nEvidence: " + row.EvidenceId + "\n\n" + (related.Length == 0 ? "No exact message-ID links in collected evidence." : "Same-account exact message-ID links (not proof of causation):\n" + string.Join("\n", related)) + "\n\nNearby activity for this account (±1 hour, first 50; timing does not establish causation):\n" + string.Join("\n", nearby) + "\n\nOriginal evidence:\n" + evidence?.Data.ToString();
        new Window { Owner = this, Title = "Activity evidence", Icon = Icon, Width = 900, Height = 650, WindowStartupLocation = WindowStartupLocation.CenterOwner, Background = Background, Content = new TextBox { Text = text, IsReadOnly = true, TextWrapping = TextWrapping.Wrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Margin = new Thickness(16), Background = (System.Windows.Media.Brush)FindResource("CardBrush"), Foreground = (System.Windows.Media.Brush)FindResource("InkBrush") } }.ShowDialog();
    }
    private void DiagnosticViewChanged(object sender, SelectionChangedEventArgs e)
    {
        if (IsInitialized) RefreshDiagnostics();
    }
    private void RefreshDiagnostics()
    {
        if (diagnostics is null) return;
        ObservedIPs.ItemsSource = diagnostics.IPs;
        ObservedCountries.ItemsSource = diagnostics.Countries;
        ObservedRegions.ItemsSource = diagnostics.Regions;
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
        FindingsList.ItemsSource = suspicious;
        FindingDetail.Text = investigation.Evidence.Count == 0 && investigation.Coverage.Any(c => c.Status is "Failed" or "Partial")
            ? "Collection did not return evidence. This investigation cannot assess account compromise; review the sources incomplete above."
            : "Select a finding to see its explanation. No matching indicators does not establish that an account is safe.";
        RawPanel.Visibility = page == "Findings" ? Visibility.Visible : Visibility.Collapsed;
        RawEvidence.Text = page == "Findings" ? JsonSerializer.Serialize(investigation.Evidence, new JsonSerializerOptions { WriteIndented = true }) : "";
    }
    private void FindingSelected(object sender, SelectionChangedEventArgs e)
    {
        if (FindingsList.SelectedItem is not SuspiciousItem finding || investigation is null) return;
        FindingDetail.Text = finding.Time + " · " + finding.Account + "\n" + finding.Explanation;
        var supporting = investigation.Evidence.Where(x => finding.EvidenceIds.Contains(x.Id)).ToArray();
        new Window { Owner = this, Title = "Suspicious behavior — supporting evidence", Icon = Icon, Width = 900, Height = 650, WindowStartupLocation = WindowStartupLocation.CenterOwner, Background = Background,
            Content = new TextBox { Text = finding.Title + "\n" + finding.Basis + "\n" + FindingDetail.Text + "\n\n" + JsonSerializer.Serialize(supporting, new JsonSerializerOptions { WriteIndented = true }), IsReadOnly = true, TextWrapping = TextWrapping.Wrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Margin = new Thickness(16), Background = (System.Windows.Media.Brush)FindResource("CardBrush"), Foreground = (System.Windows.Media.Brush)FindResource("InkBrush") } }.ShowDialog();
    }
    private void TenantLookup(object sender, RoutedEventArgs e)
    {
        try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("https://gettenantpartitionweb.azurewebsites.net/") { UseShellExecute = true }); }
        catch (System.ComponentModel.Win32Exception) { StatusLabel.Text = "Could not open tenant lookup in your browser."; }
    }
    private void ScopeChanged(object sender, RoutedEventArgs e)
    {
        if (AccountBox is null) return;
        AccountBox.IsEnabled = TenantWide.IsChecked != true;
        CollectButton.Content = TenantWide.IsChecked == true ? "Investigate tenant" : "Investigate account";
    }
    private void ExportFindings(object sender, RoutedEventArgs e)
    {
        if (investigation is null) return;
        var dialog = new SaveFileDialog { Title = "Save findings and evidence (JSON + CSV)", Filter = "Investigation archive (*.zip)|*.zip", FileName = $"365Lantern-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}.zip", OverwritePrompt = true };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            File.WriteAllBytes(dialog.FileName, EvidenceExport.Create(investigation));
            StatusLabel.Text = "Exported findings.json, findings.csv, evidence.json, summary.txt and manifest.json. Treat the archive as sensitive case material.";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        { StatusLabel.Text = "Export failed. Check the destination; a partial file may exist."; }
    }
    private async Task RunSmokeTest(string directory)
    {
        // Explicit developer-only invocation; exclusively synthetic data. No auth is started.
        Directory.CreateDirectory(directory);
        ShowPage("Investigate"); SetBusy(true); CollectionAnimation.Visibility = Visibility.Visible;
        foreach (var theme in new[] { "Light", "Dark" })
        {
            themes.Set(theme); UpdateLayout(); await Task.Delay(350);
            if (!CollectionAnimation.IsVisible || !CancelButton.IsEnabled) throw new InvalidOperationException("Collection indicator unavailable.");
            var surface = (FrameworkElement)Content;
            var bitmap = new System.Windows.Media.Imaging.RenderTargetBitmap((int)surface.ActualWidth, (int)surface.ActualHeight, 96, 96, System.Windows.Media.PixelFormats.Pbgra32);
            bitmap.Render(surface);
            var encoder = new System.Windows.Media.Imaging.PngBitmapEncoder(); encoder.Frames.Add(System.Windows.Media.Imaging.BitmapFrame.Create(bitmap));
            using var file = File.Create(Path.Combine(directory, "collecting-" + theme.ToLowerInvariant() + ".png")); encoder.Save(file);
        }
        SetBusy(false);
        if (CollectionAnimation.Visibility != Visibility.Collapsed) throw new InvalidOperationException("Collection indicator did not stop.");
        RunDemo(this, new RoutedEventArgs());
        if (suspicious.Count != 3 || FindingsList.Items.Count != 3 || !SuspiciousSummary.Text.Contains("2 high priority")) throw new InvalidOperationException("Suspicious behavior block failed.");
        if (timeline.Count != 5 || timeline.Count(r => r.Category == "Mail flow") != 1) throw new InvalidOperationException("Timeline rows missing.");
        TimelineCategory.SelectedIndex = 2;
        if (TimelineEvents.Items.Count != 1) throw new InvalidOperationException("Timeline category filter failed.");
        TimelineCategory.SelectedIndex = 0;
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
        var related = new RelatedAccountsWindow(investigation!, false, (_, _, _) => throw new InvalidOperationException("Smoke must not access tenant")) { Owner = this, Icon = Icon };
        related.Show(); related.UpdateLayout(); await Task.Delay(150);
        if (((System.Windows.Controls.Button)related.FindName("SearchButton")).IsEnabled || ((System.Windows.Controls.Button)related.FindName("InvestigateButton")).IsEnabled) throw new InvalidOperationException("Demo must not allow live related collection.");
        var relatedSurface = (FrameworkElement)related.Content;
        var relatedBitmap = new System.Windows.Media.Imaging.RenderTargetBitmap((int)relatedSurface.ActualWidth, (int)relatedSurface.ActualHeight, 96, 96, System.Windows.Media.PixelFormats.Pbgra32);
        relatedBitmap.Render(relatedSurface);
        var relatedPng = new System.Windows.Media.Imaging.PngBitmapEncoder(); relatedPng.Frames.Add(System.Windows.Media.Imaging.BitmapFrame.Create(relatedBitmap));
        using (var file = File.Create(Path.Combine(directory, "related.png"))) relatedPng.Save(file);
        related.Close();
        if (ResultsPanel.Visibility != Visibility.Visible || InvestigationPanel.Visibility != Visibility.Collapsed) throw new InvalidOperationException("Findings must not show launch controls.");
        ShowPage("Investigate");
        if (ResultsPanel.Visibility != Visibility.Collapsed || InvestigationPanel.Visibility != Visibility.Visible) throw new InvalidOperationException("Investigate must not show results.");
        if (investigation?.Findings.Count != 2 || !ExportFindingsButton.IsEnabled) throw new InvalidOperationException("Demo UI failed.");
        ShowPage("Connect tenant");
        ShowConnected("synthetic-tenant", "alex@example.com");
        if (ConnectionPanel.Visibility != Visibility.Collapsed || InvestigationPanel.Visibility != Visibility.Visible ||
            AccountBox.Text != "alex@example.com" || page != "Investigate") throw new InvalidOperationException("Connected transition failed.");
        ShowInvestigation(investigation with { Findings = [], Evidence = [], Coverage = [new("Entra sign-ins", "Failed", 0, "Synthetic failure")] });
        if (!SummaryLabel.Text.Contains("Investigation incomplete") || !FindingDetail.Text.Contains("cannot assess")) throw new InvalidOperationException("Failed collection UI failed.");
        var imported = JsonSignInImport.Read(System.Text.Encoding.UTF8.GetBytes("""[{"id":"smoke","userPrincipalName":"alex@example.com","createdDateTime":"2026-09-10T10:00:00Z","riskLevelDuringSignIn":"high"}]"""), DateTimeOffset.UtcNow);
        ShowInvestigation(imported);
        if (!ScopeLabel.Text.Contains("IMPORTED DATA") || !ExportFindingsButton.IsEnabled || investigation.Findings.Count != 1)
            throw new InvalidOperationException("Import UI failed.");
        await session.DisconnectAsync(); ClearInvestigation();
        if (FindingsList.ItemsSource is not null || suspicious.Count != 0 || SuspiciousSummary.Text.Length != 0 || RawEvidence.Text.Length != 0 || ExportFindingsButton.IsEnabled) throw new InvalidOperationException("Clear UI failed.");
        File.WriteAllText(Path.Combine(directory, "smoke-result.txt"), "PASS: demo findings, light/dark renders, connected navigation, failed collection summary, and clearing investigation UI.");
        Close();
    }
}
