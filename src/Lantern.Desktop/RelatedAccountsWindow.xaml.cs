using System.Windows;
using System.Windows.Controls;
using Lantern.Core;
namespace Lantern.Desktop;

public partial class RelatedAccountsWindow : Window
{
    private readonly Func<Investigation, RelatedSeed, CancellationToken, Task<Investigation>> search;
    private readonly bool live;
    private CancellationTokenSource? cancellation;
    private bool closeAfterSearch;
    public Investigation Investigation { get; private set; }
    public string? SelectedAccount { get; private set; }
    public RelatedAccountsWindow(Investigation investigation, bool canSearch, Func<Investigation, RelatedSeed, CancellationToken, Task<Investigation>> search)
    {
        InitializeComponent(); ThemeMode = Application.Current.ThemeMode; Investigation = investigation; live = canSearch; this.search = search;
        Seeds.ItemsSource = RelatedAccounts.Seeds(investigation.Evidence); Seeds.SelectedIndex = 0; Refresh();
        Closing += (_, e) => { if (cancellation is not null) { e.Cancel = true; closeAfterSearch = true; cancellation.Cancel(); } };
    }
    private void SeedChanged(object sender, SelectionChangedEventArgs e) { if (Investigation is not null) Refresh(); }
    private void Refresh()
    {
        var seed = Seeds.SelectedItem as RelatedSeed;
        var rows = seed is null ? [] : RelatedAccounts.Find(Investigation.Evidence, seed);
        Accounts.ItemsSource = rows.Take(2000).ToArray();
        Status.Text = $"{rows.Count} matching accounts/addresses in collected evidence (showing up to 2,000). " + (live ? "New queries keep existing evidence. Mail addresses may be external or aliases; investigation attempts to resolve a mailbox UPN." : "Local evidence only. Live search requires the same connected tenant and a live investigation.");
        SearchButton.IsEnabled = live && seed is not null && cancellation is null;
        InvestigateButton.IsEnabled = live && Accounts.SelectedItem is RelatedAccount && cancellation is null;
    }
    private void AccountChanged(object sender, SelectionChangedEventArgs e) => InvestigateButton.IsEnabled = live && Accounts.SelectedItem is RelatedAccount && cancellation is null;
    private async void Search(object sender, RoutedEventArgs e)
    {
        if (Seeds.SelectedItem is not RelatedSeed seed || cancellation is not null) return;
        cancellation = new(); Seeds.IsEnabled = SearchButton.IsEnabled = InvestigateButton.IsEnabled = false; CancelButton.IsEnabled = true;
        Status.Text = "Searching the original tenant and time window. Unavailable sources will be recorded in coverage…";
        string outcome = "";
        try { Investigation = await search(Investigation, seed, cancellation.Token); }
        catch (OperationCanceledException) { outcome = "Search canceled. Existing case retained. "; }
        catch (Exception) { outcome = "Search interrupted. Existing case retained; verify connection and collection scope. "; }
        finally
        {
            cancellation.Dispose(); cancellation = null; Seeds.IsEnabled = true; CancelButton.IsEnabled = false;
            var seeds = RelatedAccounts.Seeds(Investigation.Evidence); Seeds.ItemsSource = seeds; Seeds.SelectedItem = seeds.FirstOrDefault(s => s == seed); Refresh();
            Status.Text = outcome + Status.Text + " Review collection coverage in Findings for query failures or limits.";
            if (closeAfterSearch) Close();
        }
    }
    private void Cancel(object sender, RoutedEventArgs e) => cancellation?.Cancel();
    private void Investigate(object sender, RoutedEventArgs e) { if (Accounts.SelectedItem is RelatedAccount row) { SelectedAccount = row.Account; DialogResult = true; } }
    private void Return(object sender, RoutedEventArgs e) => Close();
}
