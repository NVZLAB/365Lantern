using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Security;
using System.Runtime.InteropServices;
using Lantern.Core;

namespace Lantern.Desktop;

public partial class MainWindow
{
    private static string ResponseText(JsonElement value, string key) => value.TryGetProperty(key, out var item) && item.ValueKind == JsonValueKind.String ? item.GetString() ?? "" : "";
    private bool responseBusy;
    private int exportedResponses;
    private sealed record ResponseLink(string Key, string Label);
    private string SelectedResponseOperation => (ResponseOperation.SelectedItem as ComboBoxItem)?.Tag as string ?? "revoke";
    private void ResponseOperationChanged(object sender, SelectionChangedEventArgs e) => UpdateResponseActionInfo();
    private void UpdateResponseActionInfo()
    {
        if (ResponseActionInfo is null) return;
        ResponseActionInfo.Text = SelectedResponseOperation switch {
            "password" => "Sets a temporary password and requires a change at next sign-in. A random temporary password is generated for you; retrieve it in the private handoff window after execution. Synchronized accounts are excluded.",
            "device" => "Remove one unmanaged Entra-registered device identity after reviewing its impact on all users. Managed, joined and system-managed devices require their management tools. Separate broad Directory.AccessAsUser.All consent is required; no wipe is performed.",
            "method" => "Review the registered methods and select one to remove. Other methods remain. Re-enrollment depends on tenant policy; this does not enforce MFA or revoke sessions.",
            _ => "Invalidates refresh tokens and browser session cookies. Keeps registered MFA methods. Effects can be delayed; application-owned sessions may remain." };
    }
    private void RefreshResponse()
    {
        var eligible = ResponseActions.Eligible(investigation, session.TenantId) && session.IsConnected;
        ResponseAvailability.Text = eligible ? "Choose a collected account. Response authorization uses Microsoft Graph PowerShell in a separate process."
            : "Connect to the same tenant and collect a live investigation first. Offline and synthetic cases cannot perform tenant changes.";
        var selected = (ResponseAccount.SelectedItem as AccountDetail)?.Id;
        ResponseAccount.ItemsSource = investigation?.Accounts.Where(a => Guid.TryParse(a.Id, out _)).ToArray();
        if (eligible && ResponseAccount.Items.Count == 0) ResponseAvailability.Text = "No directory account identities were collected. Resolve the account inventory permission or collection gap and investigate again before responding.";
        ResponseAccount.SelectedItem = investigation?.Accounts.FirstOrDefault(a => a.Id == selected);
        if (ResponseAccount.SelectedIndex < 0 && ResponseAccount.Items.Count > 0) ResponseAccount.SelectedIndex = 0;
        var link = (ResponseIndicator.SelectedItem as ResponseLink)?.Key;
        var links = new[] { new ResponseLink("", "No indicator linked — explain the reason below") }.Concat(investigation is null ? [] : IncidentReport.Indicators(investigation).Select(i => new ResponseLink(i.Key, i.Indicator.Account + " — " + i.Indicator.Title))).ToArray();
        ResponseIndicator.ItemsSource = links;
        ResponseIndicator.SelectedItem = links.FirstOrDefault(l => l.Key == link) ?? links[0];
        ResponseRecords.ItemsSource = investigation?.Responses;
        UpdateResponseActionInfo();
        ResponseEditor.IsEnabled = eligible && !responseBusy && operation is null && ResponseAccount.Items.Count > 0;
        ExportResponseButton.IsEnabled = !responseBusy && operation is null && investigation is not null;
    }
    private bool LeaveResponseRecords()
    {
        if (responseBusy) return false;
        return investigation is null || investigation.Responses.Count <= exportedResponses || MessageBox.Show(this,
            "Response records have not been exported to the evidence ZIP. Continuing will discard them from memory. Cancel and export first to preserve the record of tenant changes.",
            "Unexported response records", MessageBoxButton.OKCancel, MessageBoxImage.Warning, MessageBoxResult.Cancel) == MessageBoxResult.OK;
    }
    private async void PrepareRevocation(object sender, RoutedEventArgs e)
    {
        if (responseBusy || operation is not null || !session.IsConnected || !ResponseActions.Eligible(investigation, session.TenantId)
            || investigation is null || ResponseAccount.SelectedItem is not AccountDetail selected || !LeaveAssessment()) return;
        var reason = ResponseReason.Text.Trim();
        if (reason.Length == 0) { ResponseStatus.Text = "Enter a reason or authorization reference before preparing the action."; return; }
        var caseValue = investigation;
        var tenant = session.TenantId!;
        var actor = session.Operator!;
        var linked = (ResponseIndicator.SelectedItem as ResponseLink)?.Key ?? "";
        var responseOperation = SelectedResponseOperation;
        SecureString? password = null;
        var preparationDetail = "Preparation failed, expired or was canceled. No tenant change was sent. Check module availability, response consent, operator role and identity. Guest and administrator self-targeting are excluded.";
        ResponseActionRecord? pending = null;
        using var helper = new ModuleSession();
        responseBusy = true;
        operation = new CancellationTokenSource(TimeSpan.FromMinutes(5)); SetBusy(true);
        CancelResponseButton.IsEnabled = true;
        ResponseStatus.Text = "Preparing response access. Sign in as the connected administrator. No tenant change has been sent.";
        SessionLabel.Text = "Response authorization · No action sent";
        try
        {
            var preview = await helper.PrepareResponseAsync(tenant, actor, selected.Id, operation.Token, responseOperation);
            if (ResponseText(preview, "reason") == "SyncedAccount") preparationDetail = "Not performed: this account is synchronized from another directory. Reset its password through the authoritative directory or an approved password-writeback workflow.";
            if (ResponseText(preview, "reason") == "SyncStateUnavailable") preparationDetail = "Not performed: the account's synchronization state could not be established. Verify its authoritative directory before resetting the password.";
            if (ResponseText(preview, "status") != "Prepared") throw new InvalidOperationException();
            var target = new ResponseTarget(ResponseText(preview, "id"), ResponseText(preview, "account"), ResponseText(preview, "displayName"),
                ResponseText(preview, "userType"), ResponseText(preview, "operatorId"), ResponseText(preview, "beforeValidFrom"), preview.GetProperty("preparedUtc").GetDateTimeOffset())
                { IsSynced = preview.TryGetProperty("isSynced", out var synced) && synced.ValueKind == JsonValueKind.True, BeforePasswordChange = ResponseText(preview, "beforePasswordChange") };
            // Validate before offering approval, then revalidate after the confirmation dialog.
            ResponseActions.Prepare(caseValue, tenant, actor, target, reason, linked, DateTimeOffset.UtcNow);
            var approval = new ResponseApprovalWindow(responseOperation, tenant, actor, target, reason, preview) { Owner = this };
            if (approval.ShowDialog() != true) { ResponseStatus.Text = "Canceled before execution. No tenant change was sent."; return; }
            password = approval.ApprovedPassword;
            var method = approval.SelectedMethod;
            var device = approval.SelectedDevice;
            operation.Token.ThrowIfCancellationRequested();
            pending = ResponseActions.Prepare(caseValue, tenant, actor, target, reason, linked, DateTimeOffset.UtcNow, responseOperation, method?.Id ?? "", method?.Type ?? "", device?.Id ?? "", device?.Label ?? "");
            investigation = caseValue with { Responses = caseValue.Responses.Append(pending).ToArray() };
            ResponseRecords.ItemsSource = investigation.Responses;
            CancelButton.IsEnabled = false; // A dispatched tenant write cannot be undone by canceling locally.
            CancelResponseButton.IsEnabled = false;
            SessionLabel.Text = "Response · Approved action in progress";
            ResponseStatus.Text = "Sending the approved request once, then checking the available result…";
            JsonElement result;
            if (responseOperation == "password")
            {
                var pointer = Marshal.SecureStringToBSTR(password ?? throw new InvalidOperationException());
                try { result = await helper.RequestAsync(new { action = responseOperation, tenant, actor, targetId = target.Id, approved = true, temporaryPassword = Marshal.PtrToStringBSTR(pointer) }, CancellationToken.None); }
                finally { Marshal.ZeroFreeBSTR(pointer); }
            }
            else result = await helper.RequestAsync(new { action = responseOperation, tenant, actor, targetId = target.Id, approved = true, methodId = method?.Id, methodType = method?.Type, deviceObjectId = device?.Id, deviceImpactApproved = device is not null }, CancellationToken.None);
            StoreResponseResult(ResponseActions.Complete(pending, result, DateTimeOffset.UtcNow));
        }
        catch (Exception)
        {
            if (pending is not null) StoreResponseResult(ResponseActions.Unknown(pending));
            else
            {
                var failed = new ResponseActionRecord(Guid.NewGuid().ToString("D"), ResponseActions.Title(responseOperation), tenant, selected.Account, selected.Id, actor, "", reason, linked,
                    DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, "Not performed", "Not checked", "", "", preparationDetail) { Operation = responseOperation };
                investigation = caseValue with { Responses = caseValue.Responses.Append(failed).ToArray() };
                ResponseStatus.Text = failed.Detail;
            }
        }
        finally
        {
            var helperClosed = true;
            try { await helper.CloseAsync(); }
            catch { helperClosed = false; ResponseStatus.Text += " Response-process cleanup could not be confirmed. Close Lantern before another response attempt."; }
            if (password is not null && pending is not null)
            {
                var completed = investigation?.Responses.FirstOrDefault(r => r.Id == pending.Id);
                try
                {
                    if (completed?.Status is "Accepted" or "Unknown") new PasswordHandoffWindow(password, pending.Account, completed.Status) { Owner = this }.ShowDialog();
                }
                catch { ResponseStatus.Text += " Password handoff could not be displayed. Verify the recorded outcome before initiating another reset."; }
                finally { password.Dispose(); password = null; }
            }
            password?.Dispose();
            responseBusy = false;
            CancelResponseButton.IsEnabled = false;
            operation?.Dispose(); operation = null;
            SessionLabel.Text = session.IsConnected ? "Connected · Read-only" : "Not connected";
            SetBusy(false); RefreshResponse();
            StatusLabel.Text = (helperClosed ? "Response session closed. " : "Response-process cleanup needs attention. ") + "Export the evidence ZIP to preserve action records. Microsoft consent may remain in the tenant.";
        }
    }
    private void StoreResponseResult(ResponseActionRecord result)
    {
        investigation = investigation! with { Responses = investigation!.Responses.Select(r => r.Id == result.Id ? result : r).ToArray() };
        ResponseStatus.Text = result.Status + " · " + result.Verification + ". " + result.Detail;
    }
}
