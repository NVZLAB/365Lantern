using System.Security;
using System.Text.Json;
using System.Windows;
using Lantern.Core;

namespace Lantern.Desktop;

public sealed record ResponseMethodChoice(string Id, string Type, string Label, bool Supported)
{
    public string Availability => Supported ? "Available for removal" : "Not removable by Lantern";
}
public sealed record ResponseDeviceChoice(string Id, string DeviceId, string Label, bool Supported, string Availability);
public partial class ResponseApprovalWindow : Window
{
    private readonly string operation;
    public ResponseDeviceChoice? SelectedDevice => DeviceList.SelectedItem as ResponseDeviceChoice;
    public SecureString? ApprovedPassword { get; private set; }
    public ResponseMethodChoice? SelectedMethod => MethodList.SelectedItem as ResponseMethodChoice;
    public ResponseApprovalWindow(string operation, string tenant, string actor, ResponseTarget target, string reason, JsonElement preview)
    {
        InitializeComponent(); this.operation = operation;
        ActionHeading.Text = ResponseActions.Title(operation);
        TargetSummary.Text = $"Tenant: {tenant}\nAccount: {target.Account}\nName: {target.DisplayName}\nObject ID: {target.Id}\nOperator: {actor}\n\nReason: {reason}";
        ImpactSummary.Text = operation switch {
            "device" => "Remove a selected Entra device identity. This action needs separate Directory.AccessAsUser.All consent, a broad delegated directory permission, and an appropriate administrator role.",
            "password" => "This replaces the account password and requires a change at next sign-in. Cloud-managed passwords only; synchronized accounts are excluded. Existing sign-in sessions are a separate response action.",
            "method" => "This deletes a registered MFA or passwordless authentication method. It cannot be restored by undoing the action. Existing sign-in sessions are a separate response action.",
            _ => "This invalidates sign-in refresh tokens and browser session cookies. Reauthentication may take several minutes. Registered MFA methods are retained; not every application's own session is guaranteed to end." };
        PasswordPanel.Visibility = operation == "password" ? Visibility.Visible : Visibility.Collapsed;
        MethodPanel.Visibility = operation == "method" ? Visibility.Visible : Visibility.Collapsed;
        if (operation == "method" && preview.TryGetProperty("methods", out var methods) && methods.ValueKind == JsonValueKind.Array)
            MethodList.ItemsSource = methods.EnumerateArray().Select(m => new ResponseMethodChoice(m.GetProperty("id").GetString() ?? "", m.GetProperty("type").GetString() ?? "", m.GetProperty("label").GetString() ?? "", m.GetProperty("supported").GetBoolean())).ToArray();
        DevicePanel.Visibility = operation == "device" ? Visibility.Visible : Visibility.Collapsed;
        if (operation == "device" && preview.TryGetProperty("devices", out var devices))
            DeviceList.ItemsSource = devices.EnumerateArray().Select(d => new ResponseDeviceChoice(d.GetProperty("id").GetString() ?? "", d.GetProperty("deviceId").GetString() ?? "", d.GetProperty("label").GetString() ?? "", d.GetProperty("supported").GetBoolean(), d.GetProperty("availability").GetString() ?? "")).ToArray();
        if (operation == "password") GeneratePassword(this, new RoutedEventArgs());
        if (operation == "device") DeviceInventorySummary.Text = DeviceList.Items.Count == 0 ? "No registered devices were returned for this account. No device can be removed here."
            : $"{DeviceList.Items.Count} registrations returned; {DeviceList.Items.OfType<ResponseDeviceChoice>().Count(d => d.Supported)} eligible for removal in Lantern. Select one to review.";
        ApproveButton.Content = operation switch { "password" => "Reset password", "method" => "Remove selected method", "device" => "Remove selected device", _ => "Revoke sign-ins" };
        Closed += (_, _) => { TemporaryPassword.Clear(); };
    }
    private void GeneratePassword(object sender, RoutedEventArgs e) => TemporaryPassword.Password = TemporaryPasswords.Generate();
    private void Approve(object sender, RoutedEventArgs e)
    {
        if (Acknowledge.IsChecked != true) { ValidationMessage.Text = "Confirm that you approve this account change."; return; }
        if (operation == "password")
        {
            if (TemporaryPassword.SecurePassword.Length < 8)
            { ValidationMessage.Text = "Use a temporary password of at least eight characters. Microsoft enforces the tenant's password policy."; return; }
            ApprovedPassword = TemporaryPassword.SecurePassword.Copy(); ApprovedPassword.MakeReadOnly();
        }
        if (operation == "method" && (SelectedMethod is not { Supported: true } chosen || !ResponseActions.AuthenticationMethodTypes.Contains(chosen.Type)))
        { ValidationMessage.Text = "Select a supported registration. Unsupported methods must be handled in Microsoft administration tools."; return; }
        if (operation == "device" && (SelectedDevice is not { Supported: true } device || !Guid.TryParse(device.Id, out _) || !DeviceConfirmation.Text.Trim().Equals(device.Id, StringComparison.OrdinalIgnoreCase) || DeviceRecoveryAcknowledged.IsChecked != true))
        { ValidationMessage.Text = "Select an eligible device, type its object ID and confirm the recovery and shared-device impact."; return; }
        DialogResult = true;
    }
}
