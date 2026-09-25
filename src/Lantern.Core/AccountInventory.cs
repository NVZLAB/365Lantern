using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Lantern.Core;

public sealed record AccountDetail(string Id, string Account, string Methods, string MfaRegistered, string Devices, string DeviceStatus);
public sealed record InventoryResult(IReadOnlyList<AccountDetail> Accounts, IReadOnlyList<Evidence> Evidence, IReadOnlyList<Coverage> Coverage);

public sealed class AccountInventory(HttpClient http, Func<CancellationToken, Task<string>> token)
{
    public static bool Allowed(Uri uri) => uri.Scheme == "https" && uri.Host == "graph.microsoft.com" && uri.Port == 443 && uri.UserInfo.Length == 0 && uri.Fragment.Length == 0 &&
        (uri.AbsolutePath is "/v1.0/users" or "/v1.0/reports/authenticationMethods/userRegistrationDetails" || Regex.IsMatch(uri.AbsolutePath, @"^/v1\.0/users/[0-9a-fA-F-]{36}/registeredDevices$"));
    public async Task<InventoryResult> CollectAsync(string? account, CancellationToken ct)
    {
        var evidence = new List<Evidence>(); var coverage = new List<Coverage>(); var accounts = new List<AccountDetail>();
        string Filter(string? upn) => upn is null ? "" : "&$filter=" + Uri.EscapeDataString("userPrincipalName eq '" + upn.Replace("'", "''") + "'");
        var users = await ReadAsync("https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName&$top=999" + Filter(account), 1000, ct);
        coverage.Add(new("Account inventory", users.State, users.Rows.Count, users.Detail));
        var methods = await ReadAsync("https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999" + Filter(account), 10000, ct);
        coverage.Add(new("MFA registration report", methods.State, methods.Rows.Count, methods.Detail + " Registration is not proof that MFA was enforced. Report freshness and licensing apply."));
        foreach (var method in methods.Rows) evidence.Add(new("mfa-" + SignInFindings.Text(method, "id"), "MFA registration", method));
        foreach (var user in users.Rows)
        {
            ct.ThrowIfCancellationRequested();
            var id = SignInFindings.Text(user, "id"); var upn = SignInFindings.Text(user, "userPrincipalName");
            if (!Guid.TryParse(id, out _) || string.IsNullOrWhiteSpace(upn)) continue;
            var devices = await ReadAsync($"https://graph.microsoft.com/v1.0/users/{id}/registeredDevices?$select=id,displayName,deviceId,operatingSystem,trustType,isManaged,isCompliant", 1000, ct);
            coverage.Add(new("Registered devices", devices.State, devices.Rows.Count, upn + ": " + devices.Detail));
            foreach (var device in devices.Rows) evidence.Add(new("device-" + id + "-" + SignInFindings.Text(device, "id"), "Registered devices", JsonSerializer.SerializeToElement(new { account = upn, device })));
            var method = methods.Rows.FirstOrDefault(m => SignInFindings.Text(m, "id") == id);
            var list = SignInFindings.Field(method, "methodsRegistered");
            var names = list.ValueKind == JsonValueKind.Array ? string.Join(", ", list.EnumerateArray().Where(v => v.ValueKind == JsonValueKind.String).Select(v => v.GetString())) : "Unavailable / not in report";
            var mfa = SignInFindings.Field(method, "isMfaRegistered");
            accounts.Add(new(id, upn, names.Length == 0 ? "None reported" : names, mfa.ValueKind is JsonValueKind.True or JsonValueKind.False ? mfa.GetBoolean() ? "Yes" : "No" : "Unknown",
                devices.Rows.Count == 0 ? devices.State == "Complete" ? "None returned" : "Unavailable" : string.Join("; ", devices.Rows.Select(d => SignInFindings.Text(d, "displayName") is { Length: > 0 } name ? name : SignInFindings.Text(d, "id"))), devices.State));
        }
        return new(accounts, evidence, coverage);
    }
    private async Task<(List<JsonElement> Rows, string State, string Detail)> ReadAsync(string url, int limit, CancellationToken ct)
    {
        var rows = new List<JsonElement>(); var seen = new HashSet<string>(); var ids = new HashSet<string>();
        var original = new Uri(url).AbsolutePath;
        try
        {
            while (url.Length > 0)
            {
                var uri = new Uri(url);
                if (!Allowed(uri) || uri.AbsolutePath != original || !seen.Add(url) || seen.Count > 50) throw new InvalidDataException();
                using var request = new HttpRequestMessage(HttpMethod.Get, uri);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await token(ct));
                using var response = await http.SendAsync(request, ct);
                if (!response.IsSuccessStatusCode) return (rows, rows.Count == 0 ? "Failed" : "Partial", $"HTTP {(int)response.StatusCode}; verify read permissions, role and licensing. No error body retained.");
                using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
                foreach (var row in document.RootElement.GetProperty("value").EnumerateArray())
                {
                    if (!ids.Add(SignInFindings.Text(row, "id"))) continue;
                    if (rows.Count >= limit) return (rows, "Partial", $"Stopped at the {limit}-record limit; additional records were not collected.");
                    rows.Add(row.Clone());
                }
                url = SignInFindings.Text(document.RootElement, "@odata.nextLink");
            }
            return (rows, "Complete", "Current snapshot query completed.");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception) { return (rows, rows.Count == 0 ? "Failed" : "Partial", "Query interrupted or unexpected response; retained records may be incomplete."); }
    }
}
