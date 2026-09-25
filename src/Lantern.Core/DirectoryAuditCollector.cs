using System.Net.Http.Headers;
using System.Text.Json;

namespace Lantern.Core;

public sealed record ActivityResult(IReadOnlyList<Evidence> Evidence, IReadOnlyList<Coverage> Coverage);

public sealed class DirectoryAuditCollector(HttpClient http, Func<CancellationToken, Task<string>> token)
{
    public static bool Allowed(Uri uri) => uri.Scheme == "https" && uri.Host == "graph.microsoft.com" && uri.Port == 443 &&
        uri.UserInfo.Length == 0 && uri.Fragment.Length == 0 && uri.AbsolutePath == "/v1.0/auditLogs/directoryAudits";

    public async Task<ActivityResult> CollectAsync(string? account, string? accountId, DateTimeOffset start, DateTimeOffset end, CancellationToken ct)
    {
        var rows = new List<Evidence>(); var seen = new HashSet<string>(); var ids = new HashSet<string>();
        string state = "Complete", detail = "Date-scoped directory audit query finished; account matching uses actor/target UPN or directory ID. Retention and ingestion limits apply.";
        var filter = $"activityDateTime ge {start.UtcDateTime:yyyy-MM-ddTHH:mm:ssZ} and activityDateTime le {end.UtcDateTime:yyyy-MM-ddTHH:mm:ssZ}";
        string next = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$top=1000&$filter=" + Uri.EscapeDataString(filter);
        try
        {
            while (next.Length > 0)
            {
                ct.ThrowIfCancellationRequested();
                var uri = new Uri(next);
                if (!Allowed(uri) || !seen.Add(next) || seen.Count > 50) throw new InvalidDataException();
                using var request = new HttpRequestMessage(HttpMethod.Get, uri);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await token(ct));
                using var response = await http.SendAsync(request, ct);
                if (!response.IsSuccessStatusCode)
                {
                    state = rows.Count == 0 ? "Failed" : "Partial";
                    detail = $"HTTP {(int)response.StatusCode}; access, role, service or licensing may restrict this source. Cause unconfirmed; other checks continue.";
                    break;
                }
                using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
                foreach (var row in json.RootElement.GetProperty("value").EnumerateArray())
                {
                    var id = SignInFindings.Text(row, "id");
                    if (id.Length == 0) throw new InvalidDataException();
                    if (account is not null && !Matches(row, account, accountId)) continue;
                    if (ids.Add(id)) rows.Add(new("directory-audit-" + id, "Entra audit", row.Clone()));
                }
                next = SignInFindings.Text(json.RootElement, "@odata.nextLink");
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        { state = "Partial"; detail = "Canceled; completed pages retained."; }
        catch (Exception)
        { state = rows.Count == 0 ? "Failed" : "Partial"; detail = "Query interrupted, response invalid or 50-page limit reached; completed pages retained. Other checks continue."; }
        return new(rows, [new("Entra audit", state, rows.Count, detail)]);
    }

    private static bool Matches(JsonElement row, string account, string? id)
    {
        bool Match(JsonElement user) => string.Equals(SignInFindings.Text(user, "userPrincipalName"), account, StringComparison.OrdinalIgnoreCase) ||
            (!string.IsNullOrEmpty(id) && string.Equals(SignInFindings.Text(user, "id"), id, StringComparison.OrdinalIgnoreCase));
        if (Match(SignInFindings.Field(SignInFindings.Field(row, "initiatedBy"), "user"))) return true;
        var targets = SignInFindings.Field(row, "targetResources");
        return targets.ValueKind == JsonValueKind.Array && targets.EnumerateArray().Any(Match);
    }
}
