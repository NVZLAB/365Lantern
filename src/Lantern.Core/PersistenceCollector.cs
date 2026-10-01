using System.Net.Http.Headers;
using System.Text.Json;

namespace Lantern.Core;

public sealed class PersistenceCollector(Func<object, CancellationToken, Task<JsonElement>> request)
{
    public async Task<ActivityResult> CollectAsync(string account, CancellationToken ct)
    {
        var evidence = new List<Evidence>(); var coverage = new List<Coverage>();
        foreach (var (kind, source) in new[] { ("fullAccess", "Mailbox Full Access"), ("sendAs", "Mailbox Send As"), ("sendOnBehalf", "Mailbox Send on Behalf") })
        {
            int count = 0; string state = "Complete", detail = "Current configuration only, not grant time. Group expansion and effective access are not evaluated.";
            try
            {
                ct.ThrowIfCancellationRequested();
                var response = await request(new { action = "activity", kind, account }, ct);
                if (SignInFindings.Text(response, "status") != "ok") throw new InvalidOperationException();
                var rows = response.GetProperty("rows").EnumerateArray().ToArray();
                foreach (var row in rows.Take(1000))
                    evidence.Add(new("persistence:" + account + ":" + kind + ":" + count++, source, JsonSerializer.SerializeToElement(new { account, record = row })) { CollectedUtc = DateTimeOffset.UtcNow });
                if (rows.Length >= 1000) { state = "Partial"; detail += " Reached 1,000-row safety boundary; additional entries may be missing."; }
            }
            catch (Exception) { state = count > 0 || ct.IsCancellationRequested ? "Partial" : "Failed"; detail = ct.IsCancellationRequested ? "Canceled; completed snapshots retained." : "Read unavailable. Verify Exchange read roles, module commands and mailbox existence. Other checks continue; exact failure cause unconfirmed."; }
            coverage.Add(new(source, state, count, account + ": " + detail));
        }
        return new(evidence, coverage);
    }
}

public sealed class GrantCollector(HttpClient http, Func<CancellationToken, Task<string>> token)
{
    public static bool ApplicationAllowed(Uri uri) => uri.Scheme == "https" && uri.Host == "graph.microsoft.com" && uri.Port == 443 && uri.UserInfo.Length == 0 && uri.Fragment.Length == 0 &&
        uri.AbsolutePath.StartsWith("/v1.0/servicePrincipals/", StringComparison.Ordinal) && Guid.TryParseExact(uri.AbsolutePath["/v1.0/servicePrincipals/".Length..], "D", out _) && uri.Query == "?$select=id,appId,displayName,publisherName,servicePrincipalType";
    public static bool Allowed(Uri uri) => uri.Scheme == "https" && uri.Host == "graph.microsoft.com" && uri.Port == 443 && uri.UserInfo.Length == 0 && uri.Fragment.Length == 0 && uri.AbsolutePath == "/v1.0/oauth2PermissionGrants";
    public async Task<ActivityResult> CollectAsync(string? account, string? id, IReadOnlyList<AccountDetail> accounts, CancellationToken ct)
    {
        var evidence = new List<Evidence>(); var coverage = new List<Coverage>(); var ids = new HashSet<string>();
        var filters = account is null ? new[] { "" } : Guid.TryParse(id, out _) ? new[] { "principalId eq '" + id + "'", "consentType eq 'AllPrincipals'" } : new[] { "consentType eq 'AllPrincipals'" };
        if (account is not null && !Guid.TryParse(id, out _)) coverage.Add(new("User OAuth grants", "Not collected", 0, "Directory user ID unavailable. Attempting tenant-wide delegated grants that may apply to this account."));
        foreach (var filter in filters)
        {
            int count = 0; string state = "Complete", detail = "Current delegated grants only; not historical changes or proof of use. Client/resource values are service-principal object IDs, not application IDs. Application-only app-role grants are not covered.";
            var next = "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" + (filter.Length == 0 ? "" : "?$filter=" + Uri.EscapeDataString(filter));
            var visited = new HashSet<string>();
            try
            {
                while (next.Length > 0)
                {
                    ct.ThrowIfCancellationRequested();
                    var uri = new Uri(next);
                    if (!Allowed(uri) || !visited.Add(next) || visited.Count > 50) throw new InvalidDataException();
                    using var message = new HttpRequestMessage(HttpMethod.Get, uri);
                    message.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await token(ct));
                    using var response = await http.SendAsync(message, ct);
                    if (!response.IsSuccessStatusCode)
                    { state = count > 0 ? "Partial" : "Failed"; detail = $"HTTP {(int)response.StatusCode}. Requires Directory.Read.All and a supported read role. Enable optional application-grant access when connecting if desired. No permission was broadened automatically; other checks continue."; break; }
                    using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
                    foreach (var row in json.RootElement.GetProperty("value").EnumerateArray())
                    {
                        string T(string name) => SignInFindings.Text(row, name);
                        var key = T("id"); if (key.Length == 0) throw new InvalidDataException();
                        if (account is not null && T("consentType") != "AllPrincipals" && !string.Equals(T("principalId"), id, StringComparison.OrdinalIgnoreCase)) continue;
                        if (!ids.Add(key)) continue;
                        if (evidence.Count >= 10000) throw new InvalidDataException();
                        var owner = T("consentType") == "AllPrincipals" ? "All tenant users" : accounts.FirstOrDefault(a => string.Equals(a.Id, T("principalId"), StringComparison.OrdinalIgnoreCase))?.Account ?? account ?? T("principalId");
                        evidence.Add(new("oauth-grant:" + key, "OAuth delegated grants", JsonSerializer.SerializeToElement(new { account = owner, record = row })) { CollectedUtc = DateTimeOffset.UtcNow }); count++;
                    }
                    next = SignInFindings.Text(json.RootElement, "@odata.nextLink");
                }
            }
            catch (Exception) { state = count > 0 || ct.IsCancellationRequested ? "Partial" : "Failed"; detail = ct.IsCancellationRequested ? "Canceled; completed pages retained." : "Query interrupted, unexpected response or safety limit reached (50 pages / 10,000 grants). Completed pages retained."; }
            coverage.Add(new("OAuth delegated grants", state, count, (account ?? "Entire tenant") + ": " + detail));
        }
        if (evidence.Count > 0) await ResolveApplications(evidence, coverage, ct);
        return new(evidence, coverage);
    }

    private async Task ResolveApplications(List<Evidence> evidence, List<Coverage> coverage, CancellationToken ct)
    {
        var cache = new Dictionary<string, JsonElement?>(StringComparer.OrdinalIgnoreCase);
        int attempted = 0;
        bool stop = false;
        async Task<JsonElement?> Resolve(string id)
        {
            if (cache.TryGetValue(id, out var existing)) return existing;
            cache[id] = null;
            if (stop || ct.IsCancellationRequested || !Guid.TryParseExact(id, "D", out _) || attempted >= 200) return null;
            attempted++;
            try
            {
                var uri = new Uri("https://graph.microsoft.com/v1.0/servicePrincipals/" + id + "?$select=id,appId,displayName,publisherName,servicePrincipalType");
                if (!ApplicationAllowed(uri)) throw new InvalidDataException();
                using var request = new HttpRequestMessage(HttpMethod.Get, uri);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await token(ct));
                using var response = await http.SendAsync(request, ct);
                if (!response.IsSuccessStatusCode)
                {
                    if ((int)response.StatusCode is 401 or 403 or 429 || (int)response.StatusCode >= 500) stop = true;
                    return null;
                }
                using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
                var row = json.RootElement;
                if (!string.Equals(SignInFindings.Text(row, "id"), id, StringComparison.OrdinalIgnoreCase)) return null;
                cache[id] = JsonSerializer.SerializeToElement(new { id, appId = SignInFindings.Text(row, "appId"), displayName = SignInFindings.Text(row, "displayName"), publisherName = SignInFindings.Text(row, "publisherName"), servicePrincipalType = SignInFindings.Text(row, "servicePrincipalType") });
                return cache[id];
            }
            catch (Exception) { stop = true; return null; }
        }
        for (int n = 0; n < evidence.Count; n++)
        {
            var e = evidence[n]; var record = e.Data.GetProperty("record");
            var clientApplication = await Resolve(SignInFindings.Text(record, "clientId"));
            var resourceApplication = await Resolve(SignInFindings.Text(record, "resourceId"));
            evidence[n] = e with { Data = JsonSerializer.SerializeToElement(new { account = SignInFindings.Text(e.Data, "account"), record, clientApplication, resourceApplication }) };
        }
        int resolved = cache.Values.Count(v => v.HasValue && SignInFindings.Text(v.Value, "displayName").Length > 0);
        coverage.Add(new("Application identities", resolved == cache.Count ? "Complete" : "Partial", resolved,
            $"Resolved {resolved} of {cache.Count} referenced service-principal names; maximum 200 lookups. Unavailable names retain object IDs. Permissions, cancellation, deleted objects or request limits may prevent resolution. Names and publishers are directory labels, not proof of trust. Grant records remain available."));
    }
}
