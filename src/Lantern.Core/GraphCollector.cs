using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace Lantern.Core;

public sealed class GraphCollector(HttpClient http, Func<CancellationToken, Task<string>> getToken)
{
    public static bool IsAllowedEndpoint(Uri uri) => uri.Scheme == "https" && uri.Host == "graph.microsoft.com" &&
        uri.Port == 443 && uri.UserInfo.Length == 0 && uri.AbsolutePath is "/v1.0/auditLogs/signIns" or "/beta/auditLogs/signIns" && uri.Fragment.Length == 0;

    public async Task<Investigation> CollectAsync(string tenant, string account, DateTimeOffset start, DateTimeOffset end, CancellationToken ct, bool tenantWide = false, bool noninteractive = false, RelatedSeed? pivot = null)
    {
        ct.ThrowIfCancellationRequested();
        if (!tenantWide && (string.IsNullOrWhiteSpace(account) || account.Length > 254 || account.Any(char.IsControl) || !account.Contains('@')))
            throw new ArgumentException("Enter an account UPN, such as analyst@example.com.");
        if (start >= end || end - start > TimeSpan.FromDays(30)) throw new ArgumentException("Choose a period of 1–30 days.");
        string filter = $"userPrincipalName eq '{account.Replace("'", "''")}' and createdDateTime ge {start.UtcDateTime:yyyy-MM-ddTHH:mm:ssZ} and createdDateTime le {end.UtcDateTime:yyyy-MM-ddTHH:mm:ssZ}";
        if (tenantWide) { filter = $"createdDateTime ge {start.UtcDateTime:yyyy-MM-ddTHH:mm:ssZ} and createdDateTime le {end.UtcDateTime:yyyy-MM-ddTHH:mm:ssZ}"; account = "Entire tenant"; }
        if (pivot is not null) filter += " and " + pivot.GraphFilter();
        if (noninteractive) filter += " and signInEventTypes/any(t: t eq 'nonInteractiveUser')";
        string path = noninteractive ? "/beta/auditLogs/signIns" : "/v1.0/auditLogs/signIns";
        string source = noninteractive ? SignInTypes.Noninteractive : "Entra sign-ins";
        Uri? next = new("https://graph.microsoft.com" + path + "?$top=1000&$filter=" + Uri.EscapeDataString(filter));
        var evidence = new List<Evidence>();
        var ids = new HashSet<string>();
        var visited = new HashSet<string>();
        string state = "Complete", detail = "Interactive sign-in query completed. Retention, licensing, ingestion delay and permissions may limit returned data; risk/CA fields may be unavailable.";
        if (noninteractive) detail = "Noninteractive user sign-in query completed using Microsoft Graph beta (preview schema). These are background authentication events, not evidence of physical user presence. Retention, licensing, permissions and aggregation may limit data.";
        try
        {
            while (next is not null)
            {
                ct.ThrowIfCancellationRequested();
                if (!IsAllowedEndpoint(next) || next.AbsolutePath != path || !visited.Add(next.AbsoluteUri)) throw new InvalidDataException();
                if (visited.Count > 50) { state = "Partial"; detail = "Stopped at the 50-page safety limit. Narrow the time range."; break; }
                using var response = await GetAsync(next, ct);
                if (!response.IsSuccessStatusCode)
                {
                    state = evidence.Count == 0 ? "Failed" : "Partial";
                    detail = await GraphFailure.DescribeAsync(response, ct);
                    break;
                }
                using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
                foreach (var item in json.RootElement.GetProperty("value").EnumerateArray())
                {
                    var id = item.GetProperty("id").GetString() ?? throw new InvalidDataException();
                    if (ids.Add(id)) evidence.Add(new(noninteractive ? "noninteractive:" + id : id, source, item.Clone()));
                }
                next = json.RootElement.TryGetProperty("@odata.nextLink", out var link) && link.ValueKind == JsonValueKind.String
                    ? new Uri(link.GetString()!, UriKind.Absolute) : null;
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        { state = "Partial"; detail = "Canceled; completed sign-in pages retained. Remaining checks were not performed."; }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException or InvalidDataException or UriFormatException or KeyNotFoundException or InvalidOperationException)
        {
            state = evidence.Count == 0 ? "Failed" : "Partial";
            detail = "Collection stopped because a request failed or an unexpected response was received. Narrow the range or retry; retained records are included.";
        }
        return new(tenant, account, start, end, DateTimeOffset.UtcNow, false, SignInFindings.Analyze(evidence, account),
            [new(source, state, evidence.Count, detail + (pivot is null ? "" : " Related search: " + pivot.Label)),
             new("Exchange rules", "Not collected", 0, "Not included in this sign-in query."),
             new("Mailbox forwarding", "Not collected", 0, "Not included in this sign-in query.")], evidence);
    }

    private async Task<HttpResponseMessage> GetAsync(Uri uri, CancellationToken ct)
    {
        for (int attempt = 0; ; attempt++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await getToken(ct));
            var response = await http.SendAsync(request, ct);
            if (attempt >= 2 || response.StatusCode is not (HttpStatusCode.TooManyRequests or HttpStatusCode.ServiceUnavailable)) return response;
            var delay = response.Headers.RetryAfter?.Delta ?? TimeSpan.FromSeconds(2 * (attempt + 1));
            if (delay > TimeSpan.FromSeconds(30)) return response;
            response.Dispose();
            await Task.Delay(delay < TimeSpan.Zero ? TimeSpan.Zero : delay, ct);
        }
    }
}
