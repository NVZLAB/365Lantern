using System.Globalization;
using System.Net;

namespace Lantern.Core;

public sealed record DiagnosticEvent(string EvidenceId, string Account, string IP, string Country, string Region, string Client, string Application, string Outcome, string Time);
public sealed record DiagnosticGroup(string Value, int Events, int Successful, int NonSuccess, int Unknown, string FirstUtc, string LastUtc);
public sealed record SignInDiagnostics(IReadOnlyList<DiagnosticEvent> Events, int Duplicates)
{
    public IReadOnlyList<DiagnosticGroup> IPs => Group(Events, e => e.IP);
    public IReadOnlyList<DiagnosticGroup> Countries => Group(Events, e => e.Country);
    public IReadOnlyList<DiagnosticGroup> Regions => Group(Events, e => e.Region);
    public IReadOnlyList<DiagnosticGroup> Applications => Group(Events, e => e.Application);
    public string Summary => $"{Events.Count} distinct events · {Events.Count(e => e.Outcome == "Success")} successful · {Events.Count(e => e.Outcome.StartsWith("Non-success"))} non-success · {Events.Count(e => e.Outcome == "Unknown")} unknown outcome\n" +
        $"{IPs.Count(g => g.Value != "Unknown")} distinct IPs ({Events.Where(e => e.Outcome == "Success" && e.IP != "Unknown").Select(e => e.IP).Distinct().Count()} with success) · {Countries.Count(g => g.Value != "Unknown")} countries/territories · {Regions.Count(g => g.Value != "Unknown")} country/state regions\n" +
        $"Missing/invalid IP: {Events.Count(e => e.IP == "Unknown")}; unknown country: {Events.Count(e => e.Country == "Unknown")}; unknown state/region: {Events.Count(e => e.Region == "Unknown")}. {Duplicates} duplicate records excluded from these totals.";
    public static SignInDiagnostics Create(IEnumerable<Evidence> evidence)
    {
        var events = new List<DiagnosticEvent>();
        var seen = new HashSet<(string, string)>();
        int duplicates = 0;
        foreach (var row in evidence.Where(e => SignInTypes.IsSignIn(e)))
        {
            string Text(string name) => SignInFindings.Text(row.Data, name).Trim();
            var account = Text("userPrincipalName"); var id = Text("id");
            if (id.Length > 0 && !seen.Add((account.ToLowerInvariant(), id))) { duplicates++; continue; }
            var location = SignInFindings.Field(row.Data, "location");
            var country = SignInFindings.Text(location, "countryOrRegion").Trim().ToUpperInvariant();
            var state = SignInFindings.Text(location, "state").Trim().ToUpperInvariant();
            var code = SignInFindings.Field(SignInFindings.Field(row.Data, "status"), "errorCode");
            string outcome = code.ValueKind == System.Text.Json.JsonValueKind.Number && code.TryGetInt32(out var n) ? n == 0 ? "Success" : $"Non-success ({n})" : "Unknown";
            var ip = IPAddress.TryParse(Text("ipAddress"), out var address) ? (address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address).ToString() : "Unknown";
            var time = DateTimeOffset.TryParse(Text("createdDateTime"), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var date) ? date.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) : "Unknown";
            events.Add(new(row.Id, account.Length == 0 ? "Unknown" : account, ip, country.Length == 0 ? "Unknown" : country,
                country.Length == 0 || state.Length == 0 ? "Unknown" : country + " / " + state,
                Text("clientAppUsed") is { Length: > 0 } client ? client : "Unknown", Text("appDisplayName") is { Length: > 0 } app ? app : "Unknown", outcome, time));
        }
        return new(events.OrderByDescending(e => e.Time).ToArray(), duplicates);
    }
    private static IReadOnlyList<DiagnosticGroup> Group(IEnumerable<DiagnosticEvent> events, Func<DiagnosticEvent, string> key) => events.GroupBy(key).Select(g =>
    {
        var times = g.Where(e => e.Time != "Unknown").Select(e => e.Time).Order().ToArray();
        return new DiagnosticGroup(g.Key, g.Count(), g.Count(e => e.Outcome == "Success"), g.Count(e => e.Outcome.StartsWith("Non-success")), g.Count(e => e.Outcome == "Unknown"), times.FirstOrDefault() ?? "Unknown", times.LastOrDefault() ?? "Unknown");
    }).OrderByDescending(g => g.Events).ThenBy(g => g.Value).ToArray();
}
