using System.Net;
using System.Text.Json;
namespace Lantern.Core;

public sealed record RelatedSeed(string Kind, string Value)
{
    public string Label => Kind + ": " + Value;
    public string GraphFilter() => Kind switch
    {
        "IP" when IPAddress.TryParse(Value, out _) => "ipAddress eq '" + Value + "'",
        "Application" when Guid.TryParse(Value, out var id) => "appId eq '" + id + "'",
        _ => throw new ArgumentException("Choose a valid IP address or application ID from the evidence.")
    };
    public bool ValidMessage => Kind == "Message" && Value.Length is > 0 and <= 512 && !Value.Any(char.IsControl);
}
public sealed record RelatedAccount(string Account, string Reason, IReadOnlyList<string> EvidenceIds)
{
    public int Records => EvidenceIds.Count;
}
public sealed record InvestigationPivot(string Kind, string Value, DateTimeOffset StartUtc, DateTimeOffset EndUtc, DateTimeOffset CollectedUtc, string Status);

public static class RelatedAccounts
{
    private static string T(JsonElement d, string name) => SignInFindings.Text(d, name);
    private static string IP(string value) => IPAddress.TryParse(value, out var ip) ? ip.MapToIPv6().ToString() : "";
    public static IReadOnlyList<RelatedSeed> Seeds(IEnumerable<Evidence> evidence)
    {
        var seeds = new HashSet<RelatedSeed>();
        foreach (var e in evidence)
        {
            if (SignInTypes.IsSignIn(e))
            {
                var ip = T(e.Data, "ipAddress"); if (IPAddress.TryParse(ip, out var address)) seeds.Add(new("IP", address.IsIPv4MappedToIPv6 ? address.MapToIPv4().ToString() : address.ToString()));
                if (Guid.TryParse(T(e.Data, "appId"), out var id)) seeds.Add(new("Application", id.ToString()));
            }
            var d = SignInFindings.Field(e.Data, "record");
            if (e.Source is "Mail flow inbound" or "Mail flow outbound" or "Related message trace" or "Microsoft 365 audit")
            {
                var seed = new RelatedSeed("Message", T(d, e.Source == "Microsoft 365 audit" ? "InternetMessageId" : "MessageId"));
                if (seed.ValidMessage) seeds.Add(seed);
            }
        }
        return seeds.OrderBy(s => s.Kind).ThenBy(s => s.Value, StringComparer.Ordinal).ToArray();
    }
    public static IReadOnlyList<RelatedAccount> Find(IEnumerable<Evidence> evidence, RelatedSeed seed)
    {
        var matches = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        void Add(string account, string id) { if (!account.Contains('@') || account.Any(char.IsControl)) return; if (!matches.TryGetValue(account, out var ids)) matches[account] = ids = []; ids.Add(id); }
        foreach (var e in evidence)
        {
            if (SignInTypes.IsSignIn(e) && (seed.Kind == "IP" ? IP(seed.Value).Length > 0 && IP(T(e.Data, "ipAddress")) == IP(seed.Value) : seed.Kind == "Application" && Guid.TryParse(seed.Value, out var id) && Guid.TryParse(T(e.Data, "appId"), out var found) && id == found)) Add(T(e.Data, "userPrincipalName"), e.Id);
            if (seed.Kind != "Message") continue;
            var d = SignInFindings.Field(e.Data, "record");
            if (e.Source is "Mail flow inbound" or "Mail flow outbound" or "Related message trace")
            {
                if (T(d, "MessageId") != seed.Value) continue;
                Add(T(d, "SenderAddress"), e.Id); Add(T(d, "RecipientAddress"), e.Id);
            }
            else if (e.Source == "Microsoft 365 audit" && T(d, "InternetMessageId") == seed.Value) Add(T(e.Data, "account"), e.Id);
        }
        string reason = seed.Kind == "Message" ? "Exact message ID · participant address; tenant membership and sender attribution unverified" : "Shared " + seed.Kind.ToLowerInvariant() + " · may be shared infrastructure or a common app; not proof of compromise";
        return matches.OrderBy(m => m.Key, StringComparer.OrdinalIgnoreCase).Select(m => new RelatedAccount(m.Key, reason, m.Value.Order().ToArray())).ToArray();
    }
    public static Investigation Merge(Investigation original, Investigation added, string kind, string value)
    {
        if (original.Import is not null || added.Import is not null || original.IsDemo != added.IsDemo || !string.Equals(original.Tenant, added.Tenant, StringComparison.OrdinalIgnoreCase) || original.StartUtc != added.StartUtc || original.EndUtc != added.EndUtc)
            throw new InvalidOperationException("Related collection must match the original tenant, provenance and time window.");
        var evidence = original.Evidence.ToList(); var lookup = evidence.ToDictionary(e => e.Id); var map = new Dictionary<string, string>();
        foreach (var e in added.Evidence)
        {
            var item = e;
            if (lookup.TryGetValue(e.Id, out var existing))
            {
                if (existing.Source == e.Source && existing.Data.GetRawText() == e.Data.GetRawText()) { map[e.Id] = e.Id; continue; }
                item = e with { Id = e.Id + ":observation:" + Guid.NewGuid().ToString("N") };
            }
            map[e.Id] = item.Id; evidence.Add(item); lookup[item.Id] = item;
        }
        var findings = original.Findings.Concat(added.Findings.Select(f => f with { EvidenceId = map.GetValueOrDefault(f.EvidenceId, f.EvidenceId) })).DistinctBy(f => (f.Title, f.Account, f.EvidenceId)).ToArray();
        var status = added.Coverage.Any(c => c.Status is "Failed" or "Partial" or "Not collected") ? "Partial / review coverage" : "Query completed";
        return original with { Evidence = evidence, Findings = findings, Coverage = original.Coverage.Concat(added.Coverage.Select(c => c with { Detail = "Related " + kind + " " + value + ": " + c.Detail })).ToArray(),
            Accounts = original.Accounts.Concat(added.Accounts).GroupBy(a => a.Id).Select(g => g.Last()).ToArray(), CollectedUtc = added.CollectedUtc,
            Pivots = original.Pivots.Append(new InvestigationPivot(kind, value, added.StartUtc, added.EndUtc, added.CollectedUtc, status)).ToArray() };
    }
}
