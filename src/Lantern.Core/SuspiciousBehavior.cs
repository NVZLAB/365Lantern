using System.Globalization;
using System.Text.Json;

namespace Lantern.Core;

public sealed record SuspiciousItem(string RuleId, string Priority, string Basis, DateTimeOffset? TimestampUtc,
    string Account, string Title, string Explanation, IReadOnlyList<string> EvidenceIds)
{
    public string Time => TimestampUtc?.ToString("yyyy-MM-dd HH:mm:ss 'UTC'") ?? "Time unavailable";
}

public static class SuspiciousBehavior
{
    public const string Version = "3";
    public const string Limitations = "Indicators require analyst review; no matches does not establish safety. Travel uses approximate Microsoft IP locations and can be explained by VPNs/proxies. Mail traces alone cannot identify phishing, reading or clicks. Suspect-mail access requires a recorded Microsoft threat verdict and matching message evidence; access is not proof a human opened or clicked the email. Review collection coverage for missing data.";
    private static JsonElement F(JsonElement d, string key) => SignInFindings.Field(d, key);
    private static string T(JsonElement d, string key) => SignInFindings.Text(d, key);
    private static DateTimeOffset? Date(JsonElement d, string key) => DateTimeOffset.TryParse(T(d, key), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var value) ? value : null;
    private static IEnumerable<JsonElement> Array(JsonElement d) => d.ValueKind == JsonValueKind.Array ? d.EnumerateArray() : [];
    private static bool Eq(string a, string b) => a.Equals(b, StringComparison.OrdinalIgnoreCase);
    private static bool Failed(JsonElement d) => new[] { "false", "failed", "failure", "error" }.Contains(T(d, "ResultStatus"), StringComparer.OrdinalIgnoreCase);

    public static IReadOnlyList<SuspiciousItem> Analyze(Investigation investigation)
    {
        var result = PersistenceReview.Analyze(investigation).ToList();
        var evidence = investigation.Evidence.DistinctBy(e => e.Id).ToDictionary(e => e.Id);
        var times = ActivityTimeline.Create(investigation).GroupBy(r => r.EvidenceId).ToDictionary(g => g.Key, g => g.First().Timestamp);
        void Add(string rule, string priority, string basis, DateTimeOffset? time, string account, string title, string explanation, params string[] ids)
        { result.Add(new(rule, priority, basis, time, account, title, explanation, ids.Distinct().ToArray())); }
        foreach (var finding in investigation.Findings)
            if (evidence.ContainsKey(finding.EvidenceId))
                Add("existing-indicator", finding.Priority, "Existing detector · review required", times.GetValueOrDefault(finding.EvidenceId), finding.Account, finding.Title, finding.Explanation, finding.EvidenceId);

        foreach (var group in evidence.Values.Where(e => e.Source == "Entra sign-ins" && !SignInTypes.IsBackground(e))
            .GroupBy(e => T(e.Data, "userPrincipalName"), StringComparer.OrdinalIgnoreCase))
        {
            if (string.IsNullOrEmpty(group.Key)) continue;
            (Evidence Evidence, DateTimeOffset Time, double Lat, double Lon)? previous = null;
            foreach (var e in group.DistinctBy(e => T(e.Data, "id") is { Length: > 0 } id ? id : e.Id).OrderBy(e => Date(e.Data, "createdDateTime")))
            {
                var status = F(F(e.Data, "status"), "errorCode");
                if (status.ValueKind != JsonValueKind.Number || !status.TryGetInt32(out var code) || code != 0) continue;
                var time = Date(e.Data, "createdDateTime");
                var geo = F(F(e.Data, "location"), "geoCoordinates");
                bool Number(string name, out double value) { value = 0; var p = F(geo, name); return p.ValueKind == JsonValueKind.Number && p.TryGetDouble(out value) && double.IsFinite(value); }
                if (time is null || !Number("latitude", out var lat) || !Number("longitude", out var lon) || Math.Abs(lat) > 90 || Math.Abs(lon) > 180 || (lat == 0 && lon == 0)) { previous = null; continue; }
                if (previous is { } before)
                {
                    var hours = (time.Value - before.Time).TotalHours;
                    double Rad(double n) => n * Math.PI / 180;
                    var a = Math.Pow(Math.Sin(Rad(lat - before.Lat) / 2), 2) + Math.Cos(Rad(before.Lat)) * Math.Cos(Rad(lat)) * Math.Pow(Math.Sin(Rad(lon - before.Lon) / 2), 2);
                    var distance = 6371 * 2 * Math.Asin(Math.Sqrt(Math.Clamp(a, 0, 1)));
                    var firstIp = T(before.Evidence.Data, "ipAddress"); var nextIp = T(e.Data, "ipAddress");
                    if (hours > 0 && hours <= 24 && distance >= 500 && distance / hours > 900 &&
                        System.Net.IPAddress.TryParse(firstIp, out var ip1) && System.Net.IPAddress.TryParse(nextIp, out var ip2) && !ip1.MapToIPv6().Equals(ip2.MapToIPv6()))
                        Add("travel-speed", "High", "Geolocation heuristic", time, group.Key, "Potential impossible travel between successful sign-ins",
                            FormattableString.Invariant($"Microsoft IP coordinates imply approximately {distance:F0} km in {hours * 60:F0} minutes ({distance / hours:F0} km/h), from {firstIp} to {nextIp}. Threshold: at least 500 km and over 900 km/h within 24 hours. VPNs, proxies, shared sessions and geolocation errors can explain this; it is not proof of physical travel or compromise."), before.Evidence.Id, e.Id);
                }
                previous = (e, time.Value, lat, lon);
            }
        }

        var identityOperations = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { "Add member to role", "Add eligible member to role", "Add scoped member to role", "Add app role assignment to service principal", "Add app role assignment to the service principal", "Add delegated permission grant", "Consent to application" };
        foreach (var e in evidence.Values)
        {
            if (e.Source == "Entra audit" && Eq(T(e.Data, "result"), "success") && identityOperations.Contains(T(e.Data, "activityDisplayName").TrimEnd('.')))
            {
                var actor = T(F(F(e.Data, "initiatedBy"), "user"), "userPrincipalName");
                var targetRows = Array(F(e.Data, "targetResources")).ToArray();
                var targets = targetRows.Select(t => T(t, "userPrincipalName") is { Length: > 0 } upn ? upn : T(t, "displayName")).Where(t => t.Length > 0);
                var affected = targetRows.Select(t => T(t, "userPrincipalName")).FirstOrDefault(t => t.Length > 0);
                var affectedAccount = affected ?? (actor.Length > 0 ? actor : "Unresolved audit identity");
                Add("identity-permission-change", "High", "Sensitive change · review required", Date(e.Data, "activityDateTime"), affectedAccount,
                    "Role or application permission granted", $"Successful audit operation: {T(e.Data, "activityDisplayName")}. Actor: {actor}. Targets: {string.Join(", ", targets)}. Confirm the actor, recipient and authorization; routine administration can cause this event.", e.Id);
            }
            if (e.Source != "Microsoft 365 audit") continue;
            var d = F(e.Data, "record"); var account = T(e.Data, "account"); var operation = T(d, "Operation");
            if (IsThreat(d))
                Add("microsoft-mail-verdict", "High", "Recorded Microsoft threat verdict", Date(d, "CreationTime") ?? Date(d, "MessageTime"), account,
                    "Microsoft reported phishing or malware in mail",
                    $"Microsoft Verdict or ThreatsAndDetectionTech reports phishing/malware. Verdict field: {T(d, "Verdict")}; direction: {T(d, "Directionality")}; message: {T(d, "InternetMessageId")}. A verdict does not establish delivery, account misuse or user interaction. Review original threat fields, delivery action and subsequent verdicts.", e.Id);
            if (Failed(d)) continue;
            var parameters = Array(F(d, "Parameters")).ToArray();
            bool Parameter(string name, bool boolean = false) => parameters.Any(p => Eq(T(p, "Name"), name) &&
                (boolean ? Eq(T(p, "Value"), "true") || F(p, "Value").ValueKind == JsonValueKind.True : !string.IsNullOrWhiteSpace(T(p, "Value")) && !new[] { "null", "$null", "[]", "false" }.Contains(T(p, "Value"), StringComparer.OrdinalIgnoreCase)));
            bool rule = new[] { "New-InboxRule", "Set-InboxRule", "UpdateInboxRules" }.Contains(operation, StringComparer.OrdinalIgnoreCase);
            bool forward = new[] { "ForwardTo", "ForwardAsAttachmentTo", "RedirectTo", "ForwardingAddress", "ForwardingSmtpAddress" }.Any(p => Parameter(p));
            bool hiding = Parameter("DeleteMessage", true) || Parameter("MarkAsRead", true) || Parameter("MoveToFolder");
            if (rule || (Eq(operation, "Set-Mailbox") && forward))
                Add("mailbox-rule-change", forward || hiding ? "High" : "Medium", "Sensitive change · review required", Date(d, "CreationTime"), account,
                    forward ? "Mail forwarding or redirection changed" : hiding ? "Mailbox rule changed message visibility" : "Inbox rule changed",
                    $"Recorded operation: {operation}; actor: {T(d, "UserId")}; result: {T(d, "ResultStatus")}. " + (forward || hiding ? "Forwarding, redirecting or hiding actions were present. " : "Rule details may be incomplete. ") + "Verify authorization and business purpose. This is not automatically malicious; absent outcome data does not establish success.", e.Id);
            if (Eq(operation, "Add-MailboxPermission") || Eq(operation, "Add-RecipientPermission") || (Eq(operation, "Set-Mailbox") && Parameter("GrantSendOnBehalfTo")))
                Add("mailbox-permission-change", "High", "Sensitive change · review required", Date(d, "CreationTime"), account, "Mailbox permissions changed",
                    $"Recorded operation: {operation}; actor: {T(d, "UserId")}; result: {T(d, "ResultStatus")}. Inspect AccessRights, trustee and Deny in the original evidence. Verify whether access was actually granted and authorized; routine administration is a possible explanation.", e.Id);
        }

        var threats = evidence.Values.Where(e => e.Source == "Microsoft 365 audit").Select(e => (Evidence: e, Record: F(e.Data, "record")))
            .Where(x => IsThreat(x.Record) && T(x.Record, "InternetMessageId").Length > 0)
            .GroupBy(x => (T(x.Evidence.Data, "account").ToLowerInvariant(), T(x.Record, "InternetMessageId"))).ToDictionary(g => g.Key, g => g.ToArray());
        foreach (var e in evidence.Values)
        {
            var d = F(e.Data, "record"); var account = T(e.Data, "account");
            if (account.Length == 0) continue;
            bool trace = e.Source is "Mail flow inbound" or "Mail flow outbound";
            bool access = e.Source == "Microsoft 365 audit" && !Failed(d) && new[] { "MailItemsAccessed", "MessageBind" }.Contains(T(d, "Operation"), StringComparer.OrdinalIgnoreCase);
            if (!trace && !access) continue;
            var messageIds = trace ? new[] { T(d, "MessageId") } : MessageIds(d);
            foreach (var id in messageIds.Where(id => id.Length > 0).Distinct(StringComparer.Ordinal))
            {
                if (!threats.TryGetValue((account.ToLowerInvariant(), id), out var matching)) continue;
                var ids = matching.Select(m => m.Evidence.Id).Prepend(e.Id).ToArray();
                var verdicts = string.Join(", ", matching.Select(m => T(m.Record, "Verdict")).Distinct());
                Add(access ? "suspect-mail-access" : "suspect-mail-flow", "High", "Microsoft verdict + exact message-ID match", Date(d, access ? "CreationTime" : "Received"), account,
                    access ? "Access recorded for a Microsoft-flagged message" : e.Source == "Mail flow outbound" ? "Outbound message linked to a Microsoft threat verdict" : "Inbound message linked to a Microsoft threat verdict",
                    $"Exact Internet Message-ID: {id}. Recorded Microsoft verdict field(s): {verdicts}; the Verdict or ThreatsAndDetectionTech field reports phishing/malware. " + (access ? "Mailbox access may be automated or aggregated; it does not prove a human opened, read or clicked the message." : $"Transport status: {T(d, "Status")}. Sender identity, delivery and attribution require review; a trace does not prove that the account owner sent or read the message.") + " Verdicts may be revised; check the original evidence timestamps.", ids);
            }
        }
        return result.DistinctBy(r => (r.RuleId, r.Title, r.Account, string.Join("|", r.EvidenceIds)))
            .OrderBy(r => r.Priority == "High" ? 0 : r.Priority == "Medium" ? 1 : 2).ThenBy(r => r.TimestampUtc).ToArray();
    }

    private static bool IsThreat(JsonElement d)
    {
        var type = F(d, "RecordType");
        if (!(type.ValueKind == JsonValueKind.Number && type.TryGetInt32(out var n) && n == 28) && !Eq(T(d, "RecordType"), "ThreatIntelligence")) return false;
        if (new[] { "Phish", "Phishing", "High Confidence Phish", "Malware" }.Contains(T(d, "Verdict"), StringComparer.OrdinalIgnoreCase)) return true;
        bool Threat(string value) => value.StartsWith("Phish:", StringComparison.OrdinalIgnoreCase) || value.StartsWith("Malware:", StringComparison.OrdinalIgnoreCase);
        var technologies = F(d, "ThreatsAndDetectionTech");
        if (technologies.ValueKind == JsonValueKind.Array) return technologies.EnumerateArray().Any(t => t.ValueKind == JsonValueKind.String && Threat(t.GetString()!));
        if (technologies.ValueKind == JsonValueKind.String)
        {
            try
            {
                using var parsed = JsonDocument.Parse(technologies.GetString()!);
                return Array(parsed.RootElement).Any(t => t.ValueKind == JsonValueKind.String && Threat(t.GetString()!));
            }
            catch (JsonException) { }
        }
        return false;
    }
    private static IEnumerable<string> MessageIds(JsonElement d)
    {
        yield return T(d, "InternetMessageId"); yield return T(F(d, "Item"), "InternetMessageId");
        foreach (var folder in Array(F(d, "Folders")))
            foreach (var item in Array(F(folder, "FolderItems"))) yield return T(item, "InternetMessageId");
    }
}
