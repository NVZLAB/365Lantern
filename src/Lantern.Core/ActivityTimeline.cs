using System.Globalization;
using System.Text.Json;

namespace Lantern.Core;

public sealed record ActivityRow(DateTimeOffset? Timestamp, string Account, string Category, string Activity,
    string Outcome, string IP, string MessageId, string EvidenceId, string Source)
{
    public string Time => Timestamp?.ToString("yyyy-MM-dd HH:mm:ss 'UTC'") ?? "Time unavailable";
}

public static class ActivityTimeline
{
    public static IReadOnlyList<ActivityRow> Create(Investigation investigation)
    {
        var rows = new List<ActivityRow>();
        foreach (var evidence in investigation.Evidence)
        {
            var d = evidence.Data;
            string T(string key) => SignInFindings.Text(d, key);
            DateTimeOffset? Date(string value) => DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var date) ? date : null;
            if (SignInTypes.IsSignIn(evidence))
            {
                var status = SignInFindings.Field(SignInFindings.Field(d, "status"), "errorCode");
                rows.Add(new(Date(T("createdDateTime")), T("userPrincipalName"), "Authentication", (SignInTypes.IsBackground(evidence) ? "Noninteractive sign-in · " : "Interactive sign-in · ") + T("appDisplayName"),
                    status.TryGetInt32Safe(out var code) ? code == 0 ? "Success" : "Error " + code : "Unknown", T("ipAddress"), "", evidence.Id, evidence.Source));
            }
            else if (evidence.Source is "Mail flow inbound" or "Mail flow outbound" or "Related message trace" or "Microsoft 365 audit")
            {
                var account = T("account"); d = SignInFindings.Field(d, "record");
                if (evidence.Source == "Microsoft 365 audit")
                    rows.Add(new(Date(T("CreationTime")), account, "Audit", T("Operation") + " · Actor: " + T("UserId") + " · " + T("ObjectId"), T("ResultStatus"), T("ClientIP"), T("InternetMessageId"), evidence.Id, evidence.Source));
                else
                    rows.Add(new(Date(T("Received")), account, "Mail flow", (evidence.Source == "Mail flow inbound" ? "Inbound · " : evidence.Source == "Related message trace" ? "Related message · " : "Outbound · ") + T("SenderAddress") + " → " + T("RecipientAddress") + " · " + T("Subject"), T("Status"), T("FromIP"), T("MessageId"), evidence.Id, evidence.Source));
            }
            else if (evidence.Source == "Entra audit")
            {
                var actor = SignInFindings.Field(SignInFindings.Field(d, "initiatedBy"), "user");
                var accounts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var actorUpn = SignInFindings.Text(actor, "userPrincipalName");
                if (actorUpn.Length > 0) accounts.Add(actorUpn);
                var targets = SignInFindings.Field(d, "targetResources");
                if (targets.ValueKind == JsonValueKind.Array)
                    foreach (var target in targets.EnumerateArray())
                    {
                        var upn = SignInFindings.Text(target, "userPrincipalName");
                        if (upn.Length == 0) upn = investigation.Accounts.FirstOrDefault(a => a.Id == SignInFindings.Text(target, "id"))?.Account ?? "";
                        if (upn.Length > 0) accounts.Add(upn);
                    }
                if (accounts.Count == 0) accounts.Add("Unresolved audit identity");
                foreach (var account in accounts)
                    rows.Add(new(Date(T("activityDateTime")), account, "Identity", T("activityDisplayName"), T("result"), SignInFindings.Text(actor, "ipAddress"), "", evidence.Id, evidence.Source));
            }
            else if (PersistenceReview.IsSnapshot(evidence))
            {
                var item = PersistenceReview.Rows([evidence])[0];
                rows.Add(new(evidence.CollectedUtc ?? investigation.CollectedUtc, item.Account, "Snapshot", item.Source + " · " + item.Principal + " · " + item.Access, item.State, "", "", evidence.Id, evidence.Source));
            }
            else if (evidence.Source is "Exchange rules" or "Mailbox forwarding")
            {
                var account = evidence.Id.Contains(':') ? evidence.Id[..evidence.Id.IndexOf(':')] : investigation.Account;
                rows.Add(new(evidence.CollectedUtc ?? investigation.CollectedUtc, account, "Snapshot", "Current " + evidence.Source.ToLowerInvariant() + " (not change time)", "Observed configuration", "", "", evidence.Id, evidence.Source));
            }
        }
        return rows.OrderBy(r => r.Timestamp is null).ThenBy(r => r.Timestamp).ThenBy(r => r.EvidenceId, StringComparer.Ordinal).ToArray();
    }

    private static bool TryGetInt32Safe(this JsonElement value, out int number)
    { number = 0; return value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out number); }
}
