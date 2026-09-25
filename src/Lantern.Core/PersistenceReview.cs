using System.Text.Json;
namespace Lantern.Core;

public sealed record PersistenceRow(string Account, string Source, string Principal, string Access, string State, string EvidenceId);
public static class PersistenceReview
{
    private static string T(JsonElement row, string key) => SignInFindings.Text(row, key);
    public static bool IsSnapshot(Evidence e) => e.Source is "Mailbox Full Access" or "Mailbox Send As" or "Mailbox Send on Behalf" or "OAuth delegated grants";
    public static IReadOnlyList<PersistenceRow> Rows(IEnumerable<Evidence> evidence) => evidence.Where(IsSnapshot).Select(e =>
    {
        var d = SignInFindings.Field(e.Data, "record");
        var access = SignInFindings.Field(d, "AccessRights");
        var rights = access.ValueKind == JsonValueKind.Array ? string.Join(", ", access.EnumerateArray().Where(r => r.ValueKind == JsonValueKind.String).Select(r => r.GetString())) : T(d, "AccessRights");
        var deny = SignInFindings.Field(d, "Deny"); var inherited = SignInFindings.Field(d, "IsInherited");
        return new PersistenceRow(T(e.Data, "account"), e.Source, e.Source == "OAuth delegated grants" ? T(d, "clientId") : T(d, "Trustee"), e.Source == "OAuth delegated grants" ? T(d, "scope") : rights,
            e.Source == "OAuth delegated grants" ? T(d, "consentType") + " · client object ID" : $"Deny: {(deny.ValueKind == JsonValueKind.True ? "Yes" : deny.ValueKind == JsonValueKind.False ? "No" : "Unreported")}; type: {T(d, "AccessControlType")}; inherited: {(inherited.ValueKind == JsonValueKind.True ? "Yes" : inherited.ValueKind == JsonValueKind.False ? "No" : "Unreported")}", e.Id);
    }).ToArray();

    public static IReadOnlyList<SuspiciousItem> Analyze(Investigation investigation)
    {
        var results = new List<SuspiciousItem>();
        var sensitive = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Mail.Read", "Mail.ReadWrite", "Mail.Read.Shared", "Mail.ReadWrite.Shared", "Mail.Send", "Mail.Send.Shared", "MailboxSettings.ReadWrite", "Files.Read.All", "Files.ReadWrite.All", "Sites.ReadWrite.All", "Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory" };
        var authChanges = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Admin registered security info", "Admin updated security info", "Admin deleted security info", "User registered security info", "User updated security info", "User deleted security info", "User changed default security info", "Update per-user multifactor authentication state" };
        foreach (var e in investigation.Evidence)
        {
            var d = SignInFindings.Field(e.Data, "record"); var account = T(e.Data, "account");
            if (IsSnapshot(e))
            {
                bool flagged = false; string detail;
                if (e.Source == "OAuth delegated grants")
                {
                    var matched = T(d, "scope").Split(' ', StringSplitOptions.RemoveEmptyEntries).Where(sensitive.Contains).ToArray();
                    flagged = matched.Length > 0;
                    detail = $"Client service-principal object ID: {T(d, "clientId")}; resource object ID: {T(d, "resourceId")}; consent: {T(d, "consentType")}; sensitive delegated scopes: {string.Join(", ", matched)}. Confirm the application and business purpose. This is not application-only access or evidence the grant was used.";
                }
                else
                {
                    var trustee = T(d, "Trustee");
                    var rights = SignInFindings.Field(d, "AccessRights");
                    bool Has(string right) => rights.ValueKind == JsonValueKind.Array && rights.EnumerateArray().Any(v => v.ValueKind == JsonValueKind.String && string.Equals(v.GetString(), right, StringComparison.OrdinalIgnoreCase));
                    bool inherited = SignInFindings.Field(d, "IsInherited").ValueKind == JsonValueKind.True;
                    bool self = trustee.Equals("NT AUTHORITY\\SELF", StringComparison.OrdinalIgnoreCase) || trustee == "S-1-5-10" || trustee.Equals(account, StringComparison.OrdinalIgnoreCase);
                    flagged = trustee.Length > 0 && !self && !inherited && (e.Source == "Mailbox Full Access" ? Has("FullAccess") && SignInFindings.Field(d, "Deny").ValueKind == JsonValueKind.False : e.Source == "Mailbox Send As" ? Has("SendAs") && T(d, "AccessControlType").Equals("Allow", StringComparison.OrdinalIgnoreCase) : true);
                    detail = $"Trustee: {trustee}. Review this {e.Source} entry and verify authorization. Groups, inherited permissions and deny precedence can alter effective access; this tool does not compute effective permissions.";
                }
                if (flagged) results.Add(new("persistence-snapshot", "Medium", "Current access · review required", e.CollectedUtc ?? investigation.CollectedUtc, account, "Review current " + e.Source.ToLowerInvariant(), detail + " Snapshot time is collection time, not grant time; legitimate delegation is common.", [e.Id]));
            }
            if (e.Source != "Entra audit" || !T(e.Data, "result").Equals("success", StringComparison.OrdinalIgnoreCase) || !authChanges.Contains(T(e.Data, "activityDisplayName"))) continue;
            var actor = T(SignInFindings.Field(SignInFindings.Field(e.Data, "initiatedBy"), "user"), "userPrincipalName");
            var targets = SignInFindings.Field(e.Data, "targetResources");
            var affected = targets.ValueKind == JsonValueKind.Array ? targets.EnumerateArray().Select(t => T(t, "userPrincipalName")).FirstOrDefault(v => v.Length > 0) : null;
            DateTimeOffset? time = DateTimeOffset.TryParse(T(e.Data, "activityDateTime"), out var parsed) ? parsed : null;
            results.Add(new("authentication-method-change", "Medium", "Successful sensitive change · review required", time, affected ?? actor, "Authentication or MFA configuration changed",
                $"Operation: {T(e.Data, "activityDisplayName")}; actor: {actor}. Verify the target and authorization in the original audit record. Account recovery and legitimate registration can cause this event; a successful change alone does not establish compromise.", [e.Id]));
        }
        return results;
    }
}
