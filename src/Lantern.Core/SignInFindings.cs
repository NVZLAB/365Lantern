using System.Globalization;
using System.Text.Json;

namespace Lantern.Core;

public static class SignInFindings
{
    internal static JsonElement Field(JsonElement row, string name) => row.ValueKind == JsonValueKind.Object && row.TryGetProperty(name, out var field) ? field : default;
    internal static string Text(JsonElement row, string name) => Field(row, name) is var field && field.ValueKind == JsonValueKind.String ? field.GetString()! : "";
    private static int? Status(JsonElement row) => Field(Field(row, "status"), "errorCode") is var code && code.TryInt(out var number) ? number : null;

    public static IReadOnlyList<Finding> Analyze(IEnumerable<Evidence> evidence, string account)
    {
        var result = new List<Finding>();
        var rows = evidence.Where(e => SignInTypes.IsSignIn(e))
            .DistinctBy(e => (Text(e.Data, "userPrincipalName").ToLowerInvariant(), Text(e.Data, "id") is { Length: > 0 } id ? id : e.Id)).ToArray();
        foreach (var group in rows.GroupBy(e => Text(e.Data, "userPrincipalName") is { Length: > 0 } upn ? upn : account, StringComparer.OrdinalIgnoreCase))
        {
            void Add(Evidence e, string priority, string title, string explanation) => result.Add(new(priority, title, group.Key, e.Source, explanation + " This is an indicator for review, not proof of compromise.", e.Id));
            foreach (var item in group)
            {
                var risk = Text(item.Data, "riskLevelDuringSignIn");
                if (risk is "high" or "medium") Add(item, risk == "high" ? "High" : "Medium", "Sign-in flagged by Entra risk", $"Entra reported {risk} risk. Confirm activity with the account owner.");
                var client = Text(item.Data, "clientAppUsed");
                if (Status(item.Data) == 0 && client is "Exchange ActiveSync" or "IMAP" or "IMAP4" or "POP" or "POP3" or "SMTP" or "Authenticated SMTP" or "Other clients")
                    Add(item, "Medium", "Successful sign-in through a legacy client category", $"Client category: {client}. Verify the client and authentication details; the category alone does not prove basic authentication.");
            }
            var dated = group.Where(e => !SignInTypes.IsBackground(e)).Select(e => (Event: e, Time: DateTimeOffset.TryParse(Text(e.Data, "createdDateTime"), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var time) ? (DateTimeOffset?)time : null))
                .Where(x => x.Time.HasValue).OrderBy(x => x.Time).ToArray();
            var failures = new Queue<(Evidence Event, DateTimeOffset Time)>();
            (Evidence Event, DateTimeOffset Time)? previousSuccess = null;
            foreach (var item in dated)
            {
                var time = item.Time!.Value;
                while (failures.TryPeek(out var old) && time - old.Time > TimeSpan.FromMinutes(15)) failures.Dequeue();
                var status = Status(item.Event.Data);
                // 50126 is invalid credentials. Do not classify MFA/CA interruptions as password failures.
                if (status == 50126) failures.Enqueue((item.Event, time));
                if (status != 0) continue;
                if (failures.Count >= 5)
                {
                    Add(item.Event, "High", "Success after repeated invalid-credential failures", $"{failures.Count} invalid-credential events preceded this success within 15 minutes. Supporting evidence: {string.Join(", ", failures.Take(5).Select(x => x.Event.Id))}. Password mistakes and automated clients can also cause this pattern.");
                    failures.Clear();
                }
                var country = Text(Field(item.Event.Data, "location"), "countryOrRegion");
                if (previousSuccess is { } previous && time - previous.Time <= TimeSpan.FromMinutes(60))
                {
                    var before = Text(Field(previous.Event.Data, "location"), "countryOrRegion");
                    if (country.Length > 0 && before.Length > 0 && !country.Equals(before, StringComparison.OrdinalIgnoreCase))
                        Add(item.Event, "Medium", "Successful sign-ins change country within one hour", $"Reported countries changed from {before} to {country}. Previous evidence: {previous.Event.Id}. VPNs, proxies and IP geolocation errors can explain this; no impossible-travel verdict is made.");
                }
                previousSuccess = (item.Event, time);
            }
        }
        return result;
    }
    private static bool TryInt(this JsonElement value, out int number)
    {
        number = 0;
        return value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out number);
    }
}
