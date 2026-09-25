using System.Text;
using System.Text.Json;

namespace Lantern.Core;

public static class SuspiciousExport
{
    public static string Json(Investigation value) => JsonSerializer.Serialize(new
    {
        schemaVersion = 1, ruleVersion = SuspiciousBehavior.Version, value.Tenant, value.Account,
        value.StartUtc, value.EndUtc, value.CollectedUtc, value.IsDemo, value.Import, value.Pivots,
        limitations = SuspiciousBehavior.Limitations,
        suspicious = SuspiciousBehavior.Analyze(value)
    }, new JsonSerializerOptions { WriteIndented = true });

    public static string Csv(Investigation value)
    {
        static string Cell(string text)
        {
            if (text.TrimStart().StartsWith('=') || text.TrimStart().StartsWith('+') || text.TrimStart().StartsWith('-') || text.TrimStart().StartsWith('@') || text.StartsWith('\t') || text.StartsWith('\r')) text = "'" + text;
            return "\"" + text.Replace("\"", "\"\"") + "\"";
        }
        var csv = new StringBuilder("Tenant,Scope,IsDemo,RuleVersion,RuleId,Priority,Basis,TimestampUtc,Account,Title,Explanation,EvidenceIds\r\n");
        foreach (var item in SuspiciousBehavior.Analyze(value))
            csv.AppendLine(string.Join(",", new[] { value.Tenant, value.Account, value.IsDemo.ToString(), SuspiciousBehavior.Version, item.RuleId, item.Priority, item.Basis,
                item.TimestampUtc?.ToString("O") ?? "", item.Account, item.Title, item.Explanation, JsonSerializer.Serialize(item.EvidenceIds) }.Select(Cell)));
        return csv.ToString();
    }
}
