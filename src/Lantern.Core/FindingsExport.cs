using System.Text;
using System.Text.Json;
namespace Lantern.Core;
public static class FindingsExport
{
    public static string Json(Investigation value) => JsonSerializer.Serialize(new { value.Tenant, value.Account, value.StartUtc, value.EndUtc, value.CollectedUtc, value.IsDemo, value.Import, value.Pivots, value.Coverage, value.Findings }, new JsonSerializerOptions { WriteIndented = true });
    public static string TimelineCsv(Investigation value)
    {
        static string Cell(string text)
        {
            if (text.TrimStart().StartsWith('=') || text.TrimStart().StartsWith('+') || text.TrimStart().StartsWith('-') || text.TrimStart().StartsWith('@') || text.StartsWith('\t') || text.StartsWith('\r')) text = "'" + text;
            return "\"" + text.Replace("\"", "\"\"") + "\"";
        }
        var csv = new StringBuilder("TimestampUtc,Account,Category,Activity,Outcome,IP,MessageId,EvidenceId,Source\r\n");
        foreach (var r in ActivityTimeline.Create(value)) csv.AppendLine(string.Join(",", new[] { r.Timestamp?.ToString("O") ?? "", r.Account, r.Category, r.Activity, r.Outcome, r.IP, r.MessageId, r.EvidenceId, r.Source }.Select(Cell)));
        return csv.ToString();
    }
    public static string Csv(Investigation value)
    {
        static string Cell(string text)
        {
            if (text.TrimStart().StartsWith('=') || text.TrimStart().StartsWith('+') || text.TrimStart().StartsWith('-') || text.TrimStart().StartsWith('@') || text.StartsWith('\t') || text.StartsWith('\r')) text = "'" + text;
            return "\"" + text.Replace("\"", "\"\"") + "\"";
        }
        var csv = new StringBuilder("Tenant,Scope,StartUtc,EndUtc,Priority,Title,Account,Source,Explanation,EvidenceId\r\n");
        foreach (var f in value.Findings) csv.AppendLine(string.Join(",", new[] { value.Tenant, value.Account, value.StartUtc.ToString("O"), value.EndUtc.ToString("O"), f.Priority, f.Title, f.Account, f.Source, f.Explanation, f.EvidenceId }.Select(Cell)));
        return csv.ToString();
    }
}
