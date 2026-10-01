using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Lantern.Core;

public sealed record IndicatorAssessment(string IndicatorKey, string Status, string Notes, string Analyst, DateTimeOffset ReviewedUtc);
public sealed record ReportDraft
{
    public string CaseReference { get; init; } = "";
    public string Analyst { get; init; } = "";
    public string Summary { get; init; } = "";
    public string PotentialImpact { get; init; } = "";
    public string AffectedAccounts { get; init; } = "";
    public string NextSteps { get; init; } = "";
    public IReadOnlyList<IndicatorAssessment> Assessments { get; init; } = [];
}
public sealed record ReportIndicator(string Key, SuspiciousItem Indicator, IndicatorAssessment? Assessment)
{
    public string AssessmentLabel => Assessment?.Status ?? "Unexplained — not assessed";
}

public static class IncidentReport
{
    public static IReadOnlyList<string> Statuses { get; } = Array.AsReadOnly(new[] { "Unexplained", "Expected activity", "Suspicious", "Confirmed malicious" });
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    // Bind a review to the detector output AND original supporting observations.
    public static string Key(Investigation investigation, SuspiciousItem indicator)
        => Key(investigation, indicator, investigation.Evidence.ToLookup(e => e.Id));
    private static string Key(Investigation investigation, SuspiciousItem indicator, ILookup<string, Evidence> evidence)
    {
        var payload = JsonSerializer.Serialize(new { DetectorVersion = SuspiciousBehavior.Version, investigation.Tenant,
            indicator.RuleId, indicator.Priority, indicator.Account, indicator.Title, indicator.Explanation, indicator.Basis, indicator.TimestampUtc,
            Evidence = indicator.EvidenceIds.Order(StringComparer.Ordinal).Select(id => new { Id = id,
                Observations = evidence[id].Select(e => new { e.Source, Data = e.Data.GetRawText(), e.CollectedUtc }).ToArray() }).ToArray() });
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(payload)));
    }
    public static IReadOnlyList<ReportIndicator> Indicators(Investigation investigation)
    {
        var evidence = investigation.Evidence.ToLookup(e => e.Id);
        var reviews = investigation.Report.Assessments.GroupBy(a => a.IndicatorKey).ToDictionary(g => g.Key, g => g.Last());
        return SuspiciousBehavior.Analyze(investigation).Select(i => { var key = Key(investigation, i, evidence); return new ReportIndicator(key, i, reviews.GetValueOrDefault(key)); }).ToArray();
    }

    public static Investigation Assess(Investigation investigation, SuspiciousItem indicator, string status, string notes, string analyst, DateTimeOffset reviewedUtc)
    {
        if (!Statuses.Contains(status)) throw new ArgumentException("Choose a valid assessment.");
        if (string.IsNullOrWhiteSpace(notes) || string.IsNullOrWhiteSpace(analyst)) throw new ArgumentException("Enter an analyst name and supporting notes before saving an assessment.");
        var key = Key(investigation, indicator);
        if (!Indicators(investigation).Any(i => i.Key == key)) throw new ArgumentException("This indicator is no longer part of the investigation.");
        var review = new IndicatorAssessment(key, status, notes.Trim(), analyst.Trim(), reviewedUtc);
        return investigation with { Report = investigation.Report with { Assessments = investigation.Report.Assessments.Where(a => a.IndicatorKey != key).Append(review).ToArray() } };
    }
    public static string Json(Investigation investigation) => JsonSerializer.Serialize(new { schemaVersion = 1,
        tool = "365Lantern", build = BuildInfo.InformationalVersion, classification = "Sensitive case material — analyst working report",
        investigation.Tenant, investigation.Account, investigation.StartUtc, investigation.EndUtc, investigation.CollectedUtc,
        investigation.IsDemo, investigation.Import, investigation.Pivots, AnalystDraft = investigation.Report,
        Indicators = Indicators(investigation), investigation.Coverage, Limitations = InvestigationCoverage.Describe(investigation) + " " + SuspiciousBehavior.Limitations,
        ResponseActions = investigation.Responses, ResponseSummary = Lantern.Core.ResponseActions.Summary(investigation) }, JsonOptions);

    public static string Html(Investigation investigation)
    {
        static string E(string? value) => WebUtility.HtmlEncode(value ?? "");
        var b = new StringBuilder("""
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>365Lantern executive summary</title><style>
body{font:15px/1.55 system-ui,Segoe UI,sans-serif;color:#18263b;max-width:1100px;margin:40px auto;padding:0 24px}h1{color:#0078d4}h2{border-bottom:2px solid #dce5ee;padding-bottom:8px;margin-top:32px}h3{margin-bottom:6px}.notice{background:#eef5fb;border-left:4px solid #0078d4;padding:16px}.text,pre{white-space:pre-wrap;overflow-wrap:anywhere}pre{font-size:12px;background:#f5f7fb;padding:12px}table{border-collapse:collapse;width:100%;font-size:13px}th,td{border:1px solid #dce5ee;padding:8px;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#eef5fb}.indicator{border:1px solid #dce5ee;padding:16px;margin:16px 0}.muted{color:#51617a}a{color:#0063a8}@media print{body{margin:0;max-width:none;padding:0;font-size:11pt}thead{display:table-header-group}h2,h3{break-after:avoid}pre{font-size:9pt}a{color:inherit;text-decoration:none}}@page{margin:18mm}
</style></head><body><h1>365Lantern · Executive summary</h1>
<p class="notice">Confidential · Investigator-prepared summary. Conclusions reflect the evidence available and the analyst assessment.</p>

""");
        void Text(string label, string value) => b.Append("<p><strong>").Append(E(label)).Append("</strong></p><div class=\"text\">").Append(E(string.IsNullOrWhiteSpace(value) ? "Not provided" : value)).Append("</div>");
        var draft = investigation.Report;
        var indicators = Indicators(investigation);
        b.Append("<h2>At a glance</h2>");
        Text("Case reference / prepared by", draft.CaseReference + " / " + draft.Analyst);
        Text("Organization / investigated scope", investigation.Tenant + " / " + investigation.Account);
        Text(investigation.Import is null ? "Investigation period (UTC)" : "Dates represented in imported records (UTC)", $"{investigation.StartUtc:yyyy-MM-dd HH:mm} to {investigation.EndUtc:yyyy-MM-dd HH:mm}");
        Text("Evidence collected (UTC)", $"{investigation.CollectedUtc:yyyy-MM-dd HH:mm}");
        if (investigation.IsDemo) Text("Data origin", "SYNTHETIC DEMO — not a real incident");
        else if (investigation.Import is not null) Text("Data origin", "IMPORTED DATA — original source, filters and completeness have not been independently verified.");
        b.Append("<h2>What happened</h2>");
        Text("Investigator summary", string.IsNullOrWhiteSpace(draft.Summary) ? "The investigator has not yet provided a summary. Automated observations alone do not establish compromise." : draft.Summary);
        b.Append("<h2>Who was affected</h2>");
        Text("Investigator assessment", string.IsNullOrWhiteSpace(draft.AffectedAccounts) ? "Affected accounts have not yet been established. The investigation scope is not a list of confirmed compromised accounts." : draft.AffectedAccounts);
        b.Append("<h2>Potential business impact</h2>");
        Text("Impact and uncertainties", string.IsNullOrWhiteSpace(draft.PotentialImpact) ? "Business impact has not yet been established." : draft.PotentialImpact);
        b.Append("<h2>Review status</h2>");
        int confirmed = indicators.Count(i => i.Assessment?.Status == "Confirmed malicious");
        int suspect = indicators.Count(i => i.Assessment?.Status == "Suspicious");
        int expected = indicators.Count(i => i.Assessment?.Status == "Expected activity");
        int unresolved = indicators.Count - confirmed - suspect - expected;
        b.Append($"<p>Of {indicators.Count} observations flagged for review, the analyst classified {confirmed} as malicious, {suspect} as suspicious and {expected} as expected activity. {unresolved} remain unexplained or unreviewed. These counts describe observations, not separate incidents or affected people.</p>");
        if (confirmed == 0) b.Append("<p>No observation has been classified as confirmed malicious by the analyst. This does not establish safety.</p>");
        var highlights = indicators.Where(i => i.Assessment?.Status is "Confirmed malicious" or "Suspicious")
            .GroupBy(i => new { i.Indicator.Title, i.Assessment!.Status }).OrderByDescending(g => g.Key.Status == "Confirmed malicious").ThenBy(g => g.Key.Title).ToArray();
        if (highlights.Length > 0)
        {
            b.Append("<p><strong>Key concerns identified by the analyst</strong></p><ul>");
            foreach (var group in highlights.Take(5)) b.Append($"<li>{E(group.Key.Title)} — {E(group.Key.Status)} ({group.Count()} observations)</li>");
            b.Append("</ul>");
            if (highlights.Length > 5) b.Append("<p>Additional concerns are recorded in the supporting evidence package.</p>");
        }
        if (draft.Assessments.Any(a => !indicators.Any(i => i.Key == a.IndicatorKey))) b.Append("<p>Some earlier assessments no longer match current evidence and are excluded from these totals. Review them before sharing this summary.</p>");
        b.Append("<h2>What remains uncertain</h2>");
        var gaps = investigation.Coverage.Where(c => c.Status != "Complete").ToArray();
        if (investigation.Evidence.Count == 0) b.Append("<p>No evidence was collected. This investigation cannot determine whether compromise occurred.</p>");
        if (gaps.Length > 0)
        {
            b.Append($"<p>{gaps.Length} collection checks have limitations or did not complete. Some activity may therefore be missing.</p><ul>");
            foreach (var gap in gaps.Select(c => new { c.Source, c.Status }).Distinct().Take(8)) b.Append($"<li>{E(gap.Source)}: {E(gap.Status)}</li>");
            b.Append("</ul><p>Full reasons and any additional incomplete checks are documented in the evidence package.</p>");
        }
        else b.Append("<p>The listed collection checks completed. Retention periods and available Microsoft data still limit what can be established.</p>");
        b.Append("<p>The period reviewed is not proof of an incident's start or end. Current settings do not establish when a change occurred. Email delivery does not prove a message was read or a link clicked.</p>");
        b.Append("<h2>Response and next steps</h2>");
        Text("Investigator recommendations / reported actions", draft.NextSteps);
        if (new[] { "[assign]", "[set]", "[record]" }.Any(draft.NextSteps.Contains))
            b.Append("<p><strong>Draft action plan:</strong> ownership, target dates or verification details still need to be completed by the investigator.</p>");
        Text("Actions recorded by Lantern", ResponseActions.Summary(investigation));
        if (investigation.Responses.Count > 0)
        {
            b.Append("<table><thead><tr><th>When (UTC)</th><th>Account</th><th>Action / operator</th><th>Result</th></tr></thead><tbody>");
            foreach (var r in investigation.Responses) b.Append($"<tr><td>{E(r.RequestedUtc.ToString("yyyy-MM-dd HH:mm"))}</td><td>{E(r.Account)}</td><td>{E(r.Action)}{(r.DeviceName.Length > 0 ? "<br>" + E(r.DeviceName) : "")}<br>{E(r.Operator)}</td><td>{E(r.Status)}<br>{E(r.Verification)}</td></tr>");
            b.Append("</tbody></table>");
            Text("Response limitations", ResponseActions.Limitation);
        }
        b.Append("<p>Actions described in the investigator's narrative are analyst-reported. Containment and recovery must be verified separately. Detailed action records are in response.json/csv.</p>");
        b.Append("<h2>Supporting investigation material</h2><p>The accompanying evidence package contains the detailed activity timeline, event records, individual assessments and collection limitations for technical review. Refer to timeline.csv/json, evidence.json, suspicious.csv/json and report.json. Integrity hashes are in manifest.json.</p>");
        b.Append("<p class=\"muted\">Confidential · Share only with authorized recipients. Prepared with 365Lantern ").Append(E(BuildInfo.Version)).Append(".</p>");
        return b.Append("</body></html>").ToString();
    }
}
