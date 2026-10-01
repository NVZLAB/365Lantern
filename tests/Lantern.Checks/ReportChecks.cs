using System.IO.Compression;
using System.Text.Json;
using Lantern.Core;

static class ReportChecks
{
    public static void Run(Action<bool, string> check)
    {
        var now = DateTimeOffset.Parse("2026-09-29T12:00:00Z");
        var demo = DemoInvestigation.Run(now, 7);
        check(ActionPrompts.All.Count >= 8 && ActionPrompts.All.All(p => p.Draft.Contains("Owner: [assign]") && p.Draft.Contains("Target date: [set]") && p.Draft.Contains("Proposed — not performed")), "action blueprint requires ownership, dates and honest proposed status");
        check(IncidentReport.Html(demo with { Report = new ReportDraft { NextSteps = ActionPrompts.All[0].Draft } }).Contains("Draft action plan:"), "executive report visibly labels incomplete action-plan placeholders");
        var first = IncidentReport.Indicators(demo)[0];
        check(IncidentReport.Indicators(demo).All(i => i.Assessment is null), "report never auto-confirms detector output");
        foreach (var entry in new[] { ("Expected activity", "", "Analyst"), ("Confirmed malicious", "Reason", ""), ("Safe", "Reason", "Analyst") })
        {
            try { IncidentReport.Assess(demo, first.Indicator, entry.Item1, entry.Item2, entry.Item3, now); throw new Exception("Accepted invalid assessment"); }
            catch (ArgumentException) { check(true, "assessment requires valid classification, analyst and supporting notes"); }
        }
        var reviewed = IncidentReport.Assess(demo, first.Indicator, "Expected activity", "Owner confirmed authorized test", "Test analyst", now);
        check(IncidentReport.Indicators(reviewed).Single(i => i.Key == first.Key).Assessment?.Status == "Expected activity" && reviewed.Findings.SequenceEqual(demo.Findings), "analyst classification preserves automated indicators and raw evidence");
        var altered = reviewed with { Evidence = reviewed.Evidence.Select(e => first.Indicator.EvidenceIds.Contains(e.Id) ? e with { Data = JsonSerializer.SerializeToElement(new { changed = true }) } : e).ToArray() };
        check(IncidentReport.Indicators(altered).All(i => i.Assessment is null), "changed supporting observation cannot inherit an old assessment");
        var related = RelatedAccounts.Merge(reviewed, demo with { Account = "other@example.com" }, "Account", "other@example.com");
        check(IncidentReport.Indicators(related).Any(i => i.Assessment?.Notes == "Owner confirmed authorized test"), "related collection retains reviews bound to unchanged evidence");
        var hostile = reviewed with { Report = reviewed.Report with { Summary = "<script>alert('test')</script>", Analyst = "<img src=https://example.com>" }, Coverage = [new("Test <source>", "Failed", 0, "Denied <details>")] };
        var html = IncidentReport.Html(hostile);
        check(!html.Contains("<script>") && !html.Contains("<img ") && html.Contains("&lt;script&gt;") && html.Contains("default-src 'none'"), "HTML report encodes untrusted text and denies external resources");
        check(html.Contains("Failed") && html.Contains("Test &lt;source&gt;") && html.Contains("SYNTHETIC DEMO") && html.Contains("No response actions"), "report retains failed coverage, origin and response limitations");
        check(!html.Contains("href=\"#evidence-") && !html.Contains("Owner confirmed authorized test") && html.Contains("Executive summary"), "executive report excludes raw references and internal review notes");
        using var report = JsonDocument.Parse(IncidentReport.Json(reviewed));
        check(report.RootElement.GetProperty("AnalystDraft").GetProperty("Assessments").GetArrayLength() == 1, "JSON report retains attributable analyst review");
        using var zip = new ZipArchive(new MemoryStream(EvidenceExport.Create(reviewed)));
        check(zip.GetEntry("report.html") is not null && zip.GetEntry("report.json") is not null, "evidence archive includes readable and structured reports");
        using (var reader = new StreamReader(zip.GetEntry("report.json")!.Open()))
            check(reader.ReadToEnd().Contains("Owner confirmed authorized test"), "technical report retains internal assessment notes excluded from HTML");
        using (var reader = new StreamReader(zip.GetEntry("timeline.csv")!.Open()))
            check(reader.ReadToEnd().Contains("demo-mail-001"), "technical timeline retains event references excluded from executive summary");
        var clientDraft = reviewed with { Report = reviewed.Report with { NextSteps = "Confirm containment with client <POC>." } };
        check(IncidentReport.Html(clientDraft).Contains("Confirm containment with client &lt;POC&gt;.") && IncidentReport.Html(clientDraft).Contains("not proof of an incident"), "executive summary includes encoded next steps and distinguishes investigation dates from incident dates");
        var empty = IncidentReport.Html(demo with { Findings = [], Evidence = [], Coverage = [new("Entra sign-ins", "Failed", 0, "Permission denied")] });
        check(empty.Contains("does not establish safety") && empty.Contains("Failed"), "empty failed collection cannot produce a clean bill of health");
        var imported = JsonSignInImport.Read(System.Text.Encoding.UTF8.GetBytes("""[{"id":"imported","userPrincipalName":"alex@example.com","createdDateTime":"2026-09-29T10:00:00Z","riskLevelDuringSignIn":"high"}]"""), now);
        check(IncidentReport.Html(imported).Contains("IMPORTED DATA") && !IncidentReport.Html(imported).Contains(imported.Import!.Sha256), "executive report identifies imports without technical provenance hashes");
        var raw = demo with { Evidence = demo.Evidence.Select(e => e.Id == "demo-mail-001" ? e with { Data = JsonSerializer.SerializeToElement(new { account = "alex@example.com", record = new { Subject = "<img src=x onerror=alert(1)>", Received = now } }) } : e).ToArray() };
        check(!IncidentReport.Html(raw).Contains("<img ") && !IncidentReport.Html(raw).Contains("&lt;img"), "executive report omits source event records");
        check(IncidentReport.Html(altered).Contains("earlier assessments no longer match"), "unmatched earlier reviews are explicitly distinguished from current assessments");
    }
}
