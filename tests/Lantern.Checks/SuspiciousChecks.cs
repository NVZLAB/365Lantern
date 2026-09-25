using System.IO.Compression;
using System.Text.Json;
using Lantern.Core;

static class SuspiciousChecks
{
    public static void Run(Action<bool, string> check)
    {
        var now = DateTimeOffset.Parse("2026-09-24T12:00:00Z");
        JsonElement Json(object value) => JsonSerializer.SerializeToElement(value);
        Investigation Case(params Evidence[] rows) => new("test-tenant", "alex@example.com", now.AddDays(-1), now, now, true, [], [], rows);
        Evidence Sign(string id, int minutes, double lat, double lon, string ip, string account = "alex@example.com", int status = 0) => new(id, "Entra sign-ins", Json(new { id, userPrincipalName = account, createdDateTime = now.AddMinutes(minutes), ipAddress = ip, status = new { errorCode = status }, location = new { geoCoordinates = new { latitude = lat, longitude = lon } } }));
        var ny = Sign("ny", -30, 40.7, -74, "192.0.2.1"); var london = Sign("london", 0, 51.5, -0.1, "192.0.2.2");
        var travel = SuspiciousBehavior.Analyze(Case(ny, london));
        check(travel.Single().RuleId == "travel-speed" && travel.Single().EvidenceIds.SequenceEqual(new[] { "ny", "london" }), "travel heuristic includes both successful sign-ins as supporting evidence");
        check(travel.Single().Title.Contains("Potential") && travel.Single().Explanation.Contains("VPNs"), "travel heuristic states uncertainty and alternative explanations");
        check(SuspiciousBehavior.Analyze(Case(ny, Sign("other", 0, 51.5, -0.1, "192.0.2.2", "other@example.com"))).Count == 0, "travel never crosses account boundaries");
        check(SuspiciousBehavior.Analyze(Case(ny, Sign("failed", 0, 51.5, -0.1, "192.0.2.2", status: 50126))).Count == 0, "failed sign-in cannot establish travel");
        check(SuspiciousBehavior.Analyze(Case(ny, Sign("sameip", 0, 51.5, -0.1, "::ffff:192.0.2.1"))).Count == 0, "same canonical IP with inconsistent coordinates is not travel");
        check(SuspiciousBehavior.Analyze(Case(ny, Sign("missinggeo", 0, 0, 0, "192.0.2.2"))).Count == 0, "placeholder coordinates do not create impossible travel");
        check(SuspiciousBehavior.Analyze(Case(ny, Sign("simultaneous", -30, 51.5, -0.1, "192.0.2.2"))).Count == 0, "zero time difference does not invent infinite travel speed");
        check(SuspiciousBehavior.Analyze(Case(Sign("earlier", -600, 40.7, -74, "192.0.2.1"), london)).Count == 0, "plausible flight speed is not flagged");

        Evidence Audit(string id, object record, string account = "alex@example.com") => new(id, "Microsoft 365 audit", Json(new { account, record }));
        var rule = Audit("rule", new { Operation = "Set-InboxRule", CreationTime = now, ResultStatus = "True", UserId = "admin@example.com", Parameters = new[] { new { Name = "ForwardTo", Value = "outside@example.net" } } });
        var denied = Audit("denied", new { Operation = "Add-MailboxPermission", CreationTime = now, ResultStatus = "Failed" });
        var granted = Audit("grant", new { Operation = "Add-MailboxPermission", CreationTime = now, ResultStatus = "True" });
        var changes = SuspiciousBehavior.Analyze(Case(rule, denied, granted));
        check(changes.Count == 2 && changes.Any(i => i.Title == "Mail forwarding or redirection changed") && changes.All(i => !i.EvidenceIds.Contains("denied")), "audit rule and permission changes are flagged while failed changes are excluded");
        var identity = new Evidence("identity", "Entra audit", Json(new { activityDisplayName = "Consent to application", activityDateTime = now, result = "success", initiatedBy = new { user = new { userPrincipalName = "alex@example.com" } }, targetResources = new[] { new { displayName = "Example app" } } }));
        check(SuspiciousBehavior.Analyze(Case(identity)).Single().RuleId == "identity-permission-change", "successful application consent is surfaced for review");
        check(SuspiciousBehavior.Analyze(Case(identity with { Data = Json(new { activityDisplayName = "Consent to application", result = "failure" }) })).Count == 0, "failed identity change is not reported as a grant");

        var threat = Audit("threat", new { RecordType = 28, Verdict = "Phish", InternetMessageId = "<exact@example.net>", CreationTime = now, Directionality = "Inbound" });
        var inbound = new Evidence("inbound", "Mail flow inbound", Json(new { account = "alex@example.com", record = new { MessageId = "<exact@example.net>", Received = now, Status = "Delivered", Subject = "Invoice" } }));
        var outbound = inbound with { Id = "outbound", Source = "Mail flow outbound" };
        var access = Audit("access", new { Operation = "MailItemsAccessed", CreationTime = now, ResultStatus = "Succeeded", Folders = new[] { new { FolderItems = new[] { new { InternetMessageId = "<exact@example.net>" } } } } });
        var correlated = SuspiciousBehavior.Analyze(Case(threat, inbound, outbound, access));
        check(correlated.Count == 4 && correlated.Any(i => i.Title.StartsWith("Outbound message")), "Microsoft threat verdict correlates with inbound/outbound transport and message access");
        check(correlated.Single(i => i.RuleId == "suspect-mail-access").EvidenceIds.Count == 2 && correlated.Single(i => i.RuleId == "suspect-mail-access").Explanation.Contains("does not prove a human"), "access finding links threat and access evidence without claiming a human opened or clicked");
        check(SuspiciousBehavior.Analyze(Case(inbound, access)).Count == 0, "delivery and access alone do not label email phishing");
        var otherThreat = Audit("other-threat", new { RecordType = 28, Verdict = "Phish", InternetMessageId = "<exact@example.net>" }, "other@example.com");
        check(!SuspiciousBehavior.Analyze(Case(otherThreat, inbound, access)).Any(i => i.RuleId is "suspect-mail-flow" or "suspect-mail-access"), "email correlations cannot cross account boundaries");
        var unknownThreat = Audit("unknown-threat", new { RecordType = 28, Verdict = "Unknown", InternetMessageId = "<exact@example.net>" });
        check(SuspiciousBehavior.Analyze(Case(unknownThreat, inbound, access)).Count == 0, "unknown verdict does not become a threat");
        var arbitraryVerdict = Audit("arbitrary", new { Operation = "Other", Verdict = "Phish", InternetMessageId = "<exact@example.net>" });
        check(SuspiciousBehavior.Analyze(Case(arbitraryVerdict, inbound)).Count == 0, "threat verdict requires the documented threat record type");
        var multiVerdict = Audit("multi", new { RecordType = 28, Verdict = "Spam", ThreatsAndDetectionTech = "[\"Phish: [Spoof DMARC]\",\"Spam: [URL malicious reputation]\"]", InternetMessageId = "<exact@example.net>" });
        check(SuspiciousBehavior.Analyze(Case(multiVerdict, inbound)).Count == 2, "multi-verdict threat field supports phishing correlation even when primary verdict is spam");
        var malformedVerdict = Audit("malformed", new { RecordType = 28, Verdict = "Unknown", ThreatsAndDetectionTech = "not valid JSON" });
        check(SuspiciousBehavior.Analyze(Case(malformedVerdict)).Count == 0, "malformed threat metadata does not invent a verdict");

        var example = Case(ny, london, rule, inbound);
        using var exported = JsonDocument.Parse(SuspiciousExport.Json(example));
        check(exported.RootElement.GetProperty("suspicious").GetArrayLength() == 2 && !exported.RootElement.TryGetProperty("Evidence", out _), "suspicious JSON contains only indicators with metadata, not the entire timeline");
        check(SuspiciousExport.Csv(Case()).Split('\n', StringSplitOptions.RemoveEmptyEntries).Length == 1, "empty suspicious CSV still has a usable header");
        var injection = example with { Tenant = "=HYPERLINK(\"bad\")" };
        check(SuspiciousExport.Csv(injection).Contains("\"'=HYPERLINK(\"\"bad\"\")\""), "suspicious CSV neutralizes formulas and escapes quotes");
        using var zip = new ZipArchive(new MemoryStream(EvidenceExport.Create(example)));
        check(zip.GetEntry("suspicious.json") is not null && zip.GetEntry("suspicious.csv") is not null, "final archive automatically includes both suspicious formats");
        check(SuspiciousBehavior.Analyze(Case(new Evidence("bad", "Entra sign-ins", Json(new { status = "unknown", location = "bad" })))).Count == 0, "malformed optional properties do not crash or invent suspicious behavior");
    }
}
