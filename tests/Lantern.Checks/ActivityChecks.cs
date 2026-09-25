using System.Net;
using System.Text.Json;
using Lantern.Core;

static class ActivityChecks
{
    public static async Task Run(Action<bool, string> check)
    {
        var start = DateTimeOffset.Parse("2026-09-01T00:00:00Z"); var end = start.AddDays(21);
        JsonElement Json(object value) => JsonSerializer.SerializeToElement(value);
        JsonElement Ok(object[] rows) => Json(new { status = "ok", rows });
        var calls = new List<JsonElement>();
        var auditSeen = new HashSet<string>();
        var collector = new MailActivityCollector((command, ct) =>
        {
            var c = Json(command); calls.Add(c);
            var kind = c.GetProperty("kind").GetString();
            if (kind == "addresses") return Task.FromResult(Ok(["alex@example.com", "alias@example.com"]));
            if (kind == "trace")
            {
                var date = c.GetProperty("start").GetDateTimeOffset();
                if (c.GetProperty("direction").GetString() == "inbound") return Task.FromResult(Json(new { status = "accessDenied" }));
                return Task.FromResult(Ok([new { Received = date.AddHours(1), MessageTraceId = date.ToString("yyyyMMdd"), RecipientAddress = "recipient@example.net", SenderAddress = "alias@example.com", Subject = "=untrusted()", MessageId = "<message@example.com>", Status = "Delivered" }]));
            }
            var mode = c.GetProperty("mode").GetString()!;
            if (!auditSeen.Add(mode)) return Task.FromResult(Ok([]));
            return Task.FromResult(Ok([new { Identity = "audit1", AuditData = JsonSerializer.Serialize(new { Id = "audit1", CreationTime = start.AddHours(2), Operation = "Send", UserId = "alex@example.com", MailboxOwnerUPN = "alex@example.com", InternetMessageId = "<message@example.com>" }) }]));
        });
        var result = await collector.CollectAsync("alex@example.com", start, end, default);
        check(result.Coverage.Single(c => c.Source == "Mail flow inbound").Status == "Failed" && result.Coverage.Single(c => c.Source == "Mail flow outbound").Status == "Complete", "denied inbound collection does not block outbound or audit checks");
        check(result.Evidence.Count(e => e.Source == "Mail flow outbound") == 3 && result.Evidence.Count(e => e.Source == "Microsoft 365 audit") == 1, "21-day trace splits into bounded windows and duplicate audit IDs deduplicate across queries");
        check(calls.Where(c => c.GetProperty("kind").GetString() == "trace").All(c => c.GetProperty("end").GetDateTimeOffset() - c.GetProperty("start").GetDateTimeOffset() <= TimeSpan.FromDays(10) && c.GetProperty("addresses").GetArrayLength() == 2), "trace requests honor ten-day windows and mailbox aliases");
        var investigation = DemoInvestigation.Run(end, 30) with { Evidence = result.Evidence, Coverage = result.Coverage };
        var timeline = ActivityTimeline.Create(investigation);
        check(timeline.Count == 4 && timeline[0].Category == "Mail flow" && timeline[1].Category == "Audit", "timeline interleaves mail and audit evidence by event time");
        check(timeline.All(r => result.Evidence.Any(e => e.Id == r.EvidenceId)) && timeline.All(r => r.Account == "alex@example.com"), "every timeline row retains account and original evidence reference");
        check(FindingsExport.TimelineCsv(investigation).Contains("'=untrusted()") == false && FindingsExport.TimelineCsv(investigation).Contains("=untrusted()"), "subject is literal text within descriptive activity, not an executable CSV formula");
        var snapshot = ActivityTimeline.Create(DemoInvestigation.Run(end, 7)).Single(r => r.Source == "Mailbox forwarding");
        check(snapshot.Category == "Snapshot" && snapshot.Timestamp == end && snapshot.Activity.Contains("not change time"), "current configuration is not falsely dated as a historical change");

        var fallbackCalls = new List<JsonElement>();
        var fallback = await new MailActivityCollector((command, ct) =>
        {
            var c = Json(command); fallbackCalls.Add(c);
            return Task.FromResult(c.GetProperty("kind").GetString() == "addresses" ? Json(new { status = "accessDenied" }) : Ok([]));
        }).CollectAsync("alex@example.com", start, start.AddDays(1), default);
        check(fallback.Coverage.All(c => c.Status == "Partial") && fallbackCalls.Count == 6, "address denial falls back to UPN and continues all checks with explicit gaps");

        var page = Enumerable.Range(0, 1000).Select(i => (object)new { Received = start.AddHours(20).AddSeconds(-i), MessageTraceId = "trace" + i, RecipientAddress = "recipient@example.com", SenderAddress = "alex@example.com" }).ToArray();
        int inboundPages = 0;
        var partial = await new MailActivityCollector((command, ct) =>
        {
            var c = Json(command);
            if (c.GetProperty("kind").GetString() == "addresses") return Task.FromResult(Ok(["alex@example.com"]));
            if (c.GetProperty("kind").GetString() == "trace" && c.GetProperty("direction").GetString() == "inbound")
                return Task.FromResult(++inboundPages == 1 ? Ok(page) : Json(new { status = "accessDenied" }));
            return Task.FromResult(Ok([]));
        }).CollectAsync("alex@example.com", start, start.AddDays(1), default);
        check(partial.Evidence.Count == 1000 && partial.Coverage.Single(c => c.Source == "Mail flow inbound").Status == "Partial", "later page denial retains first trace page and marks partial");
        using var canceled = new CancellationTokenSource(); canceled.Cancel();
        var cancel = await new MailActivityCollector((_, _) => throw new Exception("Must not call transport")).CollectAsync("alex@example.com", start, end, canceled.Token);
        check(cancel.Coverage.All(c => c.Status == "Partial"), "cancellation never reports unperformed mail/audit checks complete");

        var threatSessions = new HashSet<string>();
        var threatCollection = await new MailActivityCollector((command, ct) =>
        {
            var c = Json(command);
            if (c.GetProperty("kind").GetString() == "addresses") return Task.FromResult(Ok(["alex@example.com", "alias@example.com"]));
            if (c.TryGetProperty("mode", out var mode) && mode.GetString() == "threat")
            {
                if (c.GetProperty("queryAddress").GetString() == "alex@example.com") return Task.FromResult(Json(new { status = "accessDenied" }));
                if (threatSessions.Add(c.GetProperty("sessionId").GetString()!))
                    return Task.FromResult(Ok([
                        new { Identity = "related", AuditData = JsonSerializer.Serialize(new { Id = "related", RecordType = 28, Verdict = "Phish", Recipients = new[] { "alias@example.com" } }) },
                        new { Identity = "unrelated", AuditData = JsonSerializer.Serialize(new { Id = "unrelated", RecordType = 28, Verdict = "Phish", Recipients = new[] { "other@example.com" } }) }
                    ]));
            }
            return Task.FromResult(Ok([]));
        }).CollectAsync("alex@example.com", start, start.AddDays(1), default);
        check(threatCollection.Evidence.Count == 1 && threatCollection.Evidence[0].Id.EndsWith("related") && !threatCollection.Evidence[0].Id.EndsWith("unrelated"), "threat queries retain exact alias matches and discard unrelated recipients");
        check(threatCollection.Coverage.Count(c => c.Source == "Audit threat" && c.Status == "Failed") == 1 && threatCollection.Coverage.Any(c => c.Source == "Mail flow outbound" && c.Status == "Complete"), "denied threat query is a coverage gap without blocking other aliases or mail flow");

        check(!DirectoryAuditCollector.Allowed(new Uri("https://graph.microsoft.com.evil.invalid/v1.0/auditLogs/directoryAudits")), "directory audit rejects external pagination hosts");
        using var http = new HttpClient(new ScriptedHandler([
            new(HttpStatusCode.OK) { Content = new StringContent("""{"value":[{"id":"one","activityDateTime":"2026-09-01T10:00:00Z","activityDisplayName":"Update user","initiatedBy":{"user":{"userPrincipalName":"other@example.com"}},"targetResources":[{"id":"user1","userPrincipalName":"alex@example.com"}]},{"id":"unrelated","targetResources":[]}],"@odata.nextLink":"https://example.invalid/steal"}""") }
        ]));
        var directory = await new DirectoryAuditCollector(http, _ => Task.FromResult("synthetic-token")).CollectAsync("alex@example.com", "user1", start, end, default);
        check(directory.Evidence.Count == 1 && directory.Coverage.Single().Status == "Partial", "directory target matching retains relevant events and unsafe continuation becomes a gap");
        var identityTimeline = ActivityTimeline.Create(investigation with { Evidence = directory.Evidence });
        check(identityTimeline.Any(r => r.Account == "alex@example.com") && identityTimeline.Any(r => r.Account == "other@example.com"), "directory audit timeline associates actor and affected account without changing raw evidence");
    }
}
