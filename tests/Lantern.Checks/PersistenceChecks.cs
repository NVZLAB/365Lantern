using System.Net;
using System.Text.Json;
using Lantern.Core;

static class PersistenceChecks
{
    public static async Task Run(Action<bool, string> check)
    {
        var now = DateTimeOffset.Parse("2026-09-24T12:00:00Z");
        JsonElement J(object value) => JsonSerializer.SerializeToElement(value);
        JsonElement Ok(params object[] rows) => J(new { status = "ok", rows });
        Investigation Case(params Evidence[] rows) => new("tenant", "alex@example.com", now.AddDays(-1), now, now, false, [], [], rows);
        Evidence Sign(string id, string account, string ip, bool interactive = true) => new(id, interactive ? "Entra sign-ins" : SignInTypes.Noninteractive, J(new { id, userPrincipalName = account, ipAddress = ip, appId = "11111111-1111-1111-1111-111111111111", isInteractive = interactive, createdDateTime = now, status = new { errorCode = 0 } }));
        HttpResponseMessage Response(object data) => new(HttpStatusCode.OK) { Content = new StringContent(JsonSerializer.Serialize(data)) };
        using var handler = new InspectHandler(Response(new { value = new[] { new { id = "background", isInteractive = false } } }));
        using var http = new HttpClient(handler);
        var background = await new GraphCollector(http, _ => Task.FromResult("synthetic-token")).CollectAsync("tenant", "", now.AddDays(-1), now, default, true, true, new("IP", "192.0.2.1"));
        var uri = Uri.UnescapeDataString(handler.Uris.Single().AbsoluteUri);
        check(uri.Contains("/beta/auditLogs/signIns") && uri.Contains("nonInteractiveUser") && uri.Contains("ipAddress eq '192.0.2.1'") && !uri.Contains("userPrincipalName eq"), "background pivot uses explicit beta event filter and tenant scope");
        check(background.Evidence.Single().Source == SignInTypes.Noninteractive && background.Coverage[0].Detail.Contains("beta"), "background evidence and beta coverage are labeled");
        using var unsafeHandler = new InspectHandler(Response(new Dictionary<string, object> { ["value"] = new[] { new { id = "one" } }, ["@odata.nextLink"] = "https://graph.microsoft.com/v1.0/auditLogs/signIns" }));
        using var unsafeHttp = new HttpClient(unsafeHandler);
        var partial = await new GraphCollector(unsafeHttp, _ => Task.FromResult("synthetic-token")).CollectAsync("tenant", "alex@example.com", now.AddDays(-1), now, default, false, true);
        check(partial.Evidence.Count == 1 && partial.Coverage[0].Status == "Partial" && unsafeHandler.Uris.Count == 1, "background pagination cannot switch API versions and retains completed pages");
        var signs = new[] { Sign("a", "alex@example.com", "192.0.2.1"), Sign("b", "other@example.com", "::ffff:192.0.2.1", false) };
        check(RelatedAccounts.Find(signs, new("IP", "192.0.2.1")).Count == 2 && RelatedAccounts.Seeds(signs).Count == 2, "related IP matching normalizes mapped addresses and includes background activity");
        check(ActivityTimeline.Create(Case(signs)).Any(r => r.Activity.Contains("Noninteractive")), "timeline distinguishes background authentication");
        bool rejected = false; try { new RelatedSeed("IP", "1.2.3.4' or true").GraphFilter(); } catch (ArgumentException) { rejected = true; }
        check(rejected && !new RelatedSeed("Message", "bad\nmessage").ValidMessage, "pivot input rejects filter injection and control characters");
        Evidence Geo(string id, bool interactive, double lat, double lon, int minute) => new(id, "Entra sign-ins", J(new { userPrincipalName = "alex@example.com", isInteractive = interactive, createdDateTime = now.AddMinutes(minute), ipAddress = id == "ny" ? "192.0.2.1" : "192.0.2.2", status = new { errorCode = 0 }, location = new { geoCoordinates = new { latitude = lat, longitude = lon } } }));
        check(!SuspiciousBehavior.Analyze(Case(Geo("ny", true, 40.7, -74, -30), Geo("ldn", false, 51.5, -.1, 0))).Any(r => r.RuleId == "travel-speed"), "imported noninteractive events cannot create physical travel alerts");

        int calls = 0;
        var permissions = await new PersistenceCollector((command, ct) => {
            calls++; var kind = J(command).GetProperty("kind").GetString();
            return Task.FromResult(kind == "sendAs" ? J(new { status = "accessDenied" }) : Ok(new { Trustee = "delegate@example.com", AccessRights = new[] { "FullAccess" }, Deny = false, IsInherited = false }));
        }).CollectAsync("alex@example.com", default);
        check(calls == 3 && permissions.Evidence.Count == 2 && permissions.Coverage.Single(c => c.Source == "Mailbox Send As").Status == "Failed", "denied Send As does not block other persistence snapshots");
        Evidence Access(string id, string trustee, bool deny, bool inherited) => new(id, "Mailbox Full Access", J(new { account = "alex@example.com", record = new { Trustee = trustee, AccessRights = new[] { "FullAccess" }, Deny = deny, IsInherited = inherited } })) { CollectedUtc = now };
        var access = Case(Access("allow", "delegate@example.com", false, false), Access("deny", "delegate@example.com", true, false), Access("self", "NT AUTHORITY\\SELF", false, false), Access("inherited", "delegate@example.com", false, true));
        check(PersistenceReview.Analyze(access).Single().EvidenceIds.Single() == "allow" && PersistenceReview.Rows(access.Evidence).Count == 4, "permission review excludes denies, self and inherited entries while preserving all raw rows");
        check(ActivityTimeline.Create(access).All(r => r.Category == "Snapshot" && r.Timestamp == now), "persistence timestamps are collection snapshots");
        var mfa = new Evidence("mfa", "Entra audit", J(new { activityDisplayName = "Admin registered security info", result = "success", activityDateTime = now, initiatedBy = new { user = new { userPrincipalName = "admin@example.com" } }, targetResources = new[] { new { userPrincipalName = "other@example.com" } } }));
        check(PersistenceReview.Analyze(Case(mfa)).Single().Account == "other@example.com", "MFA changes identify affected account rather than case starting account");
        check(PersistenceReview.Analyze(Case(mfa with { Data = J(new { activityDisplayName = "Admin registered security info", result = "failure" }) })).Count == 0, "failed MFA change is not reported as persistence");
        var unknownAudit = new Evidence("unknown", "Entra audit", J(new { activityDisplayName = "Consent to application", result = "success" }));
        check(ActivityTimeline.Create(Case(unknownAudit)).Single().Account == "Unresolved audit identity" && SuspiciousBehavior.Analyze(Case(unknownAudit)).Single().Account == "Unresolved audit identity", "unresolved audit identities are never attributed to the initial case account");

        var grant = new { id = "grant", clientId = "client-object", resourceId = "resource-object", consentType = "AllPrincipals", scope = "Mail.Read offline_access" };
        using var grantsHttp = new HttpClient(new InspectHandler(Response(new { value = new[] { grant } }), Response(new { value = new[] { grant } })));
        var grants = await new GrantCollector(grantsHttp, _ => Task.FromResult("synthetic-token")).CollectAsync("alex@example.com", "11111111-1111-1111-1111-111111111111", [], default);
        check(grants.Coverage.Count == 2 && grants.Evidence.Count == 1 && PersistenceReview.Analyze(Case(grants.Evidence.ToArray())).Count == 1, "user and tenant-wide delegated grants deduplicate and sensitive scopes surface for review");
        using var deniedHttp = new HttpClient(new InspectHandler(new HttpResponseMessage(HttpStatusCode.Forbidden)));
        var denied = await new GrantCollector(deniedHttp, _ => Task.FromResult("synthetic-token")).CollectAsync(null, null, [], default);
        check(denied.Evidence.Count == 0 && denied.Coverage.Single().Status == "Failed" && denied.Coverage.Single().Detail.Contains("Directory.Read.All"), "grant denial remains a coverage gap with optional permission guidance");
        check(!GrantCollector.Allowed(new("https://graph.microsoft.com.evil.invalid/v1.0/oauth2PermissionGrants")) && !GrantCollector.Allowed(new("https://graph.microsoft.com/v1.0/users")), "grant endpoint allowlist rejects foreign hosts and unrelated paths");
        using var grantHandler = new InspectHandler(Response(new Dictionary<string, object> { ["value"] = new[] { grant }, ["@odata.nextLink"] = "https://example.invalid/steal" }));
        using var grantHttp = new HttpClient(grantHandler);
        var safeGrant = await new GrantCollector(grantHttp, _ => Task.FromResult("synthetic-token")).CollectAsync(null, null, [], default);
        check(safeGrant.Evidence.Count == 1 && safeGrant.Coverage.Single().Status == "Partial" && grantHandler.Uris.Count == 1, "unsafe grant continuation retains first page without sending another request");

        var original = Case(signs[0]);
        var merged = RelatedAccounts.Merge(original, Case(signs[0], signs[1]), "IP", "192.0.2.1");
        check(merged.Evidence.Count == 2 && original.Evidence.Count == 1 && merged.Pivots.Count == 1 && merged.StartUtc == original.StartUtc, "related merge preserves initial case and deduplicates evidence with query provenance");
        var changed = Case(signs[0] with { Data = J(new { changed = true }) }) with { Findings = [new("Medium", "test", "alex@example.com", "test", "test", "a")] };
        var observations = RelatedAccounts.Merge(original, changed, "Account", "alex@example.com");
        check(observations.Evidence.Count == 2 && observations.Findings.Single().EvidenceId != "a" && observations.Evidence.Any(e => e.Id == observations.Findings.Single().EvidenceId), "changed observation preserves original and remaps finding evidence reference");
        rejected = false; try { RelatedAccounts.Merge(original, Case() with { Tenant = "different" }, "IP", "192.0.2.1"); } catch (InvalidOperationException) { rejected = true; }
        check(rejected, "related collection cannot cross tenant boundaries");
        rejected = false; try { RelatedAccounts.Merge(original, Case() with { EndUtc = now.AddHours(1) }, "IP", "192.0.2.1"); } catch (InvalidOperationException) { rejected = true; }
        check(rejected, "related collection cannot silently change time window");
        var requests = new List<JsonElement>();
        var messages = await new RelatedMessageCollector((command, ct) => {
            var c = J(command); requests.Add(c);
            return Task.FromResult(Ok(new { MessageId = "<exact@example.com>", MessageTraceId = requests.Count.ToString(), Received = c.GetProperty("start").GetDateTimeOffset().AddHours(1), SenderAddress = "sender@example.com", RecipientAddress = "recipient@example.com" }));
        }).CollectAsync(new("Message", "<exact@example.com>"), now.AddDays(-21), now, default);
        check(requests.Count == 3 && messages.Evidence.Count == 3 && RelatedAccounts.Find(messages.Evidence, new("Message", "<exact@example.com>")).Count == 2, "message pivots search bounded windows and return sender and recipient leads");
        var badMessage = await new RelatedMessageCollector((_, _) => Task.FromResult(Ok(new { MessageId = "wrong" }))).CollectAsync(new("Message", "<exact@example.com>"), now.AddDays(-1), now, default);
        check(badMessage.Evidence.Count == 0 && badMessage.Coverage.Single().Status == "Failed", "message search rejects unrelated or malformed response rows");
        using var cancel = new CancellationTokenSource(); cancel.Cancel();
        var canceled = await new PersistenceCollector((_, _) => throw new Exception("Unexpected transport")).CollectAsync("alex@example.com", cancel.Token);
        check(canceled.Coverage.Count == 3 && canceled.Coverage.All(c => c.Status == "Partial"), "canceled persistence collection records all unperformed sources");
    }

    sealed class InspectHandler(params HttpResponseMessage[] responses) : HttpMessageHandler
    {
        readonly Queue<HttpResponseMessage> queue = new(responses);
        public List<Uri> Uris { get; } = [];
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            if (request.Method != HttpMethod.Get || request.Headers.Authorization?.Parameter != "synthetic-token") throw new InvalidOperationException();
            Uris.Add(request.RequestUri!); return Task.FromResult(queue.Dequeue());
        }
    }
}
