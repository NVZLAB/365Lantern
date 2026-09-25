using System.Text.Json;

namespace Lantern.Core;

/// <summary>Bounded, independently failing read sources. The transport never returns tokens or raw error messages.</summary>
public sealed class MailActivityCollector(Func<object, CancellationToken, Task<JsonElement>> request)
{
    public async Task<ActivityResult> CollectAsync(string account, DateTimeOffset start, DateTimeOffset end, CancellationToken ct)
    {
        var evidence = new List<Evidence>(); var coverage = new List<Coverage>(); var auditIds = new HashSet<string>();
        var addresses = new[] { account }; bool resolved = false;
        try
        {
            var response = await Read(new { action = "activity", kind = "addresses", account }, ct);
            addresses = response.GetProperty("rows").EnumerateArray().Select(v => v.GetString() ?? "").Where(v => v.Contains('@')).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            if (addresses.Length == 0) throw new InvalidDataException();
            resolved = true;
        }
        catch (Exception) { addresses = [account]; }
        coverage.Add(new("Mailbox addresses", resolved ? "Complete" : "Partial", resolved ? addresses.Length : 0,
            account + (resolved ? ": Current SMTP aliases resolved; historical aliases may differ." : ": Address lookup unavailable; mail queries use the supplied UPN only and may miss aliases or a different primary address.")));
        foreach (var direction in new[] { "inbound", "outbound" })
        {
            var source = "Mail flow " + direction;
            var ids = new HashSet<string>(); int count = 0, pages = 0;
            string state = "Complete", detail = "Transport records only; delivery does not prove reading, clicking or malicious intent.";
            try
            {
                // Trace permits at most ten days per call. Retain completed pages before later failures.
                for (var windowStart = start; windowStart < end; windowStart = windowStart.AddDays(10))
                {
                    var windowEnd = windowStart.AddDays(10) < end ? windowStart.AddDays(10) : end;
                    var cursorEnd = windowEnd; string recipient = "";
                    var cursors = new HashSet<string>();
                    while (true)
                    {
                        ct.ThrowIfCancellationRequested();
                        if (++pages > 100 || count >= 50000) throw new CollectionLimitException();
                        var response = await Read(new { action = "activity", kind = "trace", account, addresses, direction, start = windowStart, end = cursorEnd, recipient }, ct);
                        var rows = response.GetProperty("rows").EnumerateArray().ToArray();
                        foreach (var row in rows)
                        {
                            string T(string key) => SignInFindings.Text(row, key);
                            if (!DateTimeOffset.TryParse(T("Received"), out var date) || date < start || date > end) throw new InvalidDataException();
                            var traceId = T("MessageTraceId"); var to = T("RecipientAddress");
                            if (traceId.Length == 0 || to.Length == 0) throw new InvalidDataException();
                            var key = traceId + ":" + to.ToLowerInvariant();
                            if (!ids.Add(key)) continue;
                            evidence.Add(new(source + ":" + account + ":" + key, source, JsonSerializer.SerializeToElement(new { account, record = row })));
                            count++;
                        }
                        if (rows.Length < 1000) break;
                        var last = rows[^1];
                        if (!DateTimeOffset.TryParse(SignInFindings.Text(last, "Received"), out cursorEnd)) throw new InvalidDataException();
                        recipient = SignInFindings.Text(last, "RecipientAddress");
                        if (cursorEnd <= windowStart || cursorEnd > windowEnd || !cursors.Add(cursorEnd.ToString("O") + "|" + recipient)) throw new CollectionLimitException();
                    }
                }
                if (!resolved) { state = "Partial"; detail += " Alias resolution failed; only the supplied UPN was searched."; }
            }
            catch (Exception ex) { state = count > 0 || ct.IsCancellationRequested ? "Partial" : "Failed"; detail = Describe(ex, ct); }
            coverage.Add(new(source, state, count, account + ": " + detail));
        }
        var auditQueries = new[] { (Mode: "actor", Query: account), (Mode: "mailbox", Query: account) }
            .Concat(addresses.Append(account).Distinct(StringComparer.OrdinalIgnoreCase).Take(20).Select(a => (Mode: "threat", Query: a)));
        if (addresses.Append(account).Distinct(StringComparer.OrdinalIgnoreCase).Count() > 20)
            coverage.Add(new("Threat alias coverage", "Partial", 20, account + ": Threat audit searches limited to 20 current addresses."));
        foreach (var query in auditQueries)
        {
            var mode = query.Mode;
            var ids = new HashSet<string>(); int count = 0; bool finished = false;
            string state = "Complete", detail = mode == "actor" ? "Audit events performed by this account and its current aliases." : mode == "threat" ? "ThreatIntelligence audit search for " + query.Query + "; exact sender/recipient address matches retained. Microsoft verdict availability and licensing apply." : "Mailbox-address text search; exact mailbox owner, object or Identity parameter matches retained. This is not exhaustive target coverage; GUID-only targets and historical aliases may be missing.";
            try
            {
                string sessionId = Guid.NewGuid().ToString();
                for (int page = 0; page < 50; page++)
                {
                    ct.ThrowIfCancellationRequested();
                    var response = await Read(new { action = "activity", kind = "audit", account, queryAddress = query.Query, addresses = addresses.Append(account).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(), start, end, mode, sessionId }, ct);
                    var rows = response.GetProperty("rows").EnumerateArray().ToArray();
                    if (rows.Length == 0) { finished = true; break; }
                    int added = 0;
                    foreach (var row in rows)
                    {
                        using var document = JsonDocument.Parse(SignInFindings.Text(row, "AuditData"));
                        var record = document.RootElement;
                        var id = SignInFindings.Text(record, "Id");
                        if (id.Length == 0) id = SignInFindings.Text(row, "Identity");
                        if (id.Length == 0) throw new InvalidDataException();
                        if (!ids.Add(id)) continue;
                        added++;
                        if (mode == "mailbox" && !MatchesMailbox(record, addresses.Append(account))) continue;
                        if (mode == "threat" && !MatchesThreat(record, addresses.Append(account))) continue;
                        var evidenceId = "ual:" + account + ":" + id;
                        if (!auditIds.Contains(evidenceId) && auditIds.Count >= 50000) throw new CollectionLimitException();
                        if (auditIds.Add(evidenceId)) evidence.Add(new(evidenceId, "Microsoft 365 audit", JsonSerializer.SerializeToElement(new { account, record })));
                        count++;
                    }
                    if (added == 0) throw new CollectionLimitException();
                }
                if (!finished) throw new CollectionLimitException();
                if (!resolved) { state = "Partial"; detail += " Alias lookup unavailable; supplied UPN only."; }
            }
            catch (Exception ex) { state = count > 0 || ct.IsCancellationRequested ? "Partial" : "Failed"; detail = Describe(ex, ct); }
            coverage.Add(new("Audit " + mode, state, count, account + ": " + detail + " Audit availability, retention and ingestion delay apply; zero results do not establish absence of activity."));
        }
        return new(evidence, coverage);
    }

    private static bool MatchesThreat(JsonElement record, IEnumerable<string> addresses)
    {
        bool Match(string value) => addresses.Contains(value, StringComparer.OrdinalIgnoreCase);
        if (Match(SignInFindings.Text(record, "P1Sender")) || Match(SignInFindings.Text(record, "P2Sender"))) return true;
        var recipients = SignInFindings.Field(record, "Recipients");
        return recipients.ValueKind == JsonValueKind.Array && recipients.EnumerateArray().Any(r => r.ValueKind == JsonValueKind.String && Match(r.GetString()!));
    }

    private static bool MatchesMailbox(JsonElement record, IEnumerable<string> addresses)
    {
        bool Match(string value) => addresses.Contains(value, StringComparer.OrdinalIgnoreCase);
        if (Match(SignInFindings.Text(record, "MailboxOwnerUPN")) || Match(SignInFindings.Text(record, "ObjectId"))) return true;
        var parameters = SignInFindings.Field(record, "Parameters");
        return parameters.ValueKind == JsonValueKind.Array && parameters.EnumerateArray().Any(p =>
            SignInFindings.Text(p, "Name") is "Identity" or "Mailbox" && Match(SignInFindings.Text(p, "Value")));
    }

    private async Task<JsonElement> Read(object command, CancellationToken ct)
    {
        for (int attempt = 0; ; attempt++)
        {
            ct.ThrowIfCancellationRequested();
            var response = await request(command, ct);
            var status = SignInFindings.Text(response, "status");
            if (status == "ok") return response;
            if (status == "throttled" && attempt < 2) { await Task.Delay(TimeSpan.FromSeconds(10 * (attempt + 1)), ct); continue; }
            throw new SourceUnavailableException(status);
        }
    }
    private static string Describe(Exception ex, CancellationToken ct) => ct.IsCancellationRequested ? "Canceled; completed pages retained. Remaining checks were skipped." : ex switch
    {
        CollectionLimitException => "Safety limit or non-advancing results reached. Completed pages retained; narrow the date range.",
        SourceUnavailableException { Code: "accessDenied" } => "Access denied by Microsoft. Check the operator's read roles and consent; other sources continue.",
        SourceUnavailableException { Code: "commandUnavailable" } => "Read command unavailable. Update ExchangeOnlineManagement and verify the operator's role exposes the command; other sources continue.",
        SourceUnavailableException { Code: "throttled" } => "Microsoft throttled the query after bounded retries. Completed pages retained.",
        _ => "Source unavailable or unexpected response. Check connection, read roles, licensing and service availability; the exact cause is unconfirmed. Completed pages retained; other checks continue."
    };
    private sealed class CollectionLimitException : Exception;
    private sealed class SourceUnavailableException(string code) : Exception { public string Code { get; } = code; }
}
