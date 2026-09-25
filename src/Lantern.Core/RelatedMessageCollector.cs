using System.Text.Json;
namespace Lantern.Core;

public sealed class RelatedMessageCollector(Func<object, CancellationToken, Task<JsonElement>> request)
{
    public async Task<ActivityResult> CollectAsync(RelatedSeed seed, DateTimeOffset start, DateTimeOffset end, CancellationToken ct)
    {
        if (!seed.ValidMessage || start >= end || end - start > TimeSpan.FromDays(30)) throw new ArgumentException("Choose an evidence message ID and a 1–30 day window.");
        var evidence = new List<Evidence>(); var ids = new HashSet<string>(); int pages = 0;
        string state = "Complete", detail = "Exact message-ID tenant transport search. Addresses may be external or aliases; sender attribution and account membership remain unverified. No bodies/attachments were read.";
        try
        {
            for (var first = start; first < end; first = first.AddDays(10))
            {
                var last = first.AddDays(10) < end ? first.AddDays(10) : end; var cursor = last; string recipient = ""; var cursors = new HashSet<string>();
                while (true)
                {
                    ct.ThrowIfCancellationRequested();
                    if (++pages > 100 || evidence.Count >= 50000) throw new InvalidDataException();
                    JsonElement response = default;
                    for (int retry = 0; retry < 3; retry++)
                    {
                        response = await request(new { action = "activity", kind = "messageTrace", messageId = seed.Value, start = first, end = cursor, recipient }, ct);
                        if (SignInFindings.Text(response, "status") != "throttled" || retry == 2) break;
                        await Task.Delay(TimeSpan.FromSeconds(10 * (retry + 1)), ct);
                    }
                    if (SignInFindings.Text(response, "status") != "ok") throw new InvalidOperationException();
                    var rows = response.GetProperty("rows").EnumerateArray().ToArray();
                    foreach (var row in rows)
                    {
                        string T(string key) => SignInFindings.Text(row, key);
                        if (T("MessageId") != seed.Value || !DateTimeOffset.TryParse(T("Received"), out var time) || time < start || time > end || T("MessageTraceId").Length == 0 || T("RecipientAddress").Length == 0) throw new InvalidDataException();
                        var key = T("MessageTraceId") + ":" + T("RecipientAddress").ToLowerInvariant();
                        if (ids.Add(key)) evidence.Add(new("related-message:" + key, "Related message trace", JsonSerializer.SerializeToElement(new { account = T("RecipientAddress"), record = row })));
                    }
                    if (rows.Length < 1000) break;
                    if (!DateTimeOffset.TryParse(SignInFindings.Text(rows[^1], "Received"), out cursor) || cursor <= first || cursor > last) throw new InvalidDataException();
                    recipient = SignInFindings.Text(rows[^1], "RecipientAddress");
                    if (!cursors.Add(cursor.ToString("O") + recipient)) throw new InvalidDataException();
                }
            }
        }
        catch (Exception) { state = evidence.Count > 0 || ct.IsCancellationRequested ? "Partial" : "Failed"; detail = ct.IsCancellationRequested ? "Canceled; completed pages retained." : "Read unavailable, throttled, invalid response or safety boundary reached. Verify Exchange access, module and date range. Completed pages retained; other evidence unchanged."; }
        return new(evidence, [new("Related message trace", state, evidence.Count, detail)]);
    }
}
