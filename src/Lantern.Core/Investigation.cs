using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.IO.Compression;

namespace Lantern.Core;

public sealed record Finding(string Priority, string Title, string Account, string Source, string Explanation, string EvidenceId);
public sealed record Coverage(string Source, string Status, int Records, string Detail);
public sealed record Evidence(string Id, string Source, JsonElement Data)
{
    public DateTimeOffset? CollectedUtc { get; init; }
}
public sealed record Investigation(string Tenant, string Account, DateTimeOffset StartUtc, DateTimeOffset EndUtc,
    DateTimeOffset CollectedUtc, bool IsDemo, IReadOnlyList<Finding> Findings, IReadOnlyList<Coverage> Coverage,
    IReadOnlyList<Evidence> Evidence)
{
    public IReadOnlyList<AccountDetail> Accounts { get; init; } = [];
    public IReadOnlyList<InvestigationPivot> Pivots { get; init; } = [];
    public ImportProvenance? Import { get; init; }
}

public static class DemoInvestigation
{
    public static Investigation Run(DateTimeOffset now, int days)
    {
        var events = new[]
        {
            new Evidence("demo-signin-001", "Entra sign-ins", JsonSerializer.SerializeToElement(new
            { id = "demo-signin-001", createdDateTime = now.AddHours(-2), userPrincipalName = "alex@example.com",
              ipAddress = "192.0.2.24", riskLevelDuringSignIn = "high", status = new { errorCode = 0 } })),
            new Evidence("demo-rule-001", "Exchange rules", JsonSerializer.SerializeToElement(new
            { id = "demo-rule-001", name = "Invoice archive", enabled = true, forwardTo = "archive@external.example" })),
            new Evidence("demo-forwarding-001", "Mailbox forwarding", JsonSerializer.SerializeToElement(new
            { forwardingSmtpAddress = (string?)null, deliverToMailboxAndForward = false })),
            new Evidence("demo-mail-001", "Mail flow inbound", JsonSerializer.SerializeToElement(new
            { account = "alex@example.com", record = new { Received = now.AddHours(-3), SenderAddress = "sender@example.net", RecipientAddress = "alex@example.com", Subject = "Synthetic invoice", MessageId = "<synthetic@example.net>", Status = "Delivered" } })),
            new Evidence("demo-audit-001", "Microsoft 365 audit", JsonSerializer.SerializeToElement(new
            { account = "alex@example.com", record = new { Id = "demo-audit-001", CreationTime = now.AddHours(-1), Operation = "New-InboxRule", UserId = "alex@example.com", ObjectId = "Invoice archive", ResultStatus = "True" } }))
        };
        return new("Northwind Demo", "alex@example.com", now.AddDays(-days), now, now, true,
            [new("High", "Sign-in flagged high risk", "alex@example.com", "Entra sign-ins",
                "Synthetic sign-in has a high risk value. Verify with the account owner; this is an indicator, not proof of compromise.", events[0].Id),
             new("High", "Enabled rule forwards externally", "alex@example.com", "Exchange rules",
                "Synthetic rule forwards messages to archive@external.example. Confirm whether the destination is authorized.", events[1].Id)],
            [new("Entra sign-ins", "Complete", 1, "Synthetic fixture only."),
             new("Exchange rules", "Complete", 1, "Synthetic enabled forwarding rule."),
             new("Mailbox forwarding", "Complete", 1, "Synthetic mailbox has no forwarding configured."),
             new("Mail flow inbound", "Complete", 1, "Synthetic transport evidence; no click telemetry."),
             new("Audit actor", "Complete", 1, "Synthetic historical rule change.")], events);
    }
}

public static class EvidenceExport
{
    // Construct the whole archive in memory. The caller owns the single explicit file write.
    public static byte[] Create(Investigation investigation)
    {
        var options = new JsonSerializerOptions { WriteIndented = true };
        var evidenceBytes = JsonSerializer.SerializeToUtf8Bytes(investigation, options);
        static string Safe(string text) => text.Replace("\r", " ").Replace("\n", " ");
        var summary = new StringBuilder("365Lantern — investigation summary\n");
        summary.AppendLine(investigation.IsDemo ? "SYNTHETIC DEMO DATA — not a real incident" : investigation.Import is not null ? "IMPORTED DATA — origin and completeness unverified" : "LIVE COLLECTION — analyst review required");
        summary.AppendLine($"Tenant: {Safe(investigation.Tenant)}\nAccount: {Safe(investigation.Account)}");
        if (investigation.Import is { } imported) summary.AppendLine($"Original input SHA-256: {imported.Sha256}; bytes: {imported.Bytes}; records: {imported.Records}. Original file is not embedded. Dates below are observed event bounds, not export filters.");
        summary.AppendLine($"Period (UTC): {investigation.StartUtc:O} to {investigation.EndUtc:O}\nCollected (UTC): {investigation.CollectedUtc:O}");
        foreach (var pivot in investigation.Pivots) summary.AppendLine($"Related query: {Safe(pivot.Kind)} {Safe(pivot.Value)}; {pivot.StartUtc:O} to {pivot.EndUtc:O}; collected {pivot.CollectedUtc:O}; {Safe(pivot.Status)}");
        summary.AppendLine("\nCollection coverage (Complete means the query finished, not that all historical events exist):");
        foreach (var c in investigation.Coverage) summary.AppendLine($"{Safe(c.Source)}: {c.Status}; {c.Records} records. {Safe(c.Detail)}");
        summary.AppendLine(InvestigationCoverage.Describe(investigation));
        summary.AppendLine("\nSign-in diagnostics:\n" + SignInDiagnostics.Create(investigation.Evidence).Summary);
        summary.AppendLine("\nFindings (indicators, not confirmation of compromise):");
        foreach (var f in investigation.Findings) summary.AppendLine($"[{f.Priority}] {Safe(f.Title)}\n{Safe(f.Explanation)}\nEvidence: {Safe(f.EvidenceId)}\n");
        if (investigation.Findings.Count == 0) summary.AppendLine("No configured indicators matched. This does not establish that the account is safe.");
        var suspicious = SuspiciousBehavior.Analyze(investigation);
        summary.AppendLine($"\nSuspicious behavior: {suspicious.Count} indicators requiring review. See suspicious.json and suspicious.csv for supporting evidence references.");
        summary.AppendLine(SuspiciousBehavior.Limitations);
        summary.AppendLine("\nNo response actions were performed by this build. Raw evidence is in evidence.json. Hashes establish file integrity, not independent provenance.");
        var files = new Dictionary<string, byte[]> { ["evidence.json"] = evidenceBytes, ["summary.txt"] = Encoding.UTF8.GetBytes(summary.ToString()) };
        files["findings.json"] = Encoding.UTF8.GetBytes(FindingsExport.Json(investigation));
        files["suspicious.json"] = Encoding.UTF8.GetBytes(SuspiciousExport.Json(investigation));
        files["suspicious.csv"] = Encoding.UTF8.GetBytes(SuspiciousExport.Csv(investigation));
        files["timeline.json"] = JsonSerializer.SerializeToUtf8Bytes(ActivityTimeline.Create(investigation), options);
        files["timeline.csv"] = Encoding.UTF8.GetBytes(FindingsExport.TimelineCsv(investigation));
        files["findings.csv"] = Encoding.UTF8.GetBytes(FindingsExport.Csv(investigation));
        var manifest = files.Select(f => new { file = f.Key, bytes = f.Value.Length, sha256 = Convert.ToHexString(SHA256.HashData(f.Value)) }).ToArray();
        files["manifest.json"] = JsonSerializer.SerializeToUtf8Bytes(new { schemaVersion = 1, tool = "365Lantern", version = "0.1.0", investigation.CollectedUtc, files = manifest }, options);
        using var buffer = new MemoryStream();
        using (var zip = new ZipArchive(buffer, ZipArchiveMode.Create, true))
            foreach (var f in files)
            {
                using var stream = zip.CreateEntry(f.Key).Open();
                stream.Write(f.Value);
            }
        return buffer.ToArray();
    }
}
