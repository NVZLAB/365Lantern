using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;

namespace Lantern.Core;

public sealed record ImportProvenance(string Sha256, int Bytes, int Records);

public static class JsonSignInImport
{
    public const int MaxBytes = 32 * 1024 * 1024;
    public const int MaxRecords = 100_000;

    // No file writes or network access. Retain events, never local paths or wrapper metadata.
    public static Investigation Read(byte[] bytes, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        if (bytes.Length == 0 || bytes.Length > MaxBytes)
            throw new InvalidDataException("Choose a nonempty JSON file no larger than 32 MiB.");
        cancellationToken.ThrowIfCancellationRequested();
        var json = bytes.AsMemory();
        if (bytes.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf })) json = json[3..];
        using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 64 });
        var rows = document.RootElement;
        if (rows.ValueKind == JsonValueKind.Object && rows.TryGetProperty("value", out var value)) rows = value;
        if (rows.ValueKind != JsonValueKind.Array || rows.GetArrayLength() == 0 || rows.GetArrayLength() > MaxRecords)
            throw new InvalidDataException("Expected 1–100,000 sign-in records in a JSON array or a value array.");
        var evidence = new List<Evidence>();
        var accounts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var start = DateTimeOffset.MaxValue;
        var end = DateTimeOffset.MinValue;
        foreach (var row in rows.EnumerateArray())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (row.ValueKind != JsonValueKind.Object || !row.TryGetProperty("id", out var id) ||
                id.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(id.GetString()) ||
                !row.TryGetProperty("userPrincipalName", out var upn) || upn.ValueKind != JsonValueKind.String ||
                string.IsNullOrWhiteSpace(upn.GetString()) ||
                !row.TryGetProperty("createdDateTime", out var date) || date.ValueKind != JsonValueKind.String ||
                !DateTimeOffset.TryParse(date.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var timestamp))
                throw new InvalidDataException("Every record must have a string id, userPrincipalName and valid createdDateTime. No records were imported.");
            // Reject ambiguous duplicate property names, including nested objects.
            ValidateProperties(row);
            var account = upn.GetString()!;
            accounts.Add(account);
            start = timestamp < start ? timestamp : start;
            end = timestamp > end ? timestamp : end;
            var item = new Evidence($"import-signin-{evidence.Count + 1:D6}", "Entra sign-ins", row.Clone());
            evidence.Add(item); // Preserve duplicate events as supplied; internal references remain unique.

        }
        return new Investigation("Unverified — local import", accounts.Count == 1 ? accounts.Single() : $"{accounts.Count} accounts in imported file",
            start.ToUniversalTime(), end.ToUniversalTime(), now, false, SignInFindings.Analyze(evidence, "Imported account"),
            [new("Entra sign-ins", "Imported", evidence.Count, $"{evidence.Count} file records loaded. Export filters, missing events and tenant origin are unverified. Risk fields may be unavailable; no matching findings does not establish safety."),
             new("Exchange rules", "Not collected", 0, "Not included in this sign-in import."),
             new("Mailbox forwarding", "Not collected", 0, "Not included in this sign-in import.")], evidence)
            { Import = new(Convert.ToHexString(SHA256.HashData(bytes)), bytes.Length, evidence.Count) };
    }

    private static void ValidateProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name)) throw new InvalidDataException("JSON contains duplicate property names. No records were imported.");
                ValidateProperties(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (var child in element.EnumerateArray()) ValidateProperties(child);
    }
}
