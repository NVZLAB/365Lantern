using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Lantern.Core;

int passed = 0;
void Check(bool ok, string name) { if (!ok) throw new Exception(name); Console.WriteLine("PASS " + name); passed++; }
var now = DateTimeOffset.Parse("2026-09-10T12:00:00Z");
var demo = DemoInvestigation.Run(now, 7);
Check(demo.IsDemo && demo.Findings.Count == 2, "synthetic fixture is labeled and has two findings");
using (var zip = new ZipArchive(new MemoryStream(EvidenceExport.Create(demo))))
{
    Check(zip.Entries.Count == 3, "export contains only evidence, summary and manifest");
    using var manifest = JsonDocument.Parse(zip.GetEntry("manifest.json")!.Open());
    foreach (var file in manifest.RootElement.GetProperty("files").EnumerateArray())
    {
        using var stream = zip.GetEntry(file.GetProperty("file").GetString()!)!.Open();
        Check(Convert.ToHexString(SHA256.HashData(stream)) == file.GetProperty("sha256").GetString(), "manifest verifies exported bytes");
    }
}
Check(!GraphCollector.IsAllowedEndpoint(new Uri("https://graph.microsoft.com.evil.example/v1.0/auditLogs/signIns")), "pagination cannot send token to a lookalike host");
Check(!GraphCollector.IsAllowedEndpoint(new Uri("https://graph.microsoft.com/v1.0/users")), "pagination is restricted to the sign-in endpoint");
Check(!GraphCollector.IsAllowedEndpoint(new Uri("http://graph.microsoft.com/v1.0/auditLogs/signIns")), "plaintext pagination rejected");

var handler = new ScriptedHandler([
    new(HttpStatusCode.OK) { Content = new StringContent("""{"value":[{"id":"one","riskLevelDuringSignIn":"high"}],"@odata.nextLink":"https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=two"}""") },
    new(HttpStatusCode.OK) { Content = new StringContent("""{"value":[{"id":"one","riskLevelDuringSignIn":"high"},{"id":"two","riskLevelDuringSignIn":"hidden"}]}""") }
]);
using var http = new HttpClient(handler);
var result = await new GraphCollector(http, _ => Task.FromResult("synthetic-token")).CollectAsync("test", "alex@example.com", now.AddDays(-7), now, default);
Check(result.Evidence.Count == 2 && result.Findings.Count == 1, "pagination deduplicates evidence and hidden risk is not flagged");
Check(result.Coverage[0].Status == "Complete" && result.Coverage[1].Status == "Not collected", "coverage never implies Exchange was queried");
Check(handler.Requests == 2 && handler.OnlyReadRequests, "collector uses GET only");
using var failedHttp = new HttpClient(new ScriptedHandler([new(HttpStatusCode.Forbidden)]));
var failed = await new GraphCollector(failedHttp, _ => Task.FromResult("synthetic-token")).CollectAsync("test", "alex@example.com", now.AddDays(-7), now, default);
Check(failed.Coverage[0].Status == "Failed" && failed.Findings.Count == 0, "403 is a collection failure, not a clean investigation");
using var partialHttp = new HttpClient(new ScriptedHandler([
    new(HttpStatusCode.OK) { Content = new StringContent("""{"value":[{"id":"one"}],"@odata.nextLink":"https://attacker.example/collect"}""") }
]));
var partial = await new GraphCollector(partialHttp, _ => Task.FromResult("synthetic-token")).CollectAsync("test", "alex@example.com", now.AddDays(-7), now, default);
Check(partial.Coverage[0].Status == "Partial" && partial.Evidence.Count == 1, "unsafe continuation retains prior evidence and reports a gap");
using var canceled = new CancellationTokenSource(); canceled.Cancel();
try { await new GraphCollector(http, _ => Task.FromResult("synthetic-token")).CollectAsync("test", "alex@example.com", now.AddDays(-7), now, canceled.Token); throw new Exception("Cancellation ignored"); }
catch (OperationCanceledException) { Check(true, "cancellation stops collection"); }
const string privateMarker = "PRIVATE-RESPONSE-CONTENT";
const string licenseBody = """{"error":{"code":"Authentication_RequestFromNonPremiumTenantOrB2CTenant","message":"PRIVATE-RESPONSE-CONTENT","innerError":{"request-id":"PRIVATE-RESPONSE-CONTENT"}}}""";
using var licenseHttp = new HttpClient(new ScriptedHandler([new(HttpStatusCode.Forbidden) { Content = new StringContent(licenseBody) }]));
var licenseResult = await new GraphCollector(licenseHttp, _ => Task.FromResult("synthetic-token")).CollectAsync("test", "alex@example.com", now.AddDays(-1), now, default);
Check(licenseResult.Coverage[0].Status == "Failed" && licenseResult.Coverage[0].Detail.Contains("P1 or P2"), "known licensing error produces specific guidance");
Check(!licenseResult.Coverage[0].Detail.Contains(privateMarker), "error messages and inner error data do not reach coverage");
using (var archive = new ZipArchive(new MemoryStream(EvidenceExport.Create(licenseResult))))
    foreach (var entry in archive.Entries)
    {
        using var reader = new StreamReader(entry.Open());
        Check(!reader.ReadToEnd().Contains(privateMarker), "export does not retain private error body in " + entry.Name);
    }
foreach (var body in new[] { "", "not-json", "null", "[]", "{\"error\":null}", "{\"error\":{\"code\":42}}", "{\"error\":{\"code\":\"PRIVATE-RESPONSE-CONTENT\"}}", new string('x', 17000) })
{
    using var response = new HttpResponseMessage(HttpStatusCode.Forbidden) { Content = new StringContent(body) };
    var description = await GraphFailure.DescribeAsync(response, default);
    Check(description.Contains("HTTP 403") && !description.Contains("P1 or P2") && !description.Contains(privateMarker), "unrecognized/malformed error safely falls back");
}
using var wrongStatus = new HttpResponseMessage(HttpStatusCode.BadRequest) { Content = new StringContent(licenseBody) };
Check(!(await GraphFailure.DescribeAsync(wrongStatus, default)).Contains("P1 or P2"), "licensing diagnosis requires the expected HTTP status");
using var partialLicenseHttp = new HttpClient(new ScriptedHandler([
    new(HttpStatusCode.OK) { Content = new StringContent("""{"value":[{"id":"one"}],"@odata.nextLink":"https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=two"}""") },
    new(HttpStatusCode.Forbidden) { Content = new StringContent(licenseBody) }
]));
var partialLicense = await new GraphCollector(partialLicenseHttp, _ => Task.FromResult("synthetic-token")).CollectAsync("test", "alex@example.com", now.AddDays(-1), now, default);
Check(partialLicense.Coverage[0].Status == "Partial" && partialLicense.Evidence.Count == 1 && partialLicense.Coverage[0].Detail.Contains("P1 or P2"), "licensing failure after a page preserves partial evidence");
const string importRow = """{"id":"event","userPrincipalName":"alex@example.com","createdDateTime":"2026-09-10T10:00:00Z","riskLevelDuringSignIn":"high"}""";
var input = System.Text.Encoding.UTF8.GetBytes("[" + importRow + "]");
var imported = JsonSignInImport.Read(input, now);
Check(imported.Import?.Sha256 == Convert.ToHexString(SHA256.HashData(input)) && !imported.IsDemo && imported.Coverage[0].Status == "Imported", "import hashes exact input and does not claim live or complete coverage");
Check(imported.Findings.Count == 1 && imported.StartUtc == now.AddHours(-2), "import analyzes risk and uses observed dates");
var wrapped = JsonSignInImport.Read(System.Text.Encoding.UTF8.GetBytes("{\"value\":[" + importRow + "," + importRow.Replace("alex@example.com", "other@example.com") + "],\"@odata.nextLink\":\"https://example.invalid\"}"), now);
Check(wrapped.Evidence.Count == 2 && wrapped.Findings[1].Account == "other@example.com" && wrapped.Evidence[0].Id != wrapped.Evidence[1].Id, "wrapped multi-account import preserves duplicates with unique evidence references");
foreach (var invalid in new[] { "[]", "null", "{}", "[{}]", "[" + importRow.Replace("2026-09-10T10:00:00Z", "invalid") + "]", "[" + importRow.Replace("\"id\":\"event\"", "\"id\":\"event\",\"id\":\"other\"") + "]" })
{
    try { JsonSignInImport.Read(System.Text.Encoding.UTF8.GetBytes(invalid), now); throw new Exception("Invalid import accepted"); }
    catch (InvalidDataException) { Check(true, "invalid import rejected atomically"); }
}
try { JsonSignInImport.Read(input, now, canceled.Token); throw new Exception("Import cancellation ignored"); }
catch (OperationCanceledException) { Check(true, "import honors cancellation"); }
var noRisk = JsonSignInImport.Read(System.Text.Encoding.UTF8.GetBytes("[" + importRow.Replace("\"high\"", "42") + "]"), now);
Check(noRisk.Findings.Count == 0, "unexpected risk type does not crash or invent a finding");
using (var archive = new ZipArchive(new MemoryStream(EvidenceExport.Create(imported))))
{
    using var reader = new StreamReader(archive.GetEntry("summary.txt")!.Open());
    var summary = reader.ReadToEnd();
    Check(summary.Contains("IMPORTED DATA") && summary.Contains(imported.Import!.Sha256) && !summary.Contains("LIVE COLLECTION"), "export identifies import and its source hash");
}
Evidence Event(string id, int minutes, int code, string country = "US", string upn = "alex@example.com", string client = "Browser") => new(id, "Entra sign-ins", JsonSerializer.SerializeToElement(new { id, createdDateTime = now.AddMinutes(minutes), userPrincipalName = upn, status = new { errorCode = code }, location = new { countryOrRegion = country }, clientAppUsed = client }));
var burst = Enumerable.Range(0, 5).Select(i => Event("failure" + i, i, 50126)).Append(Event("success", 6, 0)).ToArray();
Check(SignInFindings.Analyze(burst, "alex@example.com").Any(f => f.Title.Contains("repeated")), "five invalid-password failures followed by success are detected");
Check(SignInFindings.Analyze(burst.Take(5).Append(Event("other", 6, 0, upn: "other@example.com")), "fallback").Count == 0, "failure correlation stays within an account");
Check(SignInFindings.Analyze(burst.Take(5).Append(Event("late", 30, 0)), "fallback").Count == 0, "old failures do not trigger a burst finding");
Check(SignInFindings.Analyze(Enumerable.Range(0, 5).Select(i => Event("mfa" + i, i, 50076)).Append(Event("ok", 6, 0)), "fallback").Count == 0, "MFA interruptions are not invalid-password failures");
Check(SignInFindings.Analyze([Event("us", 0, 0), Event("gb", 30, 0, "GB")], "fallback").Count == 1, "rapid country change is flagged");
Check(SignInFindings.Analyze([Event("us", 0, 0), Event("gb", 90, 0, "GB")], "fallback").Count == 0, "country changes outside threshold are not flagged");
Check(SignInFindings.Analyze([Event("legacy", 0, 0, client: "IMAP"), Event("failedlegacy", 1, 50126, client: "IMAP")], "fallback").Count == 1, "legacy category requires successful status");
var exchangeResult = ExchangeEvidence.Parse("""{"rulesOk":true,"mailboxOk":true,"rules":[{"Enabled":true,"ForwardTo":["review@example.com"],"DeleteMessage":true},{"Enabled":false,"ForwardTo":["disabled@example.com"]}],"mailbox":{"ForwardingSmtpAddress":"smtp:review@example.com"}}""", "alex@example.com");
Check(exchangeResult.Evidence.Count == 3 && exchangeResult.Findings.Count == 3, "Exchange rules and mailbox forwarding are analyzed without flagging disabled rules");
var exchangePartial = ExchangeEvidence.Parse("""{"rulesOk":false,"mailboxOk":true,"rules":[],"mailbox":{"ForwardingSmtpAddress":null}}""", "alex@example.com");
Check(exchangePartial.Coverage[0].Status == "Failed" && exchangePartial.Coverage[1].Status == "Complete" && exchangePartial.Findings.Count == 0, "Exchange source failures remain independent");
Check(ExchangeEvidence.Failed("Unavailable").Coverage.All(c => c.Status == "Failed"), "Exchange failure cannot imply clean configuration");
var hiddenCoverage = InvestigationCoverage.Describe(imported with { Evidence = [new("hidden", "Entra sign-ins", JsonSerializer.SerializeToElement(new { createdDateTime = "2026-09-11T12:00:00Z", riskLevelDuringSignIn = "hidden" }))] });
Check(hiddenCoverage.Contains("1 of 1") && hiddenCoverage.Contains("2026-09-11 12:00") && hiddenCoverage.Contains("do not prove continuous coverage"), "coverage exposes hidden risk and observed dates without inventing retention");
Check(InvestigationCoverage.Describe(imported with { Evidence = [] }).Contains("dates: unavailable"), "empty evidence cannot imply date coverage");
using (var archive = new ZipArchive(new MemoryStream(EvidenceExport.Create(imported))))
{
    using var reader = new StreamReader(archive.GetEntry("summary.txt")!.Open());
    Check(reader.ReadToEnd().Contains("Entra risk assessment unavailable"), "export includes analysis limitations");
}
var diagnosticRows = new[] {
 new Evidence("a", "Entra sign-ins", JsonSerializer.SerializeToElement(new { id="a", userPrincipalName="alex@example.com", ipAddress="::ffff:192.0.2.1", createdDateTime="2026-09-10T10:00:00Z", status=new { errorCode=0 }, location=new { countryOrRegion="us", state="Washington" } })),
 new Evidence("b", "Entra sign-ins", JsonSerializer.SerializeToElement(new { id="b", userPrincipalName="alex@example.com", ipAddress="192.0.2.1", createdDateTime="2026-09-10T11:00:00Z", status=new { errorCode=50076 }, location=new { countryOrRegion="US", state="Washington" } })),
 new Evidence("c", "Entra sign-ins", JsonSerializer.SerializeToElement(new { id="c", ipAddress="not-an-ip" }))
};
var diagnostics = SignInDiagnostics.Create(diagnosticRows.Append(diagnosticRows[0]));
Check(diagnostics.Events.Count == 3 && diagnostics.Duplicates == 1, "diagnostic duplicate IDs do not inflate totals");
Check(diagnostics.IPs.Single(g => g.Value == "192.0.2.1").Events == 2 && diagnostics.IPs.Single(g => g.Value == "192.0.2.1").Successful == 1, "canonical IP grouping separates success from non-success");
Check(diagnostics.Countries.Single(g => g.Value == "US").Events == 2 && diagnostics.Regions.Any(g => g.Value == "US / WASHINGTON"), "geography grouping normalizes case and qualifies states by country");
Check(diagnostics.Events.Single(e => e.EvidenceId == "c").Outcome == "Unknown" && diagnostics.IPs.Any(g => g.Value == "Unknown"), "missing outcomes and invalid IPs are explicitly unknown");
Check(diagnostics.IPs.Single(g => g.Value == "192.0.2.1").FirstUtc == "2026-09-10 10:00:00", "group first-seen uses observed UTC date");
Check(SignInDiagnostics.Create([]).Summary.Contains("0 distinct events"), "empty diagnostics are safe");
Console.WriteLine($"{passed} checks passed.");

sealed class ScriptedHandler(IEnumerable<HttpResponseMessage> responses) : HttpMessageHandler
{
    private readonly Queue<HttpResponseMessage> queue = new(responses);
    public int Requests { get; private set; }
    public bool OnlyReadRequests { get; private set; } = true;
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested(); Requests++;
        OnlyReadRequests &= request.Method == HttpMethod.Get;
        if (request.Headers.Authorization?.Parameter != "synthetic-token") throw new Exception("Missing token");
        return Task.FromResult(queue.Dequeue());
    }
}
