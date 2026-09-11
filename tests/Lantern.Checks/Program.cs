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
