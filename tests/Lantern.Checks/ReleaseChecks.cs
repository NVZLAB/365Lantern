using System.Net;
using System.Text.Json;
using Lantern.Core;

static class ReleaseChecks
{
    public static async Task Run(Action<bool,string> check)
    {
        var versions = new[] { "0.1.0-alpha.1", "0.1.0-alpha.2", "0.1.0-alpha.10", "0.1.0-beta.1", "0.1.0-rc.1", "0.1.0", "0.1.1", "0.2.0", "1.0.0" };
        check(versions.Zip(versions.Skip(1)).All(p => ReleaseVersion.Parse(p.First)!.CompareTo(ReleaseVersion.Parse(p.Second)) < 0), "release comparison orders numeric previews and stable versions correctly");
        check(ReleaseVersion.Parse("v1.2.3+abc")!.CompareTo(ReleaseVersion.Parse("1.2.3+def")) == 0, "release comparison ignores build metadata and accepts tag prefix");
        check(new[] { "1.2", "01.2.3", "1.2.3-alpha.01", "<html>", "1.2.3\n" }.All(v => ReleaseVersion.Parse(v) is null), "malformed release versions are rejected");
        using var json = JsonDocument.Parse("""[{"tag_name":"v0.1.0","draft":false,"prerelease":false},{"tag_name":"v0.2.0-alpha.1","draft":false,"prerelease":true},{"tag_name":"v9.0.0","draft":true,"prerelease":false},{"tag_name":"v8.0.0-beta.1","draft":false,"prerelease":false},{"tag_name":"invalid","draft":false,"prerelease":false}]""");
        check(ReleaseUpdates.Select(json.RootElement, false)!.Text == "0.1.0", "stable update channel excludes drafts and prerelease tags even if mislabeled");
        check(ReleaseUpdates.Select(json.RootElement, true)!.Text == "8.0.0-beta.1", "preview channel selects highest semantic version rather than release order");
        using var handler = new UpdateHandler(HttpStatusCode.OK, "[]"); using var client = new HttpClient(handler);
        check(await ReleaseUpdates.CheckAsync(client, true, default) is null && handler.Safe, "empty release feed is handled without credentials or tenant data");
        using var deniedClient = new HttpClient(new UpdateHandler(HttpStatusCode.Forbidden, "{}"));
        bool denied = false; try { await ReleaseUpdates.CheckAsync(deniedClient, false, default); } catch (HttpRequestException) { denied = true; }
        check(denied, "GitHub rate limit is a failed check, never an up-to-date verdict");
    }
    sealed class UpdateHandler(HttpStatusCode status, string body) : HttpMessageHandler
    {
        public bool Safe { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Safe = request.Method == HttpMethod.Get && request.RequestUri!.AbsoluteUri == "https://api.github.com/repos/NVZLAB/365Lantern/releases?per_page=100&page=1" && request.Headers.Authorization is null && request.Content is null;
            return Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent(body) });
        }
    }
}
