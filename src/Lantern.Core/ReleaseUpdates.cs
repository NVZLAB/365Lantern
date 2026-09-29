using System.Numerics;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Lantern.Core;

public sealed record ReleaseVersion(string Text, BigInteger Major, BigInteger Minor, BigInteger Patch, string[] Pre) : IComparable<ReleaseVersion>
{
    public static ReleaseVersion? Parse(string text)
    {
        if (text.Length > 160) return null;
        var m = Regex.Match(text, @"^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\z", RegexOptions.CultureInvariant);
        if (!m.Success) return null;
        var pre = m.Groups[4].Success ? m.Groups[4].Value.Split('.') : [];
        if (pre.Any(p => p.All(char.IsAsciiDigit) && p.Length > 1 && p[0] == '0')) return null;
        return new(text.TrimStart('v'), BigInteger.Parse(m.Groups[1].Value), BigInteger.Parse(m.Groups[2].Value), BigInteger.Parse(m.Groups[3].Value), pre);
    }
    public int CompareTo(ReleaseVersion? other)
    {
        if (other is null) return 1;
        foreach (var pair in new[] { (Major, other.Major), (Minor, other.Minor), (Patch, other.Patch) }) { var c = pair.Item1.CompareTo(pair.Item2); if (c != 0) return c; }
        if (Pre.Length == 0 || other.Pre.Length == 0) return (Pre.Length == 0 ? 1 : 0).CompareTo(other.Pre.Length == 0 ? 1 : 0);
        for (int i = 0; i < Math.Min(Pre.Length, other.Pre.Length); i++)
        {
            bool a = Pre[i].All(char.IsAsciiDigit), b = other.Pre[i].All(char.IsAsciiDigit);
            int c = a && b ? BigInteger.Parse(Pre[i]).CompareTo(BigInteger.Parse(other.Pre[i])) : a != b ? (a ? -1 : 1) : string.CompareOrdinal(Pre[i], other.Pre[i]);
            if (c != 0) return c;
        }
        return Pre.Length.CompareTo(other.Pre.Length);
    }
}

public static class ReleaseUpdates
{
    public const string Page = "https://github.com/NVZLAB/365Lantern/releases";
    public static ReleaseVersion? Select(JsonElement releases, bool previews)
    {
        if (releases.ValueKind != JsonValueKind.Array) throw new InvalidDataException();
        return releases.EnumerateArray().Where(r => r.GetProperty("draft").ValueKind == JsonValueKind.False)
            .Where(r => previews || r.GetProperty("prerelease").ValueKind == JsonValueKind.False)
            .Select(r => ReleaseVersion.Parse(r.GetProperty("tag_name").GetString() ?? ""))
            .Where(v => v is not null && (previews || v.Pre.Length == 0)).OrderByDescending(v => v).FirstOrDefault();
    }
    public static async Task<ReleaseVersion?> CheckAsync(HttpClient client, bool previews, CancellationToken ct)
    {
        ReleaseVersion? latest = null;
        for (int page = 1; page <= 10; page++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, $"https://api.github.com/repos/NVZLAB/365Lantern/releases?per_page=100&page={page}");
            request.Headers.UserAgent.ParseAdd("365Lantern/" + BuildInfo.Version);
            request.Headers.Accept.ParseAdd("application/vnd.github+json");
            using var response = await client.SendAsync(request, ct);
            response.EnsureSuccessStatusCode();
            using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
            var candidate = Select(json.RootElement, previews);
            if (candidate is not null && candidate.CompareTo(latest) > 0) latest = candidate;
            if (json.RootElement.GetArrayLength() < 100) return latest;
        }
        throw new InvalidDataException("Release listing exceeded safety limit.");
    }
}
