using System.Net;
using System.Text.Json;

namespace Lantern.Core;

public static class GraphFailure
{
    public static async Task<string> DescribeAsync(HttpResponseMessage response, CancellationToken ct)
    {
        var fallback = $"Microsoft Graph returned HTTP {(int)response.StatusCode}. Check consent, role, licensing and availability. The response body was not retained.";
        if (response.StatusCode != HttpStatusCode.Forbidden) return fallback;

        // Inspect only a bounded error document in memory. Never return server-provided
        // messages, unknown codes, request IDs or innerError data to UI/evidence/logs.
        const int limit = 16 * 1024;
        if (response.Content.Headers.ContentLength > limit) return fallback;
        var bytes = new byte[limit + 1];
        try
        {
            using var stream = await response.Content.ReadAsStreamAsync(ct);
            int count = 0;
            while (count < bytes.Length)
            {
                int read = await stream.ReadAsync(bytes.AsMemory(count), ct);
                if (read == 0) break;
                count += read;
            }
            if (count > limit) return fallback;
            using var json = JsonDocument.Parse(bytes.AsMemory(0, count));
            if (json.RootElement.ValueKind != JsonValueKind.Object ||
                !json.RootElement.TryGetProperty("error", out var error) || error.ValueKind != JsonValueKind.Object ||
                !error.TryGetProperty("code", out var code) || code.ValueKind != JsonValueKind.String) return fallback;
            return code.GetString() == "Authentication_RequestFromNonPremiumTenantOrB2CTenant"
                ? "Microsoft Graph denied sign-in log access (HTTP 403): the tenant is not eligible for this API under its current license or tenant type. Microsoft Entra ID P1 or P2 is required for sign-in log retrieval. Verify tenant eligibility; adding broader permissions will not resolve this licensing error. The response body was not retained."
                : fallback;
        }
        catch (Exception ex) when (ex is JsonException or IOException or HttpRequestException)
        {
            return fallback;
        }
        finally { Array.Clear(bytes); }
    }
}
