using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Lantern.Core;

namespace Lantern.Desktop;

public sealed class ModuleSession : HttpMessageHandler
{
    private Process? process;
    private Task? stderr;
    public bool Connected => process is { HasExited: false };
    public async Task<JsonElement> ConnectAsync(string tenant, CancellationToken ct, bool includeGrants = false)
    {
        StartHelper("ModuleSession.ps1");
        return await RequestAsync(new { action = "connect", tenant, includeGrants }, ct);
    }
    public async Task<JsonElement> PrepareResponseAsync(string tenant, string actor, string targetId, CancellationToken ct, string operation = "revoke")
    {
        StartHelper("ResponseSession.ps1");
        return await RequestAsync(new { action = "prepare", tenant, actor, targetId, operation }, ct);
    }
    private void StartHelper(string script)
    {
        if (process is not null) throw new InvalidOperationException("A helper is already active.");
        var start = new ProcessStartInfo(PortableRuntime.PowerShellPath)
        { UseShellExecute = false, CreateNoWindow = false, WindowStyle = ProcessWindowStyle.Hidden, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8 };
        // Process only: downloaded ZIPs can mark our unsigned bundled scripts as Internet files.
        // This does not change user/machine policy; enforced Group Policy still takes precedence.
        foreach (var arg in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", Path.Combine(AppContext.BaseDirectory, script) }) start.ArgumentList.Add(arg);
        PortableRuntime.Configure(start);
        process = Process.Start(start) ?? throw new IOException();
        var activeProcess = process;
        stderr = Task.Run(async () => { var buffer = new char[4096]; while (await activeProcess.StandardError.ReadAsync(buffer) != 0) Array.Clear(buffer); });
    }
    public async Task<JsonElement> RequestAsync(object request, CancellationToken ct)
    {
        var active = process ?? throw new InvalidOperationException();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromMinutes(5));
        try
        {
            await active.StandardInput.WriteLineAsync(JsonSerializer.Serialize(request).AsMemory(), timeout.Token);
            await active.StandardInput.FlushAsync(timeout.Token);
            var line = new StringBuilder();
            var buffer = new char[1];
            int total = 0;
            while (await active.StandardOutput.ReadAsync(buffer.AsMemory(), timeout.Token) != 0)
            {
                if (++total > 32 * 1024 * 1024) throw new InvalidDataException();
                if (buffer[0] != '\n') { line.Append(buffer[0]); continue; }
                var value = line.ToString().TrimEnd('\r'); line.Clear();
                if (!value.StartsWith("LANTERN:", StringComparison.Ordinal)) continue;
                using var json = JsonDocument.Parse(value[8..]);
                if (!json.RootElement.GetProperty("ok").GetBoolean()) throw new InvalidOperationException("Microsoft module operation failed. Check module installation, consent and the selected tenant/account.");
                return json.RootElement.GetProperty("result").Clone();
            }
            throw new IOException("The PowerShell helper exited before returning a result. Check that the package is fully extracted and that organizational application or script policies allow its bundled runtime.");
        }
        catch { await CloseAsync(); throw; }
    }
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (request.Method != HttpMethod.Get || request.RequestUri is null || !(GraphCollector.IsAllowedEndpoint(request.RequestUri) || AccountInventory.Allowed(request.RequestUri) || DirectoryAuditCollector.Allowed(request.RequestUri) || GrantCollector.Allowed(request.RequestUri) || GrantCollector.ApplicationAllowed(request.RequestUri))) throw new InvalidOperationException();
        var response = await RequestAsync(new { action = "graph", uri = request.RequestUri.AbsoluteUri }, cancellationToken);
        return new HttpResponseMessage((HttpStatusCode)response.GetProperty("status").GetInt32()) { Content = new StringContent(response.GetProperty("body").GetString() ?? "{}") };
    }
    public async Task CloseAsync()
    {
        var active = process; process = null;
        if (active is null) return;
        try
        {
            if (!active.HasExited)
            {
                active.StandardInput.Close();
                using var grace = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                try { await active.WaitForExitAsync(grace.Token); }
                catch (OperationCanceledException) { if (!active.HasExited) active.Kill(true); await active.WaitForExitAsync(); }
            }
            if (stderr is not null) await stderr;
        }
        finally { active.Dispose(); }
    }
}
