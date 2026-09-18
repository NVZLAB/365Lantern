using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using Lantern.Core;

namespace Lantern.Desktop;

public sealed class ExchangeCollector
{
    private static string PowerShellPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "PowerShell", "7", "pwsh.exe");
    public async Task<ExchangeResult> CollectAsync(TenantSession session, string account, CancellationToken ct)
    {
        try
        {
            bool ready = false;
            try { ready = File.Exists(PowerShellPath) && (await RunAsync("preflight\n", ct)).Trim() == "ready"; }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception) { }
            if (!ready)
                return ExchangeEvidence.Failed("Install PowerShell 7 and ExchangeOnlineManagement 3.7.0 or later. See docs/test-tenant.md for Exchange setup.");
            var token = await session.GetExchangeTokenAsync(ct);
            var request = "collect\n" + JsonSerializer.Serialize(new { token, @operator = session.Operator, account }) + "\n";
            var json = await RunAsync(request, ct);
            return ExchangeEvidence.Parse(json, account);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception)
        {
            return ExchangeEvidence.Failed("Exchange collection failed. Verify delegated Exchange.Manage consent, the signed-in account's Exchange RBAC, and mailbox availability. No server error text was retained.");
        }
    }
    private static async Task<string> RunAsync(string input, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromMinutes(3));
        var start = new ProcessStartInfo(PowerShellPath)
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8
        };
        foreach (var argument in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-File", Path.Combine(AppContext.BaseDirectory, "Collect-Exchange.ps1") }) start.ArgumentList.Add(argument);
        start.Environment["POWERSHELL_TELEMETRY_OPTOUT"] = "1";
        using var process = Process.Start(start) ?? throw new IOException();
        using var registration = timeout.Token.Register(() => { try { if (!process.HasExited) process.Kill(true); } catch (InvalidOperationException) { } });
        // Sensitive input travels through an anonymous pipe, never arguments or a temporary file.
        var output = ReadBoundedAsync(process.StandardOutput, timeout.Token, true);
        var errors = ReadBoundedAsync(process.StandardError, timeout.Token, false);
        try
        {
            await process.StandardInput.WriteAsync(input.AsMemory(), timeout.Token);
            process.StandardInput.Close();
            await Task.WhenAll(output, errors, process.WaitForExitAsync(timeout.Token));
            timeout.Token.ThrowIfCancellationRequested();
            if (process.ExitCode != 0) throw new IOException();
            return await output;
        }
        finally
        {
            if (!process.HasExited) process.Kill(true);
        }
    }
    private static async Task<string> ReadBoundedAsync(StreamReader reader, CancellationToken ct, bool retain)
    {
        var text = new StringBuilder();
        var buffer = new char[4096];
        int total = 0, count;
        while ((count = await reader.ReadAsync(buffer.AsMemory(), ct)) != 0)
        {
            total += count;
            if (total > 16 * 1024 * 1024) throw new InvalidDataException();
            if (retain) text.Append(buffer, 0, count);
            Array.Clear(buffer);
        }
        return text.ToString();
    }
}
