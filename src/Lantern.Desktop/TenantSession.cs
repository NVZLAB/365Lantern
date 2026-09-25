using Microsoft.Identity.Client;

namespace Lantern.Desktop;

public sealed class TenantSession
{
    public ModuleSession? Modules { get; private set; }
    public async Task ConnectDefaultAsync(string tenant, CancellationToken ct, bool includeGrants = false)
    {
        if (!Guid.TryParse(tenant, out _)) throw new ArgumentException("Enter the directory tenant ID (GUID).");
        await DisconnectAsync();
        var modules = new ModuleSession();
        try
        {
            var context = await modules.ConnectAsync(tenant, ct, includeGrants);
            var connectedTenant = context.GetProperty("tenant").GetString();
            var connectedAccount = context.GetProperty("account").GetString();
            if (!string.Equals(connectedTenant, tenant, StringComparison.OrdinalIgnoreCase) || string.IsNullOrWhiteSpace(connectedAccount)) throw new InvalidOperationException("Unexpected module identity.");
            TenantId = connectedTenant; Operator = connectedAccount; Modules = modules;
        }
        catch { await modules.CloseAsync(); throw; }
    }
    private IPublicClientApplication? client;
    private IAccount? account;
    private readonly string[] BaseScopes = ["https://graph.microsoft.com/AuditLog.Read.All", "https://graph.microsoft.com/User.Read.All", "https://graph.microsoft.com/Device.Read.All"];
    private string[] Scopes = [];
    public string? TenantId { get; private set; }
    public string? Operator { get; private set; }
    public bool IsConnected => Modules?.Connected == true || (client is not null && account is not null);

    public async Task ConnectAsync(string clientId, string tenantId, CancellationToken ct, bool includeGrants = false)
    {
        if (!Guid.TryParse(clientId, out _) || !Guid.TryParse(tenantId, out _))
            throw new ArgumentException("Enter valid application and tenant IDs (GUIDs).");
        await DisconnectAsync();
        Scopes = includeGrants ? [.. BaseScopes, "https://graph.microsoft.com/Directory.Read.All"] : BaseScopes;
        var candidate = PublicClientApplicationBuilder.Create(clientId)
            .WithAuthority($"https://login.microsoftonline.com/{tenantId}")
            .WithRedirectUri("http://localhost").Build();
        // Default MSAL memory cache only: no broker, serializer, file cache, or token logging.
        try
        {
            var result = await candidate.AcquireTokenInteractive(Scopes).WithUseEmbeddedWebView(false)
                .WithPrompt(Prompt.SelectAccount).ExecuteAsync(ct);
            if (!string.Equals(result.TenantId, tenantId, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("The signed-in tenant did not match the requested tenant.");
            client = candidate; account = result.Account; TenantId = result.TenantId; Operator = result.Account.Username;
        }
        catch
        {
            foreach (var cached in await candidate.GetAccountsAsync()) await candidate.RemoveAsync(cached);
            throw;
        }
    }
    public async Task<string> GetTokenAsync(CancellationToken ct)
    {
        var active = client ?? throw new InvalidOperationException("Connect to a tenant first.");
        var result = await active.AcquireTokenSilent(Scopes, account).ExecuteAsync(ct);
        return result.AccessToken;
    }
    public async Task<string> GetExchangeTokenAsync(CancellationToken ct)
    {
        var active = client ?? throw new InvalidOperationException("Connect to a tenant first.");
        string[] scopes = ["https://outlook.office365.com/Exchange.Manage"];
        AuthenticationResult result;
        try { result = await active.AcquireTokenSilent(scopes, account).ExecuteAsync(ct); }
        catch (MsalUiRequiredException)
        {
            result = await active.AcquireTokenInteractive(scopes).WithAccount(account)
                .WithUseEmbeddedWebView(false).ExecuteAsync(ct);
        }
        if (result.TenantId != TenantId || result.Account.HomeAccountId.Identifier != account!.HomeAccountId.Identifier)
            throw new InvalidOperationException("Exchange sign-in must match the connected account and tenant.");
        return result.AccessToken;
    }
    public async Task DisconnectAsync()
    {
        var modules = Modules; Modules = null;
        if (modules is not null) await modules.CloseAsync();
        var previous = client;
        client = null; account = null; TenantId = null; Operator = null;
        if (previous is not null)
            foreach (var cached in await previous.GetAccountsAsync()) await previous.RemoveAsync(cached);
    }
}
