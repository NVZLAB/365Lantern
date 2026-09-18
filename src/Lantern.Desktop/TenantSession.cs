using Microsoft.Identity.Client;

namespace Lantern.Desktop;

public sealed class TenantSession
{
    private IPublicClientApplication? client;
    private IAccount? account;
    private static readonly string[] Scopes = ["https://graph.microsoft.com/AuditLog.Read.All"];
    public string? TenantId { get; private set; }
    public string? Operator { get; private set; }
    public bool IsConnected => client is not null && account is not null;

    public async Task ConnectAsync(string clientId, string tenantId, CancellationToken ct)
    {
        if (!Guid.TryParse(clientId, out _) || !Guid.TryParse(tenantId, out _))
            throw new ArgumentException("Enter valid application and tenant IDs (GUIDs).");
        await DisconnectAsync();
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
        var previous = client;
        client = null; account = null; TenantId = null; Operator = null;
        if (previous is not null)
            foreach (var cached in await previous.GetAccountsAsync()) await previous.RemoveAsync(cached);
    }
}
