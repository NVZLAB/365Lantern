using System.Text;
using System.Text.Json;

namespace Lantern.Core;

public sealed record ResponseTarget(string Id, string Account, string DisplayName, string UserType, string OperatorId,
    string BeforeValidFrom, DateTimeOffset PreparedUtc)
{
    public bool IsSynced { get; init; }
    public string BeforePasswordChange { get; init; } = "";
}
public sealed record ResponseActionRecord(string Id, string Action, string Tenant, string Account, string TargetId,
    string Operator, string OperatorId, string Reason, string IndicatorKey, DateTimeOffset RequestedUtc,
    DateTimeOffset? CompletedUtc, string Status, string Verification, string BeforeValidFrom, string AfterValidFrom,
    string Detail)
{
    public string Operation { get; init; } = "revoke";
    public string DeviceObjectId { get; init; } = "";
    public string DeviceName { get; init; } = "";
    public string MethodId { get; init; } = "";
    public string MethodType { get; init; } = "";
    public string BeforePasswordChange { get; init; } = "";
    public string AfterPasswordChange { get; init; } = "";
}

public static class ResponseActions
{
    public const string Limitation = "Response acceptance does not establish containment. Revocation may take several minutes and does not guarantee every application session ended. Password reset and authentication-method removal have separate effects; verify recovery with the account owner.";
    public static string Title(string operation) => operation switch { "revoke" => "Revoke sign-in sessions", "password" => "Reset password; require change at next sign-in", "method" => "Remove registered authentication method", "device" => "Remove Entra device registration", _ => throw new ArgumentException("Unsupported response action.") };
    public static bool Eligible(Investigation? value, string? tenant) => value is { IsDemo: false, Import: null }
        && Guid.TryParse(value.Tenant, out var caseTenant) && Guid.TryParse(tenant, out var liveTenant) && caseTenant == liveTenant;

    public static ResponseActionRecord Prepare(Investigation value, string tenant, string actor, ResponseTarget target, string reason, string indicatorKey, DateTimeOffset now, string operation = "revoke", string methodId = "", string methodType = "", string deviceObjectId = "", string deviceName = "")
    {
        if (!Eligible(value, tenant) || string.IsNullOrWhiteSpace(actor)) throw new ArgumentException("Response requires a live investigation in the connected tenant.");
        if (!Guid.TryParse(target.Id, out var id) || !Guid.TryParse(target.OperatorId, out var operatorId) || id == operatorId
            || target.UserType != "Member" || target.Account.Equals(actor, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Choose a member account other than the responding administrator.");
        if (!value.Accounts.Any(a => a.Id.Equals(target.Id, StringComparison.OrdinalIgnoreCase) && a.Account.Equals(target.Account, StringComparison.OrdinalIgnoreCase)))
            throw new ArgumentException("The target must match an account collected in this investigation. Refresh the investigation if its identity changed.");
        if (target.PreparedUtc > now || now - target.PreparedUtc > TimeSpan.FromMinutes(5)) throw new ArgumentException("The preview expired. Prepare the action again.");
        if (string.IsNullOrWhiteSpace(reason) || reason.Length > 2000) throw new ArgumentException("Enter a reason (up to 2,000 characters).");
        if (indicatorKey.Length > 0 && !IncidentReport.Indicators(value).Any(i => i.Key == indicatorKey)) throw new ArgumentException("The linked indicator no longer matches the investigation.");
        var title = Title(operation);
        if (operation == "password" && target.IsSynced) throw new ArgumentException("Reset synchronized account passwords through their authoritative directory.");
        if (operation == "method" && (string.IsNullOrWhiteSpace(methodId) || !AuthenticationMethodTypes.Contains(methodType))) throw new ArgumentException("Choose a supported registered method.");
        if (operation == "device" && !Guid.TryParse(deviceObjectId, out _)) throw new ArgumentException("Choose a prepared device object ID.");
        return new(Guid.NewGuid().ToString("D"), title, tenant, target.Account, target.Id, actor, target.OperatorId,
            reason.Trim(), indicatorKey, now, null, "Requested", "Not checked", operation == "revoke" ? target.BeforeValidFrom : "", "", "Approved by operator; outcome not yet known.") { Operation = operation, DeviceObjectId = operation == "device" ? deviceObjectId : "", DeviceName = operation == "device" ? deviceName : "", MethodId = methodId, MethodType = methodType, BeforePasswordChange = operation == "password" ? target.BeforePasswordChange : "" };
    }
    public static IReadOnlyList<string> AuthenticationMethodTypes { get; } = Array.AsReadOnly(new[] { "microsoftAuthenticatorMethods", "phoneMethods", "softwareOathMethods", "fido2Methods", "windowsHelloForBusinessMethods", "temporaryAccessPassMethods" });

    public static ResponseActionRecord Complete(ResponseActionRecord pending, JsonElement result, DateTimeOffset now)
    {
        var state = SignInFindings.Text(result, "status");
        if (state is not ("Accepted" or "Denied" or "Unknown" or "Not performed")) state = "Unknown";
        var after = pending.Operation == "revoke" ? SignInFindings.Text(result, "afterValidFrom") : "";
        var observed = pending.Operation == "revoke" && state == "Accepted" && DateTimeOffset.TryParse(pending.BeforeValidFrom, out var beforeTime)
            && DateTimeOffset.TryParse(after, out var afterTime) && afterTime > beforeTime;
        var verified = SignInFindings.Text(result, "verification");
        var afterPassword = pending.Operation == "password" ? SignInFindings.Text(result, "afterPasswordChange") : "";
        var verification = observed ? "Session-validity timestamp advanced" : state == "Accepted" ? "Accepted; effect not verified" : "Not verified";
        if (state == "Accepted" && pending.Operation == "password" && DateTimeOffset.TryParse(pending.BeforePasswordChange, out var beforePasswordTime) && DateTimeOffset.TryParse(afterPassword, out var afterPasswordTime) && afterPasswordTime > beforePasswordTime) verification = "Password-change timestamp advanced; actual credential not tested";
        if (state == "Accepted" && pending.Operation == "method" && verified == "methodAbsent") verification = "Selected authentication method no longer returned";
        if (state == "Accepted" && pending.Operation == "device" && verified == "deviceAbsent") verification = "Selected Entra device object no longer returned";
        return pending with { CompletedUtc = now, Status = state, AfterValidFrom = after, AfterPasswordChange = afterPassword,
            Verification = verification,
            Detail = state switch {
                "Accepted" => pending.Operation switch { "device" => "Microsoft accepted removal of the selected Entra device identity for all users. No remote wipe or Intune retirement was requested. Verify device access and recovery separately.", "password" => "Password reset submitted with change required at next sign-in. The password is not retained in the case. Revoke sign-in sessions separately; verify recovery with the owner.", "method" => "Only the selected registration was targeted. Other methods and active sessions can remain. Re-enrollment depends on tenant policy; verify the user's identity before restoring access.", _ => Limitation },
                "Denied" => pending.Operation switch {
                    "password" => "Microsoft rejected the reset. Check password policy, the authoritative identity provider, response consent and operator role. No automatic retry was made.",
                    "method" => "Microsoft rejected method removal. Check default/dependent phone restrictions, response consent and operator role. No authentication policy was changed and no automatic retry was made.",
                    _ => "Microsoft rejected the request. Check response consent and operator role. No automatic retry was made." },
                "Not performed" => "Pre-execution identity, scope or preview validation failed; no tenant change was sent.",
                _ => "The outcome could not be established. The request may have taken effect; check Microsoft before attempting it again." } };
    }
    public static ResponseActionRecord Unknown(ResponseActionRecord pending) => Complete(pending, JsonSerializer.SerializeToElement(new { status = "Unknown" }), DateTimeOffset.UtcNow);
    public static string Summary(Investigation value) => value.Responses.Count == 0 ? "No response actions were recorded by this application."
        : $"{value.Responses.Count} response attempts recorded: {value.Responses.Count(r => r.Status == "Accepted")} accepted by Microsoft; {value.Responses.Count(r => r.Status == "Denied")} denied; {value.Responses.Count(r => r.Status == "Not performed")} not performed; {value.Responses.Count(r => r.Status is "Unknown" or "Requested")} unresolved. Acceptance does not establish containment.";
    public static string Json(Investigation value) => JsonSerializer.Serialize(new { schemaVersion = 1, value.Tenant, Actions = value.Responses, Limitations = Limitation }, new JsonSerializerOptions { WriteIndented = true });
    public static string Csv(Investigation value)
    {
        static string Cell(string text) { if (text.TrimStart().StartsWith('=') || text.TrimStart().StartsWith('+') || text.TrimStart().StartsWith('-') || text.TrimStart().StartsWith('@') || text.StartsWith('\t') || text.StartsWith('\r')) text = "'" + text; return "\"" + text.Replace("\"", "\"\"") + "\""; }
        var b = new StringBuilder("Id,Action,Tenant,Account,TargetId,Operator,OperatorId,Reason,IndicatorKey,RequestedUtc,CompletedUtc,Status,Verification,BeforeValidFrom,AfterValidFrom,Detail,Operation,MethodId,MethodType,BeforePasswordChange,AfterPasswordChange,DeviceObjectId,DeviceName\r\n");
        foreach (var r in value.Responses) b.AppendLine(string.Join(",", new[] { r.Id, r.Action, r.Tenant, r.Account, r.TargetId, r.Operator, r.OperatorId, r.Reason, r.IndicatorKey, r.RequestedUtc.ToString("O"), r.CompletedUtc?.ToString("O") ?? "", r.Status, r.Verification, r.BeforeValidFrom, r.AfterValidFrom, r.Detail, r.Operation, r.MethodId, r.MethodType, r.BeforePasswordChange, r.AfterPasswordChange, r.DeviceObjectId, r.DeviceName }.Select(Cell)));
        return b.ToString();
    }
}
