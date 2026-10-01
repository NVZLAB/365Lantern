using System.IO.Compression;
using System.Text.Json;
using Lantern.Core;
using Lantern.Desktop;

static class ResponseChecks
{
    public static async Task Run(Action<bool, string> check)
    {
        const string tenant = "11111111-1111-1111-1111-111111111111", id = "22222222-2222-2222-2222-222222222222", actorId = "33333333-3333-3333-3333-333333333333";
        var now = DateTimeOffset.Parse("2026-10-01T12:00:00Z");
        var value = DemoInvestigation.Run(now, 7) with { Tenant = tenant, IsDemo = false, Accounts = [new(id, "test@example.com", "", "", "", "")] };
        var target = new ResponseTarget(id, "test@example.com", "Test", "Member", actorId, "2026-10-01T11:00:00Z", now);
        var pending = ResponseActions.Prepare(value, tenant, "admin@example.com", target, "=Synthetic approval", "", now);
        void Reject(Action action, string name) { try { action(); throw new Exception("Unsafe preparation accepted: " + name); } catch (ArgumentException) { check(true, name); } }
        Reject(() => ResponseActions.Prepare(value with { IsDemo = true }, tenant, "admin@example.com", target, "test", "", now), "synthetic cases cannot authorize response");
        check(!ResponseActions.Eligible(value with { Tenant = "Imported / unverified" }, tenant), "unverified tenant is ineligible");
        check(!ResponseActions.Eligible(value with { Import = new ImportProvenance("synthetic", 1, 1) }, tenant), "offline data cannot authorize tenant writes even with a matching tenant ID");
        Reject(() => ResponseActions.Prepare(value, actorId, "admin@example.com", target, "test", "", now), "response rejects tenant mismatch");
        Reject(() => ResponseActions.Prepare(value, tenant, "admin@example.com", target with { UserType = "Guest" }, "test", "", now), "response rejects guests");
        Reject(() => ResponseActions.Prepare(value, tenant, "admin@example.com", target with { OperatorId = id }, "test", "", now), "response rejects administrator self-target");
        Reject(() => ResponseActions.Prepare(value, tenant, "admin@example.com", target with { Account = "renamed@example.com" }, "test", "", now), "response rejects stale account identity");
        Reject(() => ResponseActions.Prepare(value, tenant, "admin@example.com", target, "", "", now), "response requires a reason");
        Reject(() => ResponseActions.Prepare(value, tenant, "admin@example.com", target, "test", "unmatched", now), "response rejects unrelated indicator key");
        Reject(() => ResponseActions.Prepare(value, tenant, "admin@example.com", target, "test", "", now.AddMinutes(6)), "response preview expires");
        var accepted = ResponseActions.Complete(pending, JsonSerializer.SerializeToElement(new { status = "Accepted", afterValidFrom = now.ToString("O") }), now);
        check(accepted.Status == "Accepted" && accepted.Verification.Contains("advanced") && accepted.Detail.Contains("does not establish"), "verification observes state without claiming containment");
        var unavailable = ResponseActions.Complete(pending, JsonSerializer.SerializeToElement(new { status = "Accepted" }), now);
        check(unavailable.Status == "Accepted" && unavailable.Verification.Contains("not verified"), "missing verification preserves accepted outcome");
        check(ResponseActions.Unknown(pending).Status == "Unknown", "transport failure never asserts success or denial");
        Reject(() => ResponseActions.Prepare(value, tenant, "admin@example.com", target with { IsSynced = true }, "test", "", now, "password"), "password reset rejects synced accounts");
        Reject(() => ResponseActions.Prepare(value, tenant, "admin@example.com", target, "test", "", now, "method", "id", "passwordMethods"), "authentication cleanup never deletes password method");
        var passwordPending = ResponseActions.Prepare(value, tenant, "admin@example.com", target with { BeforePasswordChange = "2026-10-01T11:00:00Z" }, "test", "", now, "password");
        var passwordResult = ResponseActions.Complete(passwordPending, JsonSerializer.SerializeToElement(new { status = "Accepted", afterPasswordChange = now.ToString("O"), temporaryPassword = "SYNTHETIC-Password!NeverUse1" }), now);
        check(passwordResult.Action.Contains("Reset password") && passwordResult.Verification.Contains("actual credential not tested"), "password verification distinguishes metadata from credential testing");
        var methodPending = ResponseActions.Prepare(value, tenant, "admin@example.com", target, "test", "", now, "method", "synthetic-method_1", "microsoftAuthenticatorMethods");
        var methodResult = ResponseActions.Complete(methodPending, JsonSerializer.SerializeToElement(new { status = "Accepted", verification = "methodAbsent" }), now);
        check(methodResult.Verification.Contains("no longer returned") && methodResult.Detail.Contains("Other methods"), "method deletion reports selected registration only");
        using (var secretZip = new ZipArchive(new MemoryStream(EvidenceExport.Create(value with { Responses = [passwordResult, methodResult] }))))
            foreach (var entry in secretZip.Entries)
            {
                using var reader = new StreamReader(entry.Open());
                check(!reader.ReadToEnd().Contains("SYNTHETIC-Password!NeverUse1"), "password absent from export: " + entry.Name);
            }
        var recorded = value with { Responses = [accepted] };
        check(ResponseActions.Csv(recorded).Contains("'="), "response CSV prevents spreadsheet formula execution");
        check(IncidentReport.Html(recorded).Contains("Revoke sign-in sessions") && !IncidentReport.Html(recorded).Contains("No response actions"), "executive report includes actual response attempts");
        check(IncidentReport.Html(recorded with { Responses = [accepted with { Account = "<script>" }] }).Contains("&lt;script&gt;"), "response HTML escapes account metadata");
        using (var zip = new ZipArchive(new MemoryStream(EvidenceExport.Create(recorded))))
        {
            check(zip.GetEntry("response.csv") is not null && zip.GetEntry("response.json") is not null, "response exports accompany evidence archive");
            using var reader = new StreamReader(zip.GetEntry("manifest.json")!.Open());
            check(reader.ReadToEnd().Contains("response.json"), "response exports included in integrity manifest");
        }
        check(RelatedAccounts.Merge(recorded, value, "Account", "test@example.com").Responses.Count == 1, "related investigations retain response history");
        var generated = Enumerable.Range(0, 200).Select(_ => TemporaryPasswords.Generate()).ToArray();
        check(generated.All(p => p.Length == 24 && p.Any(char.IsUpper) && p.Any(char.IsLower) && p.Any(char.IsDigit) && p.Any(c => !char.IsLetterOrDigit(c))) && generated.Distinct().Count() == generated.Length, "generated passwords have required categories and independent values");
        Reject(() => ResponseActions.Prepare(value, tenant, "admin@example.com", target, "test", "", now, "device", deviceObjectId: "../users"), "device response requires a directory object ID");
        var devicePending = ResponseActions.Prepare(value, tenant, "admin@example.com", target, "test", "", now, "device", deviceObjectId: "44444444-4444-4444-4444-444444444444", deviceName: "Synthetic laptop");
        var deviceResult = ResponseActions.Complete(devicePending, JsonSerializer.SerializeToElement(new { status = "Accepted", verification = "deviceAbsent" }), now);
        check(deviceResult.Verification.Contains("no longer returned") && deviceResult.Detail.Contains("No remote wipe"), "device receipt distinguishes directory deletion from remote wipe");
        check(IncidentReport.Html(value with { Responses = [deviceResult with { DeviceName = "<script>device</script>" }] }).Contains("&lt;script&gt;device&lt;/script&gt;"), "device names are escaped in executive report");
        check(ResponseActions.Csv(value with { Responses = [deviceResult] }).Contains(deviceResult.DeviceObjectId) && ResponseActions.Json(value with { Responses = [deviceResult] }).Contains("Synthetic laptop"), "device identity included in response exports");
        if (!OperatingSystem.IsWindows()) return;
        var oldPath = Environment.GetEnvironmentVariable("PSModulePath");
        var oldMode = Environment.GetEnvironmentVariable("LANTERN_RESPONSE_TEST_MODE");
        Environment.SetEnvironmentVariable("PSModulePath", Path.Combine(AppContext.BaseDirectory, "fixtures", "response-modules"));
        try
        {
            foreach (var mode in new[] { "ok", "deny", "unknown", "verify-fails", "delayed", "changed", "guest", "self", "wrong-actor", "wrong-target", "no-approval" })
            {
                Environment.SetEnvironmentVariable("LANTERN_RESPONSE_TEST_MODE", mode);
                using var helper = new ModuleSession();
                try
                {
                    var preview = await helper.PrepareResponseAsync(tenant, mode == "wrong-actor" ? "other@example.com" : "admin@example.com", id, default);
                    if (mode is "guest" or "self" or "wrong-actor") { check(preview.GetProperty("status").GetString() == "Not performed", "helper blocks " + mode); continue; }
                    check(preview.GetProperty("status").GetString() == "Prepared", "response helper prepares " + mode);
                    var request = new { action = "revoke", tenant, actor = "admin@example.com", targetId = mode == "wrong-target" ? actorId : id, approved = mode != "no-approval" };
                    var result = await helper.RequestAsync(request, default);
                    var expected = mode switch { "deny" => "Denied", "unknown" => "Unknown", "changed" or "wrong-target" or "no-approval" => "Not performed", _ => "Accepted" };
                    check(result.GetProperty("status").GetString() == expected, "helper outcome: " + mode);
                    if (mode == "verify-fails") check(result.GetProperty("afterValidFrom").GetString() == "", "helper retains acceptance when verification unavailable");
                    var repeated = await helper.RequestAsync(request, default);
                    check(repeated.GetProperty("status").GetString() == "Not performed", "helper never repeats a dispatched action: " + mode);
                }
                finally { await helper.CloseAsync(); }
            }
            foreach (var mode in new[] { "ok", "deny", "unknown", "verify-fails", "delayed", "changed", "no-approval", "no-device-approval", "device-id-not-object-id", "unprepared-device", "device-changed", "association-changed", "became-managed", "managed", "hybrid", "joined", "autopilot", "system-managed", "missing-device-metadata", "partial-devices", "inventory-denied" })
            {
                Environment.SetEnvironmentVariable("LANTERN_RESPONSE_TEST_MODE", mode);
                using var helper = new ModuleSession();
                try
                {
                    var preview = await helper.PrepareResponseAsync(tenant, "admin@example.com", id, default, "device");
                    if (mode is "partial-devices" or "inventory-denied") { check(preview.GetProperty("status").GetString() == "Not performed", "device preparation blocks " + mode); continue; }
                    check(preview.GetProperty("status").GetString() == "Prepared", "device prepares " + mode);
                    var blocked = mode is "managed" or "hybrid" or "joined" or "autopilot" or "system-managed" or "missing-device-metadata";
                    check(preview.GetProperty("devices")[0].GetProperty("supported").GetBoolean() != blocked, "device eligibility: " + mode);
                    var request = new { action = "device", tenant, actor = "admin@example.com", targetId = id, approved = mode != "no-approval", deviceImpactApproved = mode != "no-device-approval", deviceObjectId = mode == "device-id-not-object-id" ? "55555555-5555-5555-5555-555555555555" : mode == "unprepared-device" ? "../users" : "44444444-4444-4444-4444-444444444444" };
                    var result = await helper.RequestAsync(request, default);
                    var expected = mode switch { "ok" or "verify-fails" or "delayed" => "Accepted", "deny" => "Denied", "unknown" => "Unknown", _ => "Not performed" };
                    check(result.GetProperty("status").GetString() == expected, "device outcome: " + mode);
                    if (expected == "Accepted") check(result.GetProperty("verification").GetString() == (mode == "ok" ? "deviceAbsent" : ""), "device verification: " + mode);
                    check((await helper.RequestAsync(request, default)).GetProperty("status").GetString() == "Not performed", "device helper is single use: " + mode);
                }
                finally { await helper.CloseAsync(); }
            }
            foreach (var action in new[] { "password", "method" })
            foreach (var mode in new[] { "ok", "deny", "unknown", "verify-fails", "delayed", "changed", "operation-swap", "no-approval", "synced", "became-synced", "method-changed", "unprepared-method", "partial-methods", "missing-sync-state" })
            {
                if (action == "password" && mode is "method-changed" or "unprepared-method" or "partial-methods") continue;
                if (action == "method" && mode is "synced" or "became-synced" or "missing-sync-state") continue;
                Environment.SetEnvironmentVariable("LANTERN_RESPONSE_TEST_MODE", mode);
                using var helper = new ModuleSession();
                try
                {
                    var preview = await helper.PrepareResponseAsync(tenant, "admin@example.com", id, default, action);
                    if (mode is "synced" or "partial-methods" or "missing-sync-state") { check(preview.GetProperty("status").GetString() == "Not performed", action + " preparation blocks " + mode); continue; }
                    check(preview.GetProperty("status").GetString() == "Prepared", action + " prepares " + mode);
                    if (action == "method") check(preview.GetProperty("methods").EnumerateArray().Count(m => m.GetProperty("supported").GetBoolean()) == 1, "method preview excludes unsupported registrations");
                    var request = new { action = mode == "operation-swap" ? "revoke" : action, tenant, actor = "admin@example.com", targetId = id, approved = mode != "no-approval", temporaryPassword = "SYNTHETIC-Password!NeverUse1", methodId = mode == "unprepared-method" ? "../another-method" : "synthetic-method_1", methodType = "microsoftAuthenticatorMethods" };
                    var result = await helper.RequestAsync(request, default);
                    var expected = mode switch { "deny" => "Denied", "unknown" => "Unknown", "changed" or "operation-swap" or "no-approval" or "became-synced" or "method-changed" or "unprepared-method" => "Not performed", _ => "Accepted" };
                    check(result.GetProperty("status").GetString() == expected, action + " outcome: " + mode);
                    check(!result.GetRawText().Contains("SYNTHETIC-Password!NeverUse1"), "response pipe never returns the temporary password");
                    if (action == "method" && expected == "Accepted") check(result.GetProperty("verification").GetString() == (mode is "delayed" or "verify-fails" ? "" : "methodAbsent"), "method verification handles " + mode);
                    var repeated = await helper.RequestAsync(request, default);
                    check(repeated.GetProperty("status").GetString() == "Not performed", action + " is never repeated by helper");
                }
                finally { await helper.CloseAsync(); }
            }
        }
        finally { Environment.SetEnvironmentVariable("PSModulePath", oldPath); Environment.SetEnvironmentVariable("LANTERN_RESPONSE_TEST_MODE", oldMode); }
    }
}
