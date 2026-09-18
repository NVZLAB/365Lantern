using System.Text.Json;

namespace Lantern.Core;

public sealed record ExchangeResult(IReadOnlyList<Evidence> Evidence, IReadOnlyList<Coverage> Coverage, IReadOnlyList<Finding> Findings);

public static class ExchangeEvidence
{
    public static ExchangeResult Failed(string detail) => new([], [new("Exchange rules", "Failed", 0, detail), new("Mailbox forwarding", "Failed", 0, detail)], []);
    public static ExchangeResult Parse(string json, string account)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        var evidence = new List<Evidence>();
        var coverage = new List<Coverage>();
        var findings = new List<Finding>();
        bool Yes(JsonElement row, string name) => SignInFindings.Field(row, name).ValueKind == JsonValueKind.True;
        bool Present(JsonElement row, string name)
        {
            var field = SignInFindings.Field(row, name);
            return field.ValueKind switch { JsonValueKind.String => !string.IsNullOrWhiteSpace(field.GetString()), JsonValueKind.Array => field.GetArrayLength() > 0, JsonValueKind.Object => true, _ => false };
        }
        var rules = SignInFindings.Field(root, "rules");
        bool rulesOk = Yes(root, "rulesOk") && rules.ValueKind == JsonValueKind.Array;
        if (rulesOk)
            foreach (var rule in rules.EnumerateArray())
            {
                if (rule.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
                var item = new Evidence($"exchange-rule-{evidence.Count + 1}", "Exchange rules", rule.Clone());
                evidence.Add(item);
                if (!Yes(rule, "Enabled")) continue;
                if (Present(rule, "ForwardTo") || Present(rule, "ForwardAsAttachmentTo") || Present(rule, "RedirectTo"))
                    findings.Add(new("High", "Enabled inbox rule forwards or redirects mail", account, item.Source, "Verify the rule destinations and business purpose. Destinations have not been classified as internal or external. Current configuration is not proof of compromise.", item.Id));
                if (Yes(rule, "DeleteMessage") || Yes(rule, "MarkAsRead") || Present(rule, "MoveToFolder"))
                    findings.Add(new("Medium", "Enabled inbox rule changes message visibility", account, item.Source, "This rule deletes, moves or marks messages as read. Review its conditions; legitimate filing rules also do this.", item.Id));
            }
        coverage.Add(new("Exchange rules", rulesOk ? "Complete" : "Failed", evidence.Count, rulesOk ? "Current inbox rules queried including hidden rules; this is not historical audit coverage." : "Could not read inbox rules. Check Exchange RBAC and mailbox availability."));
        var mailbox = SignInFindings.Field(root, "mailbox");
        bool mailboxOk = Yes(root, "mailboxOk") && mailbox.ValueKind == JsonValueKind.Object;
        if (mailboxOk)
        {
            var item = new Evidence("exchange-mailbox-forwarding", "Mailbox forwarding", mailbox.Clone());
            evidence.Add(item);
            if (Present(mailbox, "ForwardingAddress") || Present(mailbox, "ForwardingSmtpAddress"))
                findings.Add(new("High", "Mailbox forwarding is configured", account, item.Source, "Verify the forwarding destination and authorization. Forwarding may be legitimate; this snapshot does not establish when or by whom it was configured.", item.Id));
        }
        coverage.Add(new("Mailbox forwarding", mailboxOk ? "Complete" : "Failed", mailboxOk ? 1 : 0, mailboxOk ? "Current mailbox forwarding configuration queried; not historical activity." : "Could not read mailbox forwarding. Check Exchange RBAC and mailbox availability."));
        return new(evidence, coverage, findings);
    }
}
