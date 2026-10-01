namespace Lantern.Core;

public sealed record ActionPrompt(string Title, string Guidance)
{
    public string Draft => $"Proposed action: {Title}\nScope / rationale: {Guidance}\nOwner: [assign]\nTarget date: [set]\nStatus: Proposed — not performed\nCompletion evidence / verification: [record]\n";
}
public static class ActionPrompts
{
    public static IReadOnlyList<ActionPrompt> All { get; } = Array.AsReadOnly(new[]
    {
        new ActionPrompt("Establish security monitoring and response ownership", "Define alerts for suspicious sign-ins, consent grants, privilege changes and mailbox forwarding. Assess existing tools, SIEM or managed monitoring against licensing, retention, budget and coverage needs. Assign an alert owner and test escalation."),
        new ActionPrompt("Provide phishing training and a reporting channel", "Provide role-appropriate training on phishing, unexpected MFA prompts and consent requests. Make suspicious-message reporting easy, practice the response process and measure reporting rather than blaming users."),
        new ActionPrompt("Evaluate geographic sign-in restrictions", "Assess Conditional Access restrictions for locations without a business need. Check licensing, travel and remote-work requirements; IP geolocation and VPNs are imperfect. Test in report-only mode where supported, protect emergency access and document exceptions before enforcement."),
        new ActionPrompt("Plan phishing-resistant MFA enforcement", "Plan phishing-resistant authentication for administrators and high-risk users, then expand coverage. Check licensing and device compatibility, protect recovery and emergency access, and verify policy enforcement. Method cleanup performed in Response is recorded separately."),
        new ActionPrompt("Reduce standing administrative access", "Review privileged roles, separate daily-use and administrative accounts, remove unnecessary standing privilege through approved changes and evaluate time-limited access where licensed. Schedule recurring access reviews."),
        new ActionPrompt("Strengthen application consent governance", "Define who can consent, an approval process, accountable application owners and periodic reviews of scopes and unused grants. Assess business dependencies before restricting existing applications."),
        new ActionPrompt("Harden mail protection and external forwarding", "Review anti-phishing controls, external-forwarding policy, SPF, DKIM and DMARC with the mail owner. Test legitimate sending services and exceptions before enforcement; define alerts for new forwarding and inbox rules."),
        new ActionPrompt("Restrict legacy authentication and unmanaged access", "Inventory older clients and service dependencies, then stage appropriate authentication and device-access policies. Verify licensing and emergency access, test changes and record approved exceptions."),
        new ActionPrompt("Improve log retention and incident readiness", "Close identified collection gaps, establish retention and protected evidence storage, document response contacts and rehearse a compromise scenario. Assign owners and measurable follow-up checks; retain only necessary information.")
    });
}
