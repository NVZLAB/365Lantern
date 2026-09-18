using System.Globalization;

namespace Lantern.Core;

public static class InvestigationCoverage
{
    public static string Describe(Investigation investigation)
    {
        var rows = investigation.Evidence.Where(e => e.Source == "Entra sign-ins").ToArray();
        var dates = rows.Select(e => DateTimeOffset.TryParse(SignInFindings.Text(e.Data, "createdDateTime"), CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal, out var date) ? (DateTimeOffset?)date : null).Where(d => d.HasValue).Select(d => d!.Value.ToUniversalTime()).ToArray();
        var unavailable = rows.Count(e => SignInFindings.Text(e.Data, "riskLevelDuringSignIn") is not ("none" or "low" or "medium" or "high"));
        var observed = dates.Length == 0 ? "Observed sign-in dates: unavailable."
            : $"Observed sign-in dates: {dates.Min():yyyy-MM-dd HH:mm} – {dates.Max():yyyy-MM-dd HH:mm} UTC ({dates.Length} dated records).";
        return $"{rows.Length} sign-in records. {observed}\n" +
            $"Entra risk assessment unavailable in {unavailable} of {rows.Length} records (hidden, missing or unknown). Unavailable risk is not a low-risk verdict.\n" +
            "Observed dates do not prove continuous coverage or explain absent events. Query completion does not establish full retention coverage. Exchange results describe current configuration, not historical changes.";
    }
}
