using System.Text.Json;
namespace Lantern.Core;

public static class SignInTypes
{
    public const string Noninteractive = "Entra noninteractive sign-ins";
    public static bool IsSignIn(Evidence e) => e.Source is "Entra sign-ins" or Noninteractive;
    public static bool IsBackground(Evidence e) => e.Source == Noninteractive ||
        SignInFindings.Field(e.Data, "isInteractive").ValueKind == JsonValueKind.False ||
        (SignInFindings.Field(e.Data, "signInEventTypes") is var types && types.ValueKind == JsonValueKind.Array && types.EnumerateArray().Any(t => t.ValueKind == JsonValueKind.String && t.GetString() == "nonInteractiveUser"));
}
