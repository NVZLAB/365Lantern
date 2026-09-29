using System.Reflection;

namespace Lantern.Core;

public static class BuildInfo
{
    public static string InformationalVersion { get; } = typeof(BuildInfo).Assembly
        .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "unknown";
    public static string Version => InformationalVersion.Split('+')[0];
}
