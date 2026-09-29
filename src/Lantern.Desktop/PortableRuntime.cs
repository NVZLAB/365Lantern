using System.Diagnostics;
using System.IO;
namespace Lantern.Desktop;

public static class PortableRuntime
{
    public static string PowerShellPath => File.Exists(Path.Combine(AppContext.BaseDirectory, "runtime", "powershell", "pwsh.exe"))
        ? Path.Combine(AppContext.BaseDirectory, "runtime", "powershell", "pwsh.exe")
        : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "PowerShell", "7", "pwsh.exe");
    public static void Configure(ProcessStartInfo start)
    {
        start.Environment["POWERSHELL_TELEMETRY_OPTOUT"] = "1";
        start.Environment["POWERSHELL_UPDATECHECK"] = "Off";
        var modules = Path.Combine(AppContext.BaseDirectory, "runtime", "modules");
        if (Directory.Exists(modules)) start.Environment["PSModulePath"] = modules + Path.PathSeparator + Path.Combine(Path.GetDirectoryName(PowerShellPath)!, "Modules");
    }
}
