# Development notes

Start with a trusted read-only single-account workflow, then add Exchange collectors before response operations. Do not wrap or execute the historical scripts. Keep collectors and detection logic separate from desktop UI. Never treat missing or failed collection as absence of compromise.

The Mira personality instructions will be supplied from the owner's other computer. No replacement persona or invented Mira rules have been added. Integrate the provided instructions when available; keep product copy clear and suitable for IT investigations.

Build with .NET 10 SDK:

```powershell
dotnet build src/Lantern.Desktop/Lantern.Desktop.csproj -c Release
dotnet run --project tests/Lantern.Checks/Lantern.Checks.csproj -c Release
dotnet src/Lantern.Desktop/bin/Release/net10.0-windows/365Lantern.dll --smoke-test work/ui-smoke
```

The last command is an explicit synthetic-only UI test: it renders Light and Dark PNGs, verifies demo state and clearing, writes a result marker, and exits. Require a zero process exit code as well as the result marker. It never signs in or uses tenant data. A Windows desktop session is required.

The app uses WPF's Fluent ThemeMode API (currently marked experimental by WPF) plus explicit resources for its custom surfaces. System theme changes are observed with SystemEvents. No theme preference is persisted. Review keyboard access, high contrast, scaling and assistive technology before release.

Dependency: Microsoft.Identity.Client 4.88.0 pinned in the desktop project. Do not add the MSAL persistent-cache extensions or token logging. OS/browser sign-in behavior must remain documented.
