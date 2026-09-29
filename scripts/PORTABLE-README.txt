365Lantern portable Windows x64 preview

Extract the entire ZIP to a new folder and run 365Lantern.exe.
Keep the runtime folder, DLLs and scripts beside the EXE. No installer,
.NET installation, PowerShell installation or module installation is required.
Do not run directly from inside the ZIP. No administrator elevation is required
to launch; Microsoft tenant permissions and consent are still required to collect.

Check for updates in the sidebar. This only contacts GitHub when clicked.
Preview builds include prereleases; stable builds check stable releases only.
Updates are manual: export your current evidence, close the app, extract the new
package to a new folder and launch it. There is no automatic replacement or restart.

This preview is unsigned. Windows or your organization's security policies may
block execution; follow your organization's approved software process.
SHA-256 checksums detect byte changes; they are not a publisher signature.

The app keeps cases in memory until an explicit export. Browser/Windows sign-in
state, Microsoft module artifacts and enterprise/OS logging can exist outside
the portable folder. Portable does not mean forensic zero footprint.
Removing the extracted folder removes the app, not your separately saved exports
or browser/Windows sign-in state. No tenant consent is removed automatically.

See CHANGELOG.md for preview limitations. dependencies.json records bundled
versions. package-files.json records file hashes. Preserve included upstream
licenses and third-party notices; dependencies retain their respective licenses.
Project: https://github.com/NVZLAB/365Lantern
