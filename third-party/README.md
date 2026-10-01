# Third-party software in portable releases

365Lantern source is MIT licensed. Bundled Microsoft runtimes, PowerShell, modules
and their dependencies retain their own licenses and notices. No Microsoft
endorsement or redistribution of Microsoft's trademarks is implied.

The release's `dependencies.json` identifies pinned module/runtime inputs;
`sbom.cdx.json` lists declared NuGet dependencies and every shipped DLL/EXE with a
SHA-256 hash. `package-files.json` covers the complete payload. Binary file versions
are vendor metadata and are not inferred NuGet versions. This inventory does not
claim a complete dependency graph for opaque vendor binaries.

Preserve these files when redistributing a portable package:

- `runtime/powershell/LICENSE.txt` and `ThirdPartyNotices.txt`, plus the notices in
  its bundled Modules directories: PowerShell and its third-party dependencies.
- `runtime/modules/ExchangeOnlineManagement/*/license.txt`: Exchange module's
  shipped license. Its manifest also links to https://aka.ms/azps-license.
- `third-party/*/LICENSE*` and `*NOTICE*`: exact resolved .NET runtime package notices.
- The supplemental upstream license texts in this directory. Their source locations
  are recorded below; all shipped vendor files/notices remain intact.

| Supplemental notice | Upstream source |
| --- | --- |
| graph-license.txt | https://github.com/microsoftgraph/msgraph-sdk-powershell/blob/v2.40.0/LICENSE.txt |
| msal-license.txt | https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/f6c9c0ac52f1d4defebe034c3a24f18f4ca3b58f/LICENSE |
| identitymodel-license.txt | https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/blob/c8f7d87bcda35557a68f6cb9c55856a2ee733856/LICENSE.txt |
| powershellget-license.txt | https://github.com/PowerShell/PowerShellGetv2/blob/2.2.5.1/LICENSE |
| packagemanagement-license.txt | https://github.com/OneGet/oneget/blob/d25ee92d7b3195c0bcf6f0a6162bd928418f20f6/LICENSE |

Graph Authentication's package manifest separately links to Microsoft's Developer
Services Agreement: https://learn.microsoft.com/legal/mdsa. Microsoft service access
is subject to the service terms and tenant licensing; Lantern's MIT license does not
grant service entitlements. Review upstream terms when changing bundled versions.
