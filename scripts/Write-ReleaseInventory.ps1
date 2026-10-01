param(
    [Parameter(Mandatory)][string]$Package,
    [Parameter(Mandatory)][string]$AssetsFile,
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][string]$Commit
)
$ErrorActionPreference = 'Stop'
$Package = (Resolve-Path -LiteralPath $Package).Path
$root = Split-Path $PSScriptRoot -Parent
$notices = Join-Path $Package 'third-party'
New-Item $notices -ItemType Directory -Force | Out-Null
Copy-Item (Join-Path $root 'third-party/*') -Destination $notices -Recurse -Force
# Preserve notices from the exact resolved runtime/NuGet packs, not the SDK version.
$assets = Get-Content -LiteralPath $AssetsFile -Raw | ConvertFrom-Json -AsHashtable
$appDeps = Get-Content (Join-Path $Package '365Lantern.deps.json') -Raw | ConvertFrom-Json -AsHashtable
foreach ($key in $appDeps.libraries.Keys) {
    if ($appDeps.libraries[$key].type -ne 'runtimepack') { continue }
    $packageKey=$key.Replace('runtimepack.','')
    $found=$false
    foreach ($cache in $assets.packageFolders.Keys) {
        $source=Join-Path $cache $packageKey.ToLowerInvariant()
        if (!(Test-Path -LiteralPath $source)) { continue }
        $target=Join-Path $notices $packageKey.Replace('/','-')
        New-Item $target -ItemType Directory -Force | Out-Null
        $licenseFiles=@(Get-ChildItem -LiteralPath $source -File | Where-Object Name -Match 'license|notice|\.nuspec$')
        if (!($licenseFiles | Where-Object Name -Match 'license')) { throw "Missing runtime license for $packageKey" }
        $licenseFiles | Copy-Item -Destination $target
        $found=$true; break
    }
    if (!$found) { throw "Runtime notices unavailable for $packageKey" }
}
foreach ($packageKey in $assets.libraries.Keys) {
    $entry = $assets.libraries[$packageKey]
    if ($entry.type -ne 'package') { continue }
    foreach ($cache in $assets.packageFolders.Keys) {
        $source = Join-Path $cache $entry.path
        if (!(Test-Path -LiteralPath $source)) { continue }
        $target = Join-Path $notices ($packageKey.Replace('/','-'))
        foreach ($file in Get-ChildItem -LiteralPath $source -File | Where-Object Name -Match 'license|notice|\.nuspec$') {
            New-Item $target -ItemType Directory -Force | Out-Null
            Copy-Item -LiteralPath $file.FullName -Destination $target
        }
        break
    }
}
$components = [Collections.Generic.List[object]]::new()
$components.Add(@{type='application';'bom-ref'='365Lantern';name='365Lantern';version=$Version;licenses=@(@{license=@{id='MIT'}});properties=@(@{name='source.commit';value=$Commit})})
$seen = @{}
foreach ($file in Get-ChildItem -LiteralPath $Package -Recurse -File -Filter '*.deps.json') {
    $deps = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json -AsHashtable
    foreach ($key in $deps.libraries.Keys) {
        if ($deps.libraries[$key].type -notin @('package','runtimepack') -or $seen.ContainsKey($key)) { continue }
        $seen[$key]=$true
        $parts=$key.Replace('runtimepack.','').Split('/')
        $components.Add(@{type='library';'bom-ref'="nuget:$key";name=$parts[0];version=$parts[1];purl="pkg:nuget/$($parts[0])@$($parts[1])";properties=@(@{name='inventory.source';value=[IO.Path]::GetRelativePath($Package,$file.FullName).Replace('\','/')})})
    }
}
# Inventory every actual DLL/EXE independently, including nested module binaries
# that have no dependency manifest. Hashes identify the shipped bytes; file versions
# are vendor metadata, not inferred NuGet package versions or license conclusions.
foreach ($file in Get-ChildItem -LiteralPath $Package -Recurse -File | Where-Object Extension -in @('.dll','.exe')) {
    $relative=[IO.Path]::GetRelativePath($Package,$file.FullName).Replace('\','/')
    $info=$file.VersionInfo
    $component=@{type='file';'bom-ref'="file:$relative";name=$relative;hashes=@(@{alg='SHA-256';content=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()})}
    if ($info.ProductVersion) { $component.version=[string]$info.ProductVersion }
    $components.Add($component)
}
$modules=Get-Content (Join-Path $Package 'dependencies.json') -Raw | ConvertFrom-Json -AsHashtable
foreach ($name in $modules.modules.Keys) {
    $components.Add(@{type='library';'bom-ref'="psmodule:$name";name=$name;version=$modules.modules[$name];externalReferences=@(@{type='distribution';url="https://www.powershellgallery.com/packages/$name/$($modules.modules[$name])"})})
}
$components.Add(@{type='application';'bom-ref'='PowerShell';name='PowerShell';version=$modules.powershell;externalReferences=@(@{type='distribution';url="https://github.com/PowerShell/PowerShell/releases/tag/v$($modules.powershell)"})})
$bom=@{bomFormat='CycloneDX';specVersion='1.6';serialNumber=('urn:uuid:'+ [guid]::NewGuid());version=1;metadata=@{timestamp=[datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ');component=@{type='application';name='365Lantern';version=$Version};properties=@(@{name='inventory.scope';value='Declared NuGet dependencies, pinned PowerShell modules, and all shipped DLL/EXE hashes. No complete dependency graph or license inference for vendor binaries is asserted.'})};components=@($components.ToArray())}
$bom | ConvertTo-Json -Depth 15 | Set-Content (Join-Path $Package 'sbom.cdx.json')
@{version=$Version;sourceCommit=$Commit;sourceRepository='https://github.com/NVZLAB/365Lantern';builtUtc=[datetime]::UtcNow.ToString('O');signing='Unsigned alpha; no publisher signature';inventory='sbom.cdx.json';notices='third-party/README.md'} | ConvertTo-Json | Set-Content (Join-Path $Package 'build-provenance.json')
