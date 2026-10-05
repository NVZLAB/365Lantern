[Setup]
AppId={{A03D1E67-74F6-4A89-922C-A9AFA20CBFB8}
AppName=365Lantern Preview
AppVersion={#Version}
AppPublisher=NVZLAB
DefaultDirName={localappdata}\Programs\365Lantern
DefaultGroupName=365Lantern
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#Output}
OutputBaseFilename=365Lantern-{#Version}-Setup
Compression=lzma2/fast
SolidCompression=yes
SetupIconFile=../src/Lantern.Desktop/Assets/Lantern.ico
UninstallDisplayIcon={app}\365Lantern.exe
CloseApplications=yes
RestartApplications=no

[Files]
Source: "{#Payload}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\365Lantern"; Filename: "{app}\365Lantern.exe"
Name: "{group}\Uninstall 365Lantern"; Filename: "{uninstallexe}"

[Run]
Filename: "{app}\365Lantern.exe"; Description: "Launch 365Lantern Preview"; Flags: nowait postinstall skipifsilent unchecked
