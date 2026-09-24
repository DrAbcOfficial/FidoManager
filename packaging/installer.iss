; Inno Setup script for FIDO2 Manager (unpackaged WinUI 3 app).
; CI invokes it as:
;   iscc packaging\installer.iss /DAppVersion=<version> /O<output-dir>
; AppVersion is the git tag without the leading "v".

#ifndef AppVersion
#define AppVersion "0.0.0"
#endif

#define AppName "FIDO2 Manager"
#define AppExe "Fido2.Manager.exe"
#define PublishDir "..\src\Fido2.Manager\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64\publish"

[Setup]
AppId={{90CA061E-F9D5-4CE3-B36F-9B968B83A099}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=Fido2Manager
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
; The NativeAOT single-file build is x64-only; {autopf} then resolves to Program Files.
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=output
OutputBaseFilename=FIDO2.Manager-v{#AppVersion}-setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#AppExe}

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#PublishDir}\*"; Excludes: "*.pdb"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent
