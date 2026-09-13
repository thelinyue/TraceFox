#ifndef AppVersion
  #define AppVersion "0.0.1"
#endif

; 按用户安装，规则目录可写；升级和卸载均保留用户修改的规则。
[Setup]
AppId={{C2B0CBB3-09A4-44D1-A71B-82D3D827FD43}
AppName=TraceFox
AppVersion={#AppVersion}
AppPublisher=thelinyue
AppPublisherURL=https://github.com/thelinyue/TraceFox
DefaultDirName={localappdata}\Programs\TraceFox
DefaultGroupName=TraceFox
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=TraceFox-{#AppVersion}-setup
SetupIconFile=..\assets\branding\tracefox.ico
UninstallDisplayIcon={app}\TraceFox.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "chinesesimplified"; MessagesFile: "ChineseSimplified.isl"

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; Flags: unchecked

[Files]
Source: "..\target\release\TraceFox.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\assets\default-rules.json"; DestDir: "{app}\assets"; Flags: onlyifdoesntexist uninsneveruninstall
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\TraceFox"; Filename: "{app}\TraceFox.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\TraceFox"; Filename: "{app}\TraceFox.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\TraceFox.exe"; Description: "启动 TraceFox"; Flags: nowait postinstall skipifsilent

; 自启由应用设置启用，安装时不默认创建；卸载移除本应用的 Windows 集成。
[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueName: "TraceFox"; Flags: dontcreatekey uninsdeletevalue
Root: HKCU; Subkey: "Software\Classes\AppUserModelId\TraceFox.Desktop"; Flags: dontcreatekey uninsdeletekey
