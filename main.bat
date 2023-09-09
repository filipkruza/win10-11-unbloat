POWERSHELL -Command "taskkill /F /IM explorer.exe"

::: installing winget
PowerShell -Command "$progressPreference = 'silentlyContinue'"
PowerShell -Command "Invoke-WebRequest -Uri https://aka.ms/getwinget -OutFile Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
PowerShell -Command "Invoke-WebRequest -Uri https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx -OutFile Microsoft.VCLibs.x64.14.00.Desktop.appx"
PowerShell -Command "Invoke-WebRequest -Uri https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.7.3/Microsoft.UI.Xaml.2.7.x64.appx -OutFile Microsoft.UI.Xaml.2.7.x64.appx"
PowerShell -Command "Add-AppxPackage Microsoft.VCLibs.x64.14.00.Desktop.appx"
PowerShell -Command "Remove-Item Microsoft.VCLibs.x64.14.00.Desktop.appx"
PowerShell -Command "Add-AppxPackage Microsoft.UI.Xaml.2.7.x64.appx"
PowerShell -Command "Remove-Item Microsoft.UI.Xaml.2.7.x64.appx"
PowerShell -Command "Add-AppxPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
PowerShell -Command "Remove-Item Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"

::: winget packages
PowerShell -Command "winget upgrade -h --all"
PowerShell -Command "winget install -e --id Mozilla.Firefox"
PowerShell -Command "winget install -e --id Valve.Steam"
PowerShell -Command "winget install -e --id=Henry++.simplewall"
PowerShell -Command "winget install -e --id RedHat.Podman"
PowerShell -Command "winget install -e --id Microsoft.WindowsTerminal"
PowerShell -Command "winget install -e --id Microsoft.VisualStudioCode"

:: removing packages

@echo off

:init
setlocal DisableDelayedExpansion
set "batchPath=%~0"
for %%k in (%0) do set batchName=%%~nk
set "vbsGetPrivileges=%temp%\OEgetPriv_%batchName%.vbs"
setlocal EnableDelayedExpansion

:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)
ECHO.
ECHO **************************************
ECHO Invoking UAC for Privilege Escalation
ECHO **************************************

ECHO Set UAC = CreateObject^("Shell.Application"^) > "%vbsGetPrivileges%"
ECHO args = "ELEV " >> "%vbsGetPrivileges%"
ECHO For Each strArg in WScript.Arguments >> "%vbsGetPrivileges%"
ECHO args = args ^& strArg ^& " "  >> "%vbsGetPrivileges%"
ECHO Next >> "%vbsGetPrivileges%"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%vbsGetPrivileges%"
"%SystemRoot%\System32\WScript.exe" "%vbsGetPrivileges%" %*
exit /B

:gotPrivileges
setlocal & pushd .
cd /d %~dp0
if '%1'=='ELEV' (del "%vbsGetPrivileges%" 1>nul 2>nul  &  shift /1)

:: configuration

echo Uninstalling OneDrive
timeout /t 2 /nobreak > NUL
set x64="%SYSTEMROOT%\SysWOW64\OneDriveSetup.exe"
taskkill /f /im OneDrive.exe > NUL 2>&1
ping 127.0.0.1 -n 5 > NUL 2>&1
if exist %x64% (
%x64% /uninstall
) else (
echo "OneDriveSetup.exe installer not found, skipping."
)
ping 127.0.0.1 -n 8 > NUL 2>&1
rd "%USERPROFILE%\OneDrive" /Q /S > NUL 2>&1
rd "C:\OneDriveTemp" /Q /S > NUL 2>&1
rd "%LOCALAPPDATA%\Microsoft\OneDrive" /Q /S > NUL 2>&1
rd "%PROGRAMDATA%\Microsoft OneDrive" /Q /S > NUL 2>&1

echo Removing OneDrive from the Explorer Side Panel.
reg delete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > NUL 2>&1
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > NUL 2>&1
echo Removing StorageSense
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense" /f > NUL 2>&1

:: CONFIGURAION

echo Showing file extensions in file explorer
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f > NUL 2>&1

echo Removing windows start menu web search
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f > NUL 2>&1

echo stop stupid services
sc config diagtrack start= disabled
sc config RetailDemo start= disabled
sc config diagnosticshub.standardcollector.service start= disabled
sc config DiagTrack start= disabled

echo Turning off USBCeip
schtasks /delete /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /f > NUL 2>&1

echo Disallow tracking
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f > NUL 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /f > NUL 2>&1

echo Uninstalling UWP apps
PowerShell -Command "Get-AppxPackage *Microsoft.GetHelp* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WebExperience* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *tarted* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *FeedbackHub* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *MicrosoftOfficeHub* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *MicrosoftTeams* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *SkypeApp* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WindowsMaps* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Sway* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *SkypeApp* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *solit* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *OneNote* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *bing* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.WindowsAlarms* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Clipchamp* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *spotify* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *PowerAutomate* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.Todos* | Remove-AppxPackage"

echo Removing people
POWERSHELL -Command "Get-ProvisionedAppxPackage -Online | ` Where-Object { $_.PackageName -match 'Microsoft.People' } | ` ForEach-Object { Remove-ProvisionedAppxPackage -Online -AllUsers -PackageName $_.PackageName }"

echo Removing family
POWERSHELL -Command "Get-ProvisionedAppxPackage -Online | ` Where-Object { $_.PackageName -match 'Family' } | ` ForEach-Object { Remove-ProvisionedAppxPackage -Online -AllUsers -PackageName $_.PackageName }"

echo Removing edge
POWERSHELL -Command "Get-ProvisionedAppxPackage -Online | ` Where-Object { $_.PackageName -match 'MicrosoftEdge' } | ` ForEach-Object { Remove-ProvisionedAppxPackage -Online -AllUsers -PackageName $_.PackageName }"
POWERSHELL -Command "TASKKILL /F /IM msedge.exe /T"
POWERSHELL -Command "rm -R 'C:\Program Files (x86)\Microsoft\Edge'"
POWERSHELL -Command "rm -R 'C:\Program Files (x86)\Microsoft\EdgeUpdate'"

echo Disabling fast startup
POWERSHELL -Command "powercfg /h off"

echo Disabling swap
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v SwapfileControl /t REG_DWORD /d 0 /f > NUL 2>&1
POWERSHELL -Command "$computersys = Get-WmiObject Win32_ComputerSystem -EnableAllPrivileges; $computersys.AutomaticManagedPagefile = $False; $computersys.Put()"

echo Removing swapfile
POWERSHELL -Command "$pagefileset = Gwmi win32_pagefilesetting | where{$_.caption -like 'C:*'}; $pagefileset.Delete()"

echo Enabling Windows Sandbox
POWERSHELL -Command "Enable-WindowsOptionalFeature -Online -FeatureName 'Containers-DisposableClientVM' -All"

echo Enabling WSL
POWERSHELL -Command "Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux"
POWERSHELL -Command "wsl --set-default-version 2"

echo Enabling Podman
POWERSHELL -Command "podman machine init"

echo Optimising animations
reg add "HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_DWORD /d 0 /f > NUL 2>&1

echo Dark theme
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "WallPaper" /t REG_SZ /d " " /f
reg add "HKEY_CURRENT_USER\Control Panel\Colors" /v "Background" /t REG_SZ /d "0 0 0" /f
POWERSHELL -Command "explorer"

echo Done.
cmd /k
