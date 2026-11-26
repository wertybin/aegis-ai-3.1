# Installs the "AEGIS AI 3.1" shortcut on the current user's Desktop.
# Idempotent: safe to run again; it only overwrites its own shortcut.
$ErrorActionPreference = "Stop"

$Root = $PSScriptRoot
if (-not $Root) { $Root = Split-Path -Parent $MyInvocation.MyCommand.FullName }
$Launcher = Join-Path $Root "launch_aegis_31.ps1"
$Icon = Join-Path $Root "assets\aegis_31.ico"
$Desktop = [Environment]::GetFolderPath("Desktop")
$ShortcutPath = Join-Path $Desktop "AEGIS AI 3.1.lnk"

if (-not (Test-Path $Launcher)) { throw "Missing launcher: $Launcher" }

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$Shortcut.Arguments = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $Launcher + '"'
$Shortcut.WorkingDirectory = $Root
$Shortcut.Description = "AEGIS AI 3.1 - Autonomous Security Intelligence Platform"
if (Test-Path $Icon) { $Shortcut.IconLocation = "$Icon,0" }
$Shortcut.Save()

if (-not (Test-Path $ShortcutPath)) { throw "Shortcut was not created" }
Write-Host "DESKTOP_SHORTCUT_OK = $ShortcutPath"
Write-Host "LAUNCHER = $Launcher"
