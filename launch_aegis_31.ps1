# AEGIS AI 3.1 desktop launcher.
# Guarantees the shared local services are up, then opens the native WebView2
# window. It never starts a second uvicorn; the URL comes from .env.
$ErrorActionPreference = "SilentlyContinue"

$Root = $PSScriptRoot
if (-not $Root) { $Root = Split-Path -Parent $MyInvocation.MyCommand.FullName }
$Base = (Get-Content (Join-Path $Root ".env") -ErrorAction SilentlyContinue |
         Where-Object { $_ -like "AEGIS_API_BASE=*" } | Select-Object -First 1) -replace "AEGIS_API_BASE=", ""
if (-not $Base) { $Base = $env:AEGIS_API_BASE }
$Base = ($Base -replace '^"|"$', "").Trim()
$Url = if ($Base) { $Base.TrimEnd("/") + "/" } else { "" }
if (-not $Url) { Write-Host "Set AEGIS_API_BASE in .env first." -ForegroundColor Red }
$PythonW = Join-Path $Root ".venv\Scripts\pythonw.exe"
if (-not (Test-Path $PythonW)) { $PythonW = Join-Path $Root ".venv\Scripts\python.exe" }

function Test-Ui {
    try {
        $r = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 3
        return ($r.StatusCode -eq 200)
    } catch { return $false }
}

if (-not (Test-Ui)) {
    Start-Process -FilePath "powershell.exe" `
        -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", `
                        "-File", "`"$Root\start_all.ps1`"") `
        -WorkingDirectory $Root -WindowStyle Hidden | Out-Null
    for ($i = 0; $i -lt 60; $i++) {
        Start-Sleep -Seconds 2
        if (Test-Ui) { break }
    }
}

if (-not (Test-Ui)) {
    # The window itself shows an honest "service unavailable" message.
    Write-Warning "AEGIS UI did not become ready within 120s; opening the status window."
}

Start-Process -FilePath $PythonW `
    -ArgumentList @("-m", "backend.desktop_window") `
    -WorkingDirectory $Root | Out-Null
exit 0
