# AegisAI desktop launcher.
# Starts all local services (if needed), waits for the UI, then opens it.
# Safe to double-click repeatedly: the underlying launcher is idempotent.
$ErrorActionPreference = "SilentlyContinue"

$Root = $PSScriptRoot
if (-not $Root) { $Root = Split-Path -Parent $MyInvocation.MyCommand.FullName }
$Base = (Get-Content (Join-Path $Root ".env") -ErrorAction SilentlyContinue |
         Where-Object { $_ -like "AEGIS_API_BASE=*" } | Select-Object -First 1) -replace "AEGIS_API_BASE=", ""
if (-not $Base) { $Base = $env:AEGIS_API_BASE }
$Base = ($Base -replace '^"|"$', "").Trim()
$Url = if ($Base) { $Base.TrimEnd("/") + "/" } else { "" }
if (-not $Url) { Write-Host "Set AEGIS_API_BASE in .env first." -ForegroundColor Red }

function Test-Ui {
    try {
        $r = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 3
        return ($r.StatusCode -eq 200)
    } catch { return $false }
}

if (-not (Test-Ui)) {
    Start-Process -FilePath "powershell.exe" `
        -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$Root\start_all.ps1`"") `
        -WorkingDirectory $Root -WindowStyle Minimized | Out-Null

    for ($i = 0; $i -lt 60; $i++) {
        Start-Sleep -Seconds 2
        if (Test-Ui) { break }
    }
}

Start-Process $Url
