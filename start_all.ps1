# AegisAI single-command launcher.
# Starts WSL lab sites, offline DNS lab and the AegisAI backend, then verifies them.
# Idempotent: already-running services are left alone.
$ErrorActionPreference = "SilentlyContinue"

$Root = $PSScriptRoot
if (-not $Root) { $Root = Split-Path -Parent $MyInvocation.MyCommand.FullName }
# V3 is self-contained: its WSL helpers live beside this script, so the V2
# backup is never started or modified by the V3 launcher.
$WslScripts = Join-Path $Root "wsl"
$LogDir = Join-Path $Root "logs"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$VenvPython = Join-Path $Root ".venv\Scripts\python.exe"

# Ollama runs locally; the backend chooses Gemini if the local model fails.
$OllamaExe = Join-Path $Root 'runtime\ollama\ollama.exe'
if (-not (Test-Path -LiteralPath $OllamaExe)) {
    $OllamaExe = Join-Path $env:LOCALAPPDATA "Programs\Ollama\ollama.exe"
}
foreach ($line in (Get-Content (Join-Path $Root '.env') -ErrorAction SilentlyContinue)) {
    if ($line -match '^AEGIS_OLLAMA_EXECUTABLE=(.+)$') { $OllamaExe = $Matches[1].Trim().Trim('"') }
    if ($line -match '^AEGIS_OLLAMA_URL=(.+)$') { $env:AEGIS_OLLAMA_URL = $Matches[1].Trim().Trim('"') }
    if ($line -match '^AEGIS_API_BASE=(.+)$') { $env:AEGIS_API_BASE = $Matches[1].Trim().Trim('"') }
    if ($line -match '^OLLAMA_MODELS=(.+)$') { $env:OLLAMA_MODELS = $Matches[1].Trim().Trim('"') }
}
if (-not [System.IO.Path]::IsPathRooted($OllamaExe)) { $OllamaExe = Join-Path $Root $OllamaExe }
if (-not $env:OLLAMA_MODELS) { $env:OLLAMA_MODELS = Join-Path $Root 'runtime\ollama-models' }
if (-not [System.IO.Path]::IsPathRooted($env:OLLAMA_MODELS)) { $env:OLLAMA_MODELS = Join-Path $Root $env:OLLAMA_MODELS }
$env:OLLAMA_NO_CLOUD = '1'
if ($env:AEGIS_OLLAMA_URL) {
    $ollamaUri = [Uri]$env:AEGIS_OLLAMA_URL
    $env:OLLAMA_HOST = "$($ollamaUri.Host):$($ollamaUri.Port)"
    if (Test-Path $OllamaExe) {
        try {
            Invoke-RestMethod -Uri ($env:AEGIS_OLLAMA_URL.TrimEnd("/") + "/api/version") -TimeoutSec 2 -ErrorAction Stop | Out-Null
        } catch {
            Start-Process -FilePath $OllamaExe -ArgumentList "serve" -WindowStyle Hidden | Out-Null
            Write-Host "  starting Ollama at $($env:AEGIS_OLLAMA_URL)"
        }
    }
} else {
    Write-Host "  AEGIS_OLLAMA_URL is empty - set your local Ollama URL in .env" -ForegroundColor DarkGray
}

function Convert-ToWslPath([string]$WindowsPath) {
    $drive = $WindowsPath.Substring(0, 1).ToLower()
    return ("/mnt/$drive" + $WindowsPath.Substring(2).Replace('\', '/'))
}
$WslScriptRoot = Convert-ToWslPath $WslScripts

function Test-Port([int]$Port) {
    return [bool](Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
}

function Test-Http([string]$Url) {
    if (-not $Url) { return $false }
    try {
        $r = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 5
        return ($r.StatusCode -eq 200)
    } catch { return $false }
}

$ApiBase = if ($env:AEGIS_API_BASE) { $env:AEGIS_API_BASE.TrimEnd("/") } else { "" }
$ApiPort = if ($ApiBase) { ([Uri]$ApiBase).Port } else { 0 }
$GateUrls = @($env:AEGIS_GATE_1_URL, $env:AEGIS_GATE_2_URL, $env:AEGIS_GATE_3_URL) |
    Where-Object { $_ } | ForEach-Object { $_.TrimEnd("/") }
if (-not $ApiBase) { Write-Host "  AEGIS_API_BASE is empty - set your AEGIS UI URL in .env" -ForegroundColor DarkGray }
if (-not $GateUrls) { Write-Host "  AEGIS_GATE_*_URL are empty - set your own target URLs in .env" -ForegroundColor DarkGray }

function Test-Dns {
    $out = wsl -e bash -c 'dig +short @127.0.0.1 aegis-lab.local A' 2>$null
    return ([string]$out -match '127\.0\.0\.1')
}

function Start-WslScript([string]$Name) {
    $path = "$WslScriptRoot/$Name"
    if (-not (Test-Path (Join-Path $WslScripts $Name))) {
        Write-Host "  missing V3 WSL helper: $Name" -ForegroundColor Red
        return
    }
    Start-Process -FilePath "wsl.exe" -ArgumentList @("-e", "bash", "`"$path`"") -WindowStyle Hidden | Out-Null
}

Write-Host ""
Write-Host "=== AegisAI :: starting all local services ===" -ForegroundColor Magenta

# No lab sites or target URLs are bundled with this release. Start your own
# localhost servers and set AEGIS_GATE_*_URL in .env; this launcher only probes
# the URLs you configured.
if (-not (Test-Dns)) {
    Start-WslScript "wsl_run_dns_lab.sh"
    Start-Sleep -Seconds 3
    Start-WslScript "wsl_hosts_fix.sh"
    Write-Host "  started DNS lab (:53 / aegis-lab.local)"
}
if ($ApiPort -and -not (Test-Port $ApiPort)) {
    $backendProc = Start-Process -FilePath $VenvPython -ArgumentList @("-m", "backend.main") `
        -WorkingDirectory $Root -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $LogDir "backend.log") `
        -RedirectStandardError (Join-Path $LogDir "backend.err")
    Write-Host "  started AegisAI at $ApiBase pid=$($backendProc.Id)"
}

# The Telegram bot is a separate long-polling process. Start it detached so it
# survives launcher/window restarts and is available to every evaluator.
# A short pause lets WMI drop processes that were just stopped; otherwise a
# restart could skip starting the bot because a dead PID is still visible.
Start-Sleep -Seconds 2
$botRunning = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Name -like 'python*' -and
        $_.CommandLine -like '*backend.telegram_bot*' -and
        $_.CommandLine -like "*$Root*"
    }).Count -gt 0
if (-not $botRunning) {
    $botProc = Start-Process -FilePath $VenvPython -ArgumentList @("-m", "backend.telegram_bot") `
        -WorkingDirectory $Root -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $LogDir "telegram_bot_live.log") `
        -RedirectStandardError (Join-Path $LogDir "telegram_bot_live.err")
    Write-Host "  started Telegram bot pid=$($botProc.Id)"
}

Write-Host "  waiting for health checks..." -ForegroundColor DarkGray
$ready = $false
for ($i = 0; $i -lt 45; $i++) {
    Start-Sleep -Seconds 2
    if ($backendProc -and $backendProc.HasExited) {
        Write-Host "  AegisAI backend exited early (code $($backendProc.ExitCode))." -ForegroundColor Red
        Get-Content (Join-Path $LogDir "backend.err") -Tail 15 -ErrorAction SilentlyContinue
        break
    }
    $gatesOk = -not @($GateUrls | Where-Object { -not (Test-Http ($_ + "/")) }).Count
    if ((Test-Http "$ApiBase/") -and $gatesOk -and (Test-Dns)) { $ready = $true; break }
}

$gateResults = @($GateUrls | ForEach-Object {
    [pscustomobject]@{ Url = $_; Ok = [bool](Test-Http ($_ + "/")) }
})
$ui = Test-Http "$ApiBase/"
$dns = Test-Dns
$botOk = $botRunning -or ($botProc -and -not $botProc.HasExited)

function Badge([bool]$Ok) { if ($Ok) { "OK" } else { "FAIL" } }

Write-Host ""
Write-Host "  AegisAI UI  : $(Badge $ui)  $ApiBase"
foreach ($gate in $gateResults) {
    Write-Host "  Your target : $(Badge $gate.Ok)  $($gate.Url)"
}
if (-not $gateResults) { Write-Host "  Your targets: NOT CONFIGURED - set AEGIS_GATE_*_URL in .env" -ForegroundColor DarkGray }
Write-Host "  DNS lab     : $(Badge $dns)  aegis-lab.local -> local resolver"
Write-Host "  Telegram    : $(Badge $botOk)  long-polling bot process"
$providerLine = (Get-Content (Join-Path $Root ".env") -ErrorAction SilentlyContinue | Where-Object { $_ -like "AEGIS_MODEL_PROVIDER=*" }) -replace "AEGIS_MODEL_PROVIDER=", ""
if ($providerLine) { Write-Host "  AI provider : $providerLine" }
$envLine = (Get-Content (Join-Path $Root ".env") -ErrorAction SilentlyContinue | Where-Object { $_ -like "AEGIS_GEMINI_MODEL=*" }) -replace "AEGIS_GEMINI_MODEL=", ""
if ($envLine) { Write-Host "  Gemini      : configured ($envLine)" }
Write-Host ""

$gatesReady = -not @($gateResults | Where-Object { -not $_.Ok }).Count
if ($ready -and $ui -and $gatesReady -and $dns -and $botOk) {
    Write-Host "ALL SERVICES READY - no errors." -ForegroundColor Green
} else {
    Write-Host "Some services did not become ready; re-run this script." -ForegroundColor Yellow
}
exit 0
