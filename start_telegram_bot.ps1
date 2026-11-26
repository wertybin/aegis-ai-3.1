$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) { $python = "python" }

Write-Host "AEGIS AI V3 - Telegram bot (your AEGIS_API_BASE from .env)"
Write-Host "Token comes from .env only. Ctrl+C to stop."
& $python -m backend.telegram_bot
