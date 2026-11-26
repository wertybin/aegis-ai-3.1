$ErrorActionPreference = 'Stop'
$projectRoot = $PSScriptRoot
$runtime = Join-Path $projectRoot 'runtime\ollama\ollama.exe'
$modelDir = Join-Path $projectRoot 'runtime\ollama-models'
$logDir = Join-Path $projectRoot 'logs'
if (-not (Test-Path -LiteralPath $runtime)) { throw "Portable Ollama executable not found: $runtime" }
$signature = Get-AuthenticodeSignature -LiteralPath $runtime
if ($signature.Status -ne 'Valid') { throw 'The Ollama executable signature is not valid.' }
$ollamaLine = Get-Content (Join-Path $projectRoot '.env') -ErrorAction SilentlyContinue |
    Where-Object { $_ -like 'AEGIS_OLLAMA_URL=*' } | Select-Object -First 1
$ollamaBase = ($ollamaLine -replace 'AEGIS_OLLAMA_URL=', '').Trim().Trim('"')
if (-not $ollamaBase) { throw 'Set AEGIS_OLLAMA_URL in .env to your local Ollama URL first.' }
$ollamaUri = [Uri]$ollamaBase
$env:OLLAMA_HOST = "$($ollamaUri.Host):$($ollamaUri.Port)"
$env:OLLAMA_MODELS = $modelDir
$env:OLLAMA_NO_CLOUD = '1'
New-Item -ItemType Directory -Force -Path $modelDir,$logDir | Out-Null
try {
    Invoke-RestMethod ($ollamaBase.TrimEnd('/') + '/api/version') -TimeoutSec 2 | Out-Null
} catch {
    $server = Start-Process -FilePath $runtime -ArgumentList 'serve' -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $logDir 'ollama-server.log') `
        -RedirectStandardError (Join-Path $logDir 'ollama-server.err')
}
$ready = $false
for ($attempt = 0; $attempt -lt 20; $attempt++) {
    try {
        Invoke-RestMethod ($ollamaBase.TrimEnd('/') + '/api/version') -TimeoutSec 2 | Out-Null
        $ready = $true
        break
    } catch { Start-Sleep -Seconds 1 }
}
if (-not $ready) { throw 'Ollama did not start. See logs\ollama-server.err.' }
Write-Host 'Downloading Qwen 2.5 14B (approximately 9 GB)...' -ForegroundColor Cyan
& $runtime pull qwen2.5:14b
if ($LASTEXITCODE -ne 0) { throw 'Model download failed. Re-run this script to resume.' }
& $runtime list
Write-Host 'Ollama and Qwen 2.5 14B are ready. Start AEGIS with START_ALL.cmd.' -ForegroundColor Green
