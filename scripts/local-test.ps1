$ErrorActionPreference = "Stop"

# Requiere: Docker daemon en funcionamiento en el host
# Uso:
#   .\scripts\local-test.ps1
# Opcionales:
#   $env:AI_API_KEY = "tu key"

$prevEap = $ErrorActionPreference
$ErrorActionPreference = "Continue"
docker version 2>&1 | Out-Null
$dockerOk = $LASTEXITCODE -eq 0
$ErrorActionPreference = $prevEap
if (-not $dockerOk) {
  Write-Host "Docker no responde. Arranca Docker Desktop o prueba sin contenedor: node scripts/smoke.js" -ForegroundColor Red
  exit 1
}

Write-Host "Building image..."
docker build -t sv-monitor:test -f Dockerfile .

$aiKey = $env:AI_API_KEY
if (-not $aiKey) { Write-Host "AI_API_KEY no definido; la IA no podrá decidir (fallback a cuarentena por umbrales)." }

$dataDir = Join-Path (Join-Path $PSScriptRoot "..") "data"

$socketMount = "//var/run/docker.sock:/var/run/docker.sock"

Write-Host "Stopping previous container (si existe)..."
$prevEap2 = $ErrorActionPreference
$ErrorActionPreference = "Continue"
docker rm -f sv-monitor-test 2>&1 | Out-Null
$ErrorActionPreference = $prevEap2

$runArgs = @(
  "--name", "sv-monitor-test",
  "-d",
  "-p", "8080:80",
  "-e", "AI_API_KEY=$aiKey",
  "-e", "ADMIN_TOKEN=",
  "-v", "${dataDir}:/app/data"
)

Write-Host "Montando docker socket: $socketMount"
$runArgs += @("-v", $socketMount)

Write-Host "Running container..."
docker run @runArgs sv-monitor:test | Out-Null

Write-Host "Waiting server..."
Start-Sleep -Seconds 3

Write-Host "Checking /api/health..."
$res = Invoke-RestMethod -UseBasicParsing http://localhost:8080/api/health
Write-Host ($res | ConvertTo-Json -Depth 3)

Write-Host "Checking /api/containers (puede tardar si Docker no está accesible)..."
try {
  $c = Invoke-RestMethod -UseBasicParsing http://localhost:8080/api/containers -Headers @{ "Authorization" = "Bearer " }
  Write-Host ("containers=" + ($c.containers | Measure-Object).Count)
} catch {
  Write-Host "No se pudieron consultar contenedores (si Docker no está accesible, es normal)." -ForegroundColor Yellow
}

Write-Host "Panel: http://localhost:8080"

