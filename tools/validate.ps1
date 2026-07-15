$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $Root

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    throw "Node.js no está disponible en PATH. Instala Node.js LTS y abre una terminal nueva."
}

Write-Host "Validando Genesis Ultra desde: $Root"
npm test
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host "Validación terminada correctamente."
