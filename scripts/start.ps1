[CmdletBinding()]
param(
    [switch]$Detach
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$envPath = Join-Path $repoRoot ".env"
$templatePath = Join-Path $repoRoot ".env.example"

function New-RandomSecret {
    $bytes = New-Object byte[] 48
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($bytes)
    }
    finally {
        $generator.Dispose()
    }
    return [Convert]::ToBase64String($bytes).TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

if (-not (Test-Path -LiteralPath $envPath)) {
    $content = [IO.File]::ReadAllText($templatePath)
    $content = $content.Replace("REPLACE_WITH_RANDOM_REDIS_PASSWORD", (New-RandomSecret))
    $content = $content.Replace("REPLACE_WITH_RANDOM_NEO4J_PASSWORD", (New-RandomSecret))
    [IO.File]::WriteAllText($envPath, $content, (New-Object Text.UTF8Encoding($false)))
    Write-Host "Created .env with random local datastore credentials."
}

$current = [IO.File]::ReadAllText($envPath)
if ($current.Contains("REPLACE_WITH_RANDOM_")) {
    throw ".env still contains credential placeholders; replace them before startup."
}

Push-Location $repoRoot
try {
    & docker compose run --rm --build --no-deps configcheck
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
    if ($Detach) {
        & docker compose up --build --detach --wait
    }
    else {
        & docker compose up --build
    }
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}
finally {
    Pop-Location
}
