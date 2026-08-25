[CmdletBinding()]
param(
    [string]$CentralRoot = 'C:\CNServerOps\Central',
    [string]$ListenAddress = '0.0.0.0',
    [string]$AdvertiseAddress = '10.1.10.51',
    [int]$Port = 8088,
    [switch]$Start
)
$ErrorActionPreference = 'Stop'
if ($Port -lt 1 -or $Port -gt 65535) { throw 'Port must be in range 1..65535.' }
$frameworkRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$configPath = Join-Path $CentralRoot 'config\central.json'
$existingConfig = $null
if (Test-Path -LiteralPath $configPath) {
    $existingConfig = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
}
$python = [string]$existingConfig.python_path
if ([string]::IsNullOrWhiteSpace($python) -or -not (Test-Path -LiteralPath $python)) {
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCommand) {
        $pythonCommand = Get-Command py -ErrorAction SilentlyContinue
    }
    if (-not $pythonCommand) { throw 'Python runtime not found. Set config\central.json python_path.' }
    $python = $pythonCommand.Source
}
foreach ($name in @('app','data','exports','logs','run','backup','config','scripts','secrets','tls','firmware')) {
    New-Item -ItemType Directory -Path (Join-Path $CentralRoot $name) -Force | Out-Null
}
$appRoot = Join-Path $CentralRoot 'app'
$destinationPackage = Join-Path $appRoot 'cnserverops'
if (Test-Path -LiteralPath $destinationPackage) {
    Copy-Item -Path (Join-Path $frameworkRoot 'cnserverops\*') -Destination $destinationPackage -Recurse -Force
} else {
    Copy-Item -LiteralPath (Join-Path $frameworkRoot 'cnserverops') -Destination $destinationPackage -Recurse
}
Copy-Item -Path (Join-Path $PSScriptRoot '*.ps1') -Destination (Join-Path $CentralRoot 'scripts') -Force
if (-not (Test-Path -LiteralPath $configPath)) {
    $config = [ordered]@{
        schema_version = 1
        central_root = $CentralRoot
        python_path = $python
        bind = $ListenAddress
        advertise_address = $AdvertiseAddress
        port = $Port
        endpoint = "https://${AdvertiseAddress}:$Port"
        database = (Join-Path $CentralRoot 'data\central.sqlite3')
        certificate = (Join-Path $CentralRoot 'tls\central-cert.pem')
        private_key = (Join-Path $CentralRoot 'tls\central-key.pem')
        token_secret = (Join-Path $CentralRoot 'secrets\central-api-token.clixml')
        csv_export = (Join-Path $CentralRoot 'exports\ASUS_PRODUCTION_MASTER.csv')
        fleet_archive_root = 'C:\Users\TechTrade Operations\Desktop\ASUS Server LOGS'
    }
    $config | ConvertTo-Json | Set-Content -LiteralPath $configPath -Encoding utf8
}
$tlsCert = Join-Path $CentralRoot 'tls\central-cert.pem'
if (-not (Test-Path -LiteralPath $tlsCert)) {
    & (Join-Path $PSScriptRoot 'New-CentralTlsCertificate.ps1') -CentralRoot $CentralRoot -IpAddress $AdvertiseAddress | Out-Null
}
& (Join-Path $PSScriptRoot 'Initialize-CentralSecret.ps1') -CentralRoot $CentralRoot | Out-Null
$env:PYTHONPATH = $appRoot
try {
    & $python -m cnserverops.cli central-init --database (Join-Path $CentralRoot 'data\central.sqlite3') | Out-Null
    & $python -m cnserverops.central_server export --database (Join-Path $CentralRoot 'data\central.sqlite3') --destination (Join-Path $CentralRoot 'exports\ASUS_PRODUCTION_MASTER.csv') | Out-Null
} finally {
    Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
}
if ($Start) {
    & (Join-Path $CentralRoot 'scripts\Start-Central.ps1') -CentralRoot $CentralRoot
} else {
    [pscustomobject]@{ status = 'INSTALLED'; root = $CentralRoot; endpoint = "https://${AdvertiseAddress}:$Port"; started = $false }
}
