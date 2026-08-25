[CmdletBinding()]
param([string]$CentralRoot = 'C:\CNServerOps\Central')
$ErrorActionPreference = 'Stop'
$config = Get-Content -LiteralPath (Join-Path $CentralRoot 'config\central.json') -Raw | ConvertFrom-Json
$stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$destinationRoot = Join-Path $CentralRoot "backup\$stamp"
New-Item -ItemType Directory -Path $destinationRoot -Force | Out-Null
$env:PYTHONPATH = Join-Path $CentralRoot 'app'
try {
    & $config.python_path -m cnserverops.central_server backup --database $config.database --destination (Join-Path $destinationRoot 'central.sqlite3') | Out-Null
} finally {
    Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
}
Copy-Item -LiteralPath (Join-Path $CentralRoot 'config\central.json') -Destination $destinationRoot
Copy-Item -LiteralPath $config.certificate -Destination $destinationRoot
Copy-Item -LiteralPath (Join-Path $CentralRoot 'exports\ASUS_PRODUCTION_MASTER.csv') -Destination $destinationRoot -ErrorAction SilentlyContinue
[pscustomobject]@{ status = 'BACKED_UP'; destination = $destinationRoot; secrets_included = $false }
