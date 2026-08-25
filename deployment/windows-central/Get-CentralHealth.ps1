[CmdletBinding()]
param([string]$CentralRoot = 'C:\CNServerOps\Central')
$ErrorActionPreference = 'Stop'
$config = Get-Content -LiteralPath (Join-Path $CentralRoot 'config\central.json') -Raw | ConvertFrom-Json
$supportsSkipCertificateCheck = (Get-Command Invoke-RestMethod).Parameters.ContainsKey('SkipCertificateCheck')
if ($supportsSkipCertificateCheck) {
    $health = Invoke-RestMethod -Uri ($config.endpoint + '/healthz') -SkipCertificateCheck -TimeoutSec 5
} else {
    $previousCertificateCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
    try {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        $health = Invoke-RestMethod -Uri ($config.endpoint + '/healthz') -TimeoutSec 5
    } finally {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $previousCertificateCallback
    }
}
[pscustomobject]@{ status = $health.status; endpoint = $config.endpoint; checked_at_utc = [DateTime]::UtcNow.ToString('o') }
