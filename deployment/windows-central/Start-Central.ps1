[CmdletBinding()]
param([string]$CentralRoot = 'C:\CNServerOps\Central')
$ErrorActionPreference = 'Stop'
$config = Get-Content -LiteralPath (Join-Path $CentralRoot 'config\central.json') -Raw | ConvertFrom-Json
$pidPath = Join-Path $CentralRoot 'run\central.pid'
if (Test-Path -LiteralPath $pidPath) {
    $oldPid = [int](Get-Content -LiteralPath $pidPath -Raw)
    $old = Get-Process -Id $oldPid -ErrorAction SilentlyContinue
    if ($old) {
        [pscustomobject]@{ status = 'ALREADY_RUNNING'; pid = $oldPid; endpoint = $config.endpoint }
        return
    }
    Remove-Item -LiteralPath $pidPath -Force
}
$credential = Import-Clixml -LiteralPath $config.token_secret
$token = $credential.GetNetworkCredential().Password
$previousToken = $env:CNSERVEROPS_CENTRAL_TOKEN
$previousPythonPath = $env:PYTHONPATH
$env:CNSERVEROPS_CENTRAL_TOKEN = $token
$env:PYTHONPATH = (Join-Path $CentralRoot 'app')
$stdout = Join-Path $CentralRoot 'logs\central.stdout.log'
$stderr = Join-Path $CentralRoot 'logs\central.stderr.log'
$fleetArchive = [string]$config.fleet_archive_root
if ([string]::IsNullOrWhiteSpace($fleetArchive)) {
    $fleetArchive = 'C:\Users\TechTrade Operations\Desktop\ASUS Server LOGS'
}
$secondaryArchive = [string]$config.secondary_archive_root
if ([string]::IsNullOrWhiteSpace($secondaryArchive)) {
    $secondaryArchive = '\\10.1.10.12\public\Operations\Selim Programs'
}
$supportsSkipCertificateCheck = (Get-Command Invoke-RestMethod).Parameters.ContainsKey('SkipCertificateCheck')
$arguments = @(
    '-m','cnserverops.central_server','serve','--root',$CentralRoot,
    '--bind',[string]$config.bind,'--port',[string]$config.port,
    '--cert',[string]$config.certificate,'--key',[string]$config.private_key,
    '--fleet-archive-root',('"' + $fleetArchive + '"'),
    '--secondary-archive-root',('"' + $secondaryArchive + '"')
)
try {
    $process = Start-Process -FilePath $config.python_path -ArgumentList $arguments -WorkingDirectory (Join-Path $CentralRoot 'app') -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
} finally {
    if ($null -eq $previousToken) { Remove-Item Env:CNSERVEROPS_CENTRAL_TOKEN -ErrorAction SilentlyContinue } else { $env:CNSERVEROPS_CENTRAL_TOKEN = $previousToken }
    if ($null -eq $previousPythonPath) { Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue } else { $env:PYTHONPATH = $previousPythonPath }
    $token = $null
}
$process.Id | Set-Content -LiteralPath $pidPath -Encoding ascii
$deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        try {
            if ($supportsSkipCertificateCheck) {
                $health = Invoke-RestMethod -Uri ($config.endpoint + '/healthz') -SkipCertificateCheck -TimeoutSec 2
            } else {
                $previousCertificateCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
                try {
                    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
                    $health = Invoke-RestMethod -Uri ($config.endpoint + '/healthz') -TimeoutSec 2
                } finally {
                    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $previousCertificateCallback
                }
            }
        if ($health.status -eq 'OK') {
            [pscustomobject]@{ status = 'RUNNING'; pid = $process.Id; endpoint = $config.endpoint; tls = $true }
            return
        }
    } catch {
        Start-Sleep -Milliseconds 500
    }
} while ([DateTime]::UtcNow -lt $deadline -and -not $process.HasExited)
throw "Central Collector failed health check. Inspect $stderr"
