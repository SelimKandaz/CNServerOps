[CmdletBinding()]
param([string]$CentralRoot = 'C:\CNServerOps\Central')
$ErrorActionPreference = 'Stop'
$pidPath = Join-Path $CentralRoot 'run\central.pid'
if (-not (Test-Path -LiteralPath $pidPath)) {
    [pscustomobject]@{ status = 'NOT_RUNNING' }
    return
}
$centralPid = [int](Get-Content -LiteralPath $pidPath -Raw)
$processInfo = Get-CimInstance Win32_Process -Filter "ProcessId=$centralPid" -ErrorAction SilentlyContinue
if ($processInfo) {
    if ($processInfo.CommandLine -notmatch 'cnserverops\.central_server' -or $processInfo.CommandLine -notmatch [regex]::Escape($CentralRoot)) {
        throw 'PID file points to a process that is not this Central Collector; refusing to stop it.'
    }
    Stop-Process -Id $centralPid -ErrorAction Stop
    Wait-Process -Id $centralPid -Timeout 15 -ErrorAction SilentlyContinue
}
Remove-Item -LiteralPath $pidPath -Force
[pscustomobject]@{ status = 'STOPPED'; pid = $centralPid }
