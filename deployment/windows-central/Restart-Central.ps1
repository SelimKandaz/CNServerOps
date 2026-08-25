[CmdletBinding()]
param([string]$CentralRoot = 'C:\CNServerOps\Central')
$ErrorActionPreference = 'Stop'
& (Join-Path $CentralRoot 'scripts\Stop-Central.ps1') -CentralRoot $CentralRoot | Out-Null
& (Join-Path $CentralRoot 'scripts\Start-Central.ps1') -CentralRoot $CentralRoot
