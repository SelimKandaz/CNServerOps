[CmdletBinding()]
param(
    [string]$CentralRoot = 'C:\CNServerOps\Central',
    [switch]$Apply
)
$ErrorActionPreference = 'Stop'
$config = Get-Content -LiteralPath (Join-Path $CentralRoot 'config\central.json') -Raw | ConvertFrom-Json
$name = "CNServerOps Central TCP $($config.port)"
$existing = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
if ($existing) {
    $portFilter = $existing | Get-NetFirewallPortFilter
    if ($portFilter.Protocol -ne 'TCP' -or [string]$portFilter.LocalPort -ne [string]$config.port) {
        throw 'Existing named firewall rule does not match the configured TCP port.'
    }
    [pscustomobject]@{ status = 'PRESENT'; display_name = $name; port = $config.port; remote_address = '10.1.10.0/24' }
    return
}
if (-not $Apply) {
    [pscustomobject]@{ status = 'REQUIRED'; display_name = $name; port = $config.port; remote_address = '10.1.10.0/24'; apply_switch = '-Apply' }
    return
}
New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Allow -Protocol TCP -LocalPort $config.port -RemoteAddress '10.1.10.0/24' -Profile Private | Out-Null
[pscustomobject]@{ status = 'CREATED'; display_name = $name; port = $config.port; remote_address = '10.1.10.0/24' }
