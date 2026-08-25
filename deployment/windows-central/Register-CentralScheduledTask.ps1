[CmdletBinding()]
param(
    [string]$CentralRoot = 'C:\CNServerOps\Central',
    [string]$TaskName = 'CNServerOps Central Collector'
)
$ErrorActionPreference = 'Stop'
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$credential = Get-Credential -UserName $identity -Message 'Enter the password for the same Windows account that owns the DPAPI Central secret.'
if ($credential.UserName -ne $identity) {
    throw "Scheduled task must use the DPAPI secret owner: $identity"
}
$script = Join-Path $CentralRoot 'scripts\Start-Central.ps1'
$argument = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$script`" -CentralRoot `"$CentralRoot`""
$action = New-ScheduledTaskAction -Execute (Get-Command pwsh -ErrorAction Stop).Source -Argument $argument
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
$principal = New-ScheduledTaskPrincipal -UserId $identity -LogonType Password -RunLevel Highest
$task = New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description 'Authenticated TLS CNServerOps Central Collector'
$plain = $credential.GetNetworkCredential().Password
try {
    Register-ScheduledTask -TaskName $TaskName -InputObject $task -User $identity -Password $plain -Force | Out-Null
} finally {
    $plain = $null
}
[pscustomobject]@{ status = 'REGISTERED'; task_name = $TaskName; account = $identity; central_root = $CentralRoot }
