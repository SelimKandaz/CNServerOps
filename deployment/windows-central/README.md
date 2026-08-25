# CNServerOps Central Collector — Windows deployment

This package deploys the initial authenticated TLS collector to `C:\CNServerOps\Central` without hard-coding the endpoint in runner code. The default endpoint is `https://10.1.10.51:8088` and is stored in `config\central.json`.

Run PowerShell as the intended long-lived service account:

```powershell
.\Install-Central.ps1 -Start
.\Set-CentralFirewall.ps1 -Apply
.\Get-CentralHealth.ps1
```

The generated API token is protected with Windows DPAPI for the installing account. It is never written to the configuration, logs, exports, or command line. The generated TLS private key is ACL-restricted. Runners must pin/trust `tls\central-cert.pem`; disabling TLS validation is not a production setting.

Lifecycle and backup commands:

```powershell
C:\CNServerOps\Central\scripts\Stop-Central.ps1
C:\CNServerOps\Central\scripts\Restart-Central.ps1
C:\CNServerOps\Central\scripts\Backup-Central.ps1
```

Optional automatic startup under the same DPAPI-owning Windows account:

```powershell
C:\CNServerOps\Central\scripts\Register-CentralScheduledTask.ps1
```

The registration command prompts at runtime for that Windows account password and does not persist it in project files. It requires an elevated PowerShell session under the deployment policy used by Operations.

`data\central.sqlite3` is authoritative for this initial deployment. `exports\ASUS_PRODUCTION_MASTER.csv` is regenerated after accepted events and is operational output only. The backup script uses SQLite's online backup API and deliberately excludes token/private-key secrets.

For a different Windows service wrapper, run `Start-Central.ps1` under a restricted service account. The DPAPI secret must be created and read by that same account.
