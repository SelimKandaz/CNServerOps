# Linux clone-firstboot deployment

Install `cnserverops-clone-firstboot.service` only on a reviewed golden image, point `/opt/cnserverops/current` at an approved immutable runtime, and enable the unit. It is inert unless `/etc/cnserverops/clone-template.json` exists.

Preparing the golden image is intentionally separate and requires an explicit acknowledgement:

```bash
PYTHONPATH=/opt/cnserverops/current python3 -m cnserverops.clone_firstboot \
  prepare-template --root / --template-id GOLDEN-YYYYMMDD \
  --i-understand-this-is-the-golden-image
```

Preparation moves any existing runner identity and stale transaction receipt into a reversible template quarantine. The first clone boot generates a unique RUNNER_ID, local UUID, machine-id, and SSH host keys; binds the runner to a hardware storage fingerprint; and quarantines stale run/upload state. Subsequent boots retain the same identity. Hostname is never used as RUNNER_ID or SERVER_ID.

## Physical production console

`cnserverops-console.service` owns tty1 and renders the vendor-first operator menu. It performs DMI/platform detection before it exposes an ASUS or exact Dell R640 production option. Merely starting the unit performs no workload, log cleanup, firmware, reset, or power action. ASUS production requires the technician to select the option and type `RUN`.

Install from the active immutable release:

```bash
sudo /opt/cnserverops/current/deployment/linux/install-production-launcher.sh \
  --disable-smartd --start
```

`--disable-smartd` is appropriate when `smartmontools.service` exits 17 because the boot USB bridge exposes no monitorable device. This does not remove `smartctl`; CNServerOps continues to invoke `/usr/sbin/smartctl` on demand.

The installer preserves the legacy Dell files, records pre-install service enablement in `/var/lib/cnserverops/launcher-install-state.json`, and installs `/usr/local/sbin/cnserverops-launcher-rollback`. The rollback helper disables the CNServerOps console and restores tty1 login without changing the immutable runtime pointer.
