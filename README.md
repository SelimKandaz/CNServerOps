# CNServerOps

CNServerOps is a bootable, technician-facing ASUS server intake, firmware, diagnostics, evidence, and handoff system. It keeps physical identity and capability decisions local to the current server and uses Central as the authoritative event/artifact synchronization service.

## Technician workflows

- **Option 1 — Fleet Intake / Serial + Log Collection:** read-only identity, inventory, NIC serials, SEL preservation, reports, Central delivery, and archive delivery.
- **Option 2 — Full Production + Extended Diagnostics:** the production lifecycle plus vendor diagnostics when the detected platform exposes it.
- **Option 5 — Firmware Update & Verification:** exact-model BIOS/BMC resolution, package verification, capability-selected transport, durable task/reboot resume, after-version proof, and handoff gating.

Vendor-first detection keeps unknown systems inventory-only and prevents a Dell workflow from running on ASUS. No destructive action starts at boot; the technician explicitly selects and confirms a workflow.

## Validated ASUS platform contracts

| Platform | Board | Management | Validated paths |
| --- | --- | --- | --- |
| RS500A-E12-RS12U | K14PA-U24 | ASMB11 | local KCS/YAFU BMC update; exact `.CAP` BIOS package routed to supported Redfish BIOS OOB; KCS recovery/handoff |
| RS700-E12-RS12U | Z14PP-D32 | ASMB12 | authenticated Redfish multipart BIOS/BMC transport; task tracking, reboot/resume, and factory handoff contracts |

Shared lifecycle logic lives in `cnserverops/firmware_lifecycle.py` and `cnserverops/production.py`. Generation, board, model, package-format, and transport differences stay in ASUS descriptors and adapters. The platform matrix is a mandatory release gate.

## Identity, safety, and credentials

Identity is fused from current-boot DMI/SMBIOS, sysfs, FRU/KCS/IPMI, and Redfish evidence with provenance, freshness, and confidence. `SERVER_ID`, `RUN_ID`, `RUNNER_ID`, and Linux `BOOT_ID` are separate. A cloned SSD receives a new runner identity and cannot resume a foreign server’s pending run.

BMC authentication is capability-specific. Recovery is generation-gated, bounded, and never password-sprays. Operational credentials are server-bound and removed by the official ASUS factory/default handoff when CNServerOps changed authentication. Secrets are excluded from reports, logs, Central events, and command arguments where avoidable.

## Fresh SSD build (no live-SSD cloning)

Installer sources are in `installer/`; image/bundle builders are in `scripts/` and `deployment/`. Build from Ubuntu 22.04/24.04 or Debian 12 using a versioned immutable runtime package:

```bash
python3 installer/build_ssd_installer_bundle.py --runtime-package dist/cnserverops-runtime-<VERSION>.tar.gz --output dist/cnserverops-ssd-installer-<VERSION>.tar.gz
sudo ./installer/cnserverops-ssd-setup.sh --check
sudo ./installer/cnserverops-ssd-setup.sh
```

The installer requires explicit target selection and confirmation, refuses the running system disk or an ambiguous/in-use disk, creates GPT/EFI/Linux filesystems, installs the verified runtime and systemd units, and runs post-install preflight. It uses generic DHCP networking and initializes clone/first-boot state; mutable production state, reports, caches, credentials, machine IDs, and pending firmware markers are not copied. `--check` is non-destructive.

## Releases and validation

Source changes must pass the full test suite and ASUS platform matrix before packaging. `scripts/build_runtime_package.py` verifies the closed tarball, member hashes, manifest, and embedded version. `cnserverops/runtime_preflight.py` validates staged and installed releases, including systemd unit parity and secret-file permissions. Golden releases are rollback targets; candidate releases are not production until package parity and platform gates pass.

Current validated production release:

- Runtime family: `3.8.x` (exact production release is selected from the verified immutable bundle)
- Runtime and rollback hashes: recorded in the private release manifest, not in this public documentation
- Central: configured per deployment; no operational endpoint is embedded in this public repository

The installer bundle and runtime tarball are generated artifacts and intentionally excluded from Git. Historical reports, firmware caches, rootfs/images, generated bundles, and live machine state remain outside this repository.

## Repository layout

- `cnserverops/` — runtime, orchestration, identity, firmware, BMC, diagnostics, reports, Central sync, and readiness policy
- `tests/` — unit, integration, installer, platform-matrix, and RS500/RS700 golden regression contracts
- `installer/` — destructive-disk safety checks and offline installer bundle sources
- `scripts/` — package, image, ISO, manifest, and test builders
- `deployment/` — Linux launcher/systemd and Windows Central deployment templates
- `config/` — secret-free configuration templates and schemas
- `cndellops_asus/` — retained vendor/reference adapter source

Generated packages and images are built from these sources in CI or a controlled Linux build host; they are not committed as normal Git objects.
