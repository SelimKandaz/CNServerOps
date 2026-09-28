# CNServerOps

A bootable tool for prepping ASUS servers: hardware identity checks, diagnostics, firmware updates, and evidence collection, all in one guided workflow.

## What it does

- **Intake**: reads hardware identity, inventory, and serials, and generates a report. Read-only, nothing changes.
- **Full production run**: intake plus the diagnostics the platform supports.
- **Firmware update**: resolves the right BIOS/BMC package for the exact model, verifies it, applies it, and proves the version after the update.

It checks the vendor and platform before doing anything. Unknown hardware stays read-only. Nothing destructive runs without a technician picking and confirming it first.

## Status

Validated on ASUS platforms in production use. This public repo is a sanitized reference version; some hardware-specific and deployment details are kept private. See [RELEASE-PROVENANCE.md](RELEASE-PROVENANCE.md).

## Build

Fresh SSD installs are supported through the `installer/` scripts. The installer won't touch the disk you're currently running from, and it always asks for confirmation before doing anything.

## Layout

- `cnserverops/` - runtime, firmware, diagnostics, reporting
- `installer/` - SSD installer and safety checks
- `scripts/` - build and packaging scripts
- `deployment/` - service and launcher templates
- `config/` - configuration templates
- `tests/` - test suite
