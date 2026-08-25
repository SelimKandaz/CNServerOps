#!/usr/bin/env python3
"""Standalone, read-only ASUS/Linux lab collector.

The script uses an explicit command allowlist, writes nothing on the target, performs
no BMC mutation, and emits one JSON document to stdout. It is designed to be streamed
to ``python3 -`` over SSH so deployment does not leave a remote file behind.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


SCHEMA_VERSION = 1
COLLECTOR_VERSION = "0.3.0-read-only"


def run_command(
    name: str,
    argv: list[str],
    *,
    timeout: int = 30,
    redact: Callable[[str], tuple[str, list[str]]] | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    executable = shutil.which(argv[0])
    if not executable:
        return {
            "name": name,
            "status": "NOT_SUPPORTED",
            "command": argv,
            "returncode": None,
            "stdout": "",
            "stderr": f"{argv[0]} not found",
            "duration_seconds": round(time.monotonic() - started, 3),
            "redacted_fields": [],
        }
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            env={**os.environ, "LC_ALL": "C", "LANG": "C"},
        )
        stdout = completed.stdout
        redacted_fields: list[str] = []
        if redact:
            stdout, redacted_fields = redact(stdout)
        return {
            "name": name,
            "status": "DETECTED" if completed.returncode == 0 else "ERROR",
            "command": argv,
            "returncode": completed.returncode,
            "stdout": stdout,
            "stderr": completed.stderr,
            "duration_seconds": round(time.monotonic() - started, 3),
            "redacted_fields": redacted_fields,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "name": name,
            "status": "TIMEOUT",
            "command": argv,
            "returncode": None,
            "stdout": _decode_timeout_value(exc.stdout),
            "stderr": _decode_timeout_value(exc.stderr),
            "duration_seconds": round(time.monotonic() - started, 3),
            "redacted_fields": [],
        }


def _decode_timeout_value(value: str | bytes | None) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value or ""


def redact_ipmi_lan(text: str) -> tuple[str, list[str]]:
    allowed = {
        "Set in Progress",
        "IP Address Source",
        "IP Address",
        "Subnet Mask",
        "MAC Address",
        "BMC ARP Control",
        "Default Gateway IP",
        "Backup Gateway IP",
        "802.1q VLAN ID",
        "802.1q VLAN Priority",
        "RMCP+ Cipher Suites",
        "Bad Password Threshold",
        "Invalid password disable",
    }
    kept: list[str] = []
    for line in text.splitlines():
        label = line.split(":", 1)[0].strip()
        if label in allowed:
            kept.append(line)
    return "\n".join(kept) + ("\n" if kept else ""), [
        "authentication type settings",
        "SNMP community string",
        "gateway MAC addresses",
        "cipher privilege map",
    ]


def read_dmi() -> dict[str, Any]:
    root = Path("/sys/class/dmi/id")
    fields = (
        "sys_vendor",
        "product_name",
        "product_version",
        "product_serial",
        "product_uuid",
        "board_vendor",
        "board_name",
        "board_version",
        "board_serial",
        "chassis_vendor",
        "chassis_type",
        "chassis_serial",
        "bios_vendor",
        "bios_version",
        "bios_date",
    )
    values: dict[str, Any] = {}
    for field in fields:
        try:
            values[field] = (root / field).read_text(encoding="utf-8", errors="replace").strip()
        except (FileNotFoundError, PermissionError, OSError) as exc:
            values[field] = {"status": "UNAVAILABLE", "error": str(exc)}
    return values


def collect_redfish_unauthenticated(ip: str) -> dict[str, Any]:
    base = f"https://{ip}"
    root = run_command(
        f"redfish_{ip}_service_root",
        ["curl", "-skS", "--connect-timeout", "5", "--max-time", "20", f"{base}/redfish/v1/"],
        timeout=25,
    )
    service: dict[str, Any] = {
        "ip": ip,
        "transport": "HTTPS with lab-only certificate verification disabled",
        "service_root": root,
        "endpoint_status": {},
        "authentication": "NOT_PROVIDED",
    }
    endpoints = (
        "Systems",
        "Managers",
        "Chassis",
        "UpdateService",
        "TaskService",
        "EventService",
        "TelemetryService",
    )
    for endpoint in endpoints:
        result = run_command(
            f"redfish_{ip}_{endpoint}_status",
            [
                "curl",
                "-skS",
                "--connect-timeout",
                "4",
                "--max-time",
                "12",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                f"{base}/redfish/v1/{endpoint}",
            ],
            timeout=16,
        )
        code = result.get("stdout", "").strip()
        if code == "401":
            status = "BLOCKED_BY_AUTH"
        elif code == "404":
            status = "BLOCKED_BY_MISSING_ENDPOINT"
        elif code.startswith("2"):
            status = "DETECTED"
        elif result["status"] in {"TIMEOUT", "ERROR"} or code == "000":
            status = "UNREACHABLE"
        else:
            status = "UNKNOWN"
        service["endpoint_status"][endpoint] = {
            "status": status,
            "http_status": code,
            "probe": result,
        }
    return service


def command_set(include_full_sel: bool) -> list[dict[str, Any]]:
    commands: list[tuple[str, list[str], int, Callable[[str], tuple[str, list[str]]] | None]] = [
        ("os_uname", ["uname", "-a"], 10, None),
        ("os_release", ["cat", "/etc/os-release"], 10, None),
        ("hostnamectl", ["hostnamectl"], 10, None),
        ("mount_root", ["findmnt", "-T", "/", "-J"], 10, None),
        ("mount_efi", ["findmnt", "-T", "/boot/efi", "-J"], 10, None),
        ("cpu", ["lscpu", "--json"], 20, None),
        ("memory_summary", ["free", "-b"], 10, None),
        ("memory_dmi", ["dmidecode", "--type", "17"], 30, None),
        ("block_devices", ["lsblk", "--json", "-e", "7", "-O"], 30, None),
        ("pci", ["lspci", "-Dnnmm"], 30, None),
        ("network_addresses", ["ip", "-j", "address", "show"], 15, None),
        ("network_links", ["ip", "-j", "link", "show"], 15, None),
        ("network_routes", ["ip", "-j", "route", "show"], 15, None),
        ("nvme", ["nvme", "list", "-o", "json"], 30, None),
        ("smart_scan", ["smartctl", "--scan"], 20, None),
        ("nvidia_gpu", ["nvidia-smi", "-q", "-x"], 30, None),
        ("amd_gpu", ["rocm-smi", "--showproductname", "--showtemp", "--showuse", "--showmemuse", "--showpower", "--json"], 30, None),
        ("ipmi_mc", ["ipmitool", "mc", "info"], 20, None),
        ("ipmi_fru", ["ipmitool", "fru", "print"], 30, None),
        ("ipmi_chassis", ["ipmitool", "chassis", "status"], 20, None),
        ("ipmi_channel_1", ["ipmitool", "channel", "info", "1"], 20, None),
        ("ipmi_lan_1", ["ipmitool", "lan", "print", "1"], 20, redact_ipmi_lan),
        ("ipmi_channel_8", ["ipmitool", "channel", "info", "8"], 20, None),
        ("ipmi_lan_8", ["ipmitool", "lan", "print", "8"], 20, redact_ipmi_lan),
        ("ipmi_sel_info", ["ipmitool", "sel", "info"], 20, None),
        ("ipmi_sel_time", ["ipmitool", "sel", "time", "get"], 20, None),
        ("ipmi_sdr", ["ipmitool", "sdr", "elist", "all"], 60, None),
        ("ipmi_sensors", ["ipmitool", "sensor", "list"], 60, None),
        (
            "cngpu_active_units",
            [
                "systemctl",
                "show",
                "cngpu-countdown-menu.service",
                "cngpu-result-vault.timer",
                "instsvcdrv.service",
                "cngpu-boot-autostart.service",
                "cngpu-r640-zero-touch.service",
                "cngpu-update.service",
                "cngpu-r640-nextboot-full-auto.service",
                "--property=Id,LoadState,ActiveState,SubState,UnitFileState,MainPID,ExecMainStatus",
                "--no-pager",
            ],
            20,
            None,
        ),
    ]
    if include_full_sel:
        commands.append(("ipmi_sel_entries", ["ipmitool", "sel", "elist"], 120, None))
    results = [run_command(name, argv, timeout=timeout, redact=redactor) for name, argv, timeout, redactor in commands]

    for interface in sorted(Path("/sys/class/net").glob("*")):
        name = interface.name
        if name == "lo":
            continue
        results.append(run_command(f"ethtool_driver_{name}", ["ethtool", "-i", name], timeout=15))
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bmc-ip", action="append", default=[])
    parser.add_argument("--include-full-sel", action="store_true")
    args = parser.parse_args()

    document = {
        "schema_version": SCHEMA_VERSION,
        "collector_version": COLLECTOR_VERSION,
        "collected_at_utc": datetime.now(timezone.utc).isoformat(),
        "runtime": {
            "python": platform.python_version(),
            "hostname_observed_not_identity": platform.node(),
        },
        "safety": {
            "mode": "READ_ONLY",
            "remote_files_written": False,
            "methods": ["local sysfs reads", "allowlisted read-only commands", "unauthenticated HTTPS GET"],
            "prohibited_actions_implemented": [],
            "credentials_collected": False,
        },
        "dmi": read_dmi(),
        "tool_availability": {
            name: shutil.which(name) or "NOT_FOUND"
            for name in (
                "python3",
                "dmidecode",
                "ipmitool",
                "curl",
                "lscpu",
                "lspci",
                "lsblk",
                "ethtool",
                "stress-ng",
                "smartctl",
                "nvme",
                "nvidia-smi",
                "rocm-smi",
                "storcli",
                "perccli",
            )
        },
        "ipmi_device": {
            "path": "/dev/ipmi0",
            "present": Path("/dev/ipmi0").exists(),
        },
        "commands": command_set(args.include_full_sel),
        "redfish_unauthenticated": [collect_redfish_unauthenticated(ip) for ip in args.bmc_ip],
    }
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
