#!/usr/bin/env python3
"""Convert raw read-only collector output into comparable lab evidence and capabilities."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cnserverops.asus import AsusBmcFingerprint, select_asus_profile
from cnserverops.identity import derive_machine_identity
from cnserverops.platform import PlatformProbe, detect_platform


def command_map(raw: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(item["name"]): item for item in raw.get("commands", [])}


def colon_lines(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        result[key.strip()] = value.strip()
    return result


def parse_cpu(text: str) -> dict[str, str]:
    try:
        rows = json.loads(text).get("lscpu", [])
    except json.JSONDecodeError:
        return {}
    wanted = {
        "Architecture:",
        "CPU(s):",
        "Vendor ID:",
        "Model name:",
        "Socket(s):",
        "Core(s) per socket:",
        "Thread(s) per core:",
        "NUMA node(s):",
        "L3 cache:",
    }
    return {row.get("field", "").rstrip(":").lower().replace(" ", "_"): row.get("data", "") for row in rows if row.get("field") in wanted}


def parse_memory(text: str) -> dict[str, Any]:
    devices: list[dict[str, str]] = []
    for block in re.split(r"(?m)^Memory Device\r?\n", text):
        fields = colon_lines(block)
        size = fields.get("Size", "")
        if not size or size == "No Module Installed":
            continue
        devices.append(
            {
                "locator": fields.get("Locator", ""),
                "size": size,
                "manufacturer": fields.get("Manufacturer", ""),
                "part_number": fields.get("Part Number", ""),
                "serial_number": fields.get("Serial Number", ""),
                "configured_speed": fields.get("Configured Memory Speed", ""),
            }
        )
    return {"installed_dimm_count": len(devices), "devices": devices}


def parse_pci(text: str) -> dict[str, list[str]]:
    lines = [line for line in text.splitlines() if line.strip()]
    classes = {
        "ethernet": "Ethernet controller",
        "gpu_vga": "VGA compatible controller",
        "gpu_3d": "3D controller",
        "nvme": "Non-Volatile memory controller",
        "raid": "RAID bus controller",
        "sas": "Serial Attached SCSI controller",
        "sata": "SATA controller",
    }
    result = {key: [line for line in lines if marker in line] for key, marker in classes.items()}
    result["all_function_count"] = [str(len(lines))]
    return result


def parse_sdr(text: str) -> dict[str, Any]:
    rows: list[dict[str, str]] = []
    for line in text.splitlines():
        parts = [part.strip() for part in line.split("|")]
        if len(parts) >= 5:
            rows.append({"sensor": parts[0], "status": parts[2], "entity": parts[3], "reading": parts[4]})
    status_counts: dict[str, int] = {}
    for row in rows:
        status_counts[row["status"]] = status_counts.get(row["status"], 0) + 1
    return {
        "row_count": len(rows),
        "status_counts": status_counts,
        "non_ok_or_unavailable": [row for row in rows if row["status"] not in {"ok", "ns"}],
        "fans": [row for row in rows if "FAN" in row["sensor"].upper()],
        "power": [row for row in rows if re.search(r"PSU|POWER", row["sensor"], re.I)],
        "temperatures": [row for row in rows if re.search(r"TEMP|TEMPERATURE", row["sensor"], re.I) and row["status"] == "ok"],
    }


def redfish_summary(raw: dict[str, Any]) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for item in raw.get("redfish_unauthenticated", []):
        root_command = item.get("service_root", {})
        root_payload: dict[str, Any] = {}
        try:
            root_payload = json.loads(root_command.get("stdout", ""))
        except json.JSONDecodeError:
            pass
        summaries.append(
            {
                "ip": item.get("ip", ""),
                "service_root_status": "LAB_VERIFIED" if root_payload else "UNREACHABLE",
                "redfish_version": root_payload.get("RedfishVersion", ""),
                "vendor": root_payload.get("Vendor", ""),
                "product": root_payload.get("Product", ""),
                "oem_ami_runtime": root_payload.get("Oem", {}).get("Ami", {}).get("RtpVersion", ""),
                "uuid": root_payload.get("UUID", ""),
                "endpoint_status": {
                    name: {
                        "status": value.get("status", "UNKNOWN"),
                        "http_status": value.get("http_status", ""),
                    }
                    for name, value in item.get("endpoint_status", {}).items()
                },
            }
        )
    return summaries


def capability(name: str, status: str, mechanism: str, evidence: str, result: Any, fallback: str, safe: bool) -> dict[str, Any]:
    return {
        "capability": name,
        "status": status,
        "mechanism": mechanism,
        "raw_evidence": evidence,
        "normalized_result": result,
        "fallback": fallback,
        "safe_for_production": safe,
    }


def build(raw: dict[str, Any], network_observations: dict[str, Any] | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    commands = command_map(raw)
    dmi = raw.get("dmi", {})
    probe = PlatformProbe.from_mapping(dmi)
    platform_decision = detect_platform(probe)
    fru_fields = colon_lines(commands.get("ipmi_fru", {}).get("stdout", ""))
    mc_fields = colon_lines(commands.get("ipmi_mc", {}).get("stdout", ""))
    identity = derive_machine_identity(
        platform_decision,
        probe,
        chassis_fru={
            "FruInfo": {
                "Product": {
                    "ProductManufacturer": fru_fields.get("Product Manufacturer", ""),
                    "ProductName": fru_fields.get("Product Name", ""),
                    "ProductSerial": fru_fields.get("Product Serial", ""),
                },
                "Board": {"BoardSerial": fru_fields.get("Board Serial", "")},
                "Chassis": {"ChassisSerial": fru_fields.get("Chassis Serial", "")},
            }
        },
        manager={"FirmwareVersion": mc_fields.get("Firmware Revision", "")},
    )
    consistency = {
        "product_name": {"dmi": probe.product_name, "fru": fru_fields.get("Product Name", "")},
        "system_serial": {"dmi": probe.system_serial, "fru": fru_fields.get("Product Serial", "")},
        "board_name": {"dmi": dmi.get("board_name", ""), "fru": fru_fields.get("Board Product", "")},
        "board_serial": {"dmi": probe.board_serial, "fru": fru_fields.get("Board Serial", "")},
        "chassis_serial": {"dmi": probe.chassis_serial, "fru": fru_fields.get("Chassis Serial", "")},
    }
    for values in consistency.values():
        values["match"] = bool(values["dmi"] and values["fru"] and values["dmi"].casefold() == values["fru"].casefold())
    consistency["all_available_sources_match"] = all(item.get("match", False) for item in consistency.values() if isinstance(item, dict))

    redfish = redfish_summary(raw)
    primary_redfish = next((item for item in redfish if item["service_root_status"] == "LAB_VERIFIED"), {})
    fingerprint = AsusBmcFingerprint(
        manufacturer_id=mc_fields.get("Manufacturer ID", ""),
        product_id=mc_fields.get("Product ID", ""),
        firmware_version=mc_fields.get("Firmware Revision", ""),
        redfish_version=primary_redfish.get("redfish_version", ""),
        redfish_vendor=primary_redfish.get("vendor", ""),
        redfish_product=primary_redfish.get("product", ""),
        redfish_oem_runtime=primary_redfish.get("oem_ami_runtime", ""),
    )
    asus_profile = select_asus_profile(fingerprint, documented_generation_hint="ASMB11")

    sel_entries = commands.get("ipmi_sel_entries", {}).get("stdout", "").splitlines()
    sdr = parse_sdr(commands.get("ipmi_sdr", {}).get("stdout", ""))
    hardware = {
        "cpu": parse_cpu(commands.get("cpu", {}).get("stdout", "")),
        "memory": parse_memory(commands.get("memory_dmi", {}).get("stdout", "")),
        "pci": parse_pci(commands.get("pci", {}).get("stdout", "")),
        "sensors": sdr,
        "block_devices_raw": commands.get("block_devices", {}).get("stdout", ""),
        "network_addresses_raw": commands.get("network_addresses", {}).get("stdout", ""),
        "tool_status": {
            name: commands.get(name, {}).get("status", "UNKNOWN")
            for name in ("nvme", "smart_scan", "nvidia_gpu", "amd_gpu")
        },
    }
    summary = {
        "schema_version": 1,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_collected_at_utc": raw.get("collected_at_utc", ""),
        "physical_lab_system": True,
        "platform": platform_decision,
        "identity": identity,
        "identity_consistency": consistency,
        "bmc": {
            "ipmi_mc": mc_fields,
            "generation_profile": asus_profile,
            "redfish": redfish,
            "lan_channel_1": colon_lines(commands.get("ipmi_lan_1", {}).get("stdout", "")),
            "lan_channel_8": colon_lines(commands.get("ipmi_lan_8", {}).get("stdout", "")),
            "channel_role_status": "INFERRED_NOT_CONFIRMED",
            "network_observations": network_observations or {},
        },
        "hardware": hardware,
        "sel": {
            "info": colon_lines(commands.get("ipmi_sel_info", {}).get("stdout", "")),
            "entry_count_collected": len([line for line in sel_entries if line.strip()]),
            "bmc_reported_time": commands.get("ipmi_sel_time", {}).get("stdout", "").strip(),
            "timestamp_quality": "UNRELIABLE_HISTORICAL_VALUES_OBSERVED",
        },
        "discrepancies_and_changes": [
            {
                "expected": "Initial code recognized one ASUS model as the adapter boundary.",
                "observed": "The real lab machine is another ASUS family and exposes usable common DMI/IPMI/Redfish capabilities.",
                "change": "All ASUS models route to asus_common capability discovery; generation/model overlays are optional and do not grant mutation rights.",
            },
            {
                "expected": "Hostname could resemble the platform name.",
                "observed": "ASUS hardware retained the Dell-derived hostname cnstress-r640.",
                "change": "Hostname is deliberately absent from platform and identity inputs.",
            },
            {
                "expected": "Standard Redfish resources may be discoverable.",
                "observed": "ServiceRoot is public on one BMC address; hardware/update/task/log resources return HTTP 401 without BMC credentials.",
                "change": "Capability status distinguishes LAB_VERIFIED service presence from BLOCKED_BY_AUTH resource validation.",
            },
        ],
        "official_sources": [
            {
                "title": "ASUS RS500A-E12-RS12U product page",
                "url": "https://servers.asus.com/products/Servers/Rack-Servers/RS500A-E12-RS12U/",
                "relevance": "Documents ASMB11-iKVM and AST2600 for this physical model."
            },
            {
                "title": "ASUS ASMB11-iKVM user guide E25502",
                "url": "https://dlcdnets.asus.com/pub/ASUS/E25502_ASMB11-iKVM_UM_V3_WEB.pdf?model=RS720Q-E11-RS8U",
                "relevance": "Documents Redfish, DM_LAN1/shared management, logs, inventory, updates, and System Diagnostics."
            }
        ],
    }

    matrix = {
        "schema_version": 1,
        "generated_at_utc": summary["generated_at_utc"],
        "system": {"vendor": identity["vendor"], "model": identity["model"], "serial": identity["primary_serial"]},
        "capabilities": [
            capability("DMI identity", "LAB_VERIFIED", "Linux sysfs", "raw.dmi", consistency, "IPMI FRU / Redfish", True),
            capability("IPMI KCS", "LAB_VERIFIED", "ipmitool /dev/ipmi0", "commands.ipmi_mc", mc_fields, "Redfish", True),
            capability("IPMI FRU", "LAB_VERIFIED", "ipmitool fru print", "commands.ipmi_fru", consistency, "DMI / Redfish FRU", True),
            capability("IPMI sensors/SDR", "LAB_VERIFIED", "ipmitool sdr/sensor", "commands.ipmi_sdr", {"rows": sdr["row_count"], "status_counts": sdr["status_counts"]}, "Redfish Sensors/Thermal", True),
            capability("IPMI SEL read", "LAB_VERIFIED", "ipmitool sel info/elist", "commands.ipmi_sel_entries", {"entries": summary["sel"]["entry_count_collected"]}, "Redfish LogServices", True),
            capability("IPMI LAN channel discovery", "LAB_VERIFIED", "ipmitool channel info/lan print", "commands.ipmi_lan_1 and ipmi_lan_8", {"channel_1": summary["bmc"]["lan_channel_1"], "channel_8": summary["bmc"]["lan_channel_8"]}, "Authenticated Redfish Manager EthernetInterfaces", True),
            capability("BMC dedicated/shared interface role", "UNKNOWN", "Network reachability correlation", "bmc.network_observations", {"status": "INFERRED_NOT_CONFIRMED"}, "Physical port trace or authenticated BMC interface inventory", False),
            capability("SEL clear", "NOT_SUPPORTED", "No command issued", "none", "Explicitly prohibited in read-only phase", "Technician approval after preserved evidence", False),
            capability("Redfish ServiceRoot", primary_redfish.get("service_root_status", "UNKNOWN"), "Unauthenticated HTTPS GET", "redfish_unauthenticated", primary_redfish, "IPMI KCS", False),
            capability("Redfish authenticated inventory", "BLOCKED_BY_AUTH", "HTTPS GET", "redfish endpoint status", primary_redfish.get("endpoint_status", {}), "IPMI and OS-local evidence", False),
            capability("ASUS System Diagnostics", "DISCOVERED", "ASMB11 WebUI documented; live API not tested", "official ASMB11 guide", "Generation/download capability documented", "Operator-provided artifact intake", False),
            capability("ASUS firmware inventory", "BLOCKED_BY_AUTH", "Redfish UpdateService GET", "HTTP 401", "Service advertised but contents not read", "IPMI/BIOS version evidence", False),
            capability("ASUS firmware apply", "NOT_SUPPORTED", "No mutating method implemented", "none", "Blocked", "Future lab-gated adapter", False),
            capability("SMART health", commands.get("smart_scan", {}).get("status", "UNKNOWN"), "smartctl", "commands.smart_scan", "Tool missing on live image", "Install only in a controlled development-image change", False),
            capability("NVMe CLI inventory", commands.get("nvme", {}).get("status", "UNKNOWN"), "nvme-cli", "commands.nvme", "Tool missing on live image", "lsblk/lspci until development-image change", False),
        ],
    }
    return summary, matrix


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("raw", type=Path)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--capabilities", type=Path, required=True)
    parser.add_argument("--network-observations", type=Path)
    args = parser.parse_args()
    raw = json.loads(args.raw.read_text(encoding="utf-8"))
    network_observations = None
    if args.network_observations:
        network_observations = json.loads(args.network_observations.read_text(encoding="utf-8"))
    summary, matrix = build(raw, network_observations)
    args.summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.capabilities.write_text(json.dumps(matrix, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
