"""Safe command line entrypoints for universal discovery and artifact intake."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import __version__
from .asus_firmware import AsusFirmwareEngine, AsusOfficialCatalogSource, AsusPlatformFingerprint
from .firmware import FirmwareRepository, HttpsPackageDownloader
from .capabilities import ValidationLevel
from .collector import CentralCollector
from .diagnostics import inspect_asmb12_system_diagnostics
from .hardware_tests import HardwareTestPlanner
from .identity import derive_machine_identity
from .local_evidence import read_local_ipmi_fru
from .orchestrator import ProductionOrchestrator
from .platform import PlatformProbe, detect_platform, read_linux_dmi
from .production import ProductionConfig, ProductionWorkflow, last_production_result
from .regression import evaluate_dell_regression
from .runner import bootstrap_runner, load_runner


def _service_result_exit_code(result: object, *, action: str) -> int:
    """Return a useful systemd exit code without exposing sensitive data.

    Boot-time firmware continuation is a durable state machine.  A successful
    continuation (or an intentionally requested reboot) exits zero; a failed
    request or blocked continuation exits non-zero so systemd's bounded
    ``Restart=on-failure`` policy can retry transient conditions.  The normal
    no-pending path is explicitly successful.  Sync is intentionally allowed
    to return zero while offline because its timer is the retry mechanism and
    the local queue remains durable.
    """
    if not isinstance(result, dict):
        return 1
    status = str(result.get("status") or "").upper()
    if action == "retry-sync":
        return 0
    if status in {
        "NO_PENDING_FIRMWARE",
        "CURRENT_VERIFIED",
        "UPDATED_VERIFIED",
        "REBOOT_REQUESTED",
        "SYNC_RETRY_COMPLETED",
        "TERMINAL_CHECKPOINT_RETIRED",
        # This is a successfully persisted terminal failure, not a failed
        # boot service.  The workload must never be re-run merely because the
        # host restarted while it was active.
        "INTERRUPTED_WORKLOAD_FINALIZED_FAIL",
    }:
        return 0
    # A completed production continuation returns its authoritative result
    # under ``run`` rather than duplicating a top-level status.  Treat that
    # terminal checkpoint as success so systemd does not restart it and try
    # to drive COMPLETE back through the workflow state machine.
    run = result.get("run")
    if isinstance(run, dict) and str(run.get("current_stage") or "").upper() in {"COMPLETE", "BLOCKED"}:
        return 0
    return 1


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description="CNServerOps safe universal discovery tools")
    subcommands = command.add_subparsers(dest="action", required=True)

    detect = subcommands.add_parser("detect-platform", help="classify Dell, ASUS, or unsupported hardware")
    detect.add_argument("--dmi-json", type=Path, help="offline DMI fixture; otherwise read Linux sysfs")
    detect.add_argument("--dmi-root", type=Path, default=Path("/sys/class/dmi/id"))

    diagnostic = subcommands.add_parser(
        "inspect-asmb12-diagnostic",
        help="hash and register an operator-downloaded ASMB12 System Diagnostics artifact without extracting it",
    )
    diagnostic.add_argument("--artifact", type=Path, required=True)

    runner = subcommands.add_parser("init-runner", help="create a stable RUNNER_ID configuration once")
    runner.add_argument("--config", type=Path, required=True)
    runner.add_argument("--runner-id", required=True)
    runner.add_argument("--runtime-version", required=True)
    runner.add_argument("--local-runner-uuid", default="")
    runner.add_argument("--storage-fingerprint-sha256", default="")

    start = subcommands.add_parser("start-run", help="create local authoritative run/state after safe identity detection")
    start.add_argument("--primary-root", type=Path, required=True)
    start.add_argument("--runner-config", type=Path, required=True)
    start.add_argument("--dmi-json", type=Path)
    start.add_argument("--dmi-root", type=Path, default=Path("/sys/class/dmi/id"))
    start.add_argument("--skip-local-fru", action="store_true")
    start.add_argument("--continuation-of", default="")

    production = subcommands.add_parser(
        "run-production",
        help="execute the complete operator-authorized production workflow for the detected supported vendor",
    )
    production.add_argument("--config", type=Path, default=Path("/etc/cnserverops/production.json"))
    production.add_argument(
        "--profile",
        choices=("QUICK", "STANDARD", "EXTENDED", "OVERNIGHT", "CUSTOM"),
        default="STANDARD",
    )
    production.add_argument("--custom-hours", type=float)
    production.add_argument(
        "--extended-diagnostics",
        action="store_true",
        help="run the proven production workflow plus capability-discovered ASUS extended diagnostics",
    )

    dry_run = subcommands.add_parser(
        "dry-run",
        help="collect authoritative identity/inventory and generate reports without workload or mutation",
    )
    dry_run.add_argument("--config", type=Path, default=Path("/etc/cnserverops/production.json"))

    finalize = subcommands.add_parser(
        "finalize-server",
        help="run the explicitly authorized ASUS handoff sequence; BMC reset and host power actions remain disabled",
    )
    finalize.add_argument("--config", type=Path, default=Path("/etc/cnserverops/production.json"))
    finalize.add_argument("--authorize", action="store_true", help="confirm the supported SEL cleanup gate")

    inventory_only = subcommands.add_parser(
        "inventory-only",
        help="collect safe local inventory for any vendor without workloads or cleanup",
    )
    inventory_only.add_argument("--config", type=Path, default=Path("/etc/cnserverops/production.json"))

    firmware_status = subcommands.add_parser(
        "firmware-status",
        help="read-only exact ASUS firmware status; never downloads, flashes, resets, or reboots",
    )
    firmware_status.add_argument("--config", type=Path, default=Path("/etc/cnserverops/production.json"))

    firmware_resume = subcommands.add_parser(
        "asus-firmware-resume",
        help="resume a staged ASUS firmware lifecycle after the required host reboot",
    )
    firmware_resume.add_argument("--config", type=Path, default=Path("/etc/cnserverops/production.json"))

    retry_sync = subcommands.add_parser(
        "retry-sync",
        help="drain durable Central event/artifact queues without starting a hardware workflow",
    )
    retry_sync.add_argument("--config", type=Path, default=Path("/etc/cnserverops/production.json"))

    menu = subcommands.add_parser("operator-menu", help="run the vendor-first physical console menu")
    menu.add_argument("--config", type=Path, default=Path("/etc/cnserverops/production.json"))
    menu.add_argument("--render-only", action="store_true")
    menu.add_argument("--no-clear", action="store_true")

    last = subcommands.add_parser("show-last-result", help="show the newest local authoritative result")
    last.add_argument("--config", type=Path, default=Path("/etc/cnserverops/production.json"))

    central = subcommands.add_parser("central-init", help="initialize the durable reference Central Collector database")
    central.add_argument("--database", type=Path, required=True)

    inventory = subcommands.add_parser("central-inventory", help="print central serial/run inventory")
    inventory.add_argument("--database", type=Path, required=True)

    hardware = subcommands.add_parser("hardware-plan", help="build a capability/tool-aware hardware test plan")
    hardware.add_argument("--capabilities-json", type=Path, required=True)
    hardware.add_argument("--tools-json", type=Path)
    hardware.add_argument("--allow-workloads", action="store_true")

    firmware = subcommands.add_parser(
        "asus-firmware-plan",
        help="discover exact ASUS firmware applicability and available transports without mutating hardware",
    )
    firmware.add_argument("--dmi-root", type=Path, default=Path("/sys/class/dmi/id"))
    firmware.add_argument("--redfish-discovery-json", type=Path)
    firmware.add_argument("--catalog-json", type=Path, help="offline official catalog evidence fixture")
    firmware.add_argument("--discover-official", action="store_true", help="query the official ASUS server catalog")
    firmware.add_argument("--current-bios", default="")
    firmware.add_argument("--current-bmc", default="")
    firmware.add_argument("--prepare-cache", type=Path, help="resolve exact official packages into this cache; never mutates hardware")

    subcommands.add_parser("dell-regression-template", help="emit the Dell regression checklist without claiming a physical pass")
    return command


def main() -> int:
    args = parser().parse_args()
    if args.action == "detect-platform":
        if args.dmi_json:
            values = json.loads(args.dmi_json.read_text(encoding="utf-8"))
            probe = PlatformProbe.from_mapping(values)
        else:
            probe = read_linux_dmi(args.dmi_root)
        print(json.dumps(detect_platform(probe), indent=2, sort_keys=True))
        return 0
    if args.action == "inspect-asmb12-diagnostic":
        record = inspect_asmb12_system_diagnostics(
            args.artifact,
            validation_level=ValidationLevel.IMPLEMENTED,
        )
        print(json.dumps(record.to_dict(), indent=2, sort_keys=True))
        return 0
    if args.action == "init-runner":
        print(
            json.dumps(
                bootstrap_runner(
                    args.config,
                    runner_id=args.runner_id,
                    runtime_version=args.runtime_version,
                    local_runner_uuid=args.local_runner_uuid,
                    storage_fingerprint_sha256=args.storage_fingerprint_sha256,
                ),
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if args.action == "start-run":
        runner = load_runner(args.runner_config)
        if args.dmi_json:
            probe = PlatformProbe.from_mapping(json.loads(args.dmi_json.read_text(encoding="utf-8")))
        else:
            probe = read_linux_dmi(args.dmi_root)
        platform = detect_platform(probe)
        fru_result = {"status": "SKIPPED", "fru": {}} if args.skip_local_fru else read_local_ipmi_fru()
        identity = derive_machine_identity(platform, probe, chassis_fru=fru_result.get("fru") or None)
        result = ProductionOrchestrator(args.primary_root, runtime_version=runner["runtime_version"]).start(
            platform=platform,
            identity=identity,
            runner_id=runner["runner_id"],
            continuation_of_run_id=args.continuation_of,
        )
        result["local_fru_collection"] = {
            "status": fru_result.get("status", "UNKNOWN"),
            "mechanism": fru_result.get("mechanism", ""),
            "error": fru_result.get("error", ""),
        }
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if args.action == "run-production":
        config = ProductionConfig.load(args.config)
        result = ProductionWorkflow(config, runtime_version=__version__).run_asus_production(
            profile_id=args.profile,
            custom_hours=args.custom_hours,
            extended_diagnostics=args.extended_diagnostics,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if args.action == "dry-run":
        config = ProductionConfig.load(args.config)
        result = ProductionWorkflow(config, runtime_version=__version__).run_dry_run()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if args.action == "finalize-server":
        config = ProductionConfig.load(args.config)
        result = ProductionWorkflow(config, runtime_version=__version__).finalize_server(
            operator_authorized=args.authorize
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if args.action == "inventory-only":
        config = ProductionConfig.load(args.config)
        result = ProductionWorkflow(config, runtime_version=__version__).inventory_only()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if args.action == "firmware-status":
        config = ProductionConfig.load(args.config)
        result = ProductionWorkflow(config, runtime_version=__version__).firmware_status_only()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if args.action == "asus-firmware-resume":
        config = ProductionConfig.load(args.config)
        result = ProductionWorkflow(config, runtime_version=__version__).resume_pending_firmware_only()
        print(json.dumps(result, indent=2, sort_keys=True))
        return _service_result_exit_code(result, action="asus-firmware-resume")
    if args.action == "retry-sync":
        config = ProductionConfig.load(args.config)
        result = ProductionWorkflow(config, runtime_version=__version__).retry_pending_sync()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if args.action == "operator-menu":
        from .operator_console import OperatorConsole

        config = ProductionConfig.load(args.config)
        console = OperatorConsole(config, runtime_version=__version__, clear_screen=not args.no_clear)
        if args.render_only:
            console.render_only()
            return 0
        return console.run()
    if args.action == "show-last-result":
        config = ProductionConfig.load(args.config)
        print(json.dumps(last_production_result(config.primary_root), indent=2, sort_keys=True))
        return 0
    if args.action == "central-init":
        collector = CentralCollector(args.database)
        collector.initialize()
        print(json.dumps({"status": "READY", "database": str(args.database), "counts": collector.counts()}, indent=2, sort_keys=True))
        return 0
    if args.action == "central-inventory":
        print(json.dumps(CentralCollector(args.database).inventory(), indent=2, sort_keys=True))
        return 0
    if args.action == "hardware-plan":
        capabilities = json.loads(args.capabilities_json.read_text(encoding="utf-8"))
        tools = json.loads(args.tools_json.read_text(encoding="utf-8")) if args.tools_json else None
        print(json.dumps(HardwareTestPlanner().plan(capabilities=capabilities, available_tools=tools, allow_workloads=args.allow_workloads), indent=2, sort_keys=True))
        return 0
    if args.action == "asus-firmware-plan":
        probe = read_linux_dmi(args.dmi_root)
        redfish = json.loads(args.redfish_discovery_json.read_text(encoding="utf-8")) if args.redfish_discovery_json else {}
        local = probe.to_dict()
        local["model"] = probe.product_name
        local["board"] = probe.board_name
        fingerprint = AsusPlatformFingerprint.from_sources(
            local=local,
            redfish=(redfish.get("normalized") or redfish) if isinstance(redfish, dict) else {},
        )
        documents = []
        if args.catalog_json:
            payload = json.loads(args.catalog_json.read_text(encoding="utf-8"))
            documents = payload if isinstance(payload, list) else [payload]
        sources = (AsusOfficialCatalogSource(),) if args.discover_official else ()
        engine = AsusFirmwareEngine(catalog_sources=sources)
        plan = engine.plan(
            fingerprint=fingerprint,
            current_versions={"BIOS": args.current_bios or probe.bios_version, "BMC": args.current_bmc},
            redfish_discovery=redfish,
            catalog_documents=documents,
        )
        output = plan.to_dict()
        if args.prepare_cache:
            prepared = engine.prepare_plan_packages(
                plan,
                repository=FirmwareRepository(args.prepare_cache),
                downloader=HttpsPackageDownloader(),
            )
            output["prepared_packages"] = prepared
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0
    if args.action == "dell-regression-template":
        print(json.dumps(evaluate_dell_regression({}), indent=2, sort_keys=True))
        return 0
    raise SystemExit("unsupported action")


if __name__ == "__main__":
    raise SystemExit(main())
