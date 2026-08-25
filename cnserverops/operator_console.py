"""Technician-facing, vendor-first physical console launcher."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, TextIO

from .production import (
    ProductionConfig,
    ProductionWorkflow,
    ProductionWorkflowError,
    central_runtime_status,
    detect_current_platform_and_identity,
    last_production_result,
)
from .runner import RunnerIdentityError, load_runner
from .stress_profiles import resolve_profile


LEGACY_DELL_ENTRYPOINT = Path("/usr/local/bin/cngpu-update-test-tsr-wrapper")


@dataclass(frozen=True)
class ConsoleSnapshot:
    platform: Mapping[str, Any]
    identity: Mapping[str, Any]
    runner: Mapping[str, Any]
    central: Mapping[str, Any]
    runtime_version: str
    motherboard_serial: str = ""
    bios_version: str = ""
    bmc_version: str = ""
    bmc_auth_state: str = "BMC_AUTH_UNAVAILABLE"
    last_result: Mapping[str, Any] | None = None


def available_actions(platform: Mapping[str, Any]) -> tuple[str, ...]:
    """Return actions only after authoritative vendor/model classification.

    The menu renderer and dispatcher must consume the same ordered registry.
    Keeping the order here is deliberate: option 5 is the explicitly
    confirmed firmware lifecycle action used by field technicians and older
    runbooks; it never mutates anything until the confirmation is accepted.
    """
    return tuple(action for action, _label in menu_options(platform))


def menu_options(platform: Mapping[str, Any]) -> tuple[tuple[str, str], ...]:
    """Authoritative ordered menu registry (labels and dispatch numbers)."""
    platform_id = str(platform.get("platform_id") or "")
    if platform_id == "ASUS_SERVER" and str(platform.get("vendor") or "") == "ASUS":
        return (
            ("FLEET_INTAKE", "FLEET INTAKE / SERIAL + LOG COLLECTION"),
            # Field procedure defines console option 2 as the one-confirm
            # unattended production lifecycle.  Keep its label explicit: it
            # includes the normal pipeline plus capability-gated extended
            # diagnostics, whose unsupported state is reported separately and
            # never suppresses firmware/tests/reporting.
            ("RUN_ASUS_EXTENDED", "FULL PRODUCTION + EXTENDED DIAGNOSTICS"),
            ("DRY_RUN", "Dry Run / Serial Collection"),
            # This action intentionally reuses the production evidence,
            # readiness, Central and archive pipeline with a longer workload
            # profile.  Say so on-screen rather than implying a separate
            # firmware/production lifecycle.
            ("STRESS_PROFILE", "Stress Test / Burn-In (full production profile)"),
            ("FIRMWARE_STATUS", "Firmware Update & Verification"),
            ("RUN_ASUS_PRODUCTION", "FULL PRODUCTION / PREPARE FOR SALE (STANDARD)"),
            ("SERIAL_MAC_INVENTORY", "Serial / MAC Inventory"),
            ("SHOW_LAST_RESULT", "Reports / Last Results"),
            ("FINALIZE_SERVER", "Finalize Server"),
            ("SHELL", "Advanced / Shell"),
            # This is the explicit ASUS ASMB11/ASMB12 factory/default
            # recovery path.  It is deliberately last so existing field
            # option numbers remain stable; the handler requires the exact
            # confirmation ``RESET BMC`` before any KCS mutation.
            ("BMC_FACTORY_RESET", "BMC RESET / FACTORY DEFAULT RECOVERY (KCS)"),
        )
    if platform_id == "DELL_POWEREDGE_R640" and str(platform.get("vendor") or "") == "DELL":
        return (
            ("RUN_EXISTING_DELL_PRODUCTION", "Run Existing Dell Production Workflow"),
            ("INVENTORY_ONLY", "Inventory Only"),
            ("SHOW_LAST_RESULT", "Show Last Result"),
            ("SHELL", "Shell / Exit"),
        )
    return (("INVENTORY_ONLY", "Inventory Only"), ("SHOW_LAST_RESULT", "Show Last Result"), ("SHELL", "Shell / Exit"))


def render_menu(snapshot: ConsoleSnapshot) -> str:
    platform = snapshot.platform
    probe = dict(platform.get("probe") or {})
    actions = available_actions(platform)
    detected = f"{platform.get('vendor', 'UNKNOWN')} {probe.get('product_name') or 'Unknown model'}".strip()
    serial = probe.get("system_serial") or snapshot.identity.get("primary_serial") or "UNKNOWN"
    runner_id = snapshot.runner.get("runner_id") or "NOT_CONFIGURED"
    central = snapshot.central.get("status") or "UNKNOWN"
    last = dict(snapshot.last_result or {})
    last_run = last.get("run_id") or "NONE"
    last_result = last.get("disposition") or "NOT_RUN"
    handoff = last.get("handoff_status") or "NOT_EVALUATED"
    width = 86
    rule = "+" + "-" * (width - 2) + "+"

    def row(label: str, value: Any, second_label: str = "", second_value: Any = "") -> str:
        if second_label:
            left = f"{label:<18} {str(value or 'UNKNOWN')[:24]:<24}"
            right = f"{second_label:<13} {str(second_value or 'UNKNOWN')[:21]:<21}"
            content = left + " | " + right
        else:
            content = f"{label:<18} {str(value or 'UNKNOWN')[:61]:<61}"
        return "| " + content[: width - 4].ljust(width - 4) + " |"

    lines = [
        rule,
        "|" + f" CNServerOps {snapshot.runtime_version} | PRODUCTION CONSOLE ".center(width - 2) + "|",
        rule,
        row("Detected", detected, "Central", central),
        row("System Serial", serial, "BMC Auth (last)", snapshot.bmc_auth_state),
        row("Motherboard Serial", snapshot.motherboard_serial or "NOT_EXPOSED", "BIOS", snapshot.bios_version or "UNKNOWN"),
        row("Runner ID", runner_id),
        row("BMC Firmware", snapshot.bmc_version or "UNKNOWN", "Last Result", last_result),
        row("Last Run", last_run),
        row("Handoff", handoff),
        rule,
        "",
    ]
    if "RUN_ASUS_PRODUCTION" in actions or "RUN_EXISTING_DELL_PRODUCTION" in actions:
        lines.extend(f"[{number}] {label}" for number, (_action, label) in enumerate(menu_options(platform), start=1))
    else:
        lines.extend(
            [
                "Production workflow unavailable for this vendor/model.",
                "Safe inventory only; no vendor-specific action is exposed.",
                "",
            ]
        )
    if "RUN_ASUS_PRODUCTION" not in actions and "RUN_EXISTING_DELL_PRODUCTION" not in actions:
        lines.extend(f"[{number}] {label}" for number, (_action, label) in enumerate(menu_options(platform), start=1))
    lines.extend(
        [
            "",
            "No test, cleanup, firmware, reset, or power action starts automatically.",
            "Fleet Intake is read-only after selection.",
            "BMC Auth (last) is historical; authenticated actions re-probe it when needed.",
            "BMC RESET may change BMC LAN/IP and credentials; explicit confirmation is required.",
            "Maintenance actions require explicit confirmation.",
        ]
    )
    return "\n".join(lines)


class OperatorConsole:
    def __init__(
        self,
        config: ProductionConfig,
        *,
        runtime_version: str,
        workflow: ProductionWorkflow | None = None,
        input_fn: Callable[[str], str] = input,
        output: TextIO = sys.stdout,
        clear_screen: bool = True,
    ) -> None:
        self.config = config
        self.runtime_version = runtime_version
        self.input_fn = input_fn
        self.output = output
        self.clear_screen = clear_screen
        self.workflow = workflow or ProductionWorkflow(
            config,
            runtime_version=runtime_version,
            progress_callback=self._render_progress,
        )

    def snapshot(self) -> ConsoleSnapshot:
        probe, platform, identity, _ = detect_current_platform_and_identity(
            dmi_root=self.workflow.dmi_root,
            fru_reader=self.workflow.fru_reader,
        )
        try:
            runner = load_runner(self.config.runner_config)
        except (OSError, ValueError, json.JSONDecodeError, RunnerIdentityError):
            runner = {}
        bmc_version = ""
        try:
            mc = self.workflow.executor.run("ipmitool", ("mc", "info"), timeout_seconds=30)
            for line in str(mc.get("stdout") or "").splitlines():
                if line.lower().strip().startswith("firmware revision") and ":" in line:
                    bmc_version = line.split(":", 1)[1].strip()
                    break
        except Exception:
            bmc_version = ""
        last = last_production_result(
            self.config.primary_root,
            expected_fingerprint=str(identity.get("fingerprint_sha256") or ""),
        )
        return ConsoleSnapshot(
            platform=platform,
            identity=identity,
            runner=runner,
            central=central_runtime_status(self.config.central_config),
            runtime_version=self.runtime_version,
            motherboard_serial=str((identity.get("anchors") or {}).get("dmi_board_serial") or identity.get("board_serial") or ""),
            bios_version=str(probe.bios_version or ""),
            bmc_version=bmc_version,
            bmc_auth_state=str(last.get("bmc_auth_state") or "BMC_AUTH_UNAVAILABLE"),
            last_result=last,
        )

    def render_only(self) -> str:
        screen = render_menu(self.snapshot())
        self._write(screen + "\n")
        return screen

    def run(self) -> int:
        while True:
            try:
                snapshot = self.snapshot()
                if self.clear_screen:
                    self._write("\033[2J\033[H")
                self._write(render_menu(snapshot) + "\n\n")
                actions = available_actions(snapshot.platform)
                numbered = {str(index): action for index, action in enumerate(actions, start=1)}
                selection = self.input_fn("Select option: ").strip()
                # A pending Enter from the workflow's return prompt can be
                # delivered to the next menu read by a physical TTY.  Treat
                # that empty line as a harmless redraw instead of displaying
                # a misleading "Invalid selection" error.
                if not selection:
                    continue
                action = numbered.get(selection)
                if action is None:
                    self._pause("Invalid selection.")
                    continue
                if action == "FLEET_INTAKE":
                    self._run_fleet_intake(snapshot)
                elif action == "RUN_ASUS_PRODUCTION":
                    self._run_asus(snapshot)
                elif action == "RUN_ASUS_EXTENDED":
                    self._run_asus_extended(snapshot)
                elif action == "DRY_RUN":
                    self._run_dry_run()
                elif action == "STRESS_PROFILE":
                    self._run_stress_profile(snapshot)
                elif action == "FIRMWARE_STATUS":
                    self._firmware_status()
                elif action == "SERIAL_MAC_INVENTORY":
                    self._serial_mac_inventory()
                elif action == "RUN_EXISTING_DELL_PRODUCTION":
                    self._run_dell(snapshot)
                elif action == "INVENTORY_ONLY":
                    result = self.workflow.inventory_only()
                    self._pause(f"Inventory saved: {result['output_directory']}")
                elif action == "SHOW_LAST_RESULT":
                    self._show_last_result()
                elif action == "FINALIZE_SERVER":
                    self._finalize_server()
                elif action == "SHELL":
                    self._shell()
                elif action == "BMC_FACTORY_RESET":
                    self._reset_bmc(snapshot)
            except KeyboardInterrupt:
                self._write("\nInterrupted. Returning to menu.\n")
                time.sleep(1)

    def _run_asus(self, displayed: ConsoleSnapshot) -> None:
        if self.input_fn("Type RUN to start CPU/RAM tests and supported SEL cleanup: ").strip() != "RUN":
            self._pause("Production workflow cancelled; nothing started.")
            return
        current = self.snapshot()
        if (
            current.platform.get("platform_id") != "ASUS_SERVER"
            or current.identity.get("fingerprint_sha256") != displayed.identity.get("fingerprint_sha256")
        ):
            self._pause("Safety stop: platform/identity changed after the menu was displayed.")
            return
        try:
            result = self.workflow.run_asus_production(profile_id="STANDARD")
        except ProductionWorkflowError as exc:
            self._pause(f"Production workflow refused: {exc}")
            return
        run = result.get("run", {})
        self._pause(self._format_final_status("Production workflow", run, result))

    def _run_asus_extended(self, displayed: ConsoleSnapshot) -> None:
        """Run Option 2: proven production plus vendor-native diagnostics.

        One explicit ``RUN`` confirmation is the technician contract for
        Option 2.  Capability discovery decides whether ASUS diagnostics is
        PASS, UNSUPPORTED, AUTH_BLOCKED, or an execution/hardware failure.
        """
        if self.input_fn(
            "Type RUN to start Full Production + Extended Diagnostics: "
        ).strip() != "RUN":
            self._pause("Extended workflow cancelled; nothing started.")
            return
        current = self.snapshot()
        if (
            current.platform.get("platform_id") != "ASUS_SERVER"
            or current.identity.get("fingerprint_sha256") != displayed.identity.get("fingerprint_sha256")
        ):
            self._pause("Safety stop: platform/identity changed after the menu was displayed.")
            return
        try:
            result = self.workflow.run_asus_production(
                profile_id="STANDARD",
                extended_diagnostics=True,
            )
        except ProductionWorkflowError as exc:
            self._pause(f"Extended workflow refused: {exc}")
            return
        run = result.get("run", {})
        self._pause(self._format_final_status("Full Production + Extended Diagnostics", run, result))

    def _run_fleet_intake(self, displayed: ConsoleSnapshot) -> None:
        current = self.snapshot()
        if current.platform.get("platform_id") != "ASUS_SERVER" or current.identity.get("fingerprint_sha256") != displayed.identity.get("fingerprint_sha256"):
            self._pause("Safety stop: ASUS identity changed after the menu was displayed.")
            return
        try:
            result = self.workflow.run_fleet_intake()
        except ProductionWorkflowError as exc:
            self._pause(f"Fleet Intake refused: {exc}")
            return
        run = result.get("run", {})
        outcome = result.get("result", {})
        self._pause(
            "FLEET INTAKE complete\n"
            f"Run:          {run.get('run_id')}\n"
            f"System Serial: {outcome.get('system_serial') or (current.identity.get('primary_serial') or 'UNKNOWN')}\n"
            f"SEL Preserved: YES\nSEL Cleanup:   NOT PERFORMED\n"
            f"Central:       {(result.get('central') or {}).get('queue_status') or outcome.get('central_link')}\n"
            f"Windows Archive:{(outcome.get('windows_archive') or {}).get('destination') or 'PENDING / CENTRAL QUEUE'}"
        )

    def _reset_bmc(self, displayed: ConsoleSnapshot) -> None:
        """Run the explicit, capability-gated ASUS KCS factory recovery."""
        self._write(
            "\nWARNING: this is the official ASUS ASMB factory/default recovery.\n"
            "It may reset BMC LAN/IP configuration and existing BMC accounts.\n"
            "Evidence is preserved first; no BIOS, host reboot, or power action is started.\n"
        )
        if self.input_fn("Type RESET BMC to continue: ").strip() != "RESET BMC":
            self._pause("BMC reset cancelled; nothing changed.")
            return
        current = self.snapshot()
        if (
            current.platform.get("platform_id") != "ASUS_SERVER"
            or current.identity.get("fingerprint_sha256") != displayed.identity.get("fingerprint_sha256")
        ):
            self._pause("Safety stop: ASUS identity changed after the menu was displayed.")
            return
        try:
            result = self.workflow.reset_bmc(operator_authorized=True)
        except ProductionWorkflowError as exc:
            self._pause(f"BMC reset refused: {exc}")
            return
        outcome = dict(result.get("result") or {})
        recovery = dict(result.get("recovery") or {})
        self._pause(
            "BMC factory/default recovery complete\n"
            f"Status:       {outcome.get('status') or recovery.get('status') or 'UNKNOWN'}\n"
            f"Generation:   {outcome.get('bmc_generation') or 'UNKNOWN'}\n"
            f"Method:       {outcome.get('method') or 'NONE'}\n"
            f"BMC IP before: {outcome.get('bmc_ip_before') or 'NOT_DISCOVERED'}\n"
            f"BMC IP after:  {outcome.get('bmc_ip_after') or 'NOT_DISCOVERED'}\n"
            f"Firmware:     {outcome.get('firmware_before') or 'UNKNOWN'} -> {outcome.get('firmware_after') or 'UNKNOWN'}\n"
            f"KCS:          {outcome.get('kcs_before') or 'UNKNOWN'} -> {outcome.get('kcs_after') or 'UNKNOWN'}\n"
            f"Evidence:     {result.get('run_directory') or 'UNKNOWN'}"
        )

    def _run_dry_run(self) -> None:
        if self.input_fn("Type DRY to collect inventory and reports without stress or mutation: ").strip() != "DRY":
            self._pause("Dry Run cancelled; nothing started.")
            return
        try:
            result = self.workflow.run_dry_run()
        except ProductionWorkflowError as exc:
            self._pause(f"Dry Run refused: {exc}")
            return
        run = result.get("run", {})
        self._pause(self._format_final_status("Dry Run", run, result))

    def _run_stress_profile(self, displayed: ConsoleSnapshot) -> None:
        quick_minutes = max(1, round(resolve_profile("QUICK").total_seconds / 60))
        standard_minutes = max(1, round(resolve_profile("STANDARD").total_seconds / 60))
        extended_hours = resolve_profile("EXTENDED").total_seconds / 3600
        overnight_hours = resolve_profile("OVERNIGHT").total_seconds / 3600
        self._write(
            "\n"
            f"[1] QUICK {quick_minutes}m  [2] STANDARD {standard_minutes}m  "
            f"[3] EXTENDED {extended_hours:g}h  [4] OVERNIGHT {overnight_hours:g}h  "
            "[5] CUSTOM 1-18h\n"
        )
        choice = self.input_fn("Select validated profile: ").strip()
        profiles = {"1": "QUICK", "2": "STANDARD", "3": "EXTENDED", "4": "OVERNIGHT", "5": "CUSTOM"}
        profile = profiles.get(choice)
        if profile is None:
            self._pause("Invalid profile; nothing started.")
            return
        custom_hours: float | None = None
        if profile == "CUSTOM":
            try:
                custom_hours = float(self.input_fn("Custom duration in hours (1-18): ").strip())
            except ValueError:
                self._pause("Invalid duration; nothing started.")
                return
        if self.input_fn(
            f"Type BURN to start the full production lifecycle with the {profile} workload profile: "
        ).strip() != "BURN":
            self._pause("Burn-in cancelled; nothing started.")
            return
        current = self.snapshot()
        if (
            current.platform.get("platform_id") != "ASUS_SERVER"
            or current.identity.get("fingerprint_sha256") != displayed.identity.get("fingerprint_sha256")
        ):
            self._pause("Safety stop: platform/identity changed after profile selection.")
            return
        try:
            result = self.workflow.run_asus_production(profile_id=profile, custom_hours=custom_hours)
        except (ProductionWorkflowError, ValueError) as exc:
            self._pause(f"Burn-in refused: {exc}")
            return
        run = result.get("run", {})
        self._pause(self._format_final_status(f"{profile} run", run, result))

    def _firmware_status(self) -> None:
        if self.input_fn(
            "Type FIRMWARE to resolve and, when required, apply the exact ASUS firmware lifecycle: "
        ).strip() != "FIRMWARE":
            self._pause("Firmware action cancelled; no mutation was started.")
            return
        try:
            result = self.workflow.firmware_update_only(operator_authorized=True)
        except ProductionWorkflowError as exc:
            self._pause(f"Firmware lifecycle refused: {exc}")
            return
        plan = result.get("firmware") or {}
        execution = result.get("execution") or {}
        lines = [
            f"Firmware plan: {plan.get('readiness') or 'UNVERIFIED'}",
            f"Execution: {execution.get('status') or result.get('status') or 'UNKNOWN'}",
        ]
        for item in plan.get("components") or []:
            lines.append(
                f"{item.get('component')}: {item.get('before') or 'UNKNOWN'} -> "
                f"{item.get('target') or '-'} [{item.get('status') or 'UNVERIFIED'}]"
            )
        lines.append(f"Mutation started: {'YES' if result.get('mutation_started') else 'NO'}")
        self._pause("\n".join(lines))

    def _serial_mac_inventory(self) -> None:
        if self.input_fn("Type SERIAL to collect read-only serial/MAC evidence without stress or mutation: ").strip() != "SERIAL":
            self._pause("Serial/MAC collection cancelled; nothing started.")
            return
        try:
            # Inventory is intentionally usable before a full trusted identity
            # exists; it is one of the evidence sources used to establish it.
            result = self.workflow.inventory_only()
        except ProductionWorkflowError as exc:
            self._pause(f"Serial/MAC collection refused: {exc}")
            return
        self._pause(
            "Serial/MAC evidence collection complete.\n"
            f"Identity state: {(result.get('identity') or {}).get('identity_state') or 'UNKNOWN'}\n"
            f"Inventory: {result.get('output_directory') or 'NOT_GENERATED'}"
        )

    def _finalize_server(self) -> None:
        # Resolve the current physical identity before looking up history.  The
        # previous implementation referenced the local variable used by
        # ``_show_last_result`` and raised ``NameError`` whenever a technician
        # selected the visible Finalize Server option.  Finalization must be
        # bound to the server currently in the console, never to an arbitrary
        # historical run.
        current = self.snapshot()
        last = last_production_result(
            self.config.primary_root,
            expected_fingerprint=str(current.identity.get("fingerprint_sha256") or ""),
        )
        if last.get("status") != "FOUND":
            self._pause("No completed run is available to finalize.")
            return
        self._write(
            "\nFinalize Server will preserve current evidence, perform supported SEL cleanup when needed, "
            "recheck identity/sensors, and retry Central delivery.\n"
            "It will NOT reset BMC, reboot/power-cycle the host, update firmware, or change configuration.\n"
        )
        if self.input_fn("Type FINALIZE to continue: ").strip() != "FINALIZE":
            self._pause("Finalization cancelled; nothing changed.")
            return
        try:
            result = self.workflow.finalize_server(operator_authorized=True)
        except ProductionWorkflowError as exc:
            self._pause(f"Finalization refused: {exc}")
            return
        status = result.get("finalization", {})
        self._pause(
            "Finalization complete\n"
            f"Run: {result.get('run_id')}\n"
            f"Overall: {status.get('overall')}\n"
            f"Handoff: {status.get('handoff_status')}\n"
            f"SEL cleanup: {status.get('sel_cleanup')}\n"
            "BMC soft reset: UNVERIFIED / NOT PERFORMED"
        )

    def _render_progress(self, payload: Mapping[str, Any]) -> None:
        stage = str(payload.get("stage") or "STARTING")
        event = str(payload.get("event") or "STATUS")
        elapsed = int(payload.get("elapsed_seconds") or 0)
        remaining = int(payload.get("remaining_seconds") or 0)
        temp = payload.get("current_temp_c")
        peak = payload.get("peak_temp_c")
        if self.clear_screen:
            self._write("\033[2J\033[H")
        self._write(
            "CNServerOps | LIVE WORKFLOW\n"
            "==============================================\n"
            f"Stage:              {stage}\n"
            f"State:              {event}\n"
            f"Profile:            {payload.get('profile') or '-'}\n"
            f"Elapsed:            {_duration(elapsed)}\n"
            f"Remaining:          {_duration(remaining)}\n"
            f"CPU Temp current:   {temp if temp is not None else '-'} C\n"
            f"CPU Temp peak:      {peak if peak is not None else '-'} C\n"
            f"Critical Sensors:   {payload.get('critical_sensors', 0)}\n"
            f"New Critical SEL:   {payload.get('new_critical_sel', 0)}\n"
            f"Kernel HW Errors:   {payload.get('kernel_hw_errors', 0)}\n"
            "Raw output:         evidence files only\n"
        )

    def _run_dell(self, displayed: ConsoleSnapshot) -> None:
        if self.input_fn("Type DELL to start the existing Dell R640 workflow: ").strip() != "DELL":
            self._pause("Dell workflow cancelled; nothing started.")
            return
        current = self.snapshot()
        if (
            current.platform.get("platform_id") != "DELL_POWEREDGE_R640"
            or current.identity.get("fingerprint_sha256") != displayed.identity.get("fingerprint_sha256")
        ):
            self._pause("Safety stop: exact Dell R640 identity is no longer current.")
            return
        if not LEGACY_DELL_ENTRYPOINT.is_file() or not os.access(LEGACY_DELL_ENTRYPOINT, os.X_OK):
            self._pause("Existing Dell entrypoint is unavailable; no fallback was attempted.")
            return
        subprocess.run([str(LEGACY_DELL_ENTRYPOINT)], check=False)
        self._pause("Existing Dell workflow returned to CNServerOps.")

    def _show_last_result(self) -> None:
        identity = self.snapshot().identity
        result = last_production_result(
            self.config.primary_root,
            expected_fingerprint=str(identity.get("fingerprint_sha256") or ""),
        )
        if result.get("status") == "NO_RESULT":
            self._pause("No prior local production result was found.")
            return
        self._pause(
            "\n".join(
                [
                    f"Run:        {result.get('run_id')}",
                    f"Disposition:{result.get('disposition')}",
                    f"Collection: {result.get('collection_status')}",
                    f"Completed:  {result.get('completed_at_utc')}",
                    f"Reasons:    {', '.join(result.get('reason_codes') or []) or 'none'}",
                    f"Reason:     {(result.get('status_summary') or {}).get('reason_text') or 'none'}",
                    f"Record:     {result.get('path')}",
                ]
            )
        )

    @staticmethod
    def _format_final_status(label: str, run: Mapping[str, Any], result: Mapping[str, Any]) -> str:
        summary = dict(result.get("result", {}).get("status_summary") or result.get("normalized_result", {}).get("status_summary") or {})
        if not summary:
            summary = dict(result.get("status_summary") or {})
        reasons = list(summary.get("reason") or [])
        lines = [
            f"{label} completed",
            f"Run:          {run.get('run_id')}",
            f"OVERALL:      {summary.get('overall') or run.get('final_disposition') or 'UNKNOWN'}",
            f"COLLECTION:   {summary.get('collection') or run.get('collection_status') or 'UNKNOWN'}",
            f"CENTRAL SYNC: {summary.get('central_sync') or 'UNKNOWN'}",
            f"REPORTS:      {summary.get('reports') or 'UNKNOWN'}",
        ]
        if reasons:
            lines.append("REASON:")
            lines.extend(f"  - {reason}" for reason in reasons[:8])
        else:
            lines.append("REASON:       none")
        return "\n".join(lines)

    def _shell(self) -> None:
        if self.input_fn("Type LOGIN to open the authenticated local login prompt: ").strip() != "LOGIN":
            self._pause("Shell cancelled.")
            return
        subprocess.run(["/bin/login"], check=False)

    def _pause(self, message: str) -> None:
        self._write("\n" + message + "\n")
        self.input_fn("Press Enter to return to CNServerOps... ")

    def _write(self, value: str) -> None:
        self.output.write(value)
        self.output.flush()


def main(argv: list[str] | None = None) -> int:
    import argparse
    from . import __version__

    parser = argparse.ArgumentParser(description="CNServerOps physical console launcher")
    parser.add_argument("--config", type=Path, default=Path("/etc/cnserverops/production.json"))
    parser.add_argument("--render-only", action="store_true", help="render one safe screen and exit without accepting actions")
    parser.add_argument("--no-clear", action="store_true")
    args = parser.parse_args(argv)
    config = ProductionConfig.load(args.config)
    console = OperatorConsole(config, runtime_version=__version__, clear_screen=not args.no_clear)
    if args.render_only:
        console.render_only()
        return 0
    return console.run()


def _duration(seconds: int) -> str:
    value = max(0, int(seconds))
    hours, remainder = divmod(value, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


if __name__ == "__main__":
    raise SystemExit(main())
