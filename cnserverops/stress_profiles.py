"""Validated technician stress profiles with safe memory sizing and monitoring."""

from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from .models import utc_now


class StressProfileError(ValueError):
    pass


class CommandExecutor(Protocol):
    def run(self, tool: str, arguments: tuple[str, ...], *, timeout_seconds: int) -> dict[str, Any]: ...


ProgressCallback = Callable[[Mapping[str, Any]], None]
_STRESS_NICE_LEVEL = 10
_HOST_WATCHDOG_TIMEOUT_SECONDS = 300


@dataclass(frozen=True)
class StressPhase:
    name: str
    duration_seconds: int
    cpu: bool = False
    memory: bool = False
    cooldown: bool = False


@dataclass(frozen=True)
class StressProfile:
    profile_id: str
    display_name: str
    description: str
    phases: tuple[StressPhase, ...]
    monitor_interval_seconds: int = 30
    checkpoint_interval_seconds: int = 60

    @property
    def total_seconds(self) -> int:
        return sum(phase.duration_seconds for phase in self.phases)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["total_seconds"] = self.total_seconds
        return payload


def _static_profiles() -> dict[str, StressProfile]:
    return {
        "QUICK": StressProfile(
            "QUICK",
            "Quick Test - 4 minutes",
            "Fast functional retest; not the default full production validation.",
            (
                StressPhase("CPU", 60, cpu=True),
                StressPhase("MEMORY", 60, memory=True),
                StressPhase("COMBINED", 60, cpu=True, memory=True),
                StressPhase("COOLDOWN_SANITY", 30, cooldown=True),
            ),
        ),
        "STANDARD": StressProfile(
            "STANDARD",
            "Standard Production - 7 minutes",
            "Practical daily production CPU, memory, combined, and cooldown validation.",
            (
                StressPhase("CPU", 120, cpu=True),
                StressPhase("MEMORY", 120, memory=True),
                StressPhase("COMBINED", 120, cpu=True, memory=True),
                StressPhase("COOLDOWN_SANITY", 60, cooldown=True),
            ),
        ),
        "EXTENDED": StressProfile(
            "EXTENDED",
            "Extended Burn-In - 2 hours",
            "Extended CPU, memory, and combined workload with continuous monitoring.",
            (
                StressPhase("CPU", 1800, cpu=True),
                StressPhase("MEMORY", 1800, memory=True),
                StressPhase("COMBINED", 3000, cpu=True, memory=True),
                StressPhase("COOLDOWN_SANITY", 600, cooldown=True),
            ),
        ),
        "OVERNIGHT": _cyclic_profile("OVERNIGHT", "Overnight Burn-In - 8 hours", 8 * 3600),
    }


def _cyclic_profile(profile_id: str, display_name: str, total_seconds: int) -> StressProfile:
    phases: list[StressPhase] = []
    remaining = total_seconds
    cycle = 1
    while remaining:
        duration = min(3600, remaining)
        cpu = max(60, round(duration * 0.25))
        memory = max(60, round(duration * 0.25))
        cooldown = max(30, round(duration * 0.08))
        combined = duration - cpu - memory - cooldown
        if combined < 60:
            combined = 60
            cpu = max(60, cpu - 30)
            memory = max(60, duration - combined - cooldown - cpu)
        phases.extend(
            [
                StressPhase(f"CYCLE_{cycle}_CPU", cpu, cpu=True),
                StressPhase(f"CYCLE_{cycle}_MEMORY", memory, memory=True),
                StressPhase(f"CYCLE_{cycle}_COMBINED", combined, cpu=True, memory=True),
                StressPhase(f"CYCLE_{cycle}_COOLDOWN", cooldown, cooldown=True),
            ]
        )
        remaining -= duration
        cycle += 1
    return StressProfile(
        profile_id,
        display_name,
        "Cyclic CPU, memory, combined, and cooldown burn-in with durable checkpoints.",
        tuple(phases),
    )


PROFILES = _static_profiles()


def resolve_profile(profile_id: str, *, custom_hours: float | None = None) -> StressProfile:
    normalized = str(profile_id or "").strip().upper()
    if normalized == "CUSTOM":
        if custom_hours is None or not 1 <= float(custom_hours) <= 18:
            raise StressProfileError("CUSTOM burn-in duration must be between 1 and 18 hours")
        seconds = int(round(float(custom_hours) * 3600))
        return _cyclic_profile("CUSTOM", f"Custom Burn-In - {float(custom_hours):g} hours", seconds)
    try:
        return PROFILES[normalized]
    except KeyError as exc:
        raise StressProfileError(f"unknown stress profile: {profile_id}") from exc


def memory_working_set(
    *,
    total_bytes: int,
    available_bytes: int,
    worker_count: int,
    max_total_fraction: float = 0.70,
) -> dict[str, int]:
    """Reserve OS headroom and never intentionally drive the host into OOM."""
    if total_bytes <= 0 or available_bytes <= 0 or worker_count <= 0:
        raise StressProfileError("memory sizing requires positive total, available, and worker values")
    if not 0.10 <= float(max_total_fraction) <= 0.70:
        raise StressProfileError("memory safety fraction must be between 0.10 and 0.70")
    # Prefer a 2 GiB/20% OS reserve on production-sized hosts, but scale that
    # reserve down when MemAvailable is small.  At least 25% of currently
    # available memory stays outside stress-ng.
    reserve_goal = max(2 * 1024**3, int(total_bytes * 0.20))
    reserve_cap = max(512 * 1024**2, int(available_bytes * 0.75))
    reserve = min(reserve_goal, reserve_cap)
    usable = max(0, available_bytes - reserve)
    target = min(int(total_bytes * float(max_total_fraction)), usable)
    minimum = min(256 * 1024**2, max(64 * 1024**2, available_bytes // 8))
    if target < minimum:
        raise StressProfileError("insufficient available memory after production safety headroom")
    target = max(minimum, target)
    per_worker = max(64 * 1024**2, target // worker_count)
    target = per_worker * worker_count
    return {
        "total_bytes": int(total_bytes),
        "available_bytes": int(available_bytes),
        "reserved_bytes": int(reserve),
        "target_bytes": int(target),
        "worker_count": int(worker_count),
        "per_worker_mib": max(64, per_worker // (1024**2)),
        "max_total_fraction": float(max_total_fraction),
    }


def production_resource_plan(profile: StressProfile, *, cpu_count: int) -> dict[str, Any]:
    """Return a deterministic resource budget for a production stress profile.

    A server with hundreds of logical CPUs must not make the CNServerOps
    console, local KCS/IPMI, network IRQs, or SSH unavailable merely because a
    *standard* functional test starts.  ``stress-ng --cpu`` takes a worker
    count, not a percentage, so the historical ``cpu_count - 1`` rule could
    launch 255 all-method workers on a 256-thread host.  That is suitable only
    for an explicitly selected burn-in window, not a seven-minute production
    acceptance test.

    Standard/quick profiles therefore retain a material scheduler reserve and
    cap concurrent workers at 128.  The workload remains substantial on large
    systems, while extended/overnight profiles retain the previous exhaustive
    behaviour for technicians deliberately selecting burn-in.  The plan is
    recorded in every evidence result so a PASS never implies an undisclosed
    all-thread burn-in.
    """
    detected = max(1, int(cpu_count or 1))
    profile_id = str(profile.profile_id or "").strip().upper()
    burn_in = profile_id in {"EXTENDED", "OVERNIGHT", "CUSTOM"}
    if burn_in:
        workers = max(1, min(256, detected - 1 if detected > 1 else 1))
        return {
            "cpu_count": detected,
            "cpu_workers": workers,
            "reserved_cpu_count": max(0, detected - workers),
            "cpu_policy": "BURN_IN_MAXIMUM_WITH_ONE_SCHEDULER_RESERVE",
            "memory_max_total_fraction": 0.70,
        }

    scheduler_reserve = max(1, (detected + 3) // 4)
    concurrent_capacity = max(1, detected - scheduler_reserve)
    workers = max(1, min(128, concurrent_capacity))
    return {
        "cpu_count": detected,
        "cpu_workers": workers,
        "reserved_cpu_count": max(0, detected - workers),
        "cpu_policy": "STANDARD_RESPONSIVE_RESERVE",
        "memory_max_total_fraction": 0.50,
    }


def _apply_stress_child_scheduling_guard() -> None:
    """Let local management, networking, and the console preempt stress-ng.

    This runs in the child immediately before ``stress-ng`` is executed.  It
    never changes a system-wide scheduler policy and intentionally tolerates
    platforms that reject a niceness adjustment.  The worker-count budget is
    the primary safety boundary; this is a second defence against a large
    all-method workload starving management daemons on a busy server.
    """
    try:
        os.nice(_STRESS_NICE_LEVEL)
    except OSError:
        pass


def read_memory_info(path: Path = Path("/proc/meminfo")) -> tuple[int, int]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return 2 * 1024**3, 1024**3
    values: dict[str, int] = {}
    for key in ("MemTotal", "MemAvailable"):
        match = re.search(rf"^{key}:\s*(\d+)\s*kB", text, re.MULTILINE)
        if match:
            values[key] = int(match.group(1)) * 1024
    total = values.get("MemTotal", 2 * 1024**3)
    available = values.get("MemAvailable", max(512 * 1024**2, total // 2))
    return total, available


def _parse_sensor_sample(text: str) -> dict[str, Any]:
    """Parse ``ipmitool sensor list`` using the actual health column.

    The sensor monitor runs independently of the inventory parser.  Keeping
    the same layout handling here is important: ``Name | Reading | Units |
    Status`` means the third column (``volts``, ``rpm``, ``degrees C``) is not
    a health state.  Treating it as one creates a false severe event and can
    terminate an otherwise successful stress phase.
    """
    rows: list[dict[str, str]] = []
    critical: list[dict[str, str]] = []
    temperatures: list[float] = []
    health_tokens = {
        "ok",
        "ns",
        "na",
        "nr",
        "nc",
        "cr",
        "unavailable",
        "disabled",
        "unknown",
    }
    for line in str(text or "").splitlines():
        parts = [part.strip() for part in line.split("|")]
        if len(parts) < 3 or not parts[0]:
            continue
        candidates = []
        if len(parts) >= 4:
            candidates.append(parts[3].lower())
        candidates.append(parts[2].lower())
        if parts[2].lower() == "discrete" and len(parts) >= 4 and re.fullmatch(r"0x[0-9a-f]+", parts[3].lower()):
            status = "ns"
        else:
            status = next((item for item in candidates if item in health_tokens), candidates[0] or "unavailable")
        row = {"sensor": parts[0], "reading": parts[1], "status": status}
        rows.append(row)
        if row["status"] not in {"ok", "ns", "na", "unavailable"}:
            critical.append(row)
        if re.search(r"temp|thermal", row["sensor"], re.IGNORECASE):
            match = re.search(r"-?\d+(?:\.\d+)?", row["reading"])
            if match:
                temperatures.append(float(match.group(0)))
    return {
        "row_count": len(rows),
        "critical_count": len(critical),
        "critical_rows": critical,
        "current_max_temp_c": max(temperatures) if temperatures else None,
    }


def _sel_count(text: str) -> int:
    match = re.search(r"^Entries\s*:\s*(\d+)\s*$", str(text or ""), re.MULTILINE | re.IGNORECASE)
    return int(match.group(1)) if match else 0


def _critical_kernel_lines(text: str) -> list[str]:
    return [
        line.strip()
        for line in str(text or "").splitlines()
        if re.search(r"MCE|machine check|EDAC.*error|uncorrectable|watchdog|out of memory|oom-kill|hardware error", line, re.IGNORECASE)
    ]


def _critical_sel_lines(text: str) -> list[str]:
    return [
        line.strip()
        for line in str(text or "").splitlines()
        if re.search(r"critical|fatal|fail|uncorrectable|overheat|non-recoverable", line, re.IGNORECASE)
    ]


def _monitor(
    executor: CommandExecutor,
    *,
    baseline_sel_count: int,
    baseline_kernel: set[str],
    baseline_critical_sel: set[str],
) -> dict[str, Any]:
    sensors = executor.run("ipmitool", ("sensor", "list"), timeout_seconds=60)
    sel_info = executor.run("ipmitool", ("sel", "info"), timeout_seconds=60)
    sel = executor.run("ipmitool", ("sel", "elist"), timeout_seconds=180)
    kernel = executor.run("dmesg", ("--level=emerg,alert,crit,err", "--color=never"), timeout_seconds=60)
    sensor_summary = _parse_sensor_sample(sensors.get("stdout", ""))
    sel_count = _sel_count(sel_info.get("stdout", ""))
    kernel_lines = set(_critical_kernel_lines(kernel.get("stdout", "")))
    new_kernel = sorted(kernel_lines - baseline_kernel)
    critical_sel = set(_critical_sel_lines(sel.get("stdout", "")))
    new_critical_sel = sorted(critical_sel - baseline_critical_sel)
    severe = bool(sensor_summary["critical_count"] or new_kernel or new_critical_sel)
    return {
        "sampled_at_utc": utc_now(),
        "sensors": sensor_summary,
        "sel_count": sel_count,
        "new_sel_count": max(0, sel_count - baseline_sel_count),
        "critical_sel_lines": new_critical_sel[-20:],
        "new_kernel_hw_errors": new_kernel[-20:],
        "severe_event": severe,
    }


def _phase_arguments(phase: StressPhase, *, cpu_workers: int, memory: Mapping[str, int]) -> tuple[str, ...]:
    arguments: list[str] = []
    if phase.cpu:
        arguments.extend(("--cpu", str(cpu_workers), "--cpu-method", "all"))
    if phase.memory:
        arguments.extend(
            (
                "--vm",
                str(memory["worker_count"]),
                "--vm-bytes",
                f"{memory['per_worker_mib']}M",
                "--vm-method",
                "all",
                "--vm-keep",
            )
        )
    arguments.extend(("--verify", "--timeout", f"{phase.duration_seconds}s", "--metrics-brief", "--times"))
    return tuple(arguments)


class _LocalKcsHostWatchdog:
    """Bounded local watchdog that recovers a kernel hang during stress.

    This uses only the host's local KCS/IPMI interface.  It never contacts a
    network BMC address and does not need a BMC password.  If the stress
    process and its monitor remain healthy, the watchdog is patted every
    sample and disabled at the end of the phase.  If the whole host becomes
    unresponsive, the BMC receives no pat and performs one hardware reset
    after the bounded timeout instead of leaving a technician with a silently
    hung server.

    Unsupported KCS/BMC implementations remain a visible capability result;
    they do not turn a normal stress run into a false pass or cause a guessed
    management operation.
    """

    def __init__(self, executor: CommandExecutor, *, timeout_seconds: int = _HOST_WATCHDOG_TIMEOUT_SECONDS) -> None:
        self.executor = executor
        self.timeout_seconds = int(timeout_seconds)
        self._armed = False
        self._attempts: list[dict[str, Any]] = []

    def _record(self, action: str, result: Mapping[str, Any]) -> bool:
        success = str(result.get("status") or "").upper() == "PASS" and result.get("exit_code") in {0, None}
        self._attempts.append(
            {
                "at_utc": utc_now(),
                "action": action,
                "status": "PASS" if success else "UNAVAILABLE",
                "exit_code": result.get("exit_code"),
                "reason": str(result.get("stderr") or "")[:240],
            }
        )
        return success

    def arm(self) -> bool:
        if self._armed:
            return self.pet()
        supported = self.executor.run("ipmitool", ("mc", "watchdog", "get"), timeout_seconds=30)
        if not self._record("DISCOVER", supported):
            return False
        configured = self.executor.run(
            "ipmitool",
            # ipmitool's documented watchdog grammar is key/value based.
            # Use SMS/OS explicitly and clear only that timer-use flag; this
            # avoids altering FRB2 or BIOS/POST watchdog semantics owned by
            # the platform firmware.
            (
                "mc",
                "watchdog",
                "set",
                f"timeout={self.timeout_seconds}",
                "action=reset",
                "use=sms",
                "clear=sms",
            ),
            timeout_seconds=30,
        )
        if not self._record("ARM", configured):
            return False
        self._armed = True
        if not self.pet():
            self.disarm()
            return False
        return True

    def pet(self) -> bool:
        if not self._armed:
            return False
        result = self.executor.run("ipmitool", ("mc", "watchdog", "reset"), timeout_seconds=30)
        return self._record("PAT", result)

    def disarm(self) -> None:
        if not self._armed:
            return
        result = self.executor.run("ipmitool", ("mc", "watchdog", "off"), timeout_seconds=30)
        self._record("DISARM", result)
        self._armed = False

    def evidence(self) -> dict[str, Any]:
        armed = any(item.get("action") == "ARM" and item.get("status") == "PASS" for item in self._attempts)
        disarmed = any(item.get("action") == "DISARM" and item.get("status") == "PASS" for item in self._attempts)
        return {
            "schema_version": 1,
            "transport": "LOCAL_KCS_IPMI_WATCHDOG",
            "timeout_seconds": self.timeout_seconds,
            "armed": armed,
            "disarmed": disarmed,
            "status": "ACTIVE_AND_CLEARED" if armed and disarmed else "UNAVAILABLE" if not armed else "CLEAR_FAILED",
            "attempts": self._attempts,
        }


class ExecutorProfileRunner:
    """Deterministic injected-executor path used by tests and offline simulations."""

    def run(
        self,
        profile: StressProfile,
        output: Path,
        *,
        executor: CommandExecutor,
        progress: ProgressCallback | None = None,
    ) -> dict[str, Any]:
        output.mkdir(parents=True, exist_ok=True)
        version = executor.run("stress-ng", ("--version",), timeout_seconds=30)
        total, available = read_memory_info()
        cpu_count = os.cpu_count() or 1
        resource_plan = production_resource_plan(profile, cpu_count=cpu_count)
        memory_workers = max(1, min(8, cpu_count // 8 or 1))
        sizing = memory_working_set(
            total_bytes=total,
            available_bytes=available,
            worker_count=memory_workers,
            max_total_fraction=float(resource_plan["memory_max_total_fraction"]),
        )
        cpu_workers = int(resource_plan["cpu_workers"])
        phases: list[dict[str, Any]] = []
        elapsed = 0
        for phase in profile.phases:
            if progress:
                progress({"event": "PHASE_STARTED", "phase": phase.name, "elapsed_seconds": elapsed, "remaining_seconds": profile.total_seconds - elapsed})
            if phase.cooldown:
                result = {"status": "PASS", "exit_code": 0, "command": [], "stdout": "", "stderr": ""}
            else:
                arguments = _phase_arguments(phase, cpu_workers=cpu_workers, memory=sizing)
                result = executor.run("stress-ng", arguments, timeout_seconds=min(7200, phase.duration_seconds + 120))
            phase_result = {
                "name": phase.name,
                "duration_seconds": phase.duration_seconds,
                "cpu": phase.cpu,
                "memory": phase.memory,
                "status": "PASS" if result.get("status") == "PASS" and result.get("exit_code", 0) in {0, None} else "FAIL",
                "exit_code": result.get("exit_code"),
                "command": result.get("command", []),
            }
            phases.append(phase_result)
            elapsed += phase.duration_seconds
            if progress:
                progress({"event": "PHASE_COMPLETED", "phase": phase.name, "status": phase_result["status"], "elapsed_seconds": elapsed, "remaining_seconds": profile.total_seconds - elapsed})
            _atomic_json(output / "stress-checkpoint.json", {"profile": profile.to_dict(), "phases": phases, "simulated": True})
        aggregate = _aggregate(profile, phases, [], sizing, cpu_workers, version, resource_plan=resource_plan)
        aggregate["verification_level"] = "UNIT_TESTED_OR_INJECTED_EXECUTOR"
        _atomic_json(output / "stress-profile-result.json", aggregate)
        return aggregate


class MonitoredStressRunner:
    """Real /usr/bin/stress-ng runner with continuous local safety sampling."""

    stress_binary = Path("/usr/bin/stress-ng")

    def run(
        self,
        profile: StressProfile,
        output: Path,
        *,
        executor: CommandExecutor,
        progress: ProgressCallback | None = None,
    ) -> dict[str, Any]:
        output.mkdir(parents=True, exist_ok=True)
        if not self.stress_binary.is_file() or not os.access(self.stress_binary, os.X_OK):
            raise StressProfileError("real stress provider is unavailable at /usr/bin/stress-ng")
        binary_hash = _sha256(self.stress_binary)
        version_result = subprocess.run(
            [str(self.stress_binary), "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
        if version_result.returncode != 0:
            raise StressProfileError("/usr/bin/stress-ng version verification failed")
        version = {"status": "PASS", "stdout": version_result.stdout, "command": [str(self.stress_binary), "--version"]}
        total, available = read_memory_info()
        cpu_count = os.cpu_count() or 1
        resource_plan = production_resource_plan(profile, cpu_count=cpu_count)
        cpu_workers = int(resource_plan["cpu_workers"])
        memory_workers = max(1, min(8, cpu_count // 8 or 1))
        sizing = memory_working_set(
            total_bytes=total,
            available_bytes=available,
            worker_count=memory_workers,
            max_total_fraction=float(resource_plan["memory_max_total_fraction"]),
        )

        baseline_sel = executor.run("ipmitool", ("sel", "info"), timeout_seconds=60)
        baseline_sel_log = executor.run("ipmitool", ("sel", "elist"), timeout_seconds=180)
        baseline_kernel_result = executor.run("dmesg", ("--level=emerg,alert,crit,err", "--color=never"), timeout_seconds=60)
        baseline_sel_count = _sel_count(baseline_sel.get("stdout", ""))
        baseline_kernel = set(_critical_kernel_lines(baseline_kernel_result.get("stdout", "")))
        baseline_critical_sel = set(_critical_sel_lines(baseline_sel_log.get("stdout", "")))
        phases: list[dict[str, Any]] = []
        samples: list[dict[str, Any]] = []
        host_watchdog = _LocalKcsHostWatchdog(executor)
        total_elapsed = 0
        peak_temp: float | None = None

        for phase_index, phase in enumerate(profile.phases, start=1):
            phase_start = time.monotonic()
            phase_started_at_utc = utc_now()
            if progress:
                progress({"event": "PHASE_STARTED", "phase": phase.name, "phase_index": phase_index, "phase_count": len(profile.phases), "elapsed_seconds": total_elapsed, "remaining_seconds": profile.total_seconds - total_elapsed})
            stdout_path = output / f"{phase_index:02d}-{phase.name.lower()}-stdout.txt"
            stderr_path = output / f"{phase_index:02d}-{phase.name.lower()}-stderr.txt"
            command: list[str] = []
            process: subprocess.Popen[str] | None = None
            return_code = 0
            severe = False
            if not phase.cooldown:
                command = [str(self.stress_binary), *_phase_arguments(phase, cpu_workers=cpu_workers, memory=sizing)]
                stdout_stream = stdout_path.open("w", encoding="utf-8")
                stderr_stream = stderr_path.open("w", encoding="utf-8")
                try:
                    # Arm immediately before the stress process.  A healthy
                    # monitor pets the bounded watchdog below; a host-wide
                    # stall therefore has a hardware escape path without
                    # relying on SSH, Codex, or a technician.
                    host_watchdog.arm()
                    process = subprocess.Popen(
                        command,
                        stdout=stdout_stream,
                        stderr=stderr_stream,
                        text=True,
                        start_new_session=True,
                        preexec_fn=_apply_stress_child_scheduling_guard,
                        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
                    )
                    while process.poll() is None:
                        host_watchdog.pet()
                        elapsed = min(phase.duration_seconds, int(time.monotonic() - phase_start))
                        sample = _monitor(
                            executor,
                            baseline_sel_count=baseline_sel_count,
                            baseline_kernel=baseline_kernel,
                            baseline_critical_sel=baseline_critical_sel,
                        )
                        sample.update({"phase": phase.name, "phase_elapsed_seconds": elapsed})
                        samples.append(sample)
                        current_temp = sample["sensors"].get("current_max_temp_c")
                        if isinstance(current_temp, (int, float)):
                            peak_temp = max(float(current_temp), peak_temp if peak_temp is not None else float(current_temp))
                        severe = severe or bool(sample["severe_event"])
                        if progress:
                            progress(
                                {
                                    "event": "MONITOR_SAMPLE",
                                    "phase": phase.name,
                                    "elapsed_seconds": total_elapsed + elapsed,
                                    "remaining_seconds": max(0, profile.total_seconds - total_elapsed - elapsed),
                                    "current_temp_c": current_temp,
                                    "peak_temp_c": peak_temp,
                                    "critical_sensors": sample["sensors"]["critical_count"],
                                    "new_critical_sel": len(sample["critical_sel_lines"]),
                                    "kernel_hw_errors": len(sample["new_kernel_hw_errors"]),
                                }
                            )
                        _atomic_json(
                            output / "stress-checkpoint.json",
                            {
                                "schema_version": 1,
                                "profile": profile.to_dict(),
                                "phase": phase.name,
                                "phase_index": phase_index,
                                "completed_phases": phases,
                                "latest_sample": sample,
                                "peak_temp_c": peak_temp,
                                "checkpointed_at_utc": utc_now(),
                            },
                        )
                        if severe:
                            os.killpg(process.pid, signal.SIGTERM)
                            break
                        time.sleep(max(1, min(profile.monitor_interval_seconds, 30)))
                    try:
                        return_code = process.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        return_code = process.wait(timeout=10)
                finally:
                    stdout_stream.close()
                    stderr_stream.close()
                    host_watchdog.disarm()
            else:
                deadline = phase_start + phase.duration_seconds
                while time.monotonic() < deadline:
                    sample = _monitor(
                        executor,
                        baseline_sel_count=baseline_sel_count,
                        baseline_kernel=baseline_kernel,
                        baseline_critical_sel=baseline_critical_sel,
                    )
                    sample.update({"phase": phase.name, "phase_elapsed_seconds": int(time.monotonic() - phase_start)})
                    samples.append(sample)
                    severe = severe or bool(sample["severe_event"])
                    if severe:
                        break
                    time.sleep(max(1, min(profile.monitor_interval_seconds, int(max(1, deadline - time.monotonic())))))
            phase_status = "PASS" if return_code == 0 and not severe else "FAIL"
            phase_result = {
                "name": phase.name,
                "duration_seconds": phase.duration_seconds,
                "cpu": phase.cpu,
                "memory": phase.memory,
                "command": command,
                "exit_code": return_code,
                "status": phase_status,
                "severe_monitor_event": severe,
                "started_at_utc": phase_started_at_utc,
                "stdout_path": str(stdout_path) if stdout_path.exists() else "",
                "stderr_path": str(stderr_path) if stderr_path.exists() else "",
            }
            phases.append(phase_result)
            total_elapsed += phase.duration_seconds
            if progress:
                progress({"event": "PHASE_COMPLETED", "phase": phase.name, "status": phase_status, "elapsed_seconds": total_elapsed, "remaining_seconds": max(0, profile.total_seconds - total_elapsed)})
            # A stressor exit failure without a severe monitor event is an
            # isolated capability result.  Continue independent phases so a
            # CPU failure does not hide memory and cooldown evidence.  A
            # severe sensor/kernel/SEL event still stops workload execution.
            if phase_status == "FAIL" and severe:
                break

        aggregate = _aggregate(profile, phases, samples, sizing, cpu_workers, version, resource_plan=resource_plan)
        aggregate.update(
            {
                "verification_level": "PHYSICAL_RUNTIME_EXECUTION",
                "stress_binary": str(self.stress_binary),
                "stress_binary_sha256": binary_hash,
                "stress_nice_level": _STRESS_NICE_LEVEL,
                "peak_temp_c": peak_temp,
                "baseline_sel_count": baseline_sel_count,
                "host_watchdog": host_watchdog.evidence(),
            }
        )
        _atomic_json(output / "stress-profile-result.json", aggregate)
        return aggregate


def _aggregate(
    profile: StressProfile,
    phases: list[dict[str, Any]],
    samples: list[dict[str, Any]],
    memory: Mapping[str, int],
    cpu_workers: int,
    version: Mapping[str, Any],
    *,
    resource_plan: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    def status_for(kind: str) -> str:
        relevant = [item for item in phases if item.get(kind)]
        if not relevant:
            return "NOT_TESTED"
        return "PASS" if all(item.get("status") == "PASS" for item in relevant) else "FAIL"

    monitor_failure = any(item.get("severe_event") for item in samples)
    all_pass = bool(phases) and all(item.get("status") == "PASS" for item in phases) and not monitor_failure
    return {
        "schema_version": 2,
        "profile": profile.to_dict(),
        "stress_binary": "/usr/bin/stress-ng",
        "stress_version": str(version.get("stdout") or "").strip(),
        "stress_version_status": version.get("status", "UNKNOWN"),
        "cpu_workers": cpu_workers,
        "resource_plan": dict(resource_plan or {}),
        "memory_allocation": dict(memory),
        "phases": phases,
        "monitor_samples": samples,
        "monitoring": {
            "continuous": bool(samples),
            "severe_event": monitor_failure,
            "critical_sensor_samples": sum(1 for item in samples if item.get("sensors", {}).get("critical_count")),
            "new_critical_sel_samples": sum(1 for item in samples if item.get("critical_sel_lines")),
            "kernel_hw_error_samples": sum(1 for item in samples if item.get("new_kernel_hw_errors")),
        },
        "boot_media_stressed": False,
        "destructive_storage_test": False,
        "cpu": {"status": status_for("cpu")},
        "memory": {"status": status_for("memory")},
        "combined": {"status": "PASS" if all(item.get("status") == "PASS" for item in phases if item.get("cpu") and item.get("memory")) else "FAIL"},
        "status": "PASS" if all_pass else "FAIL",
        "pass_requires_workload_and_monitoring": True,
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _atomic_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        Path(temporary_name).replace(path)
    finally:
        temporary = Path(temporary_name)
        if temporary.exists():
            temporary.unlink()
