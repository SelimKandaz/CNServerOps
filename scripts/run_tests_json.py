#!/usr/bin/env python3
"""Run the complete unittest suite and emit a machine-readable receipt."""

from __future__ import annotations

import argparse
import io
import json
import sys
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class RecordingResult(unittest.TextTestResult):
    def startTest(self, test: unittest.TestCase) -> None:
        super().startTest(test)
        self._current_started = time.monotonic()

    def stopTest(self, test: unittest.TestCase) -> None:
        duration = round(time.monotonic() - self._current_started, 6)
        self.test_durations.append({"test": test.id(), "duration_seconds": duration})
        super().stopTest(test)


class RecordingRunner(unittest.TextTestRunner):
    resultclass = RecordingResult

    def _makeResult(self):
        result = super()._makeResult()
        result.test_durations = []
        return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tests", type=Path, default=Path("tests"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.discover(str(args.tests))
    captured = io.StringIO()
    started = time.monotonic()
    result = RecordingRunner(stream=captured, verbosity=2).run(suite)
    failed = {test.id(): detail for test, detail in result.failures}
    errors = {test.id(): detail for test, detail in result.errors}
    skipped = {test.id(): reason for test, reason in result.skipped}
    tests = []
    for timing in result.test_durations:
        test_id = timing["test"]
        status = "FAIL" if test_id in failed else "ERROR" if test_id in errors else "SKIP" if test_id in skipped else "PASS"
        tests.append(
            timing
            | {
                "status": status,
                "skip_reason": skipped.get(test_id, ""),
                "diagnostic": (failed.get(test_id) or errors.get(test_id) or "")[:4000],
            }
        )
    payload = {
        "schema_version": 1,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "python": sys.version.split()[0],
        "command": "python scripts/run_tests_json.py --tests tests --output <path>",
        "duration_seconds": round(time.monotonic() - started, 6),
        "total": result.testsRun,
        "passed": sum(1 for item in tests if item["status"] == "PASS"),
        "failed": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "successful": result.wasSuccessful(),
        "tests": tests,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
