"""Command-line interface for the intentionally read-only initial ASUS adapter."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .asus import AsusDiscoveryAdapter
from .bundle import build_support_bundle, write_discovery
from .redfish import ReadOnlyRedfishClient, credentials_from_runtime


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description="CNDellOps ASUS read-only Redfish discovery")
    command.add_argument("action", choices=("discover", "support-bundle"))
    command.add_argument("--bmc-host", required=True, help="BMC DNS name or IP address")
    command.add_argument("--username", default="", help="BMC account name; omit when a runtime token is used")
    command.add_argument("--password-env", default="CN_ASUS_BMC_PASSWORD", help="environment variable holding BMC password")
    command.add_argument("--token-env", default="CN_ASUS_BMC_TOKEN", help="environment variable holding a short-lived BMC token")
    command.add_argument("--interactive", action="store_true", help="prompt securely when no environment secret is available")
    command.add_argument("--output", type=Path, required=True, help="local result directory")
    command.add_argument("--insecure", action="store_true", help="disable TLS certificate validation for an approved lab only")
    command.add_argument("--timeout", type=int, default=20, help="per-request timeout in seconds")
    return command


def main() -> int:
    args = parser().parse_args()
    credentials = credentials_from_runtime(
        username=args.username,
        password_env=args.password_env,
        token_env=args.token_env,
        interactive=args.interactive,
    )
    if not credentials.available:
        raise SystemExit("BMC credential is unavailable; supply a runtime environment secret or use --interactive.")
    client = ReadOnlyRedfishClient(
        args.bmc_host,
        credentials=credentials,
        verify_tls=not args.insecure,
        timeout_seconds=args.timeout,
    )
    discovery = AsusDiscoveryAdapter(client).discover()
    discovery_path = write_discovery(args.output, discovery)
    result = {"discovery": str(discovery_path), "identity": discovery["identity"], "errors": discovery["collection_errors"]}
    if args.action == "support-bundle":
        result["support_bundle"] = str(build_support_bundle(args.output, discovery_path, discovery))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
