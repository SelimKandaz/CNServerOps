"""Runnable TLS Central Collector service for the initial Windows deployment."""

from __future__ import annotations

import argparse
import json
import os
import signal
import sqlite3
import ssl
import threading
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

from .central_api import CentralApiApp, central_credential_from_env
from .collector import CentralCollector


class ThreadingWsgiServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True


class QuietHandler(WSGIRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        # Request logs contain method/path/status only; Authorization is never logged.
        super().log_message(format, *args)


class ExportingApp:
    """Refresh the non-authoritative CSV after each accepted event."""

    def __init__(self, app: CentralApiApp, collector: CentralCollector, destination: Path) -> None:
        self.app = app
        self.collector = collector
        self.destination = destination
        self._lock = threading.Lock()

    def __call__(self, environ: dict[str, Any], start_response: Any) -> Any:
        status: list[str] = []

        def capture(value: str, headers: Any, exc_info: Any = None) -> Any:
            status.append(value)
            return start_response(value, headers, exc_info)

        response = self.app(environ, capture)
        if (
            status
            and status[0].startswith("200 ")
            and environ.get("REQUEST_METHOD") == "POST"
            and environ.get("PATH_INFO") == "/v1/events"
        ):
            with self._lock:
                self.collector.export_production_csv(self.destination)
        return response


def serve(
    *,
    root: Path,
    bind: str,
    port: int,
    certificate: Path,
    private_key: Path,
    token_environment: str = "CNSERVEROPS_CENTRAL_TOKEN",
    fleet_archive_root: Path | None = None,
    secondary_archive_root: Path | None = None,
) -> None:
    root = root.resolve()
    data_root = root / "data"
    export_root = root / "exports"
    data_root.mkdir(parents=True, exist_ok=True)
    export_root.mkdir(parents=True, exist_ok=True)
    collector = CentralCollector(data_root / "central.sqlite3")
    collector.initialize()
    credential = central_credential_from_env(token_environment)
    core_app = CentralApiApp(
        collector,
        credential=credential,
        artifact_root=root / "Servers",
        fleet_archive_root=fleet_archive_root
        or Path(r"C:\Users\TechTrade Operations\Desktop\ASUS Server LOGS"),
        secondary_archive_root=secondary_archive_root
        or Path(r"\\10.1.10.12\public\Operations\Selim Programs"),
    )
    app = ExportingApp(
        core_app,
        collector,
        export_root / "ASUS_PRODUCTION_MASTER.csv",
    )
    httpd = make_server(
        bind,
        port,
        app,
        server_class=ThreadingWsgiServer,
        handler_class=QuietHandler,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(certificate), str(private_key))
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    retry_stop = threading.Event()

    def retry_secondary_archives() -> None:
        # The optional UNC mirror may be offline when an SSD uploads an
        # artifact. Retry centrally without involving a technician, the SSD,
        # or the already-completed server run. Errors are intentionally not
        # logged with paths/credentials; the durable retry DB retains state.
        while not retry_stop.is_set():
            try:
                core_app.retry_pending_secondary_archives(limit=100)
            except Exception:
                pass
            retry_stop.wait(60)

    retry_thread = threading.Thread(
        target=retry_secondary_archives,
        name="cnserverops-secondary-archive-retry",
        daemon=True,
    )
    retry_thread.start()

    def stop(_signum: int, _frame: Any) -> None:
        # shutdown() is safe from a signal handler on the Windows main thread.
        retry_stop.set()
        httpd.server_close()
        raise SystemExit(0)

    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(signum, stop)
        except (OSError, ValueError):
            pass
    print(json.dumps({"status": "LISTENING", "bind": bind, "port": port, "tls": True}), flush=True)
    try:
        httpd.serve_forever(poll_interval=0.5)
    finally:
        retry_stop.set()
        retry_thread.join(timeout=2)
        collector.export_production_csv(export_root / "ASUS_PRODUCTION_MASTER.csv")
        httpd.server_close()


def backup_database(database: Path, destination: Path) -> dict[str, Any]:
    database = database.resolve(strict=True)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise FileExistsError(f"Backup destination already exists: {destination}")
    source_connection = sqlite3.connect(database)
    destination_connection = sqlite3.connect(destination)
    try:
        with destination_connection:
            source_connection.backup(destination_connection)
    finally:
        destination_connection.close()
        source_connection.close()
    return {"status": "BACKED_UP", "source": str(database), "destination": str(destination)}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="CNServerOps Central Collector runtime")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("serve")
    run.add_argument("--root", type=Path, required=True)
    run.add_argument("--bind", default="0.0.0.0")
    run.add_argument("--port", type=int, default=8088)
    run.add_argument("--cert", type=Path, required=True)
    run.add_argument("--key", type=Path, required=True)
    run.add_argument("--token-env", default="CNSERVEROPS_CENTRAL_TOKEN")
    run.add_argument(
        "--fleet-archive-root",
        type=Path,
        default=Path(r"C:\Users\TechTrade Operations\Desktop\ASUS Server LOGS"),
    )
    run.add_argument(
        "--secondary-archive-root",
        type=Path,
        default=Path(r"\\10.1.10.12\public\Operations\Selim Programs"),
    )
    export = commands.add_parser("export")
    export.add_argument("--database", type=Path, required=True)
    export.add_argument("--destination", type=Path, required=True)
    backup = commands.add_parser("backup")
    backup.add_argument("--database", type=Path, required=True)
    backup.add_argument("--destination", type=Path, required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "serve":
        if not (1 <= args.port <= 65535):
            raise SystemExit("port must be in range 1..65535")
        serve(
            root=args.root,
            bind=args.bind,
            port=args.port,
            certificate=args.cert,
            private_key=args.key,
            token_environment=args.token_env,
            fleet_archive_root=args.fleet_archive_root,
            secondary_archive_root=args.secondary_archive_root,
        )
        return 0
    if args.command == "export":
        result = CentralCollector(args.database).export_production_csv(args.destination)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if args.command == "backup":
        print(json.dumps(backup_database(args.database, args.destination), indent=2, sort_keys=True))
        return 0
    raise SystemExit("unsupported command")


if __name__ == "__main__":
    raise SystemExit(main())
