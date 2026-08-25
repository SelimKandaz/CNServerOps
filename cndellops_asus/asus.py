"""ASUS-focused normalization layered on standard, read-only Redfish discovery."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from cnserverops.capabilities import CapabilityRecord, ValidationLevel
from cnserverops.secrets import sanitize_evidence

from .identity import derive_identity
from .redfish import ReadOnlyRedfishClient, RedfishRequestError


def _odata_path(value: Any) -> str | None:
    return value.get("@odata.id") if isinstance(value, dict) and isinstance(value.get("@odata.id"), str) else None


class AsusDiscoveryAdapter:
    """Collect common ASUS BMC capability/evidence using GET requests only.

    The adapter follows links advertised by the live Redfish service.  It is not
    tied to an ASUS model or ASMB generation; small generation overlays belong
    outside this common discovery layer.
    """

    def __init__(self, client: ReadOnlyRedfishClient) -> None:
        self.client = client
        self.errors: list[dict[str, Any]] = []
        self.raw: dict[str, dict[str, Any]] = {}
        self.endpoint_catalog: list[dict[str, Any]] = []

    def _get(self, path: str, label: str) -> dict[str, Any]:
        try:
            response = self.client.get_json(path)
            payload = sanitize_evidence(response.payload)
            self.raw[label] = payload
            self.endpoint_catalog.append(self._endpoint_record(label, path, response.status, payload))
            return payload
        except RedfishRequestError as exc:
            failure = {"label": label, **exc.to_dict(), "error": str(exc)}
            self.errors.append(failure)
            self.endpoint_catalog.append(
                {
                    "label": label,
                    "endpoint": path,
                    "http_method_used": "GET",
                    "status": exc.http_status or exc.kind.value,
                    "schema_type": "",
                    "important_actions": [],
                    "important_oem_properties": [],
                    "request_classification": "READ_ONLY",
                    "mutating_capability_advertised": False,
                }
            )
            return {}

    def _first_member(self, collection: dict[str, Any]) -> str | None:
        members = collection.get("Members", [])
        if isinstance(members, list):
            for member in members:
                path = _odata_path(member)
                if path:
                    return path
        return None

    def _collect_collection(self, path: str | None, label: str, limit: int = 64) -> list[dict[str, Any]]:
        if not path:
            return []
        collection = self._get(path, label)
        values: list[dict[str, Any]] = []
        for index, member in enumerate(collection.get("Members", []) if isinstance(collection.get("Members"), list) else []):
            if index >= limit:
                self.errors.append({"label": label, "path": path, "error": f"collection limited to {limit} members"})
                break
            member_path = _odata_path(member)
            if member_path:
                values.append(self._get(member_path, f"{label}_{index}"))
        return values

    def discover(self) -> dict[str, Any]:
        service_root = self._get("/redfish/v1/", "service_root")
        systems = self._get(_odata_path(service_root.get("Systems")) or "/redfish/v1/Systems", "systems")
        managers = self._get(_odata_path(service_root.get("Managers")) or "/redfish/v1/Managers", "managers")
        chassis_collection = self._get(_odata_path(service_root.get("Chassis")) or "/redfish/v1/Chassis", "chassis")

        system_path = self._first_member(systems) or "/redfish/v1/Systems/Self"
        manager_path = self._first_member(managers) or "/redfish/v1/Managers/Self"
        chassis_path = self._first_member(chassis_collection) or "/redfish/v1/Chassis/Self"
        system = self._get(system_path, "system")
        manager = self._get(manager_path, "manager")
        chassis = self._get(chassis_path, "chassis_detail")

        fru = self._get(_odata_path(chassis.get("Fru")) or f"{chassis_path}/Fru", "fru")
        thermal = self._get(_odata_path(chassis.get("Thermal")) or f"{chassis_path}/Thermal", "thermal")
        power = self._get(_odata_path(chassis.get("Power")) or f"{chassis_path}/Power", "power")
        update_service = self._get(_odata_path(service_root.get("UpdateService")) or "/redfish/v1/UpdateService", "update_service")
        task_service = self._get(_odata_path(service_root.get("TaskService")) or "/redfish/v1/TaskService", "task_service")
        event_service = self._get(_odata_path(service_root.get("EventService")) or "/redfish/v1/EventService", "event_service")
        telemetry_service = self._get(
            _odata_path(service_root.get("TelemetryService")) or "/redfish/v1/TelemetryService",
            "telemetry_service",
        )
        account_service = self._get(
            _odata_path(service_root.get("AccountService")) or "/redfish/v1/AccountService",
            "account_service",
        )
        session_service = self._get(
            _odata_path(service_root.get("SessionService")) or "/redfish/v1/SessionService",
            "session_service",
        )
        bios = self._get(_odata_path(system.get("Bios")) or f"{system_path}/Bios", "bios")

        processors = self._collect_collection(_odata_path(system.get("Processors")), "processors")
        memory = self._collect_collection(_odata_path(system.get("Memory")), "memory")
        storage = self._collect_collection(_odata_path(system.get("Storage")), "storage")
        ethernet_interfaces = self._collect_collection(_odata_path(system.get("EthernetInterfaces")), "ethernet_interfaces")
        network_interfaces = self._collect_collection(_odata_path(system.get("NetworkInterfaces")), "network_interfaces")
        network_adapters = self._collect_collection(_odata_path(system.get("NetworkAdapters")), "network_adapters")
        pcie_devices = self._collect_collection(_odata_path(system.get("PCIeDevices")), "pcie_devices")
        pcie_functions: list[dict[str, Any]] = []
        for index, device in enumerate(pcie_devices):
            pcie_functions.extend(
                self._collect_collection(_odata_path(device.get("PCIeFunctions")), f"pcie_functions_{index}")
            )
        sensors = self._collect_collection(_odata_path(chassis.get("Sensors")), "sensors", limit=256)
        manager_ethernet_interfaces = self._collect_collection(
            _odata_path(manager.get("EthernetInterfaces")), "manager_ethernet_interfaces"
        )
        manager_network_protocol = self._get(
            _odata_path(manager.get("NetworkProtocol")) or f"{manager_path}/NetworkProtocol",
            "manager_network_protocol",
        )
        firmware = self._collect_collection(_odata_path(update_service.get("FirmwareInventory")), "firmware_inventory")
        software = self._collect_collection(_odata_path(update_service.get("SoftwareInventory")), "software_inventory")
        tasks = self._collect_collection(_odata_path(task_service.get("Tasks")), "tasks", limit=128)

        system_logs = self._get(_odata_path(system.get("LogServices")) or f"{system_path}/LogServices", "system_log_services")
        manager_logs = self._get(_odata_path(manager.get("LogServices")) or f"{manager_path}/LogServices", "manager_log_services")
        system_log_entries = self._collect_log_entries(system_logs, "system_log")
        manager_log_entries = self._collect_log_entries(manager_logs, "manager_log")
        oem_resources = self._collect_oem_resources(
            [
                service_root,
                system,
                manager,
                chassis,
                bios,
                update_service,
                task_service,
                event_service,
                telemetry_service,
                account_service,
                session_service,
            ]
        )
        identity = derive_identity(system, fru, manager)
        capability_records = self._capability_records(
            model=str(identity.get("model") or "ASUS model not reported"),
            service_root=service_root,
            inventory_present=bool(system or chassis or processors or memory or storage),
            event_logs_present=bool(system_log_entries or manager_log_entries),
            firmware_inventory_present=bool(firmware),
            task_service_present=bool(task_service),
        )

        return {
            "schema_version": 2,
            "adapter": "asus_common_redfish_read_only",
            "collected_at_utc": datetime.now(timezone.utc).isoformat(),
            "authentication": getattr(self.client, "authentication_status", {"available": False, "mode": "UNKNOWN"}),
            "identity": identity,
            "capabilities": {
                "redfish_service_root": bool(service_root),
                "firmware_inventory": bool(firmware) or bool(_odata_path(update_service.get("FirmwareInventory"))),
                "update_service_advertised": bool(update_service),
                "system_event_log": bool(system_log_entries),
                "bmc_sel": bool(manager_log_entries),
                "thermal": bool(thermal),
                "power": bool(power),
                "bios": bool(bios),
                "ethernet_interfaces": bool(ethernet_interfaces or network_interfaces),
                "network_adapters": bool(network_adapters),
                "pcie_devices": bool(pcie_devices),
                "pcie_functions": bool(pcie_functions),
                "sensors": bool(sensors),
                "task_service_advertised": bool(task_service),
                "event_service_advertised": bool(event_service),
                "telemetry_service_advertised": bool(telemetry_service),
                "software_inventory": bool(software),
                "account_service_advertised": bool(account_service),
                "session_service_advertised": bool(session_service),
                "oem_resources": bool(oem_resources),
            },
            "capability_records": [record.to_dict() for record in capability_records],
            "normalized": {
                "system": system,
                "manager": manager,
                "chassis": chassis,
                "fru": fru,
                "thermal": thermal,
                "power": power,
                "bios": bios,
                "processors": processors,
                "memory": memory,
                "storage": storage,
                "ethernet_interfaces": ethernet_interfaces,
                "network_interfaces": network_interfaces,
                "network_adapters": network_adapters,
                "pcie_devices": pcie_devices,
                "pcie_functions": pcie_functions,
                "sensors": sensors,
                "manager_ethernet_interfaces": manager_ethernet_interfaces,
                "manager_network_protocol": manager_network_protocol,
                "firmware_inventory": firmware,
                "software_inventory": software,
                "tasks": tasks,
                "event_service": event_service,
                "telemetry_service": telemetry_service,
                "account_service": account_service,
                "session_service": session_service,
                "update_mechanisms": self._extract_update_mechanisms(update_service),
                "diagnostic_action_candidates": self._diagnostic_candidates(oem_resources),
                "oem_resources": oem_resources,
                "system_log_entries": system_log_entries,
                "manager_log_entries": manager_log_entries,
            },
            "raw_endpoints": self.raw,
            "endpoint_catalog": self.endpoint_catalog,
            "collection_errors": self.errors,
            "safety": {
                "mode": "read_only",
                "methods_issued": ["GET"],
                "firmware_actions": "not implemented",
                "event_log_clear": "not implemented",
                "power_actions": "not implemented",
            },
        }

    @staticmethod
    def _endpoint_record(label: str, path: str, status: int, payload: dict[str, Any]) -> dict[str, Any]:
        actions: list[str] = []
        oem_properties: list[str] = []

        def visit(value: Any, prefix: str = "") -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    current = f"{prefix}.{key}" if prefix else str(key)
                    if key.startswith("#"):
                        actions.append(current)
                    if prefix.startswith("Oem") or ".Oem" in prefix:
                        oem_properties.append(current)
                    visit(child, current)
            elif isinstance(value, list):
                for index, child in enumerate(value[:64]):
                    visit(child, f"{prefix}[{index}]")

        visit(payload.get("Actions") or {}, "Actions")
        visit(payload.get("Oem") or {}, "Oem")
        advertised_write_fields = [
            key
            for key in ("HttpPushUri", "MultipartHttpPushUri", "FirmwareInventory", "SoftwareInventory")
            if payload.get(key)
        ]
        return {
            "label": label,
            "endpoint": path,
            "http_method_used": "GET",
            "status": status,
            "schema_type": str(payload.get("@odata.type") or ""),
            "important_actions": sorted(set(actions)),
            "important_oem_properties": sorted(set(oem_properties))[:128],
            "advertised_update_fields": advertised_write_fields,
            "request_classification": "READ_ONLY",
            "mutating_capability_advertised": bool(actions or advertised_write_fields),
        }

    @staticmethod
    def _extract_update_mechanisms(update_service: dict[str, Any]) -> list[dict[str, Any]]:
        mechanisms: list[dict[str, Any]] = []
        for key in ("MultipartHttpPushUri", "HttpPushUri"):
            if isinstance(update_service.get(key), str):
                mechanisms.append({"kind": key, "target": update_service[key], "advertised": True})
        actions = update_service.get("Actions") if isinstance(update_service.get("Actions"), dict) else {}
        # OEM actions are nested below ``Actions.Oem``.  Flatten the concrete
        # child actions so capability discovery preserves each advertised
        # target URI and ActionInfo contract (rather than recording only the
        # non-actionable parent ``Oem`` object).
        flattened: list[tuple[str, Any]] = []
        for name, action in actions.items():
            if str(name).casefold() == "oem" and isinstance(action, dict):
                flattened.extend((str(child_name), child_action) for child_name, child_action in action.items())
            else:
                flattened.append((str(name), action))
        for name, action in flattened:
            if not isinstance(action, dict):
                continue
            target = action.get("target") or action.get("Target")
            mechanisms.append(
                {
                    "kind": str(name),
                    "target": str(target or ""),
                    "advertised": bool(target),
                    "parameters": sorted(
                        key for key in action if key not in {"target", "Target", "@Redfish.ActionInfo"}
                    ),
                    "action_info": _odata_path(action.get("@Redfish.ActionInfo")),
                }
            )
        return mechanisms

    @staticmethod
    def _diagnostic_candidates(resources: list[dict[str, Any]]) -> list[dict[str, str]]:
        candidates: list[dict[str, str]] = []

        def visit(value: Any, prefix: str = "") -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    current = f"{prefix}.{key}" if prefix else str(key)
                    lowered = current.lower()
                    if any(term in lowered for term in ("diagnostic", "supportdata", "support_data", "tsr")):
                        target = child.get("target") if isinstance(child, dict) else ""
                        candidates.append({"property": current, "target": str(target or "")})
                    visit(child, current)
            elif isinstance(value, list):
                for index, child in enumerate(value[:64]):
                    visit(child, f"{prefix}[{index}]")

        for resource in resources:
            visit(resource)
        unique = {(item["property"], item["target"]): item for item in candidates}
        return list(unique.values())

    def _collect_log_entries(self, services: dict[str, Any], label: str) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        for index, service in enumerate(
            services.get("Members", []) if isinstance(services.get("Members"), list) else []
        ):
            service_path = _odata_path(service)
            if not service_path:
                continue
            detail = self._get(service_path, f"{label}_service_{index}")
            entry_path = _odata_path(detail.get("Entries"))
            entries.extend(self._collect_collection(entry_path, f"{label}_entries_{index}", limit=256))
        return entries

    def _collect_oem_resources(self, payloads: list[dict[str, Any]], limit: int = 64) -> list[dict[str, Any]]:
        """Follow only OEM links advertised by already-read resources, with a hard limit."""
        paths: list[str] = []

        def visit(value: Any, inside_oem: bool = False) -> None:
            if isinstance(value, dict):
                current_oem = inside_oem or "Oem" in value
                if inside_oem and isinstance(value.get("@odata.id"), str):
                    paths.append(value["@odata.id"])
                for key, child in value.items():
                    visit(child, current_oem or key == "Oem")
            elif isinstance(value, list):
                for child in value:
                    visit(child, inside_oem)

        for payload in payloads:
            oem = payload.get("Oem") if isinstance(payload, dict) else None
            if oem is not None:
                visit(oem, True)

        resources: list[dict[str, Any]] = []
        for index, path in enumerate(dict.fromkeys(paths)):
            if index >= limit:
                self.errors.append(
                    {"label": "oem_resources", "path": "advertised OEM links", "status": "LIMIT_REACHED", "error": f"limited to {limit} OEM links"}
                )
                break
            resources.append(self._get(path, f"oem_resource_{index}"))
        return [item for item in resources if item]

    def _capability_records(
        self,
        *,
        model: str,
        service_root: dict[str, Any],
        inventory_present: bool,
        event_logs_present: bool,
        firmware_inventory_present: bool,
        task_service_present: bool,
    ) -> list[CapabilityRecord]:
        common = {
            "supported_model": model,
            "failure_behavior": "Record the endpoint error and continue with remaining read-only evidence.",
            "timeout_behavior": f"Fail the individual GET after {self.client.timeout_seconds} seconds.",
            "safe_for_production": False,
        }
        return [
            CapabilityRecord(
                capability="ASUS Redfish service discovery",
                mechanism_used="ASUS common HTTPS Redfish",
                raw_command_api="GET /redfish/v1/ and follow advertised resource links",
                raw_evidence="raw_endpoints.service_root",
                normalized_result={"available": bool(service_root)},
                fallback="OS-local DMI inventory; no BMC mutation.",
                validation_level=self._validation_for(("service_root",), bool(service_root)),
                **common,
            ),
            CapabilityRecord(
                capability="ASUS normalized hardware inventory",
                mechanism_used="Redfish Systems/Chassis plus OS-local evidence",
                raw_command_api="GET advertised Systems, Chassis, Processors, Memory, Storage, NIC, PCIe, Power, Thermal and Sensor resources",
                raw_evidence="raw_endpoints plus normalized inventory",
                normalized_result={"available": inventory_present},
                fallback="dmidecode, lspci, lsblk, nvme, smartctl and approved IPMI evidence.",
                validation_level=self._validation_for(("systems", "system", "chassis"), inventory_present),
                **common,
            ),
            CapabilityRecord(
                capability="ASUS event-log collection",
                mechanism_used="Redfish LogServices GET",
                raw_command_api="GET advertised Systems/Managers LogServices and Entries",
                raw_evidence="normalized.system_log_entries and normalized.manager_log_entries",
                normalized_result={"entries_collected": event_logs_present},
                fallback="Read-only ipmitool SEL export after lab validation; never clear automatically.",
                validation_level=self._validation_for(("system_log_services", "manager_log_services"), event_logs_present),
                **common,
            ),
            CapabilityRecord(
                capability="ASUS firmware inventory",
                mechanism_used="Redfish UpdateService GET",
                raw_command_api="GET UpdateService and advertised FirmwareInventory members",
                raw_evidence="normalized.firmware_inventory",
                normalized_result={"available": firmware_inventory_present},
                fallback="Report unavailable; firmware application remains blocked.",
                validation_level=self._validation_for(("update_service", "firmware_inventory"), firmware_inventory_present),
                **common,
            ),
            CapabilityRecord(
                capability="ASUS update task discovery",
                mechanism_used="Redfish TaskService GET",
                raw_command_api="GET TaskService and advertised Tasks collection",
                raw_evidence="normalized.tasks",
                normalized_result={"task_service_available": task_service_present},
                fallback="No update action; require technician review.",
                validation_level=self._validation_for(("task_service", "tasks"), task_service_present),
                **common,
            ),
        ]

    def _validation_for(self, labels: tuple[str, ...], present: bool) -> ValidationLevel:
        if present:
            return ValidationLevel.DETECTED
        statuses = {
            str(item.get("status") or "")
            for item in self.errors
            if any(str(item.get("label") or "").startswith(label) for label in labels)
        }
        if "BLOCKED_BY_AUTH" in statuses:
            return ValidationLevel.BLOCKED_BY_AUTH
        if "BLOCKED_BY_MISSING_ENDPOINT" in statuses:
            return ValidationLevel.BLOCKED_BY_MISSING_ENDPOINT
        if statuses & {"TIMEOUT", "TRANSPORT_ERROR", "MALFORMED_RESPONSE", "HTTP_ERROR"}:
            return ValidationLevel.UNKNOWN
        return ValidationLevel.IMPLEMENTED


# Explicit name for new callers while retaining AsusDiscoveryAdapter compatibility.
AsusCommonDiscoveryAdapter = AsusDiscoveryAdapter
