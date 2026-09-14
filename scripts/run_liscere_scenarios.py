#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover - graceful fallback
    yaml = None


DEFAULT_BASE_URL = "http://localhost:8000"
DEFAULT_SESSION_ID = "sess_v2_docker_local"
DEFAULT_SCENARIO_DIR = Path("studies/liscere/scenarios")
DEFAULT_OUTPUT_DIR = Path("studies/evidence/liscere_contextual_v0_1")
DEFAULT_WAIT_SECONDS = 1.25
SCENARIO_DEDUP_PREFERENCE = ("json", "yaml", "yml")

SUMMARY_COLUMNS = [
    "scenario_id",
    "title",
    "expected_decision",
    "actual_decision",
    "match",
    "expected_rule",
    "matched_rule",
    "artefact",
    "address",
    "value",
    "maintenance_window",
    "evidence_complete",
    "notes",
]


BUILTIN_SCENARIOS: list[dict[str, Any]] = [
    {
        "scenario_id": "SCN-MODBUS-SETPOINT-001",
        "title": "Valid mapped setpoint write within range",
        "description": "A client writes a valid value to a known pump flow setpoint through the monitored Modbus/TCP path.",
        "protocol_carrier": "Modbus/TCP",
        "api_action": {"endpoint": "/api/v2/lab/write-register", "method": "POST", "payload": {"register": 1, "value": 50, "unit_id": 1}},
        "protocol_operation": {"function": "write_register", "target_register": 1, "value": 50},
        "industrial_action": {"type": "write_setpoint", "value": 50},
        "automation_artefact": {"id": "PUMP_FLOW_SP", "class": "setpoint", "allowed_range": {"min": 0, "max": 100}, "mapping_confidence": "known"},
        "operational_context": {"operating_mode": "normal_operation", "maintenance_status": "not_in_maintenance", "maintenance_window": False},
        "policy_constraint": {"id": "OBS-R000", "rule": "mapped write within expected range should be allowed"},
        "expected_decision": "ALLOW",
        "expected_rule": "OBS-R000",
        "rationale": "The target artefact is known and the value is within the declared operating envelope.",
    },
    {
        "scenario_id": "SCN-MODBUS-SETPOINT-002",
        "title": "Mapped setpoint write outside operational envelope",
        "description": "A client writes an out-of-range value to a known pump flow setpoint through the monitored Modbus/TCP path.",
        "protocol_carrier": "Modbus/TCP",
        "api_action": {"endpoint": "/api/v2/lab/write-register", "method": "POST", "payload": {"register": 1, "value": 150, "unit_id": 1}},
        "protocol_operation": {"function": "write_register", "target_register": 1, "value": 150},
        "industrial_action": {"type": "write_setpoint", "value": 150},
        "automation_artefact": {"id": "PUMP_FLOW_SP", "class": "setpoint", "allowed_range": {"min": 0, "max": 100}, "mapping_confidence": "known"},
        "operational_context": {"operating_mode": "normal_operation", "maintenance_status": "not_in_maintenance", "maintenance_window": False},
        "policy_constraint": {"id": "OBS-R001", "rule": "write outside declared operational envelope should alert"},
        "expected_decision": "ALERT",
        "expected_rule": "OBS-R001",
        "rationale": "The Modbus operation is protocol-valid, but the value violates the declared operating envelope for the affected setpoint.",
    },
    {
        "scenario_id": "SCN-MODBUS-CONFIG-001",
        "title": "Sensitive configuration write outside maintenance context",
        "description": "A client writes to a sensitive alarm high setpoint during normal operation.",
        "protocol_carrier": "Modbus/TCP",
        "api_action": {"endpoint": "/api/v2/lab/write-register", "method": "POST", "payload": {"register": 3, "value": 5, "unit_id": 1}},
        "protocol_operation": {"function": "write_register", "target_register": 3, "value": 5},
        "industrial_action": {"type": "modify_configuration", "value": 5},
        "automation_artefact": {"id": "ALARM_HI_SP", "class": "sensitive_configuration", "mapping_confidence": "known", "criticality": "high"},
        "operational_context": {"operating_mode": "normal_operation", "maintenance_status": "not_in_maintenance", "maintenance_window": False},
        "policy_constraint": {"id": "OBS-R002", "rule": "write to sensitive configuration parameter should alert"},
        "expected_decision": "ALERT",
        "expected_rule": "OBS-R002",
        "framework_interpretation": {
            "possible_future_decision": "ESCALATE",
            "note": "ESCALATE should only be used if implemented as a distinct output in OT Lab.",
        },
        "rationale": "The action targets a sensitive configuration artefact. In the current baseline this is expected to alert; future richer context may escalate it.",
    },
    {
        "scenario_id": "SCN-MODBUS-UNKNOWN-001",
        "title": "Write to unmapped register",
        "description": "A client writes to a Modbus register that is not mapped to a known process artefact.",
        "protocol_carrier": "Modbus/TCP",
        "api_action": {"endpoint": "/api/v2/lab/write-register", "method": "POST", "payload": {"register": 65000, "value": 123, "unit_id": 1}},
        "protocol_operation": {"function": "write_register", "target_register": 65000, "value": 123},
        "industrial_action": {"type": "write_unknown_target", "value": 123},
        "automation_artefact": {"id": "unknown", "class": "unknown", "mapping_confidence": "unknown"},
        "operational_context": {"operating_mode": "normal_operation", "maintenance_status": "not_in_maintenance", "maintenance_window": False},
        "policy_constraint": {"id": "OBS-R003", "rule": "write to unmapped or unknown address should alert"},
        "expected_decision": "ALERT",
        "expected_rule": "OBS-R003",
        "framework_interpretation": {
            "possible_future_decision": "ESCALATE",
            "note": "ESCALATE should only be used if implemented as a distinct output in OT Lab.",
        },
        "rationale": "The operation is protocol-valid, but OT Lab cannot determine the affected automation artefact from the available mapping.",
    },
    {
        "scenario_id": "SCN-MODBUS-CTX-CONFIG-PROD-001",
        "title": "Sensitive configuration write during normal operation",
        "description": "A client writes to ALARM_HI_SP outside a maintenance window.",
        "protocol_carrier": "Modbus/TCP",
        "api_action": {"endpoint": "/api/v2/lab/write-register", "method": "POST", "payload": {"register": 3, "value": 5, "unit_id": 1}},
        "protocol_operation": {"function": "write_register", "target_register": 3, "value": 5},
        "industrial_action": {"type": "modify_configuration", "value": 5},
        "automation_artefact": {"id": "ALARM_HI_SP", "class": "sensitive_configuration", "mapping_confidence": "known", "criticality": "high"},
        "operational_context": {"operating_mode": "normal_operation", "maintenance_status": "not_in_maintenance", "maintenance_window": False},
        "policy_constraint": {"id": "OBS-R002", "rule": "write to sensitive configuration parameter should alert"},
        "expected_decision": "ALERT",
        "expected_rule": "OBS-R002",
        "rationale": "The same protocol-valid action should alert while the monitor context declares no maintenance window.",
    },
    {
        "scenario_id": "SCN-MODBUS-CTX-CONFIG-MAINT-001",
        "title": "Sensitive configuration write during maintenance",
        "description": "A client writes to ALARM_HI_SP during an active maintenance window.",
        "protocol_carrier": "Modbus/TCP",
        "api_action": {"endpoint": "/api/v2/lab/write-register", "method": "POST", "payload": {"register": 3, "value": 5, "unit_id": 1}},
        "protocol_operation": {"function": "write_register", "target_register": 3, "value": 5},
        "industrial_action": {"type": "modify_configuration", "value": 5},
        "automation_artefact": {"id": "ALARM_HI_SP", "class": "sensitive_configuration", "mapping_confidence": "known", "criticality": "high"},
        "operational_context": {"operating_mode": "maintenance", "maintenance_status": "in_maintenance", "maintenance_window": True},
        "policy_constraint": {"id": "OBS-R004", "rule": "Sensitive configuration write permitted during active maintenance window"},
        "expected_decision": "ALLOW",
        "expected_rule": "OBS-R004",
        "rationale": "The same protocol-valid action should be allowed because the monitor context declares an active maintenance window.",
    },
    {
        "scenario_id": "SCN-MODBUS-CTX-RANGE-MAINT-001",
        "title": "Out-of-range setpoint write during maintenance",
        "description": "A client writes an out-of-range setpoint during maintenance; range validation must still alert.",
        "protocol_carrier": "Modbus/TCP",
        "api_action": {"endpoint": "/api/v2/lab/write-register", "method": "POST", "payload": {"register": 1, "value": 150, "unit_id": 1}},
        "protocol_operation": {"function": "write_register", "target_register": 1, "value": 150},
        "industrial_action": {"type": "write_setpoint", "value": 150},
        "automation_artefact": {"id": "PUMP_FLOW_SP", "class": "setpoint", "allowed_range": {"min": 0, "max": 100}, "mapping_confidence": "known"},
        "operational_context": {"operating_mode": "maintenance", "maintenance_status": "in_maintenance", "maintenance_window": True},
        "policy_constraint": {"id": "OBS-R001", "rule": "write outside declared operational envelope should alert"},
        "expected_decision": "ALERT",
        "expected_rule": "OBS-R001",
        "rationale": "Maintenance context must not override the declared operating envelope for mapped setpoints.",
    },
    {
        "scenario_id": "SCN-MODBUS-CTX-NORMAL-MAINT-001",
        "title": "Valid mapped setpoint write during maintenance",
        "description": "A valid mapped setpoint write during maintenance should remain allowed.",
        "protocol_carrier": "Modbus/TCP",
        "api_action": {"endpoint": "/api/v2/lab/write-register", "method": "POST", "payload": {"register": 1, "value": 50, "unit_id": 1}},
        "protocol_operation": {"function": "write_register", "target_register": 1, "value": 50},
        "industrial_action": {"type": "write_setpoint", "value": 50},
        "automation_artefact": {"id": "PUMP_FLOW_SP", "class": "setpoint", "allowed_range": {"min": 0, "max": 100}, "mapping_confidence": "known"},
        "operational_context": {"operating_mode": "maintenance", "maintenance_status": "in_maintenance", "maintenance_window": True},
        "policy_constraint": {"id": "OBS-R000", "rule": "mapped write within expected range should be allowed"},
        "expected_decision": "ALLOW",
        "expected_rule": "OBS-R000",
        "rationale": "The maintenance window should not change the result for a normal mapped write inside the declared operating envelope.",
    },
]


@dataclass
class LoadedScenario:
    path: str
    data: dict[str, Any]


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def read_text_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_text_yaml(path: Path) -> dict[str, Any]:
    if yaml is None:
        raise RuntimeError("PyYAML is required to load YAML scenarios")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise RuntimeError(f"Scenario file is not a mapping: {path}")
    return data


def load_scenarios(scenario_dir: Path, use_builtin_if_missing: bool) -> list[LoadedScenario]:
    loaded_by_id: dict[str, LoadedScenario] = {}
    yaml_missing = False
    preference_rank = {suffix: idx for idx, suffix in enumerate(SCENARIO_DEDUP_PREFERENCE)}
    if scenario_dir.exists():
        for path in sorted(scenario_dir.iterdir()):
            if not path.is_file():
                continue
            suffix = path.suffix.lower().lstrip(".")
            if suffix not in {".yaml".lstrip("."), ".yml".lstrip("."), ".json".lstrip(".")}:
                continue
            if suffix == "json":
                data = read_text_json(path)
            else:
                if yaml is None:
                    yaml_missing = True
                    continue
                data = read_text_yaml(path)
            scenario_id = str(data.get("scenario_id") or "").strip()
            if not scenario_id:
                raise RuntimeError(f"Scenario file missing scenario_id: {path}")
            candidate = LoadedScenario(path=str(path), data=data)
            existing = loaded_by_id.get(scenario_id)
            if existing is None:
                loaded_by_id[scenario_id] = candidate
                continue
            existing_suffix = Path(existing.path).suffix.lower().lstrip(".")
            if preference_rank.get(suffix, 999) < preference_rank.get(existing_suffix, 999):
                loaded_by_id[scenario_id] = candidate
    loaded = [loaded_by_id[scenario_id] for scenario_id in sorted(loaded_by_id)]
    if loaded:
        return loaded
    if yaml_missing and use_builtin_if_missing:
        return [LoadedScenario(path=f"<builtin:{item['scenario_id']}>", data=item) for item in BUILTIN_SCENARIOS]
    if yaml_missing:
        raise RuntimeError(
            f"No JSON scenarios found in {scenario_dir} and PyYAML is not installed for YAML parsing"
        )
    if use_builtin_if_missing:
        return [LoadedScenario(path=f"<builtin:{item['scenario_id']}>", data=item) for item in BUILTIN_SCENARIOS]
    raise RuntimeError(f"No scenario files found in {scenario_dir}")


def write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=False), encoding="utf-8")


def call_json(
    session: requests.Session,
    method: str,
    url: str,
    *,
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    response = session.request(method=method.upper(), url=url, params=params, json=json_body, timeout=timeout)
    try:
        payload = response.json()
    except Exception:
        payload = {"raw_text": response.text}
    return {
        "status_code": response.status_code,
        "ok_http": response.ok,
        "payload": payload,
    }


def normalize_decision(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip().upper()
    return text or None


def maintenance_window_for_scenario(scenario: dict[str, Any]) -> bool:
    op_context = scenario.get("operational_context") or {}
    raw = op_context.get("maintenance_window", False)
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, (int, float)):
        return bool(raw)
    text = str(raw).strip().lower()
    return text in {"1", "true", "yes", "on"}


def select_decision(
    new_entries: list[dict[str, Any]],
    all_entries: list[dict[str, Any]],
    scenario: dict[str, Any],
) -> tuple[dict[str, Any] | None, str]:
    expected_rule = str(scenario.get("expected_rule") or "").strip()
    expected_decision = normalize_decision(scenario.get("expected_decision"))
    api_payload = ((scenario.get("api_action") or {}).get("payload") or {})
    protocol_op = scenario.get("protocol_operation") or {}
    register = protocol_op.get("target_register", api_payload.get("register"))
    value = protocol_op.get("value", api_payload.get("value"))
    asset = ((scenario.get("automation_artefact") or {}).get("id") or "").strip()
    maintenance_window = maintenance_window_for_scenario(scenario)

    candidates = new_entries if new_entries else all_entries

    def score(entry: dict[str, Any]) -> tuple[int, int, int, int, float]:
        s = 0
        if expected_rule and str(entry.get("rule_id") or "").strip() == expected_rule:
            s += 100
        if expected_decision and normalize_decision(entry.get("decision")) == expected_decision:
            s += 30
        if register is not None and entry.get("address") == register:
            s += 25
        if value is not None and entry.get("value") == value:
            s += 20
        if asset and str(entry.get("asset") or "").strip() == asset:
            s += 10
        if bool(entry.get("maintenance_window", False)) == maintenance_window:
            s += 8
        ts = 0.0
        try:
            ts = float(entry.get("timestamp") or 0.0)
        except Exception:
            ts = 0.0
        return (
            s,
            int(str(entry.get("rule_id") or "").strip() == expected_rule),
            int(entry.get("address") == register),
            int(entry.get("value") == value),
            ts,
        )

    if not candidates:
        return None, "No policy decision entries available after scenario execution."

    best = max(candidates, key=score)
    reason = "Selected from new decisions captured after the scenario action." if new_entries else "Fell back to the full policy decision history because no delta entries were found."
    return best, reason


def extract_new_entries(before_entries: list[dict[str, Any]], after_entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if len(after_entries) >= len(before_entries):
        delta = after_entries[len(before_entries):]
        if delta:
            return delta
    before_fingerprints = {
        json.dumps(item, sort_keys=True, separators=(",", ":"))
        for item in before_entries
    }
    return [
        item for item in after_entries
        if json.dumps(item, sort_keys=True, separators=(",", ":")) not in before_fingerprints
    ]


def make_summary_row(
    scenario: dict[str, Any],
    selected: dict[str, Any] | None,
    request_record: dict[str, Any],
    response_record: dict[str, Any],
    notes: list[str],
    evidence_complete: bool,
) -> dict[str, Any]:
    expected_decision = normalize_decision(scenario.get("expected_decision"))
    actual_decision = normalize_decision((selected or {}).get("decision"))
    expected_rule = str(scenario.get("expected_rule") or "").strip()
    matched_rule = str((selected or {}).get("rule_id") or "").strip()
    artefact = str((selected or {}).get("asset") or ((scenario.get("automation_artefact") or {}).get("id") or ""))
    address = (selected or {}).get("address")
    if address is None:
        address = ((scenario.get("protocol_operation") or {}).get("target_register"))
    value = (selected or {}).get("value")
    if value is None:
        value = ((scenario.get("protocol_operation") or {}).get("value"))
    maintenance_window = maintenance_window_for_scenario(scenario)

    match = bool(expected_decision and actual_decision == expected_decision)
    if expected_rule:
        match = match and (matched_rule == expected_rule)

    response_payload = response_record.get("payload") or {}
    if not response_record.get("ok_http", False):
        notes.append(f"API returned HTTP {response_record.get('status_code')}")
    if isinstance(response_payload, dict) and response_payload.get("ok") is False and response_payload.get("error"):
        notes.append(f"Action response error: {response_payload.get('error')}")

    return {
        "scenario_id": scenario.get("scenario_id"),
        "title": scenario.get("title"),
        "expected_decision": expected_decision,
        "actual_decision": actual_decision,
        "match": match,
        "expected_rule": expected_rule,
        "matched_rule": matched_rule,
        "artefact": artefact,
        "address": address,
        "value": value,
        "maintenance_window": maintenance_window,
        "evidence_complete": evidence_complete,
        "notes": " | ".join(note for note in notes if note),
    }


def export_summary_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=SUMMARY_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key) for key in SUMMARY_COLUMNS})


def set_monitor_context(
    session: requests.Session,
    *,
    base_url: str,
    session_id: str,
    maintenance_window: bool,
) -> dict[str, Any]:
    return call_json(
        session,
        "POST",
        f"{base_url}/api/v2/monitor/context",
        params={"session_id": session_id},
        json_body={"maintenance_window": bool(maintenance_window)},
        timeout=10.0,
    )


def assert_control_pair(summary_rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_id = {str(row.get("scenario_id") or ""): row for row in summary_rows}
    prod = by_id.get("SCN-MODBUS-CTX-CONFIG-PROD-001")
    maint = by_id.get("SCN-MODBUS-CTX-CONFIG-MAINT-001")
    if not prod or not maint:
        return {
            "pair": ["SCN-MODBUS-CTX-CONFIG-PROD-001", "SCN-MODBUS-CTX-CONFIG-MAINT-001"],
            "available": False,
            "passed": False,
            "reason": "Control-pair scenarios were not both executed.",
        }

    same_asset = prod.get("artefact") == maint.get("artefact")
    same_address = prod.get("address") == maint.get("address")
    same_value = prod.get("value") == maint.get("value")
    different_context = bool(prod.get("maintenance_window")) != bool(maint.get("maintenance_window"))
    different_decision_or_rule = (
        prod.get("actual_decision") != maint.get("actual_decision")
        or prod.get("matched_rule") != maint.get("matched_rule")
    )
    passed = all([same_asset, same_address, same_value, different_context, different_decision_or_rule])
    return {
        "pair": ["SCN-MODBUS-CTX-CONFIG-PROD-001", "SCN-MODBUS-CTX-CONFIG-MAINT-001"],
        "available": True,
        "same_asset": same_asset,
        "same_address": same_address,
        "same_value": same_value,
        "different_context": different_context,
        "different_decision_or_rule": different_decision_or_rule,
        "prod": prod,
        "maint": maint,
        "passed": passed,
    }


def summarize_contextual_negative_controls(summary_rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_id = {str(row.get("scenario_id") or ""): row for row in summary_rows}
    targets = [
        "SCN-MODBUS-CTX-RANGE-MAINT-001",
        "SCN-MODBUS-CTX-NORMAL-MAINT-001",
    ]
    available_rows = [by_id[scenario_id] for scenario_id in targets if scenario_id in by_id]
    if not available_rows:
        return {
            "available": False,
            "targets": targets,
            "passed": False,
            "matched": 0,
            "total": 0,
        }
    matched = sum(1 for row in available_rows if row.get("match"))
    total = len(available_rows)
    return {
        "available": True,
        "targets": targets,
        "passed": matched == total,
        "matched": matched,
        "total": total,
    }


def run() -> int:
    parser = argparse.ArgumentParser(description="Run the initial Liscere Modbus/TCP OT Lab baseline scenarios.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--session-id", default=DEFAULT_SESSION_ID)
    parser.add_argument("--scenario-dir", default=str(DEFAULT_SCENARIO_DIR))
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    parser.add_argument("--wait-seconds", type=float, default=DEFAULT_WAIT_SECONDS)
    parser.add_argument("--start-openplc", action="store_true")
    parser.add_argument("--no-monitor-route", action="store_true")
    parser.add_argument("--use-builtin-if-missing", action="store_true")
    parser.add_argument("--scenario-id-prefix", default="")
    args = parser.parse_args()

    base_url = str(args.base_url).rstrip("/")
    scenario_dir = Path(args.scenario_dir)
    output_dir = Path(args.output_dir)
    ensure_dir(output_dir)

    scenarios = load_scenarios(scenario_dir, use_builtin_if_missing=bool(args.use_builtin_if_missing))
    scenario_id_prefix = str(args.scenario_id_prefix or "").strip()
    if scenario_id_prefix:
        scenarios = [
            loaded for loaded in scenarios
            if str((loaded.data or {}).get("scenario_id") or "").startswith(scenario_id_prefix)
        ]
        if not scenarios:
            raise RuntimeError(f"No scenarios matched prefix: {scenario_id_prefix}")
    session = requests.Session()

    preflight = call_json(session, "GET", f"{base_url}/api/status", params={"session_id": args.session_id}, timeout=10.0)
    if not preflight.get("ok_http"):
        write_json(output_dir / "preflight_status.json", preflight)
        raise RuntimeError(f"Preflight failed against {base_url}/api/status: HTTP {preflight.get('status_code')}")
    write_json(output_dir / "preflight_status.json", preflight)

    if args.start_openplc:
        openplc_start = call_json(session, "POST", f"{base_url}/api/v2/lab/openplc/start", params={"session_id": args.session_id}, timeout=20.0)
        write_json(output_dir / "openplc_start.json", openplc_start)

    if not args.no_monitor_route:
        route_resp = call_json(
            session,
            "POST",
            f"{base_url}/api/v2/monitor/route",
            params={"session_id": args.session_id},
            json_body={"enabled": True},
            timeout=10.0,
        )
        write_json(output_dir / "monitor_route.json", route_resp)

    summary_rows: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []

    for loaded in scenarios:
        scenario = loaded.data
        scenario_id = str(scenario.get("scenario_id") or "").strip() or "UNKNOWN"
        scenario_dir_out = output_dir / scenario_id
        ensure_dir(scenario_dir_out)

        notes: list[str] = [f"source={loaded.path}"]
        write_json(scenario_dir_out / "scenario.json", scenario)

        maintenance_window = maintenance_window_for_scenario(scenario)
        context_request = {"maintenance_window": maintenance_window}
        write_json(scenario_dir_out / "context_request.json", context_request)
        context_response = set_monitor_context(
            session,
            base_url=base_url,
            session_id=args.session_id,
            maintenance_window=maintenance_window,
        )
        write_json(scenario_dir_out / "context_response.json", context_response)
        if not context_response.get("ok_http", False):
            notes.append(f"Context HTTP {context_response.get('status_code')}")

        before_export = call_json(
            session,
            "POST",
            f"{base_url}/api/v2/policy-decisions/export",
            params={"session_id": args.session_id},
            timeout=10.0,
        )
        write_json(scenario_dir_out / "policy_decisions_before.json", before_export)
        before_entries = (((before_export.get("payload") or {}).get("export") or {}).get("entries") or [])

        api_action = scenario.get("api_action") or {}
        endpoint = str(api_action.get("endpoint") or "").strip()
        method = str(api_action.get("method") or "POST").upper()
        payload = api_action.get("payload") or {}
        request_url = f"{base_url}{endpoint}"
        request_record = {
            "url": request_url,
            "method": method,
            "params": {"session_id": args.session_id},
            "payload": payload,
            "sent_at": time.time(),
        }
        write_json(scenario_dir_out / "request.json", request_record)

        response_record = call_json(
            session,
            method,
            request_url,
            params={"session_id": args.session_id},
            json_body=payload,
            timeout=10.0,
        )
        write_json(scenario_dir_out / "response.json", response_record)

        time.sleep(max(0.2, float(args.wait_seconds)))

        after_export = call_json(
            session,
            "POST",
            f"{base_url}/api/v2/policy-decisions/export",
            params={"session_id": args.session_id},
            timeout=10.0,
        )
        write_json(scenario_dir_out / "policy_decisions_after.json", after_export)
        after_entries = (((after_export.get("payload") or {}).get("export") or {}).get("entries") or [])

        new_entries = extract_new_entries(before_entries, after_entries)
        selected, selection_note = select_decision(new_entries, after_entries, scenario)
        notes.append(selection_note)
        write_json(scenario_dir_out / "selected_decision.json", selected)

        evidence_complete = all(
            (scenario_dir_out / name).exists()
            for name in [
                "scenario.json",
                "request.json",
                "response.json",
                "policy_decisions_before.json",
                "policy_decisions_after.json",
                "selected_decision.json",
                "context_request.json",
                "context_response.json",
            ]
        )

        row = make_summary_row(
            scenario=scenario,
            selected=selected,
            request_record=request_record,
            response_record=response_record,
            notes=notes,
            evidence_complete=evidence_complete,
        )
        result_payload = {
            "scenario_id": row["scenario_id"],
            "title": row["title"],
            "maintenance_window": row["maintenance_window"],
            "expected_decision": row["expected_decision"],
            "actual_decision": row["actual_decision"],
            "expected_rule": row["expected_rule"],
            "matched_rule": row["matched_rule"],
            "match": row["match"],
            "selected_decision": selected,
            "notes": row["notes"],
            "request_http_ok": bool(response_record.get("ok_http")),
            "request_status_code": response_record.get("status_code"),
            "response_payload": response_record.get("payload"),
            "new_entries_count": len(new_entries),
        }
        write_json(scenario_dir_out / "result.json", result_payload)

        row["evidence_complete"] = row["evidence_complete"] and (scenario_dir_out / "result.json").exists()
        summary_rows.append(row)
        results.append(result_payload)

        print(
            f"{row['scenario_id']} -> expected={row['expected_decision']}/{row['expected_rule']} "
            f"actual={row['actual_decision'] or '-'} / {row['matched_rule'] or '-'} "
            f"maintenance_window={'true' if row['maintenance_window'] else 'false'} "
            f"match={'YES' if row['match'] else 'NO'}"
        )

    summary_payload = {
        "generated_at": time.time(),
        "base_url": base_url,
        "session_id": args.session_id,
        "scenario_dir": str(scenario_dir),
        "output_dir": str(output_dir),
        "scenario_id_prefix": scenario_id_prefix,
        "results": results,
        "summary_rows": summary_rows,
    }
    control_pair = assert_control_pair(summary_rows)
    contextual_negative_controls = summarize_contextual_negative_controls(summary_rows)
    write_json(output_dir / "control_pair_assertions.json", control_pair)
    summary_payload["control_pair_assertion"] = control_pair
    summary_payload["contextual_negative_controls"] = contextual_negative_controls
    write_json(output_dir / "summary.json", summary_payload)
    export_summary_csv(output_dir / "summary.csv", summary_rows)

    scenario_failures = [row for row in summary_rows if not row.get("match")]
    control_pair_failed = bool(control_pair.get("available") and not control_pair.get("passed"))
    negative_controls_failed = bool(
        contextual_negative_controls.get("available") and not contextual_negative_controls.get("passed")
    )
    print(f"\nSummary: {len(summary_rows) - len(scenario_failures)}/{len(summary_rows)} scenarios matched expected decision/rule.")
    if control_pair.get("available"):
        prod = control_pair.get("prod") or {}
        maint = control_pair.get("maint") or {}
        if control_pair.get("passed"):
            print(
                "context-flip verified: "
                f"{prod.get('artefact', 'ALARM_HI_SP')}={prod.get('value', '-')}"
                f" -> {prod.get('actual_decision', '-').upper()}(prod) / {maint.get('actual_decision', '-').upper()}(maint); "
                "identical operation, artefact, value"
            )
        else:
            print(
                "context-flip failed: "
                "(SCN-MODBUS-CTX-CONFIG-PROD-001 vs SCN-MODBUS-CTX-CONFIG-MAINT-001)"
            )
    if contextual_negative_controls.get("available"):
        print(
            "Negative controls: "
            f"{contextual_negative_controls.get('matched', 0)}/{contextual_negative_controls.get('total', 0)} held"
        )
    print(f"Evidence: {output_dir / 'summary.csv'}")
    return 1 if (scenario_failures or control_pair_failed or negative_controls_failed) else 0


if __name__ == "__main__":
    raise SystemExit(run())
