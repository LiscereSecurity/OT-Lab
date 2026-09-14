from __future__ import annotations

import time
import uuid
from dataclasses import dataclass


PROCESS_PROFILES = {
    "tank_v1": {
        "id": "tank_v1",
        "version": "1.0.0",
        "name": "Tank Process v1",
        "protocols": ["modbus", "ethercat"],
        "states": ["idle", "fill", "drain", "alarm"],
        "variables": [
            {"tag": "level", "unit": "%", "min": 0, "max": 100},
            {"tag": "pump", "type": "bool"},
            {"tag": "valve", "type": "bool"},
            {"tag": "alarm_hi", "type": "bool"},
            {"tag": "alarm_lo", "type": "bool"},
        ],
        "io_map": {
            "modbus": {"pump": 2, "valve": 3, "alarm_hi_th": 8, "alarm_lo_th": 9},
            "ethercat": {"pump": "0x7000:02", "valve": "0x7000:03", "level": "0x6000:00"},
        },
        "constraints": {
            "register_map": {
                "pump_flow_sp": 1,
                "valve_flow_sp": 2,
                "alarm_hi_sp": 3,
                "alarm_lo_sp": 4,
                "level_ai": 6,
            },
            "level_hi_block": 95,
            "level_lo_block": 5,
            "min_command_interval_s": 0.15,
            "burst_block_threshold": 10,
            "setpoint_rate_limit": 35,
            "safe_alarm_hi_min": 50,
            "safe_alarm_lo_max": 40,
            "safe_alarm_gap_min": 10,
        },
    },
    "pumping_line_v1": {
        "id": "pumping_line_v1",
        "version": "1.0.0",
        "name": "Pumping Line v1",
        "protocols": ["modbus", "ethercat"],
        "states": ["idle", "transfer", "interlocked"],
        "variables": [
            {"tag": "line_pressure", "unit": "bar", "min": 0, "max": 16},
            {"tag": "pump", "type": "bool"},
            {"tag": "valve", "type": "bool"},
        ],
        "io_map": {
            "modbus": {"pump": 2, "valve": 3},
            "ethercat": {"pump": "0x7000:02", "valve": "0x7000:03"},
        },
        "constraints": {"min_command_interval_s": 0.20},
    },
}


SEMANTIC_POLICIES = {
    "tank_v1": {
        "policy_id": "policy_tank_v1",
        "version": "1.0.0",
        "rules": [
            {"id": "R001", "type": "critical", "name": "Write requires running process"},
            {"id": "R101", "type": "critical", "name": "Block unsafe alarm-setpoint tampering"},
            {"id": "R102", "type": "critical", "name": "Block dangerous hydraulic setpoint conflicts"},
            {"id": "R103", "type": "warning", "name": "Detect suspicious write bursts/replay"},
            {"id": "R104", "type": "warning", "name": "Detect fast out-of-pattern setpoint ramps"},
        ],
    },
    "pumping_line_v1": {
        "policy_id": "policy_pumping_line_v1",
        "version": "1.0.0",
        "rules": [
            {"id": "R001", "type": "critical", "name": "Write requires running process"},
            {"id": "R005", "type": "warning", "name": "Command burst / replay pattern"},
        ],
    },
}


ATTACK_LIBRARY = {
    "t0836_modify_parameter_setpoint_surge": {
        "id": "t0836_modify_parameter_setpoint_surge",
        "name": "Setpoint Surge Near Operational Limit",
        "framework": "ATT&CK ICS",
        "technique": "T0836 (Modify Parameter)",
        "profile": "tank_v1",
        "steps": [
            {"address": 2, "value": 10, "delay_s": 0.08},
            {"address": 1, "value": 95, "delay_s": 0.08},
            {"address": 1, "value": 98, "delay_s": 0.08},
            {"address": 2, "value": 5, "delay_s": 0.08},
        ],
    },
    "t0838_modify_alarm_settings_blinding": {
        "id": "t0838_modify_alarm_settings_blinding",
        "name": "Alarm Threshold Blinding",
        "framework": "ATT&CK ICS",
        "technique": "T0838 (Modify Alarm Settings)",
        "profile": "tank_v1",
        "steps": [
            {"address": 3, "value": 20, "delay_s": 0.10},
            {"address": 4, "value": 19, "delay_s": 0.10},
            {"address": 3, "value": 15, "delay_s": 0.10},
        ],
    },
    "t0806_bruteforce_io_register_replay": {
        "id": "t0806_bruteforce_io_register_replay",
        "name": "High-Frequency Register Replay Burst",
        "framework": "ATT&CK ICS",
        "technique": "T0806 (Brute Force I/O)",
        "profile": "tank_v1",
        "steps": [
            {"address": 1, "value": 80, "delay_s": 0.02},
            {"address": 1, "value": 20, "delay_s": 0.02},
            {"address": 1, "value": 80, "delay_s": 0.02},
            {"address": 1, "value": 20, "delay_s": 0.02},
            {"address": 1, "value": 80, "delay_s": 0.02},
            {"address": 1, "value": 20, "delay_s": 0.02},
            {"address": 1, "value": 80, "delay_s": 0.02},
            {"address": 1, "value": 20, "delay_s": 0.02},
            {"address": 1, "value": 80, "delay_s": 0.02},
            {"address": 1, "value": 20, "delay_s": 0.02},
            {"address": 1, "value": 80, "delay_s": 0.02},
            {"address": 1, "value": 20, "delay_s": 0.02},
        ],
    },
    "t0831_manipulation_of_control_conflict": {
        "id": "t0831_manipulation_of_control_conflict",
        "name": "Conflicting Control Manipulation",
        "framework": "ATT&CK ICS",
        "technique": "T0831 (Manipulation of Control)",
        "profile": "tank_v1",
        "steps": [
            {"address": 1, "value": 95, "delay_s": 0.06},
            {"address": 2, "value": 95, "delay_s": 0.06},
            {"address": 1, "value": 99, "delay_s": 0.06},
            {"address": 2, "value": 2, "delay_s": 0.06},
        ],
    },
}


@dataclass
class PolicyDecision:
    decision: str
    rule_id: str
    reason: str
    risk_score: int
    impact_avoided: str | None = None


def _extract_level(register_values: list[int]) -> int:
    if not register_values:
        return 0
    try:
        return int(register_values[0])
    except Exception:
        return 0


def _read_reg(register_values: list[int], register_id: int, default: int = 0) -> int:
    # Handle both 0-based and 1-based snapshots defensively.
    for idx in (int(register_id), int(register_id) - 1):
        if idx >= 0 and idx < len(register_values):
            try:
                return int(register_values[idx])
            except Exception:
                continue
    return int(default)


def evaluate_semantic_policy(
    *,
    profile_id: str,
    process_running: bool,
    register_values: list[int],
    address: int,
    value: int,
    now_ts: float,
    last_writes: list[dict],
) -> PolicyDecision:
    profile = PROCESS_PROFILES.get(profile_id) or PROCESS_PROFILES["tank_v1"]
    constraints = profile.get("constraints") or {}
    reg_map = constraints.get("register_map") or {}
    level = _read_reg(register_values, int(reg_map.get("level_ai", 6)), _extract_level(register_values))
    pump_flow = _read_reg(register_values, int(reg_map.get("pump_flow_sp", 1)), 0)
    valve_flow = _read_reg(register_values, int(reg_map.get("valve_flow_sp", 2)), 0)
    alarm_hi = _read_reg(register_values, int(reg_map.get("alarm_hi_sp", 3)), 0)
    alarm_lo = _read_reg(register_values, int(reg_map.get("alarm_lo_sp", 4)), 0)

    if not process_running:
        return PolicyDecision("BLOCK", "R001", "Process is not running for command execution", 95, "Unsafe write while process offline")

    if int(address) == int(reg_map.get("alarm_hi_sp", 3)):
        safe_hi_min = int(constraints.get("safe_alarm_hi_min", 50))
        safe_gap_min = int(constraints.get("safe_alarm_gap_min", 10))
        current_lo = alarm_lo
        if int(value) < safe_hi_min:
            return PolicyDecision(
                "BLOCK",
                "R101",
                f"Alarm HI threshold too low ({value}); minimum safe bound is {safe_hi_min}",
                94,
                "Alarm blinding attempt prevented",
            )
        if int(value) <= (int(current_lo) + safe_gap_min):
            return PolicyDecision(
                "BLOCK",
                "R101",
                f"Alarm HI threshold ({value}) too close to LO ({current_lo})",
                93,
                "Unsafe alarm envelope compression prevented",
            )

    if int(address) == int(reg_map.get("alarm_lo_sp", 4)):
        safe_lo_max = int(constraints.get("safe_alarm_lo_max", 40))
        safe_gap_min = int(constraints.get("safe_alarm_gap_min", 10))
        current_hi = alarm_hi
        if int(value) > safe_lo_max:
            return PolicyDecision(
                "BLOCK",
                "R101",
                f"Alarm LO threshold too high ({value}); maximum safe bound is {safe_lo_max}",
                94,
                "Alarm blinding attempt prevented",
            )
        if int(value) >= (int(current_hi) - safe_gap_min):
            return PolicyDecision(
                "BLOCK",
                "R101",
                f"Alarm LO threshold ({value}) too close to HI ({current_hi})",
                93,
                "Unsafe alarm envelope compression prevented",
            )

    recent_same = [
        item for item in last_writes
        if int(item.get("address", -1)) == int(address)
        and (now_ts - float(item.get("ts", 0))) <= float(constraints.get("min_command_interval_s", 0.15))
    ]
    if recent_same:
        if len(recent_same) >= int(constraints.get("burst_block_threshold", 10)):
            return PolicyDecision("BLOCK", "R103", "High-frequency write burst/replay pattern detected", 88, "Burst write manipulation limited")
        return PolicyDecision("ALLOW_WITH_ALERT", "R103", "High-frequency repeated write pattern detected", 72, None)

    if int(address) == int(reg_map.get("pump_flow_sp", 1)):
        delta = abs(int(value) - int(pump_flow))
        if delta > int(constraints.get("setpoint_rate_limit", 35)):
            return PolicyDecision("ALLOW_WITH_ALERT", "R104", f"Fast pump setpoint ramp detected ({pump_flow} -> {value})", 68, None)
        if int(value) >= 90 and int(valve_flow) <= 20 and int(level) >= 80:
            return PolicyDecision(
                "BLOCK",
                "R102",
                f"Unsafe control conflict: pump_flow={value}, valve_flow={valve_flow}, level={level}",
                91,
                "Potential overflow acceleration prevented",
            )

    if int(address) == int(reg_map.get("valve_flow_sp", 2)):
        delta = abs(int(value) - int(valve_flow))
        if delta > int(constraints.get("setpoint_rate_limit", 35)):
            return PolicyDecision("ALLOW_WITH_ALERT", "R104", f"Fast valve setpoint ramp detected ({valve_flow} -> {value})", 68, None)
        if int(value) >= 90 and int(level) <= 10 and int(pump_flow) <= 5:
            return PolicyDecision(
                "BLOCK",
                "R102",
                f"Unsafe drain command: valve_flow={value}, level={level}, pump_flow={pump_flow}",
                90,
                "Potential dry-run/depletion condition prevented",
            )

    return PolicyDecision("ALLOW", "R000", "Command accepted by semantic policy", 25, None)


def ai_support_for_decision(decision: PolicyDecision) -> dict:
    if decision.decision == "BLOCK":
        suggestion = "Review process sequence and state preconditions before reissuing this command."
    elif decision.decision == "ALLOW_WITH_ALERT":
        suggestion = "Command allowed, but should be reviewed for contextual consistency."
    else:
        suggestion = "Behavior aligned with current semantic policy."
    return {
        "risk_score": decision.risk_score,
        "explanation": decision.reason,
        "suggested_policy_adjustment": suggestion,
    }


def make_policy_trace_entry(*, profile_id: str, command: dict, decision: PolicyDecision, ai_meta: dict) -> dict:
    return {
        "id": f"pd_{uuid.uuid4().hex[:16]}",
        "timestamp": time.time(),
        "profile_id": profile_id,
        "command": command,
        "decision": decision.decision,
        "rule_id": decision.rule_id,
        "reason": decision.reason,
        "impact_avoided": decision.impact_avoided,
        "ai": ai_meta,
    }


def evaluate_execution_impact(entries: list[dict], final_registers: list[int]) -> dict:
    blocked = sum(1 for e in entries if e.get("decision") == "BLOCK")
    warned = sum(1 for e in entries if e.get("decision") == "ALLOW_WITH_ALERT")
    allowed = sum(1 for e in entries if e.get("decision") == "ALLOW")
    level = _extract_level(final_registers)
    physical_risk = 100 if level >= 96 or level <= 2 else (60 if level >= 90 or level <= 5 else 20)
    score = max(0, physical_risk - blocked * 15)
    return {
        "blocked": blocked,
        "warned": warned,
        "allowed": allowed,
        "final_level": level,
        "impact_score": score,
    }
