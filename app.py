from __future__ import annotations

import ipaddress
import json
import re
import socket
import time
import uuid
import os
import requests

from collections import deque
from pathlib import Path
from threading import Lock

from fastapi import Body, FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from agent.protocols.modbus.modbus_builder import build_modbus_tcp_request
from agent.protocols.modbus.modbus_definitions import (
    get_modbus_function_definitions,
    get_modbus_write_function_codes,
)
from agent.protocols.modbus.modbus_validators import (
    ValidationError as ModbusValidationError,
    validate_modbus_action_payload,
)
from agent.runtime import SimpleModbusClient, SimpleModbusServer
from v2_engine import (
    ATTACK_LIBRARY,
    PROCESS_PROFILES,
    SEMANTIC_POLICIES,
    ai_support_for_decision,
    evaluate_execution_impact,
    evaluate_semantic_policy,
    make_policy_trace_entry,
)

app = FastAPI(title="OT Lab App")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent
SESSION_COOKIE = "scada_session_id"
AGENT_LIVENESS_WINDOW_SECONDS = 45
SESSION_ID_PATTERN = re.compile(r"^sess_[A-Za-z0-9_-]{8,128}$")

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

lock = Lock()
agents_by_session = {}
APP_INSTANCE_ID = (
    str(os.getenv("RAILWAY_REPLICA_ID") or "").strip()
    or str(os.getenv("HOSTNAME") or "").strip()
    or f"inst-{uuid.uuid4().hex[:8]}"
)


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("socket closed while receiving")
        data += chunk
    return data


def modbus_write_single_register(host: str, port: int, register: int, value: int, unit_id: int = 1, timeout_s: float = 2.0):
    tx_id = int(time.time() * 1000) & 0xFFFF
    function_code = 6
    pdu = bytes([function_code]) + int(register).to_bytes(2, "big") + int(value).to_bytes(2, "big")
    mbap = (
        tx_id.to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + (len(pdu) + 1).to_bytes(2, "big")
        + int(unit_id).to_bytes(1, "big")
    )

    with socket.create_connection((host, int(port)), timeout=timeout_s) as conn:
        conn.settimeout(timeout_s)
        conn.sendall(mbap + pdu)

        resp_header = recv_exact(conn, 7)
        resp_tx_id = int.from_bytes(resp_header[0:2], "big")
        resp_proto_id = int.from_bytes(resp_header[2:4], "big")
        resp_len = int.from_bytes(resp_header[4:6], "big")
        if resp_tx_id != tx_id or resp_proto_id != 0:
            raise RuntimeError("invalid Modbus response header")

        resp_pdu = recv_exact(conn, resp_len - 1)
        if len(resp_pdu) < 2:
            raise RuntimeError("short Modbus response")

        fc = resp_pdu[0]
        if fc & 0x80:
            exc_code = resp_pdu[1]
            raise RuntimeError(f"modbus exception code={exc_code}")
        if fc != function_code:
            raise RuntimeError(f"unexpected function code in response: {fc}")

    return {"ok": True, "transaction_id": tx_id}


def modbus_write_single_coil(host: str, port: int, coil: int, value: bool, unit_id: int = 1, timeout_s: float = 2.0):
    tx_id = int(time.time() * 1000) & 0xFFFF
    function_code = 5
    coil_value = 0xFF00 if bool(value) else 0x0000
    pdu = bytes([function_code]) + int(coil).to_bytes(2, "big") + int(coil_value).to_bytes(2, "big")
    mbap = (
        tx_id.to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + (len(pdu) + 1).to_bytes(2, "big")
        + int(unit_id).to_bytes(1, "big")
    )

    with socket.create_connection((host, int(port)), timeout=timeout_s) as conn:
        conn.settimeout(timeout_s)
        conn.sendall(mbap + pdu)
        resp_header = recv_exact(conn, 7)
        resp_tx_id = int.from_bytes(resp_header[0:2], "big")
        resp_proto_id = int.from_bytes(resp_header[2:4], "big")
        resp_len = int.from_bytes(resp_header[4:6], "big")
        if resp_tx_id != tx_id or resp_proto_id != 0:
            raise RuntimeError("invalid Modbus response header")
        resp_pdu = recv_exact(conn, resp_len - 1)
        if len(resp_pdu) < 5:
            raise RuntimeError("short Modbus response")
        fc = resp_pdu[0]
        if fc & 0x80:
            exc_code = resp_pdu[1]
            raise RuntimeError(f"modbus exception code={exc_code}")
        if fc != function_code:
            raise RuntimeError(f"unexpected function code in response: {fc}")
    return {"ok": True, "transaction_id": tx_id}


def modbus_read_holding_registers(
    host: str,
    port: int,
    start: int,
    quantity: int,
    unit_id: int = 1,
    timeout_s: float = 2.0,
):
    tx_id = int(time.time() * 1000) & 0xFFFF
    function_code = 3
    pdu = bytes([function_code]) + int(start).to_bytes(2, "big") + int(quantity).to_bytes(2, "big")
    mbap = (
        tx_id.to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + (len(pdu) + 1).to_bytes(2, "big")
        + int(unit_id).to_bytes(1, "big")
    )

    with socket.create_connection((host, int(port)), timeout=timeout_s) as conn:
        conn.settimeout(timeout_s)
        conn.sendall(mbap + pdu)

        resp_header = recv_exact(conn, 7)
        resp_tx_id = int.from_bytes(resp_header[0:2], "big")
        resp_proto_id = int.from_bytes(resp_header[2:4], "big")
        resp_len = int.from_bytes(resp_header[4:6], "big")
        if resp_tx_id != tx_id or resp_proto_id != 0:
            raise RuntimeError("invalid Modbus response header")

        resp_pdu = recv_exact(conn, resp_len - 1)
        if len(resp_pdu) < 2:
            raise RuntimeError("short Modbus response")

        fc = resp_pdu[0]
        if fc & 0x80:
            exc_code = resp_pdu[1] if len(resp_pdu) > 1 else -1
            raise RuntimeError(f"modbus exception code={exc_code}")
        if fc != function_code:
            raise RuntimeError(f"unexpected function code in response: {fc}")
        byte_count = int(resp_pdu[1])
        data = resp_pdu[2 : 2 + byte_count]
        if len(data) != byte_count:
            raise RuntimeError("invalid byte count in read response")
        values = []
        for i in range(0, len(data), 2):
            values.append(int.from_bytes(data[i : i + 2], "big"))
        return {"ok": True, "transaction_id": tx_id, "values": values}


def modbus_read_coils(
    host: str,
    port: int,
    start: int,
    quantity: int,
    unit_id: int = 1,
    timeout_s: float = 2.0,
):
    tx_id = int(time.time() * 1000) & 0xFFFF
    function_code = 1
    pdu = bytes([function_code]) + int(start).to_bytes(2, "big") + int(quantity).to_bytes(2, "big")
    mbap = (
        tx_id.to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + (len(pdu) + 1).to_bytes(2, "big")
        + int(unit_id).to_bytes(1, "big")
    )

    with socket.create_connection((host, int(port)), timeout=timeout_s) as conn:
        conn.settimeout(timeout_s)
        conn.sendall(mbap + pdu)
        resp_header = recv_exact(conn, 7)
        resp_tx_id = int.from_bytes(resp_header[0:2], "big")
        resp_proto_id = int.from_bytes(resp_header[2:4], "big")
        resp_len = int.from_bytes(resp_header[4:6], "big")
        if resp_tx_id != tx_id or resp_proto_id != 0:
            raise RuntimeError("invalid Modbus response header")
        resp_pdu = recv_exact(conn, resp_len - 1)
        if len(resp_pdu) < 2:
            raise RuntimeError("short Modbus response")
        fc = resp_pdu[0]
        if fc & 0x80:
            exc_code = resp_pdu[1] if len(resp_pdu) > 1 else -1
            raise RuntimeError(f"modbus exception code={exc_code}")
        if fc != function_code:
            raise RuntimeError(f"unexpected function code in response: {fc}")
        byte_count = int(resp_pdu[1])
        data = resp_pdu[2 : 2 + byte_count]
        bits = []
        for b in data:
            for i in range(8):
                bits.append((b >> i) & 0x01)
        return {"ok": True, "transaction_id": tx_id, "values": bits[: int(quantity)]}


class ProcessSimulationManager:
    def __init__(self):
        self._lock = Lock()
        self._server = None
        self._client = None
        self._config = {
            "plc_host": "127.0.0.1",
            "plc_port": 15020,
            "hmi_host": "127.0.0.1",
            "hmi_port": 15020,
            "poll_interval": 0.5,
            "poll_start": 0,
            "poll_quantity": 16,
            "process_type": "tank_v1",
        }

    def _normalize_config(self, host=None, port=None, hmi_host=None, hmi_port=None, poll_interval=None, poll_start=None, poll_quantity=None, process_type=None):
        plc_host = str(host or self._config["plc_host"]).strip() or "127.0.0.1"
        plc_port = int(port if port is not None else self._config["plc_port"])
        hmi_host = str(hmi_host or self._config["hmi_host"] or plc_host).strip() or plc_host
        hmi_port = int(hmi_port if hmi_port is not None else self._config["hmi_port"])
        poll_interval = float(poll_interval if poll_interval is not None else self._config["poll_interval"])
        poll_start = int(poll_start if poll_start is not None else self._config["poll_start"])
        poll_quantity = int(poll_quantity if poll_quantity is not None else self._config["poll_quantity"])
        process_type = str(process_type or self._config["process_type"]).strip() or "tank_v1"

        if process_type not in {"tank_v1", "pumping_line_v1"}:
            raise ValueError("Unsupported process_type")
        if plc_port < 1 or plc_port > 65535 or hmi_port < 1 or hmi_port > 65535:
            raise ValueError("Ports must be between 1 and 65535")
        if poll_interval <= 0:
            raise ValueError("poll_interval must be > 0")
        if poll_start < 0:
            raise ValueError("poll_start must be >= 0")
        if poll_quantity < 1 or poll_quantity > 125:
            raise ValueError("poll_quantity must be between 1 and 125")

        return {
            "plc_host": plc_host,
            "plc_port": plc_port,
            "hmi_host": hmi_host,
            "hmi_port": hmi_port,
            "poll_interval": poll_interval,
            "poll_start": poll_start,
            "poll_quantity": poll_quantity,
            "process_type": process_type,
        }

    def _snapshot_locked(self):
        server = self._server
        client = self._client
        server_running = bool(server and server.running)
        client_running = bool(client and client.running)

        server_preview = {"start": 0, "quantity": 0, "values": []}
        if server_running:
            try:
                server_preview = server.get_registers_preview(start=0, quantity=16)
            except Exception:
                pass

        client_snapshot = {
            "last_values": [],
            "last_error": None,
            "last_poll_at": None,
            "last_success_at": None,
        }
        if client_running:
            try:
                client_snapshot = client.get_snapshot()
            except Exception:
                pass

        return {
            "running": server_running and client_running,
            "process_type": self._config["process_type"],
            "server": {
                "running": server_running,
                "host": self._config["plc_host"],
                "port": self._config["plc_port"],
                "registers_preview": server_preview,
            },
            "client": {
                "running": client_running,
                "host": self._config["hmi_host"],
                "port": self._config["hmi_port"],
                "poll_interval": self._config["poll_interval"],
                "poll_start": self._config["poll_start"],
                "poll_quantity": self._config["poll_quantity"],
                "last_values": list(client_snapshot.get("last_values") or []),
                "last_error": client_snapshot.get("last_error"),
                "last_poll_at": client_snapshot.get("last_poll_at"),
                "last_success_at": client_snapshot.get("last_success_at"),
            },
        }

    def snapshot(self):
        with self._lock:
            return self._snapshot_locked()

    def stop(self):
        with self._lock:
            server = self._server
            client = self._client
            self._server = None
            self._client = None

        if client:
            try:
                client.stop()
            except Exception:
                pass
        if server:
            try:
                server.stop()
            except Exception:
                pass

        return self.snapshot()

    def configure(self, host=None, port=None, hmi_host=None, hmi_port=None, poll_interval=None, poll_start=None, poll_quantity=None, process_type=None):
        new_config = self._normalize_config(
            host=host,
            port=port,
            hmi_host=hmi_host,
            hmi_port=hmi_port,
            poll_interval=poll_interval,
            poll_start=poll_start,
            poll_quantity=poll_quantity,
            process_type=process_type,
        )
        with self._lock:
            self._config.update(new_config)
            return self._snapshot_locked()

    def start(self, host=None, port=None, hmi_host=None, hmi_port=None, poll_interval=None, poll_start=None, poll_quantity=None, process_type=None):
        new_config = self._normalize_config(
            host=host,
            port=port,
            hmi_host=hmi_host,
            hmi_port=hmi_port,
            poll_interval=poll_interval,
            poll_start=poll_start,
            poll_quantity=poll_quantity,
            process_type=process_type,
        )

        self.stop()

        server = SimpleModbusServer(host=new_config["plc_host"], port=new_config["plc_port"])
        server_started = server.start()
        if not server_started:
            try:
                server.stop()
            except Exception:
                pass
            raise RuntimeError("failed to start process simulation server")

        client = SimpleModbusClient(
            host=new_config["hmi_host"],
            port=new_config["hmi_port"],
            poll_interval=new_config["poll_interval"],
            poll_start=new_config["poll_start"],
            poll_quantity=new_config["poll_quantity"],
        )
        client_started = client.start()

        with self._lock:
            self._config.update(new_config)
            self._server = server if server_started else None
            self._client = client if client_started else None
            return self._snapshot_locked()

    def write_register(self, address: int, value: int, unit_id: int = 1):
        with self._lock:
            host = self._config["hmi_host"]
            port = self._config["hmi_port"]
            running = bool(self._server and self._server.running)

        if not running:
            raise RuntimeError("process simulation is not running")

        if address < 0 or address > 65535:
            raise ValueError("address must be between 0 and 65535")
        if value < 0 or value > 65535:
            raise ValueError("value must be between 0 and 65535")
        if unit_id < 0 or unit_id > 255:
            raise ValueError("unit_id must be between 0 and 255")

        modbus_write_single_register(host=host, port=port, register=address, value=value, unit_id=unit_id)
        return self.snapshot()


process_sim = ProcessSimulationManager()


def default_agent_snapshot():
    return {
        "agent_id": None,
        "mode": None,
        "iface": None,
        "port_mode": None,
        "custom_ports": [],
        "hostname": None,
        "function_codes_seen": [],
        "initiators_seen": [],
        "responders_seen": [],
        "read_patterns": [],
        "write_registers": [],
        "event_counts": {},
        "traffic_overview": {
            "clients_identified": 0,
            "servers_identified": 0,
            "function_codes_identified": [],
            "read_pattern_count": 0,
            "write_register_count": 0,
        },
        "timestamp": None,
    }


def default_agent_info():
    return {
        "connected": False,
        "agent_id": None,
        "hostname": None,
        "iface": None,
        "mode": None,
        "port_mode": None,
        "custom_ports": [],
        "running": False,
        "last_seen": None,
        "available_ifaces": [],
        "available_monitored_ifaces": [],
        "available_unmonitored_ifaces": [],
        "capabilities": [],
    }


def default_agent_config():
    return {
        "iface": "ALL",
        "mode": "MONITORING",
        "port_mode": "MODBUS_PORTS",
        "custom_ports": [],
        "updated_at": None,
    }


def normalize_custom_ports(value):
    if value is None:
        return []

    if isinstance(value, str):
        items = value.replace(";", ",").split(",")
    elif isinstance(value, list):
        items = value
    else:
        items = [value]

    ports = []
    seen = set()
    for raw in items:
        token = str(raw).strip()
        if not token:
            continue
        try:
            port = int(token)
        except (TypeError, ValueError):
            raise ValueError(f"Invalid port '{token}'")
        if port < 1 or port > 65535:
            raise ValueError(f"Port out of range: {port}")
        if port in seen:
            continue
        seen.add(port)
        ports.append(port)

    return ports


def safe_normalize_custom_ports(value):
    try:
        return normalize_custom_ports(value)
    except Exception:
        return []


def default_remote_server():
    return {
        "running": False,
        "host": "127.0.0.1",
        "port": 5020,
        "registers_preview": {
            "start": 0,
            "quantity": 0,
            "values": [],
        },
        "updated_at": None,
    }


def default_remote_client():
    return {
        "running": False,
        "host": "127.0.0.1",
        "port": 5020,
        "poll_interval": 1.0,
        "poll_start": 0,
        "poll_quantity": 4,
        "last_values": [],
        "last_error": None,
        "last_poll_at": None,
        "last_success_at": None,
        "updated_at": None,
    }

def default_process_sim():
    return {
        "running": False,
        "process_type": "tank_v1",
        "server": {
            "running": False,
            "host": "127.0.0.1",
            "port": 15020,
            "registers_preview": {
                "start": 0,
                "quantity": 0,
                "values": [],
            },
        },
        "client": {
            "running": False,
            "host": "127.0.0.1",
            "port": 15020,
            "poll_interval": 0.5,
            "poll_start": 0,
            "poll_quantity": 16,
            "last_values": [],
            "last_error": None,
            "last_poll_at": None,
            "last_success_at": None,
        },
    }


def default_runtime_state():
    return {
        "runtime": {"running": False, "mode": "local_runtime_first", "last_updated": None},
        "monitor": {"running": False, "last_updated": None},
        "process": {"running": False, "profile_id": "tank_v1", "last_updated": None},
        "defense": {"running": True, "mode": "semantic_policy_ai_assist", "last_updated": None},
    }


def default_defense_state():
    return {
        "enabled": True,
        "policy_mode": "semantic_policy_ai_assist",
        "profile_id": "tank_v1",
        "last_decision": None,
        "decision_counts": {"ALLOW": 0, "ALLOW_WITH_ALERT": 0, "BLOCK": 0},
    }


def default_lab_target():
    return {"host": "runtime", "port": 15020}

def default_monitor_proxy_target():
    return {"host": "openplc", "port": 502}


def default_ui_endpoints():
    openplc_web_port = int(os.getenv("OPENPLC_WEB_PORT", "8081"))
    openplc_modbus_port = int(os.getenv("OPENPLC_MODBUS_PORT", "1502"))
    hmi_web_port = int(os.getenv("HMI_WEB_PORT", "1881"))
    monitor_proxy_port = int(os.getenv("MONITOR_PROXY_PORT", "15020"))
    return {
        "plc": {
            "ip": "10.20.0.11",
            "port": 502,
            "ui_url": f"http://localhost:{openplc_web_port}",
            "host_modbus": f"localhost:{openplc_modbus_port}",
        },
        "hmi": {
            "ip": "10.20.0.21",
            "port": 1881,
            "ui_url": f"http://localhost:{hmi_web_port}",
            "plc_target_ip": "10.30.0.31",
            "plc_target_port": monitor_proxy_port,
        },
        "monitor_proxy": {
            "ip": "10.30.0.31",
            "port": 15020,
            "host_modbus": f"localhost:{monitor_proxy_port}",
        },
    }


def default_monitor_operating_mode():
    # observe: passive visibility-only
    # protect: semantic policy can enforce blocks
    return "observe"


def default_monitor_route_enabled():
    return True


def default_modbus_summary():
    return {
        "detected": False,
        "protocol": "Modbus/TCP",
        "interface": None,
        "port": None,
        "client_ip": None,
        "server_ip": None,
        "functions_seen": [],
        "exception_functions_seen": [],
        "avg_polling_s": None,
        "writes_detected": False,
        "state": "Inactive",
        # Packet timestamp (may differ from backend wall-clock)
        "last_seen": None,
        # Backend ingestion timestamp (authoritative for UI liveness)
        "ingest_last_seen": None,
    }


def default_monitor_context():
    return {
        "maintenance_window": False,
    }


def ensure_session_state(session_id: str):
    with lock:
        if session_id not in agents_by_session:
            agents_by_session[session_id] = {
                "events": deque(maxlen=300),
                "alerts": deque(maxlen=100),
                "operational_actions": deque(maxlen=300),
                "logs": deque(maxlen=100),
                "agent_info": default_agent_info(),
                "agent_snapshot": default_agent_snapshot(),
                "agent_config": default_agent_config(),
                "remote_server": default_remote_server(),
                "remote_client": default_remote_client(),
                "process_sim": default_process_sim(),
                "modbus_summary": default_modbus_summary(),
                "connection_history": deque(maxlen=80),
                "pending_commands": [],
                "runtime_commands": {},
                "action_commands": deque(maxlen=80),
                "event_log_signatures": deque(maxlen=600),
                "recent_event_signatures": {},
                "recent_alert_signatures": {},
                "recent_operational_action_signatures": {},
                "runtime_state": default_runtime_state(),
                "defense_state": default_defense_state(),
                "policy_decisions": deque(maxlen=600),
                "command_history": deque(maxlen=400),
                "execution_reports": deque(maxlen=100),
                "lab_target": default_lab_target(),
                "monitor_proxy_target": default_monitor_proxy_target(),
                "monitor_operating_mode": default_monitor_operating_mode(),
                "monitor_route_enabled": default_monitor_route_enabled(),
                "monitor_context": default_monitor_context(),
                "ui_endpoints": default_ui_endpoints(),
                "tag_map_overrides": {"coil": {}, "register": {}},
                "tag_map_use_defaults": True,
                "ot_subnet_override": "",
                "dmz_subnet_override": "",
            }
        return agents_by_session[session_id]


def normalize_session_id(value):
    raw = str(value or "").strip()
    if not raw:
        return None
    if not SESSION_ID_PATTERN.match(raw):
        return None
    return raw


def get_or_create_session_id(request: Request):
    explicit = normalize_session_id(request.query_params.get("session_id"))
    if explicit:
        return explicit

    explicit_header = normalize_session_id(request.headers.get("x-otlab-session-id"))
    if explicit_header:
        return explicit_header

    cookie_session = normalize_session_id(request.cookies.get(SESSION_COOKIE))
    if cookie_session:
        return cookie_session

    return f"sess_{uuid.uuid4().hex}"


def _find_most_recent_connected_session_id(now_ts: float | None = None) -> str | None:
    if now_ts is None:
        now_ts = time.time()
    best_sid = None
    best_seen = -1.0
    with lock:
        for sid, st in agents_by_session.items():
            agent_info = st.get("agent_info") or {}
            last_seen = agent_info.get("last_seen")
            if last_seen is None:
                continue
            try:
                last_seen_f = float(last_seen)
            except Exception:
                continue
            if (float(now_ts) - last_seen_f) > AGENT_LIVENESS_WINDOW_SECONDS:
                continue
            if last_seen_f > best_seen:
                best_seen = last_seen_f
                best_sid = sid
    return best_sid


def resolve_active_session_id(preferred_session_id: str, now_ts: float | None = None) -> str:
    # Never switch requests to another session automatically.
    # In shared/public deployments this can route commands to the wrong agent.
    return preferred_session_id


def get_session_state_from_request(request: Request):
    requested_session_id = get_or_create_session_id(request)
    active_session_id = resolve_active_session_id(requested_session_id)
    return active_session_id, ensure_session_state(active_session_id)


def set_session_cookie_if_needed(request: Request, response: Response, session_id: str):
    current = request.cookies.get(SESSION_COOKIE)
    if current != session_id:
        response.set_cookie(
            key=SESSION_COOKIE,
            value=session_id,
            httponly=False,
            samesite="lax",
        )


def _cleanup_recent_signature_cache(cache: dict, now_ts: float, ttl_s: float, max_items: int):
    if len(cache) <= max_items:
        return
    cutoff = now_ts - ttl_s
    stale_keys = [k for k, v in cache.items() if float(v) < cutoff]
    for key in stale_keys[: max_items]:
        cache.pop(key, None)


def _event_signature(event: dict):
    return (
        normalize_event_type(event.get("type")),
        event.get("transaction_id"),
        event.get("function_code"),
        event.get("src_ip"),
        event.get("src_port"),
        event.get("dst_ip"),
        event.get("dst_port"),
        event.get("register"),
        event.get("start_addr"),
        event.get("quantity"),
        event.get("value"),
        tuple(event.get("values") or []),
    )


def _alert_signature(alert: dict):
    summary = str(alert.get("summary") or "")
    summary = re.sub(r"\s*\|\s*rtt=[0-9.]+", "", summary, flags=re.IGNORECASE).strip()
    return (
        normalize_event_type(alert.get("event_type")),
        alert.get("function_code"),
        alert.get("src"),
        alert.get("dst"),
        alert.get("register"),
        alert.get("start_addr"),
        alert.get("quantity"),
        alert.get("value"),
        alert.get("exception_code"),
        summary,
    )


def push_event(state: dict, event: dict):
    now_ts = time.time()
    signature = _event_signature(event)
    with lock:
        cache = state.get("recent_event_signatures")
        if cache is None:
            cache = {}
            state["recent_event_signatures"] = cache
        prev_ts = cache.get(signature)
        if prev_ts is not None and (now_ts - float(prev_ts)) <= 4.0:
            return
        cache[signature] = now_ts
        _cleanup_recent_signature_cache(cache, now_ts=now_ts, ttl_s=15.0, max_items=2000)
        state["events"].append(event)


def push_alert(state: dict, alert: dict):
    now_ts = time.time()
    signature = _alert_signature(alert)
    with lock:
        cache = state.get("recent_alert_signatures")
        if cache is None:
            cache = {}
            state["recent_alert_signatures"] = cache
        prev_ts = cache.get(signature)
        if prev_ts is not None and (now_ts - float(prev_ts)) <= 30.0:
            return
        cache[signature] = now_ts
        _cleanup_recent_signature_cache(cache, now_ts=now_ts, ttl_s=120.0, max_items=1200)
        state["alerts"].append(alert)


def push_log_for_session(session_id: str, message: str):
    print(message)
    state = ensure_session_state(session_id)
    with lock:
        state["logs"].append(message)

MODBUS_WRITE_FUNCTIONS = get_modbus_write_function_codes()
MODBUS_ACTIVE_WINDOW_SECONDS = 2.0
MAX_EVENT_CLOCK_DRIFT_SECONDS = 30.0
OP_ACTION_COALESCE_WINDOW_SECONDS = 2.0
OP_ACTION_TAG_MAP = {
    "coil": {
        0: "PUMP_CMD",
        1: "VALVE_CMD",
        2: "ALARM_HI_ACTIVE",
        3: "ALARM_LO_ACTIVE",
    },
    "register": {
        1: "PUMP_FLOW_SP",
        2: "VALVE_FLOW_SP",
        3: "ALARM_HI_SP",
        4: "ALARM_LO_SP",
        6: "LEVEL_AI",
    },
}

OBSERVED_POLICY_ID = "observed_modbus_tank_v1"
OBSERVED_POLICY_VERSION = "0.2.0"
OBSERVED_SETPOINT_MIN = 0
OBSERVED_SETPOINT_MAX = 100
OBSERVED_SENSITIVE_CONFIG_TAGS = {
    "ALARM_HI_SP",
    "ALARM_LO_SP",
}


def normalize_boolish(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off", ""}:
        return False
    return default


def get_effective_monitor_context(state: dict):
    current = state.get("monitor_context") or {}
    out = default_monitor_context()
    out["maintenance_window"] = normalize_boolish(current.get("maintenance_window"), False)
    return out


def make_observed_policy_decision(
    *,
    action: dict,
    decision: str,
    rule_id: str,
    rule_name: str,
    reason: str,
    severity: str,
):
    return {
        "kind": "observed_semantic_policy_decision",
        "policy_id": OBSERVED_POLICY_ID,
        "policy_version": OBSERVED_POLICY_VERSION,
        "timestamp": action.get("timestamp") or time.time(),
        "mode": "observe",
        "decision": decision,
        "rule_id": rule_id,
        "rule_name": rule_name,
        "reason": reason,
        "severity": severity,
        "protocol": action.get("protocol") or "MODBUS/TCP",
        "action_type": action.get("action_type"),
        "asset": action.get("asset"),
        "address": action.get("address"),
        "value": action.get("value_to"),
        "actor": action.get("actor"),
        "target": action.get("target"),
        "function_code": action.get("function_code"),
        "maintenance_window": normalize_boolish(action.get("maintenance_window"), False),
    }


def evaluate_observed_action_policy(action: dict, tag_map: dict):
    action_type = str(action.get("action_type") or "")
    asset = str(action.get("asset") or "").strip()
    value = normalize_modbus_value(action.get("value_to"))
    address = action.get("address")
    is_register = action_type == "write_register"
    is_coil = action_type == "write_coil"
    maintenance_window = normalize_boolish(action.get("maintenance_window"), False)

    try:
        addr_int = int(address)
    except Exception:
        addr_int = None

    mapped_tags = tag_map.get("register" if is_register else "coil", {}) if isinstance(tag_map, dict) else {}
    is_mapped = addr_int in mapped_tags if addr_int is not None else False

    if not is_mapped:
        return make_observed_policy_decision(
            action=action,
            decision="ALERT",
            rule_id="OBS-R003",
            rule_name="Unknown or unmapped target",
            reason=f"Write targets an address that is not mapped to the declared process model ({asset or address}).",
            severity="medium",
        )

    if is_register and asset.endswith("_SP") and value is not None:
        if value < OBSERVED_SETPOINT_MIN or value > OBSERVED_SETPOINT_MAX:
            return make_observed_policy_decision(
                action=action,
                decision="ALERT",
                rule_id="OBS-R001",
                rule_name="Setpoint outside process envelope",
                reason=f"{asset}={value} is outside the declared operational range {OBSERVED_SETPOINT_MIN}..{OBSERVED_SETPOINT_MAX}.",
                severity="high",
            )

    if is_register and asset in OBSERVED_SENSITIVE_CONFIG_TAGS:
        if maintenance_window:
            return make_observed_policy_decision(
                action=action,
                decision="ALLOW",
                rule_id="OBS-R004",
                rule_name="Sensitive configuration write during maintenance",
                reason=f"{asset} is being modified during an active maintenance window declared in the monitor context.",
                severity="info",
            )
        return make_observed_policy_decision(
            action=action,
            decision="ALERT",
            rule_id="OBS-R002",
            rule_name="Sensitive configuration write",
            reason=f"{asset} is a process configuration parameter and should be changed only under authorised conditions.",
            severity="medium",
        )

    if is_coil and asset in {"ALARM_HI_ACTIVE", "ALARM_LO_ACTIVE"}:
        return make_observed_policy_decision(
            action=action,
            decision="ALERT",
            rule_id="OBS-R005",
            rule_name="Direct alarm-state write",
            reason=f"{asset} is an alarm-state output and should not be directly commanded by an operator endpoint.",
            severity="high",
        )

    return make_observed_policy_decision(
        action=action,
        decision="ALLOW",
        rule_id="OBS-R000",
        rule_name="Observed action accepted",
        reason="Action is mapped to the process model and remains within the initial semantic policy.",
        severity="info",
    )


def stronger_observed_policy_decision(current: dict | None, incoming: dict | None):
    priority = {"BLOCK": 3, "ALERT": 2, "ALLOW_WITH_ALERT": 2, "ALLOW": 1}
    current_score = priority.get(str((current or {}).get("decision") or "").upper(), 0)
    incoming_score = priority.get(str((incoming or {}).get("decision") or "").upper(), 0)
    return incoming if incoming_score >= current_score else current


def get_effective_tag_map(state: dict):
    use_defaults = bool(state.get("tag_map_use_defaults", True))
    if not use_defaults:
        out = {"coil": {}, "register": {}}
        overrides = state.get("tag_map_overrides") or {}
        for bucket in ("coil", "register"):
            src = overrides.get(bucket) or {}
            for k, v in dict(src).items():
                try:
                    key = int(k)
                except Exception:
                    continue
                val = str(v or "").strip()
                if val:
                    out[bucket][key] = val
        return out
    base = {
        "coil": dict(OP_ACTION_TAG_MAP.get("coil") or {}),
        "register": dict(OP_ACTION_TAG_MAP.get("register") or {}),
    }
    overrides = state.get("tag_map_overrides") or {}
    for bucket in ("coil", "register"):
        src = overrides.get(bucket) or {}
        for k, v in dict(src).items():
            try:
                key = int(k)
            except Exception:
                continue
            val = str(v or "").strip()
            if val:
                base[bucket][key] = val
    return base


def normalize_event_type(event_type: str):
    return str(event_type or "").upper().strip()


def endpoint_host(value):
    raw = str(value or "").strip()
    if not raw:
        return raw
    if raw.count(":") == 1 and "." in raw:
        return raw.rsplit(":", 1)[0]
    return raw


def resolve_role_for_ip(state: dict, ip_value: str):
    ip = endpoint_host(ip_value)
    if not ip:
        return "UNKNOWN"
    endpoints = state.get("ui_endpoints") or default_ui_endpoints()
    hmi_ip = endpoint_host((endpoints.get("hmi") or {}).get("ip"))
    plc_ip = endpoint_host((endpoints.get("plc") or {}).get("ip"))
    mon_ip = endpoint_host((endpoints.get("monitor_proxy") or {}).get("ip"))
    if ip == hmi_ip:
        return "HMI"
    if ip == plc_ip:
        return "PLC"
    if ip == mon_ip:
        return "MONITOR"
    try:
        arch = _build_network_architecture(endpoints)
        monitor_alias_ips = set(arch.get("monitor_alias_ips") or [])
        web_alias_ips = set(arch.get("web_alias_ips") or [])
        if ip in monitor_alias_ips:
            return "MONITOR"
        if ip in web_alias_ips:
            return "WEB"
    except Exception:
        pass
    return ip


def normalize_modbus_value(raw):
    if raw is None:
        return None
    txt = str(raw).strip().upper()
    if txt == "ON":
        return 1
    if txt == "OFF":
        return 0
    try:
        return int(float(txt))
    except Exception:
        return None


def extract_write_target_and_value(payload: dict):
    summary = str(payload.get("summary") or "")
    register = payload.get("register")
    value = payload.get("value")
    if register is None:
        m = re.search(r"register\s*=\s*(-?\d+)", summary, flags=re.IGNORECASE)
        if m:
            register = int(m.group(1))
    if value is None:
        m = re.search(r"value\s*=\s*(ON|OFF|-?\d+)", summary, flags=re.IGNORECASE)
        if m:
            value = normalize_modbus_value(m.group(1))
    else:
        value = normalize_modbus_value(value)
    return register, value


def push_operational_action(state: dict, action: dict):
    now_ts = time.time()
    with lock:
        sig_cache = state.get("recent_operational_action_signatures")
        if sig_cache is None:
            sig_cache = {}
            state["recent_operational_action_signatures"] = sig_cache
        dedupe_sig = action.get("_dedupe_sig")
        if dedupe_sig:
            prev_ts = sig_cache.get(dedupe_sig)
            if prev_ts is not None and (now_ts - float(prev_ts)) <= 3.0:
                return
            sig_cache[dedupe_sig] = now_ts
            _cleanup_recent_signature_cache(sig_cache, now_ts=now_ts, ttl_s=30.0, max_items=4000)

    with lock:
        actions = state.get("operational_actions")
        if actions is None:
            actions = deque(maxlen=300)
            state["operational_actions"] = actions
        if actions:
            try:
                action_ts = float(action.get("timestamp", 0.0))
            except Exception:
                action_ts = 0.0
            for idx in range(len(actions) - 1, max(-1, len(actions) - 16), -1):
                prev = actions[idx]
                try:
                    same_key = (
                        prev.get("action_type") == action.get("action_type")
                        and prev.get("asset") == action.get("asset")
                        and prev.get("target") == action.get("target")
                        and str(prev.get("value_to")) == str(action.get("value_to"))
                    )
                    prev_ts = float(prev.get("timestamp", 0.0))
                    within_window = abs(action_ts - prev_ts) <= 2.5
                    if not (same_key and within_window):
                        continue
                    count = int(prev.get("count", 1)) + 1
                    prev["count"] = count
                    prev["value_to"] = action.get("value_to")
                    prev["timestamp"] = action.get("timestamp")
                    # Prefer HMI attribution when available.
                    if str(prev.get("actor") or "").upper() != "HMI" and str(action.get("actor") or "").upper() == "HMI":
                        prev["actor"] = action.get("actor")
                    prev["policy_decision"] = stronger_observed_policy_decision(
                        prev.get("policy_decision"),
                        action.get("policy_decision"),
                    )
                    return
                except Exception:
                    continue
        actions.append(action)


def ingest_operational_action_from_event(state: dict, payload: dict):
    event_type = normalize_event_type(payload.get("type"))
    if event_type != "WRITE_REQUEST":
        return
    function_code = payload.get("function_code")
    try:
        function_code = int(function_code) if function_code is not None else None
    except Exception:
        function_code = None
    if function_code is None:
        return
    base_fc = function_code & 0x7F if function_code > 127 else function_code
    if base_fc not in MODBUS_WRITE_FUNCTIONS:
        return

    register, value = extract_write_target_and_value(payload)
    if register is None:
        return

    is_coil = base_fc in {5, 15}
    tag_map = get_effective_tag_map(state)
    tag = tag_map["coil"].get(int(register)) if is_coil else tag_map["register"].get(int(register))
    if not tag:
        if is_coil:
            byte = int(register) // 8
            bit = int(register) % 8
            tag = f"%Q{byte}.{bit}"
        else:
            tag = f"HR{int(register)}"

    client_ip, server_ip, _port = extract_event_client_server(payload)
    src_ip = endpoint_host(client_ip)
    dst_ip = endpoint_host(server_ip)
    actor = resolve_role_for_ip(state, src_ip)
    target = resolve_role_for_ip(state, dst_ip)
    plc_ip = endpoint_host(((state.get("ui_endpoints") or default_ui_endpoints()).get("plc") or {}).get("ip"))
    if plc_ip and dst_ip != plc_ip:
        return
    try:
        arch = _build_network_architecture(state.get("ui_endpoints") or default_ui_endpoints())
        monitor_alias_ips = set(arch.get("monitor_alias_ips") or [])
        web_alias_ips = set(arch.get("web_alias_ips") or [])
    except Exception:
        monitor_alias_ips = set()
        web_alias_ips = set()
    # Drop DMZ-side reflected proxy writes (they duplicate the same command seen on OT side).
    if src_ip in web_alias_ips and dst_ip == plc_ip:
        return
    # OT-side proxy writes represent HMI-originated operator actions for this lab view.
    if (src_ip in monitor_alias_ips) and dst_ip == plc_ip:
        actor = "HMI"
    event_ts = resolve_event_time(payload)
    monitor_context = get_effective_monitor_context(state)

    action = {
        "kind": "operational_action",
        "timestamp": event_ts,
        "protocol": "MODBUS/TCP",
        "event_type": event_type,
        "action_type": "write_coil" if is_coil else "write_register",
        "asset": tag,
        "address": int(register),
        "value_from": value,
        "value_to": value,
        "count": 1,
        "actor": actor,
        "target": target,
        "path": "via_monitor_proxy",
        "function_code": base_fc,
        "maintenance_window": bool(monitor_context.get("maintenance_window", False)),
        "_dedupe_sig": (
            f"{payload.get('transaction_id')}|{base_fc}|{int(register)}|{value}"
            if payload.get("transaction_id") is not None
            else f"no-tx|{base_fc}|{int(register)}|{value}"
        ),
    }
    policy_decision = evaluate_observed_action_policy(action, tag_map)
    action["policy_decision"] = policy_decision
    with lock:
        decisions = state.get("policy_decisions")
        if decisions is None:
            decisions = deque(maxlen=600)
            state["policy_decisions"] = decisions
        decisions.append(policy_decision)
    push_operational_action(state, action)


def extract_event_client_server(payload: dict):
    event_type = normalize_event_type(payload.get("type"))

    src_ip = payload.get("src_ip")
    dst_ip = payload.get("dst_ip")
    src_port = payload.get("src_port")
    dst_port = payload.get("dst_port")

    client = payload.get("client")
    server = payload.get("server")

    if event_type in {"READ_REQUEST", "WRITE_REQUEST"}:
        client_ip = client or src_ip
        server_ip = server or dst_ip
        port = dst_port
    elif event_type in {"READ_RESPONSE", "WRITE_RESPONSE"}:
        client_ip = client or dst_ip
        server_ip = server or src_ip
        port = src_port
    else:
        client_ip = client or src_ip
        server_ip = server or dst_ip
        port = dst_port

    return client_ip, server_ip, port


def extract_avg_polling_from_snapshot(snapshot: dict, server_ip: str):
    if not snapshot:
        return None

    read_patterns = snapshot.get("read_patterns") or []
    if not isinstance(read_patterns, list):
        return None

    for pattern in read_patterns:
        if not isinstance(pattern, dict):
            continue

        pattern_server = pattern.get("server")
        avg_period = pattern.get("avg_period")

        if server_ip and pattern_server and pattern_server != server_ip:
            continue

        if avg_period is None:
            continue

        try:
            return round(float(avg_period), 2)
        except (TypeError, ValueError):
            continue

    return None


def resolve_event_time(payload: dict) -> float:
    """
    Resolve a safe event timestamp for state/liveness calculations.
    Uses packet timestamp when it is reasonably close to backend wall-clock.
    Falls back to current backend time when agent/system clocks are skewed.
    """
    now = time.time()
    raw_ts = payload.get("timestamp")
    try:
        event_ts = float(raw_ts) if raw_ts is not None else now
    except (TypeError, ValueError):
        event_ts = now

    if abs(event_ts - now) > MAX_EVENT_CLOCK_DRIFT_SECONDS:
        return now
    return event_ts


def update_modbus_summary_from_event(state: dict, payload: dict):
    summary = state["modbus_summary"]

    event_type = normalize_event_type(payload.get("type"))
    function_code = payload.get("function_code")

    client_ip, server_ip, port = extract_event_client_server(payload)
    iface = (
        payload.get("iface")
        or state["agent_info"].get("iface")
        or state["agent_config"].get("iface")
    )
    event_ts = resolve_event_time(payload)

    if function_code is None:
        return

    try:
        function_code = int(function_code)
    except (TypeError, ValueError):
        return

    is_exception = event_type == "EXCEPTION_RESPONSE"
    if function_code > 127:
        base_fc = function_code & 0x7F
    else:
        base_fc = function_code

    summary["detected"] = True
    summary["protocol"] = "Modbus/TCP"
    summary["interface"] = iface
    summary["port"] = port
    summary["client_ip"] = client_ip
    summary["server_ip"] = server_ip
    # Use packet timestamp to avoid delayed-queue artifacts.
    summary["last_seen"] = event_ts
    summary["ingest_last_seen"] = time.time()
    summary["state"] = "Active"

    existing_fc = set(summary.get("functions_seen") or [])
    exception_fc = set(summary.get("exception_functions_seen") or [])

    if is_exception:
        exception_fc.add(base_fc)
    else:
        existing_fc.add(base_fc)

    summary["functions_seen"] = sorted(existing_fc)
    summary["exception_functions_seen"] = sorted(exception_fc)

    if base_fc in MODBUS_WRITE_FUNCTIONS or event_type in {"WRITE_REQUEST", "WRITE_RESPONSE"}:
        summary["writes_detected"] = True

    avg_polling = payload.get("avg_polling_s")

    if avg_polling is None:
        avg_polling = extract_avg_polling_from_snapshot(
            state.get("agent_snapshot") or {},
            server_ip
        )

    if avg_polling is not None:
        try:
            summary["avg_polling_s"] = round(float(avg_polling), 2)
        except (TypeError, ValueError):
            pass

    update_connection_history_from_event(
        state=state,
        iface=iface,
        client_ip=client_ip,
        server_ip=server_ip,
        port=port,
        function_code=base_fc,
        is_exception=is_exception,
        is_write=(base_fc in MODBUS_WRITE_FUNCTIONS or event_type in {"WRITE_REQUEST", "WRITE_RESPONSE"}),
        event_ts=event_ts,
    )


def update_connection_history_from_event(
    state: dict,
    iface: str,
    client_ip: str,
    server_ip: str,
    port,
    function_code: int,
    is_exception: bool,
    is_write: bool,
    event_ts: float,
):
    history = state.get("connection_history")
    if history is None:
        history = deque(maxlen=80)
        state["connection_history"] = history

    def endpoint_host(endpoint: str):
        value = str(endpoint or "").strip()
        if not value:
            return value
        if value.count(":") == 1 and "." in value:
            return value.rsplit(":", 1)[0]
        return value

    client_host = endpoint_host(client_ip)
    server_host = endpoint_host(server_ip)
    key = f"{iface}|{client_host}|{server_host}|{port}"
    now = float(event_ts) if event_ts is not None else time.time()
    target = None

    for item in history:
        if item.get("key") == key:
            target = item
            break

    if target is None:
        stable_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"modbus|{key}"))
        target = {
            "id": str(uuid.uuid4()),
            "connection_id": stable_id,
            "key": key,
            "protocol": "Modbus/TCP",
            "interface": iface,
            "client_ip": client_ip,
            "client_host": client_host,
            "server_ip": server_ip,
            "server_host": server_host,
            "port": port,
            "first_seen": now,
            "last_seen": now,
            "event_count": 0,
            "functions_seen": [],
            "exception_functions_seen": [],
            "writes_detected": False,
            "reconnect_count": 0,
            "instance_id": 1,
        }
        history.appendleft(target)
    else:
        last_seen_prev = target.get("last_seen")
        if last_seen_prev is not None and (now - float(last_seen_prev)) > (MODBUS_ACTIVE_WINDOW_SECONDS * 1.5):
            target["reconnect_count"] = int(target.get("reconnect_count") or 0) + 1
            target["instance_id"] = int(target.get("instance_id") or 1) + 1
            target["first_seen"] = now
            target["event_count"] = 0
            target["functions_seen"] = []
            target["exception_functions_seen"] = []
            target["writes_detected"] = False
        target["last_seen"] = now
        target["client_ip"] = client_ip
        target["server_ip"] = server_ip
        target["client_host"] = client_host
        target["server_host"] = server_host

    target["event_count"] = int(target.get("event_count") or 0) + 1
    fc = set(target.get("functions_seen") or [])
    exc = set(target.get("exception_functions_seen") or [])
    if is_exception:
        exc.add(function_code)
    else:
        fc.add(function_code)
    target["functions_seen"] = sorted(fc)
    target["exception_functions_seen"] = sorted(exc)
    if is_write:
        target["writes_detected"] = True


def build_modbus_summary(state: dict):
    summary = dict(state.get("modbus_summary") or default_modbus_summary())

    if not summary.get("detected"):
        return {"detected": False}

    # Prefer backend ingestion time for liveness in UI to avoid packet-time skew effects.
    last_seen = summary.get("ingest_last_seen")
    if last_seen is None:
        last_seen = summary.get("last_seen")
    if last_seen is not None and (time.time() - last_seen > MODBUS_ACTIVE_WINDOW_SECONDS):
        summary["state"] = "Inactive"
    else:
        summary["state"] = "Active"

    return {
        "detected": bool(summary.get("detected")),
        "protocol": summary.get("protocol") or "Modbus/TCP",
        "interface": summary.get("interface"),
        "port": summary.get("port"),
        "client_ip": summary.get("client_ip"),
        "server_ip": summary.get("server_ip"),
        "functions_seen": summary.get("functions_seen") or [],
        "exception_functions_seen": summary.get("exception_functions_seen") or [],
        "avg_polling_s": summary.get("avg_polling_s"),
        "writes_detected": bool(summary.get("writes_detected")),
        "state": summary.get("state") or "Inactive",
    }


def build_connection_history(state: dict):
    now = time.time()
    rows = []
    for item in list(state.get("connection_history") or []):
        last_seen = item.get("last_seen")
        first_seen = item.get("first_seen")
        active = bool(last_seen is not None and (now - float(last_seen)) <= MODBUS_ACTIVE_WINDOW_SECONDS)
        duration_s = None
        if first_seen is not None and last_seen is not None:
            duration_s = round(max(0.0, float(last_seen) - float(first_seen)), 3)

        rows.append({
            "id": item.get("id"),
            "connection_id": item.get("connection_id"),
            "protocol": item.get("protocol") or "Modbus/TCP",
            "interface": item.get("interface"),
            "client_ip": item.get("client_ip"),
            "client_host": item.get("client_host"),
            "server_ip": item.get("server_ip"),
            "server_host": item.get("server_host"),
            "port": item.get("port"),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "active": active,
            "age_s": round(max(0.0, now - float(last_seen)), 3) if last_seen is not None else None,
            "duration_s": duration_s,
            "event_count": item.get("event_count") or 0,
            "functions_seen": item.get("functions_seen") or [],
            "exception_functions_seen": item.get("exception_functions_seen") or [],
            "writes_detected": bool(item.get("writes_detected")),
            "reconnect_count": int(item.get("reconnect_count") or 0),
            "instance_id": int(item.get("instance_id") or 1),
        })
    return list(reversed(rows[:60]))


def build_command_log_message(command_type: str, payload: dict):
    if command_type == "CONFIGURE_SERVER":
        return f"Modbus server configuration sent to agent ({payload.get('host', '-') }:{payload.get('port', '-')})"
    if command_type == "START_SERVER":
        return f"Modbus server start requested ({payload.get('host', '-') }:{payload.get('port', '-')})"
    if command_type == "STOP_SERVER":
        return "Modbus server stop requested"
    if command_type == "CONFIGURE_CLIENT":
        return (
            f"Modbus client configuration sent to agent "
            f"({payload.get('host', '-') }:{payload.get('port', '-')}, "
            f"poll={payload.get('poll_interval', '-') }s, "
            f"start={payload.get('poll_start', '-') }, qty={payload.get('poll_quantity', '-')})"
        )
    if command_type == "START_CLIENT":
        return (
            f"Modbus client start requested "
            f"({payload.get('host', '-') }:{payload.get('port', '-')}, "
            f"poll={payload.get('poll_interval', '-') }s, "
            f"start={payload.get('poll_start', '-') }, qty={payload.get('poll_quantity', '-')})"
        )
    if command_type == "STOP_CLIENT":
        return "Modbus client stop requested"
    if command_type == "RUN_MODBUS_ACTION":
        return (
            f"Modbus action queued "
            f"({payload.get('function_id', '-')}, {payload.get('host', '-') }:{payload.get('port', '-')})"
        )
    if command_type == "START_PROCESS_SIM":
        return (
            "Process simulation start requested "
            f"({payload.get('host', '-') }:{payload.get('port', '-')}, "
            f"poll={payload.get('poll_interval', '-') }s, "
            f"start={payload.get('poll_start', '-') }, qty={payload.get('poll_quantity', '-')})"
        )
    if command_type == "STOP_PROCESS_SIM":
        return "Process simulation stop requested"
    if command_type == "WRITE_PROCESS_SIM":
        return (
            "Process simulation write requested "
            f"(HR{payload.get('address', '-') }={payload.get('value', '-')}, unit={payload.get('unit_id', 1)})"
        )
    if command_type == "CONFIGURE_PROXY_TARGET":
        return (
            "Monitor proxy destination updated "
            f"({payload.get('upstream_host', '-') }:{payload.get('upstream_port', '-')})"
        )
    return f"Command queued: {command_type}"


def queue_command(session_id: str, command_type: str, payload: dict):
    state = ensure_session_state(session_id)
    cmd = {
        "id": str(uuid.uuid4()),
        "type": command_type,
        "payload": payload,
        "created_at": time.time(),
        "dispatched_at": None,
        "dispatch_count": 0,
    }
    with lock:
        if "action_commands" not in state:
            state["action_commands"] = deque(maxlen=80)
        if "runtime_commands" not in state:
            state["runtime_commands"] = {}

        # Keep process runtime queue coherent: a new START supersedes stale STOP/WRITE
        # and a new STOP supersedes stale START/WRITE to avoid delayed inversions.
        if command_type in {"START_PROCESS_SIM", "STOP_PROCESS_SIM"}:
            opposite = "STOP_PROCESS_SIM" if command_type == "START_PROCESS_SIM" else "START_PROCESS_SIM"
            superseded_ids = []
            retained_pending = []
            for pending in state.get("pending_commands", []):
                p_type = pending.get("type")
                p_id = pending.get("id")
                if p_type in {opposite, "WRITE_PROCESS_SIM"}:
                    superseded_ids.append(p_id)
                    continue
                retained_pending.append(pending)
            state["pending_commands"] = retained_pending
            for old_id in superseded_ids:
                old_entry = state["runtime_commands"].get(old_id)
                if not old_entry:
                    continue
                old_entry["status"] = "error"
                old_entry["updated_at"] = time.time()
                old_entry["message"] = f"Superseded by {command_type}"

        state["pending_commands"].append(cmd)
        if command_type in {"START_PROCESS_SIM", "STOP_PROCESS_SIM", "WRITE_PROCESS_SIM"}:
            state["runtime_commands"][cmd["id"]] = {
                "type": command_type,
                "payload": payload,
                "status": "queued",
                "created_at": cmd["created_at"],
                "updated_at": cmd["created_at"],
            }
        if command_type == "RUN_MODBUS_ACTION":
            state["action_commands"].appendleft({
                "id": cmd["id"],
                "status": "queued",
                "protocol": "modbus",
                "function_id": payload.get("function_id"),
                "function_name": payload.get("function_name"),
                "code_label": payload.get("code_label"),
                "created_at": cmd["created_at"],
                "updated_at": cmd["created_at"],
                "message": "Queued for agent execution",
            })

    push_log_for_session(session_id, build_command_log_message(command_type, payload))
    print(
        f"[app:{APP_INSTANCE_ID}] command queued "
        f"session={session_id} type={command_type} id={cmd['id']}"
    )
    return cmd


def update_action_command_status(
    state: dict,
    command_id: str,
    status: str,
    message: str = "",
):
    history = state.get("action_commands") or []
    now = time.time()
    for entry in history:
        if entry.get("id") != command_id:
            continue
        entry["status"] = status
        entry["updated_at"] = now
        if message:
            entry["message"] = message
        return entry
    return None


def update_runtime_command_status(
    state: dict,
    command_id: str,
    status: str,
    message: str = "",
):
    commands = state.get("runtime_commands") or {}
    entry = commands.get(command_id)
    if not entry:
        return None
    entry["status"] = status
    entry["updated_at"] = time.time()
    if message:
        entry["message"] = message
    return entry


def runtime_command_label(entry: dict):
    command_type = entry.get("type") or "Runtime command"
    status = entry.get("status") or "-"
    message = entry.get("message") or ""
    suffix = f": {message}" if message else ""
    return f"{command_type} {status}{suffix}"


def has_pending_process_start(state: dict, now_ts=None):
    now_ts = time.time() if now_ts is None else now_ts
    commands = state.get("runtime_commands") or {}
    for entry in commands.values():
        if entry.get("type") != "START_PROCESS_SIM":
            continue
        if entry.get("status") not in {"queued", "sent"}:
            continue
        updated_at = float(entry.get("updated_at") or entry.get("created_at") or 0)
        if now_ts - updated_at <= 20:
            return True
    return False


def get_latest_runtime_command(state: dict, command_types=None):
    commands = state.get("runtime_commands") or {}
    if not commands:
        return None
    allowed = set(command_types or [])
    candidates = []
    for command_id, entry in commands.items():
        if allowed and entry.get("type") not in allowed:
            continue
        item = dict(entry)
        item["id"] = command_id
        candidates.append(item)
    if not candidates:
        return None
    return max(candidates, key=lambda item: float(item.get("updated_at") or item.get("created_at") or 0))


def expire_stale_runtime_commands(state: dict, session_id: str, now_ts=None):
    now_ts = time.time() if now_ts is None else now_ts
    commands = state.get("runtime_commands") or {}
    expired = []
    for command_id, entry in commands.items():
        if entry.get("type") not in {"START_PROCESS_SIM", "STOP_PROCESS_SIM", "WRITE_PROCESS_SIM"}:
            continue
        if entry.get("status") not in {"queued", "sent"}:
            continue
        updated_at = float(entry.get("updated_at") or entry.get("created_at") or 0)
        if now_ts - updated_at <= 20:
            continue
        entry["status"] = "error"
        entry["updated_at"] = now_ts
        entry["message"] = "Local runtime did not confirm the command in time"
        expired.append(entry)

    for entry in expired:
        command_type = entry.get("type")
        if command_type == "START_PROCESS_SIM":
            current = state.get("process_sim") or default_process_sim()
            # If runtime telemetry already reports process running, do not flip UI to stopped
            # just because explicit command confirmation was lost.
            if bool(current.get("running")):
                entry["status"] = "done"
                entry["updated_at"] = now_ts
                entry["message"] = "Confirmed by runtime telemetry (command result timeout)"
                push_log_for_session(session_id, "START_PROCESS_SIM confirmed by runtime telemetry after command-result timeout")
            else:
                current["running"] = False
                current["server"]["running"] = False
                current["client"]["running"] = False
                current["client"]["last_error"] = entry["message"]
                state["process_sim"] = current
                push_log_for_session(session_id, f"{command_type} failed: {entry['message']}")
        else:
            push_log_for_session(session_id, f"{command_type} failed: {entry['message']}")


def build_process_control_status(state: dict, now_ts=None):
    now_ts = time.time() if now_ts is None else now_ts
    latest = get_latest_runtime_command(
        state,
        {"START_PROCESS_SIM", "STOP_PROCESS_SIM", "WRITE_PROCESS_SIM"},
    )
    pending = [
        entry for entry in (state.get("runtime_commands") or {}).values()
        if entry.get("type") in {"START_PROCESS_SIM", "STOP_PROCESS_SIM", "WRITE_PROCESS_SIM"}
        and entry.get("status") in {"queued", "sent"}
    ]
    if not latest:
        return {
            "runtime": "agent" if should_run_process_on_agent(state) else "web",
            "latest": None,
            "pending_count": len(pending),
        }

    age_s = max(0.0, now_ts - float(latest.get("updated_at") or latest.get("created_at") or now_ts))
    return {
        "runtime": "agent" if should_run_process_on_agent(state) else "web",
        "pending_count": len(pending),
        "latest": {
            "id": latest.get("id"),
            "type": latest.get("type"),
            "status": latest.get("status"),
            "message": latest.get("message", ""),
            "age_s": round(age_s, 1),
            "created_at": latest.get("created_at"),
            "updated_at": latest.get("updated_at"),
        },
    }


def build_agent_config(request: Request, session_id: str, state: dict):
    forwarded_proto = request.headers.get("x-forwarded-proto")
    forwarded_host = request.headers.get("x-forwarded-host")

    scheme = forwarded_proto or request.url.scheme
    host = forwarded_host or request.url.netloc
    server_url = f"{scheme}://{host}".rstrip("/")

    return {
        "server_url": server_url,
        "session_id": session_id,
        "iface": state["agent_config"].get("iface") or "ALL",
        "mode": state["agent_config"].get("mode") or "MONITORING",
        "port_mode": state["agent_config"].get("port_mode") or "MODBUS_PORTS",
        "custom_ports": safe_normalize_custom_ports(state["agent_config"].get("custom_ports")),
    }


def is_agent_connected(state: dict, now_ts: float | None = None) -> bool:
    if now_ts is None:
        now_ts = time.time()
    agent_info = state.get("agent_info") or {}
    last_seen = agent_info.get("last_seen")
    return bool(last_seen is not None and (float(now_ts) - float(last_seen) <= AGENT_LIVENESS_WINDOW_SECONDS))


def agent_supports_process_sim(state: dict) -> bool:
    agent_info = state.get("agent_info") or {}
    caps = agent_info.get("capabilities") or []
    if not isinstance(caps, list):
        return False
    return "process_sim_v1" in caps


def should_run_process_on_agent(state: dict) -> bool:
    return is_agent_connected(state) and agent_supports_process_sim(state)


def sync_agent_filter_to_process_port(state: dict, port: int):
    try:
        port = int(port)
    except Exception:
        return
    if port < 1 or port > 65535:
        return
    state["agent_config"]["iface"] = state["agent_config"].get("iface") or "ALL"
    state["agent_config"]["mode"] = state["agent_config"].get("mode") or "MONITORING"
    state["agent_config"]["port_mode"] = "CUSTOM"
    state["agent_config"]["custom_ports"] = [port]
    state["agent_config"]["updated_at"] = time.time()


def get_process_register_values(snapshot: dict) -> list[int]:
    client_values = (((snapshot or {}).get("client") or {}).get("last_values") or [])
    if isinstance(client_values, list) and client_values:
        return [int(v) for v in client_values[:64] if str(v).strip() != ""]
    server_values = ((((snapshot or {}).get("server") or {}).get("registers_preview") or {}).get("values") or [])
    if isinstance(server_values, list):
        return [int(v) for v in server_values[:64] if str(v).strip() != ""]
    return []


def refresh_runtime_state(state: dict):
    runtime_state = state.get("runtime_state") or default_runtime_state()
    now = time.time()
    connected = is_agent_connected(state, now)
    process_snapshot = state.get("process_sim") or default_process_sim()
    runtime_state["runtime"]["running"] = connected
    runtime_state["runtime"]["last_updated"] = now
    runtime_state["monitor"]["running"] = bool(connected and (state.get("agent_info") or {}).get("running"))
    runtime_state["monitor"]["last_updated"] = now
    runtime_state["process"]["running"] = bool(process_snapshot.get("running"))
    runtime_state["process"]["profile_id"] = str(process_snapshot.get("process_type") or "tank_v1")
    runtime_state["process"]["last_updated"] = now
    defense_state = state.get("defense_state") or default_defense_state()
    monitor_mode = str(state.get("monitor_operating_mode") or default_monitor_operating_mode()).strip().lower()
    defense_enabled = bool(defense_state.get("enabled", True))
    runtime_state["defense"]["running"] = bool(defense_enabled and monitor_mode == "protect")
    runtime_state["defense"]["mode"] = str(defense_state.get("policy_mode") or "semantic_policy_ai_assist")
    runtime_state["defense"]["operating_mode"] = monitor_mode
    runtime_state["defense"]["last_updated"] = now
    state["runtime_state"] = runtime_state
    state["defense_state"] = defense_state


def apply_process_write_with_semantic_control(
    *,
    session_id: str,
    state: dict,
    address: int,
    value: int,
    unit_id: int = 1,
    enforce_defense: bool = True,
    process_running_override: bool | None = None,
    external_target: tuple[str, int] | None = None,
):
    now_ts = time.time()
    process_snapshot = state.get("process_sim") or process_sim.snapshot()
    profile_id = str((state.get("defense_state") or {}).get("profile_id") or process_snapshot.get("process_type") or "tank_v1")
    registers = get_process_register_values(process_snapshot)
    command = {"address": int(address), "value": int(value), "unit_id": int(unit_id), "timestamp": now_ts}
    history = [item for item in list(state.get("command_history") or []) if isinstance(item, dict)]
    process_running_for_policy = bool(process_snapshot.get("running"))
    if process_running_override is not None:
        process_running_for_policy = bool(process_running_override)

    decision_obj = evaluate_semantic_policy(
        profile_id=profile_id,
        process_running=process_running_for_policy,
        register_values=registers,
        address=int(address),
        value=int(value),
        now_ts=now_ts,
        last_writes=history,
    )
    ai_meta = ai_support_for_decision(decision_obj)
    trace_entry = make_policy_trace_entry(
        profile_id=profile_id,
        command=command,
        decision=decision_obj,
        ai_meta=ai_meta,
    )
    with lock:
        state["policy_decisions"].append(trace_entry)
        state["command_history"].append({"ts": now_ts, "address": int(address), "value": int(value)})
        defense_state = state.get("defense_state") or default_defense_state()
        counts = defense_state.get("decision_counts") or {"ALLOW": 0, "ALLOW_WITH_ALERT": 0, "BLOCK": 0}
        if decision_obj.decision in counts:
            counts[decision_obj.decision] += 1
        defense_state["decision_counts"] = counts
        defense_state["last_decision"] = trace_entry
        state["defense_state"] = defense_state

    blocked = enforce_defense and bool(defense_state.get("enabled", True)) and decision_obj.decision == "BLOCK"
    if blocked:
        push_log_for_session(
            session_id,
            f"Semantic policy BLOCKED command HR{address}={value} ({decision_obj.rule_id}: {decision_obj.reason})",
        )
        return {
            "ok": False,
            "blocked": True,
            "would_block": True,
            "error": decision_obj.reason,
            "policy_decision": trace_entry,
            "process_sim": process_snapshot,
        }

    would_block = decision_obj.decision == "BLOCK"

    if external_target:
        ext_host, ext_port = external_target
        modbus_write_single_register(
            host=str(ext_host),
            port=int(ext_port),
            register=int(address),
            value=int(value),
            unit_id=int(unit_id),
        )
        result = {"ok": True, "queued": False, "runtime": "external_lab", "process_sim": process_snapshot}
    elif should_run_process_on_agent(state):
        queue_command(
            session_id,
            "WRITE_PROCESS_SIM",
            {"address": int(address), "value": int(value), "unit_id": int(unit_id)},
        )
        result = {"ok": True, "queued": True, "runtime": "agent", "process_sim": state.get("process_sim") or process_snapshot}
    else:
        snapshot = process_sim.write_register(address=int(address), value=int(value), unit_id=int(unit_id))
        state["process_sim"] = snapshot
        result = {"ok": True, "queued": False, "runtime": "web", "process_sim": snapshot}

    if decision_obj.decision == "ALLOW_WITH_ALERT":
        push_log_for_session(
            session_id,
            f"Semantic policy ALERT for HR{address}={value} ({decision_obj.rule_id}: {decision_obj.reason})",
        )
    return {
        **result,
        "blocked": False,
        "would_block": bool(would_block),
        "policy_decision": trace_entry,
    }


def probe_lab_topology():
    openplc_web_port = int(os.getenv("OPENPLC_WEB_PORT", "8081"))
    openplc_modbus_port = int(os.getenv("OPENPLC_MODBUS_PORT", "1502"))
    hmi_web_port = int(os.getenv("HMI_WEB_PORT", "1881"))
    monitor_proxy_port = int(os.getenv("MONITOR_PROXY_PORT", "15020"))
    services = [
        {
            "id": "plc",
            "name": "OpenPLC Runtime",
            "internal_url": "http://openplc:8080",
            "external_url": f"http://localhost:{openplc_web_port}",
            "zone": "OT",
            "modbus_host": "openplc",
            "modbus_port": 502,
            "external_modbus": f"localhost:{openplc_modbus_port}",
        },
        {
            "id": "hmi",
            "name": "FUXA HMI",
            "internal_url": "http://hmi:1881",
            "external_url": f"http://localhost:{hmi_web_port}",
            "zone": "OT",
            "port": 1881,
        },
        {
            "id": "monitor",
            "name": "OT Monitor Proxy",
            "internal_url": "http://runtime:15020",
            "external_url": f"tcp://localhost:{monitor_proxy_port}",
            "zone": "OT/DMZ",
            "modbus_host": "runtime",
            "modbus_port": 15020,
            "external_modbus": f"localhost:{monitor_proxy_port}",
        },
    ]
    out = []
    for svc in services:
        internal = str(svc.get("internal_url") or "")
        service_id = str(svc.get("id") or "")
        reachable = False
        err = None
        if service_id == "monitor":
            try:
                with socket.create_connection(("runtime", 15020), timeout=0.7):
                    reachable = True
            except Exception as exc:
                err = str(exc)
        else:
            try:
                r = requests.get(internal, timeout=0.7)
                reachable = r.status_code < 500
            except Exception as exc:
                err = str(exc)
        row = dict(svc)
        try:
            row["host"] = socket.gethostbyname(str(svc.get("modbus_host") or svc.get("id") or ""))
        except Exception:
            row["host"] = None
        row["reachable"] = bool(reachable)
        row["error"] = err
        if svc.get("id") == "plc":
            modbus_ready = False
            modbus_error = None
            try:
                with socket.create_connection((str(svc.get("modbus_host")), int(svc.get("modbus_port") or 502)), timeout=0.7):
                    modbus_ready = True
            except Exception as exc:
                modbus_error = str(exc)
            row["modbus_ready"] = bool(modbus_ready)
            row["modbus_error"] = modbus_error
        out.append(row)
    return out


def ensure_openplc_runtime_started():
    try:
        with socket.create_connection(("openplc", 502), timeout=0.8):
            return True, None
    except Exception:
        pass

    sess = requests.Session()
    base = "http://openplc:8080"
    last_err = None
    for _ in range(3):
        try:
            resp = sess.post(
                f"{base}/login",
                data={"username": "openplc", "password": "openplc"},
                timeout=5.0,
                allow_redirects=True,
            )
            if resp.status_code >= 400:
                last_err = f"OpenPLC login failed with status {resp.status_code}"
                time.sleep(1.0)
                continue

            resp2 = sess.get(f"{base}/start_plc", timeout=5.0, allow_redirects=True)
            if resp2.status_code >= 400:
                last_err = f"OpenPLC start_plc failed with status {resp2.status_code}"
                time.sleep(1.0)
                continue

            time.sleep(1.5)
            try:
                with socket.create_connection(("openplc", 502), timeout=1.5):
                    return True, None
            except Exception as exc:
                last_err = f"OpenPLC runtime start attempted, Modbus still unavailable: {exc}"
                time.sleep(1.0)
        except Exception as exc:
            last_err = f"OpenPLC auto-start failed: {exc}"
            time.sleep(1.0)
    return False, str(last_err or "OpenPLC runtime unavailable")


def should_log_agent_event(state: dict, payload: dict) -> bool:
    event_type = normalize_event_type(payload.get("type"))
    function_code = payload.get("function_code")
    try:
        function_code = int(function_code) if function_code is not None else None
    except (TypeError, ValueError):
        function_code = None

    # Always log high-value events.
    if event_type in {"WRITE_REQUEST", "EXCEPTION_RESPONSE", "UNKNOWN_REQUEST"}:
        return True

    # Ignore routine traffic noise.
    if event_type in {"WRITE_RESPONSE", "READ_RESPONSE", "GENERIC_RESPONSE"}:
        return False

    # For read requests, only log when pattern/function changes (new/different read).
    if event_type == "READ_REQUEST":
        signature = (
            event_type,
            function_code,
            payload.get("server"),
            payload.get("start_addr"),
            payload.get("quantity"),
        )
        seen = state.get("event_log_signatures")
        if seen is None:
            seen = deque(maxlen=600)
            state["event_log_signatures"] = seen
        if signature in seen:
            return False
        seen.append(signature)
        return True

    # Keep generic/other requests only when function changes.
    if event_type in {"GENERIC_REQUEST"}:
        signature = (event_type, function_code, payload.get("server"))
        seen = state.get("event_log_signatures")
        if seen is None:
            seen = deque(maxlen=600)
            state["event_log_signatures"] = seen
        if signature in seen:
            return False
        seen.append(signature)
        return True

    return False


def ingest_agent_event_payload(state: dict, session_id: str, payload: dict):
    agent_info = state["agent_info"]
    agent_info["connected"] = True
    agent_info["last_seen"] = time.time()

    push_event(state, payload)
    update_modbus_summary_from_event(state, payload)
    ingest_operational_action_from_event(state, payload)

    if not should_log_agent_event(state, payload):
        return

    summary = payload.get("summary")
    if summary:
        push_log_for_session(session_id, summary)
    else:
        push_log_for_session(
            session_id,
            f"Modbus event detected: {payload.get('type', 'UNKNOWN')} "
            f"({payload.get('src_ip')}:{payload.get('src_port')} -> "
            f"{payload.get('dst_ip')}:{payload.get('dst_port')})"
        )


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    session_id, _state = get_session_state_from_request(request)
    response = templates.TemplateResponse(
        request=request,
        name="index.html",
        context={}
    )
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.get("/api/status")
def api_status(request: Request):
    session_id, state = get_session_state_from_request(request)
    now = time.time()

    agent_info = state["agent_info"]
    connected = is_agent_connected(state, now)
    agent_info["connected"] = connected
    expire_stale_runtime_commands(state, session_id, now)
    web_process_snapshot = process_sim.snapshot()
    # Do not overwrite remote runtime state during transient agent disconnects.
    # Only use web snapshot when web runtime is actually running.
    if web_process_snapshot.get("running"):
        state["process_sim"] = web_process_snapshot
    refresh_runtime_state(state)

    response = JSONResponse({
        "agent": agent_info,
        "monitor": {
            "running": connected and agent_info["running"],
            "iface": agent_info["iface"] or "-",
            "mode": agent_info["mode"] or "-",
            "snapshot": state["agent_snapshot"],
        },
        "server": state["remote_server"],
        "client": state["remote_client"],
        "process_sim": state["process_sim"],
        "process_control": build_process_control_status(state, now),
        "runtime_state": state.get("runtime_state") or default_runtime_state(),
        "defense_state": state.get("defense_state") or default_defense_state(),
        "monitor_operating_mode": str(state.get("monitor_operating_mode") or default_monitor_operating_mode()),
        "monitor_route_enabled": bool(state.get("monitor_route_enabled", default_monitor_route_enabled())),
        "monitor_proxy_target": state.get("monitor_proxy_target") or default_monitor_proxy_target(),
        "lab_target": state.get("lab_target") or default_lab_target(),
        "ui_endpoints": state.get("ui_endpoints") or default_ui_endpoints(),
        "tag_map": get_effective_tag_map(state),
        "events": list(state.get("events") or []),
        "alerts": list(state.get("alerts") or []),
        "actions": list(state.get("operational_actions") or state.get("actions") or []),
        "logs": list(state.get("logs") or []),
        "modbus_summary": build_modbus_summary(state),
        "connection_history": build_connection_history(state),
        "agent_config": state["agent_config"],
        "supported_protocols": ["modbus", "ethercat"],
        "session_id": session_id,
        "instance_id": APP_INSTANCE_ID,
    })

    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.get("/api/events")
def api_events(request: Request):
    session_id, state = get_session_state_from_request(request)
    expire_stale_runtime_commands(state, session_id)
    response = JSONResponse({
        "events": list(state["events"]),
        "alerts": list(state["alerts"]),
        "actions": list(state.get("operational_actions") or []),
        "policy_decisions": list(state.get("policy_decisions") or []),
        "tag_map": get_effective_tag_map(state),
        "logs": list(state["logs"]),
        "modbus_summary": build_modbus_summary(state),
        "connection_history": build_connection_history(state),
        "process_control": build_process_control_status(state),
        "session_id": session_id,
    })
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.get("/api/process-sim/status")
def api_process_sim_status(request: Request):
    session_id, state = get_session_state_from_request(request)
    snapshot = process_sim.snapshot()
    if snapshot.get("running"):
        state["process_sim"] = snapshot
    response = JSONResponse({"ok": True, "process_sim": state["process_sim"], "session_id": session_id})
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.post("/api/process-sim/configure")
async def api_process_sim_configure(request: Request):
    session_id, state = get_session_state_from_request(request)
    try:
        payload = await request.json()
        if not isinstance(payload, dict):
            payload = {}
    except Exception:
        payload = {}

    try:
        snapshot = process_sim.configure(
            host=payload.get("plc_host") or payload.get("host"),
            port=payload.get("plc_port") or payload.get("port"),
            hmi_host=payload.get("hmi_host"),
            hmi_port=payload.get("hmi_port"),
            poll_interval=payload.get("poll_interval"),
            poll_start=payload.get("poll_start"),
            poll_quantity=payload.get("poll_quantity"),
            process_type=payload.get("process_type"),
        )
    except Exception as e:
        response = JSONResponse({"ok": False, "error": str(e)}, status_code=400)
        set_session_cookie_if_needed(request, response, session_id)
        return response

    state["process_sim"] = snapshot
    if should_run_process_on_agent(state):
        sync_agent_filter_to_process_port(state, snapshot["server"]["port"])
    response = JSONResponse({"ok": True, "process_sim": snapshot, "session_id": session_id})
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.post("/api/process-sim/start")
async def api_process_sim_start(request: Request):
    session_id, state = get_session_state_from_request(request)
    try:
        payload = await request.json()
        if not isinstance(payload, dict):
            payload = {}
    except Exception:
        payload = {}

    host = str(payload.get("plc_host") or payload.get("host") or "127.0.0.1")
    port = int(payload.get("plc_port") or payload.get("port") or 15020)
    hmi_host = str(payload.get("hmi_host") or host)
    hmi_port = int(payload.get("hmi_port") or port)
    poll_interval = float(payload.get("poll_interval") or 0.5)
    poll_start = int(payload.get("poll_start") or 0)
    poll_quantity = int(payload.get("poll_quantity") or 16)
    process_type = str(payload.get("process_type") or "tank_v1")

    if should_run_process_on_agent(state):
        current = state.get("process_sim") or default_process_sim()
        same_running_config = (
            bool(current.get("running"))
            and str((current.get("server") or {}).get("host")) == host
            and int((current.get("server") or {}).get("port") or 0) == port
            and str((current.get("client") or {}).get("host")) == hmi_host
            and int((current.get("client") or {}).get("port") or 0) == hmi_port
            and float((current.get("client") or {}).get("poll_interval") or 0) == poll_interval
            and int((current.get("client") or {}).get("poll_start") or 0) == poll_start
            and int((current.get("client") or {}).get("poll_quantity") or 0) == poll_quantity
            and str(current.get("process_type") or "tank_v1") == process_type
        )
        if same_running_config:
            push_log_for_session(session_id, "Process simulation start ignored: runtime already running with same config")
            response = JSONResponse({"ok": True, "queued": False, "process_sim": current, "runtime": "agent"})
            set_session_cookie_if_needed(request, response, session_id)
            return response

        process_sim.stop()
        snapshot = process_sim.configure(
            host=host,
            port=port,
            hmi_host=hmi_host,
            hmi_port=hmi_port,
            poll_interval=poll_interval,
            poll_start=poll_start,
            poll_quantity=poll_quantity,
            process_type=process_type,
        )
        snapshot["running"] = True
        snapshot["server"]["running"] = True
        snapshot["client"]["running"] = True
        state["process_sim"] = snapshot
        sync_agent_filter_to_process_port(state, port)
        queue_command(
            session_id,
            "START_PROCESS_SIM",
            {
                "host": host,
                "port": port,
                "poll_interval": poll_interval,
                "poll_start": poll_start,
                "poll_quantity": poll_quantity,
                "process_type": process_type,
            },
        )
        push_log_for_session(session_id, f"Process simulation start requested on local agent (PLC={host}:{port})")
        response = JSONResponse({"ok": True, "queued": True, "process_sim": state["process_sim"], "runtime": "agent"})
    else:
        try:
            snapshot = process_sim.start(
                host=host,
                port=port,
                hmi_host=hmi_host,
                hmi_port=hmi_port,
                poll_interval=poll_interval,
                poll_start=poll_start,
                poll_quantity=poll_quantity,
                process_type=process_type,
            )
        except Exception as e:
            response = JSONResponse({"ok": False, "error": str(e)}, status_code=400)
            set_session_cookie_if_needed(request, response, session_id)
            return response

        state["process_sim"] = snapshot
        push_log_for_session(session_id, f"Process simulation started in web runtime (PLC={host}:{port}, HMI target={hmi_host}:{hmi_port})")
        response = JSONResponse({"ok": True, "queued": False, "process_sim": snapshot, "runtime": "web"})
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.post("/api/process-sim/stop")
def api_process_sim_stop(request: Request):
    session_id, state = get_session_state_from_request(request)
    if should_run_process_on_agent(state):
        queue_command(session_id, "STOP_PROCESS_SIM", {})
        snapshot = state.get("process_sim") or process_sim.snapshot()
        snapshot["running"] = False
        snapshot["server"]["running"] = False
        snapshot["client"]["running"] = False
        state["process_sim"] = snapshot
        push_log_for_session(session_id, "Process simulation stop requested on local agent")
        response = JSONResponse({"ok": True, "queued": True, "process_sim": snapshot, "runtime": "agent"})
    else:
        snapshot = process_sim.stop()
        state["process_sim"] = snapshot
        push_log_for_session(session_id, "Process simulation stopped")
        response = JSONResponse({"ok": True, "queued": False, "process_sim": snapshot, "runtime": "web"})
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.post("/api/process-sim/write")
async def api_process_sim_write(request: Request):
    session_id, state = get_session_state_from_request(request)
    try:
        payload = await request.json()
    except Exception:
        payload = {}

    try:
        address = int(payload.get("address"))
        value = int(payload.get("value"))
        unit_id = int(payload.get("unit_id", 1))
    except Exception:
        response = JSONResponse({"ok": False, "error": "Invalid address/value"}, status_code=400)
        set_session_cookie_if_needed(request, response, session_id)
        return response

    try:
        result = apply_process_write_with_semantic_control(
            session_id=session_id,
            state=state,
            address=address,
            value=value,
            unit_id=unit_id,
            enforce_defense=True,
        )
    except Exception as e:
        response = JSONResponse({"ok": False, "error": str(e)}, status_code=400)
        set_session_cookie_if_needed(request, response, session_id)
        return response

    if not result.get("ok") and result.get("blocked"):
        response = JSONResponse(result, status_code=409)
    else:
        response = JSONResponse(result)
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.get("/api/v2/runtime/state")
def api_v2_runtime_state(request: Request):
    session_id, state = get_session_state_from_request(request)
    refresh_runtime_state(state)
    response = JSONResponse(
        {
            "ok": True,
            "runtime_state": state.get("runtime_state") or default_runtime_state(),
            "defense_state": state.get("defense_state") or default_defense_state(),
            "session_id": session_id,
        }
    )
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.get("/api/v2/process-profiles")
def api_v2_process_profiles(request: Request):
    session_id, _state = get_session_state_from_request(request)
    response = JSONResponse({"ok": True, "schemas": {"process_profile": "1.0.0"}, "profiles": list(PROCESS_PROFILES.values())})
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.get("/api/v2/monitor/mode")
def api_v2_monitor_mode(request: Request):
    session_id, state = get_session_state_from_request(request)
    mode = str(state.get("monitor_operating_mode") or default_monitor_operating_mode()).strip().lower()
    if mode not in {"observe", "protect"}:
        mode = default_monitor_operating_mode()
        state["monitor_operating_mode"] = mode
    response = JSONResponse({"ok": True, "mode": mode, "session_id": session_id})
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.post("/api/v2/monitor/mode")
def api_v2_set_monitor_mode(request: Request, payload: dict = Body(default={})):
    session_id, state = get_session_state_from_request(request)
    mode = str((payload or {}).get("mode") or "").strip().lower()
    if mode not in {"observe", "protect"}:
        response = JSONResponse({"ok": False, "error": "mode must be observe or protect"}, status_code=400)
        set_session_cookie_if_needed(request, response, session_id)
        return response
    state["monitor_operating_mode"] = mode
    refresh_runtime_state(state)
    push_log_for_session(session_id, f"Monitor operating mode set to {mode.upper()}")
    response = JSONResponse({"ok": True, "mode": mode, "session_id": session_id})
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.get("/api/v2/monitor/route")
def api_v2_monitor_route(request: Request):
    session_id, state = get_session_state_from_request(request)
    enabled = bool(state.get("monitor_route_enabled", default_monitor_route_enabled()))
    response = JSONResponse({"ok": True, "enabled": enabled, "lab_target": state.get("lab_target") or default_lab_target(), "session_id": session_id})
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.post("/api/v2/monitor/route")
def api_v2_set_monitor_route(request: Request, payload: dict = Body(default={})):
    session_id, state = get_session_state_from_request(request)
    enabled = bool((payload or {}).get("enabled", True))
    state["monitor_route_enabled"] = enabled
    if enabled:
        state["lab_target"] = {"host": "runtime", "port": 15020}
    else:
        state["lab_target"] = {"host": "openplc", "port": 502}
    push_log_for_session(session_id, f"Monitor route set to {'ENABLED' if enabled else 'BYPASS'}")
    response = JSONResponse({"ok": True, "enabled": enabled, "lab_target": state.get("lab_target"), "session_id": session_id})
    set_session_cookie_if_needed(request, response, session_id)
    return response

@app.get("/api/v2/monitor/proxy-target")
def api_v2_monitor_proxy_target(request: Request):
    session_id, state = get_session_state_from_request(request)
    target = state.get("monitor_proxy_target") or default_monitor_proxy_target()
    response = JSONResponse({"ok": True, "target": target, "session_id": session_id})
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.post("/api/v2/monitor/proxy-target")
def api_v2_set_monitor_proxy_target(request: Request, payload: dict = Body(default={})):
    session_id, state = get_session_state_from_request(request)
    host = str((payload or {}).get("host") or "").strip()
    try:
        port = int((payload or {}).get("port") or 502)
    except Exception:
        port = 502
    if not host:
        response = JSONResponse({"ok": False, "error": "host is required"}, status_code=400)
        set_session_cookie_if_needed(request, response, session_id)
        return response
    if port < 1 or port > 65535:
        response = JSONResponse({"ok": False, "error": "invalid port"}, status_code=400)
        set_session_cookie_if_needed(request, response, session_id)
        return response

    state["monitor_proxy_target"] = {"host": host, "port": int(port)}
    queue_command(
        session_id,
        "CONFIGURE_PROXY_TARGET",
        {"upstream_host": host, "upstream_port": int(port)},
    )
    response = JSONResponse({"ok": True, "target": state["monitor_proxy_target"], "session_id": session_id})
    set_session_cookie_if_needed(request, response, session_id)
    return response


def _probe_host_ports(host: str, ports: list[int], timeout_s: float = 0.15):
    open_ports = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout_s)
        try:
            if s.connect_ex((host, int(port))) == 0:
                open_ports.append(int(port))
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass
    return open_ports


def _build_network_architecture(ui: dict):
    mon_ip = str(((ui.get("monitor_proxy") or {}).get("ip") or "")).strip()
    monitor_alias_ips = set()
    web_alias_ips = set()
    if mon_ip:
        monitor_alias_ips.add(mon_ip)
    try:
        for fam, _, _, _, sockaddr in socket.getaddrinfo("runtime", 15020, socket.AF_INET, socket.SOCK_STREAM):
            if fam == socket.AF_INET and sockaddr and sockaddr[0]:
                monitor_alias_ips.add(str(sockaddr[0]).strip())
    except Exception:
        pass
    try:
        for fam, _, _, _, sockaddr in socket.getaddrinfo("web", 8000, socket.AF_INET, socket.SOCK_STREAM):
            if fam == socket.AF_INET and sockaddr and sockaddr[0]:
                web_alias_ips.add(str(sockaddr[0]).strip())
    except Exception:
        pass
    ot_subnet = str(os.getenv("OT_SUBNET", "10.20.0.0/24"))
    dmz_subnet = str(os.getenv("DMZ_SUBNET", "10.30.0.0/24"))
    return {
        "ot_subnet": ot_subnet,
        "dmz_subnet": dmz_subnet,
        "monitor_alias_ips": sorted([ip for ip in monitor_alias_ips if ip]),
        "web_alias_ips": sorted([ip for ip in web_alias_ips if ip]),
        "explanation": "Monitor is dual-homed (OT + DMZ): it sees OT traffic and forwards telemetry/control to Web on DMZ.",
    }


@app.get("/api/v2/network/scan")
def api_v2_network_scan(request: Request):
    session_id, state = get_session_state_from_request(request)
    ui = state.get("ui_endpoints") or default_ui_endpoints()
    plc_ip = str(((ui.get("plc") or {}).get("ip") or "")).strip()
    hmi_ip = str(((ui.get("hmi") or {}).get("ip") or "")).strip()
    mon_ip = str(((ui.get("monitor_proxy") or {}).get("ip") or "")).strip()
    architecture = _build_network_architecture(ui)
    monitor_alias_ips = set(architecture.get("monitor_alias_ips") or [])
    web_alias_ips = set(architecture.get("web_alias_ips") or [])
    extra_ips = set()
    for ev in list(state.get("events") or [])[-300:]:
        src = str(ev.get("src_ip") or "").strip()
        dst = str(ev.get("dst_ip") or "").strip()
        if src:
            extra_ips.add(src)
        if dst:
            extra_ips.add(dst)
    ips = []
    for ip in [hmi_ip, mon_ip, plc_ip, *sorted(monitor_alias_ips)]:
        if ip and ip not in ips:
            ips.append(ip)
    for ip in sorted(extra_ips):
        if ip not in ips:
            ips.append(ip)

    scan_ports = [502, 15020, 1881, 8000, 8080, 8081]
    ot_subnet = str(architecture.get("ot_subnet") or os.getenv("OT_SUBNET", "10.20.0.0/24"))
    dmz_subnet = str(architecture.get("dmz_subnet") or os.getenv("DMZ_SUBNET", "10.30.0.0/24"))
    try:
        ot_net = ipaddress.ip_network(ot_subnet, strict=False)
    except Exception:
        ot_net = ipaddress.ip_network("10.20.0.0/24")
    try:
        dmz_net = ipaddress.ip_network(dmz_subnet, strict=False)
    except Exception:
        dmz_net = ipaddress.ip_network("10.30.0.0/24")

    rows = []
    for ip in ips[:48]:
        open_ports = _probe_host_ports(ip, scan_ports)
        role = "unknown"
        if ip == plc_ip:
            role = "plc"
        elif ip == hmi_ip:
            role = "hmi"
        elif ip == mon_ip or ip in monitor_alias_ips:
            role = "monitor"
        elif ip in web_alias_ips:
            role = "web"
        zones = []
        try:
            addr = ipaddress.ip_address(ip)
            if addr in ot_net:
                zones.append("OT")
            if addr in dmz_net:
                zones.append("DMZ")
        except Exception:
            pass
        rows.append({
            "ip": ip,
            "role": role,
            "reachable": bool(open_ports),
            "open_ports": open_ports,
            "zones": zones,
        })
    response = JSONResponse({"ok": True, "hosts": rows, "architecture": architecture, "session_id": session_id})
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.get("/api/v2/lab/topology")
def api_v2_lab_topology(request: Request):
    session_id, state = get_session_state_from_request(request)
    ui_endpoints = state.get("ui_endpoints") or default_ui_endpoints()
    response = JSONResponse(
        {
            "ok": True,
            "target": state.get("lab_target") or default_lab_target(),
            "monitor_route_enabled": bool(state.get("monitor_route_enabled", default_monitor_route_enabled())),
            "monitor_proxy_target": state.get("monitor_proxy_target") or default_monitor_proxy_target(),
            "services": probe_lab_topology(),
            "ui_endpoints": ui_endpoints,
            "architecture": _build_network_architecture(ui_endpoints),
        }
    )
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.get("/api/v2/ui/endpoints")
def api_v2_ui_endpoints(request: Request):
    session_id, state = get_session_state_from_request(request)
    response = JSONResponse({"ok": True, "ui_endpoints": state.get("ui_endpoints") or default_ui_endpoints(), "session_id": session_id})
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.get("/api/v2/monitor/context")
def api_v2_monitor_context(request: Request):
    session_id, state = get_session_state_from_request(request)
    ui = state.get("ui_endpoints") or default_ui_endpoints()
    arch = _build_network_architecture(ui)
    monitor_context = get_effective_monitor_context(state)
    response = JSONResponse(
        {
            "ok": True,
            "session_id": session_id,
            "hmi_ip": endpoint_host((ui.get("hmi") or {}).get("ip")),
            "plc_ip": endpoint_host((ui.get("plc") or {}).get("ip")),
            "monitor_ip": endpoint_host((ui.get("monitor_proxy") or {}).get("ip")),
            "ot_subnet": str(state.get("ot_subnet_override") or arch.get("ot_subnet") or ""),
            "dmz_subnet": str(state.get("dmz_subnet_override") or arch.get("dmz_subnet") or ""),
            "maintenance_window": bool(monitor_context.get("maintenance_window", False)),
            "tag_map": get_effective_tag_map(state),
        }
    )
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.post("/api/v2/monitor/context")
def api_v2_set_monitor_context(request: Request, payload: dict = Body(default={})):
    session_id, state = get_session_state_from_request(request)
    with lock:
        current = dict(state.get("ui_endpoints") or default_ui_endpoints())
        monitor_context = get_effective_monitor_context(state)
        hmi_ip = endpoint_host(payload.get("hmi_ip"))
        plc_ip = endpoint_host(payload.get("plc_ip"))
        monitor_ip = endpoint_host(payload.get("monitor_ip"))
        if hmi_ip:
            current.setdefault("hmi", {})["ip"] = hmi_ip
        if plc_ip:
            current.setdefault("plc", {})["ip"] = plc_ip
        if monitor_ip:
            current.setdefault("monitor_proxy", {})["ip"] = monitor_ip
        state["ui_endpoints"] = current

        ot_subnet = str(payload.get("ot_subnet") or "").strip()
        dmz_subnet = str(payload.get("dmz_subnet") or "").strip()
        if ot_subnet:
            state["ot_subnet_override"] = ot_subnet
        if dmz_subnet:
            state["dmz_subnet_override"] = dmz_subnet

        if "maintenance_window" in payload:
            monitor_context["maintenance_window"] = normalize_boolish(payload.get("maintenance_window"), False)
        state["monitor_context"] = monitor_context

        if "tag_map" in payload:
            incoming = payload.get("tag_map") or {}
            normalized = {"coil": {}, "register": {}}
            for bucket in ("coil", "register"):
                src = incoming.get(bucket) or {}
                for k, v in dict(src).items():
                    try:
                        kk = int(k)
                    except Exception:
                        continue
                    vv = str(v or "").strip()
                    if vv:
                        normalized[bucket][kk] = vv
            state["tag_map_overrides"] = normalized
        if "tag_map_use_defaults" in payload:
            state["tag_map_use_defaults"] = bool(payload.get("tag_map_use_defaults", False))
    response = JSONResponse(
        {
            "ok": True,
            "session_id": session_id,
            "ui_endpoints": state.get("ui_endpoints"),
            "tag_map": get_effective_tag_map(state),
            "maintenance_window": bool(get_effective_monitor_context(state).get("maintenance_window", False)),
        }
    )
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.post("/api/v2/ui/endpoints")
def api_v2_set_ui_endpoints(request: Request, payload: dict = Body(default={})):
    session_id, state = get_session_state_from_request(request)
    current = dict(state.get("ui_endpoints") or default_ui_endpoints())
    updates = payload or {}
    for key in ("plc", "hmi", "monitor_proxy"):
        incoming = updates.get(key)
        if isinstance(incoming, dict):
            base = dict(current.get(key) or {})
            for k, v in incoming.items():
                base[str(k)] = v
            current[key] = base
    state["ui_endpoints"] = current
    response = JSONResponse({"ok": True, "ui_endpoints": current, "session_id": session_id})
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.post("/api/v2/lab/openplc/start")
def api_v2_lab_openplc_start(request: Request):
    session_id, _state = get_session_state_from_request(request)
    ok, err = ensure_openplc_runtime_started()
    code = 200 if ok else 409
    response = JSONResponse({"ok": ok, "error": err}, status_code=code)
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.post("/api/v2/lab/smoke-test")
def api_v2_lab_smoke_test(request: Request):
    session_id, state = get_session_state_from_request(request)
    target = state.get("lab_target") or default_lab_target()
    host = str(target.get("host") or "openplc")
    port = int(target.get("port") or 502)

    if host == "openplc" and port == 502:
        ok, err = ensure_openplc_runtime_started()
        if not ok:
            response = JSONResponse({"ok": False, "error": err or "OpenPLC runtime not ready"}, status_code=409)
            set_session_cookie_if_needed(request, response, session_id)
            return response

    register = 0
    write_value = int(time.time()) % 100
    try:
        modbus_write_single_register(host=host, port=port, register=register, value=write_value, unit_id=1, timeout_s=2.0)
        read_res = modbus_read_holding_registers(host=host, port=port, start=register, quantity=1, unit_id=1, timeout_s=2.0)
        read_back = int((read_res.get("values") or [None])[0])
    except Exception as exc:
        response = JSONResponse({"ok": False, "error": f"Smoke test failed: {exc}"}, status_code=409)
        set_session_cookie_if_needed(request, response, session_id)
        return response

    passed = read_back == write_value
    payload = {
        "ok": bool(passed),
        "target": {"host": host, "port": port},
        "register": register,
        "written": write_value,
        "read_back": read_back,
        "message": "PLC Modbus read/write smoke test passed" if passed else "PLC responded but value mismatch",
    }
    if passed:
        push_log_for_session(session_id, f"Lab smoke test OK ({host}:{port}) HR{register}={write_value}")
        response = JSONResponse(payload)
    else:
        push_log_for_session(session_id, f"Lab smoke test mismatch ({host}:{port}) write={write_value} read={read_back}")
        response = JSONResponse(payload, status_code=409)
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.get("/api/v2/lab/read-register")
def api_v2_lab_read_register(request: Request, register: int = 0, unit_id: int = 1):
    session_id, state = get_session_state_from_request(request)
    target = state.get("lab_target") or default_lab_target()
    host = str(target.get("host") or "openplc")
    port = int(target.get("port") or 502)

    if register < 0 or register > 65535:
        response = JSONResponse({"ok": False, "error": "Invalid register address"}, status_code=400)
        set_session_cookie_if_needed(request, response, session_id)
        return response
    if unit_id < 0 or unit_id > 255:
        response = JSONResponse({"ok": False, "error": "Invalid unit_id"}, status_code=400)
        set_session_cookie_if_needed(request, response, session_id)
        return response

    if host == "openplc" and port == 502:
        ok, err = ensure_openplc_runtime_started()
        if not ok:
            response = JSONResponse({"ok": False, "error": err or "OpenPLC runtime not ready"}, status_code=409)
            set_session_cookie_if_needed(request, response, session_id)
            return response

    try:
        read_res = modbus_read_holding_registers(
            host=host,
            port=port,
            start=register,
            quantity=1,
            unit_id=unit_id,
            timeout_s=2.0,
        )
        value = int((read_res.get("values") or [0])[0])
    except Exception as exc:
        response = JSONResponse({"ok": False, "error": f"Read failed: {exc}"}, status_code=409)
        set_session_cookie_if_needed(request, response, session_id)
        return response

    response = JSONResponse(
        {
            "ok": True,
            "target": {"host": host, "port": port},
            "register": register,
            "unit_id": unit_id,
            "value": value,
            "ts": int(time.time() * 1000),
        }
    )
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.post("/api/v2/lab/write-register")
def api_v2_lab_write_register(request: Request, payload: dict = Body(default={})):
    session_id, state = get_session_state_from_request(request)
    target = state.get("lab_target") or default_lab_target()
    host = str(target.get("host") or "openplc")
    port = int(target.get("port") or 502)

    try:
        register = int(payload.get("register", 2))
        value = int(payload.get("value", 0))
        unit_id = int(payload.get("unit_id", 1))
    except Exception:
        response = JSONResponse({"ok": False, "error": "Invalid payload"}, status_code=400)
        set_session_cookie_if_needed(request, response, session_id)
        return response

    if register < 0 or register > 65535:
        response = JSONResponse({"ok": False, "error": "Invalid register address"}, status_code=400)
        set_session_cookie_if_needed(request, response, session_id)
        return response
    if value < 0 or value > 65535:
        response = JSONResponse({"ok": False, "error": "Invalid register value"}, status_code=400)
        set_session_cookie_if_needed(request, response, session_id)
        return response
    if unit_id < 0 or unit_id > 255:
        response = JSONResponse({"ok": False, "error": "Invalid unit_id"}, status_code=400)
        set_session_cookie_if_needed(request, response, session_id)
        return response

    if host == "openplc" and port == 502:
        ok, err = ensure_openplc_runtime_started()
        if not ok:
            response = JSONResponse({"ok": False, "error": err or "OpenPLC runtime not ready"}, status_code=409)
            set_session_cookie_if_needed(request, response, session_id)
            return response

    try:
        modbus_write_single_register(
            host=host,
            port=port,
            register=register,
            value=value,
            unit_id=unit_id,
            timeout_s=2.0,
        )
    except Exception as exc:
        response = JSONResponse({"ok": False, "error": f"Write failed: {exc}"}, status_code=409)
        set_session_cookie_if_needed(request, response, session_id)
        return response

    response = JSONResponse(
        {
            "ok": True,
            "target": {"host": host, "port": port},
            "register": register,
            "unit_id": unit_id,
            "value": value,
            "ts": int(time.time() * 1000),
        }
    )
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.get("/api/v2/lab/read-bool")
def api_v2_lab_read_bool(request: Request, coil: int = 0, unit_id: int = 1):
    session_id, state = get_session_state_from_request(request)
    target = state.get("lab_target") or default_lab_target()
    host = str(target.get("host") or "openplc")
    port = int(target.get("port") or 502)

    if coil < 0 or coil > 65535:
        response = JSONResponse({"ok": False, "error": "Invalid coil address"}, status_code=400)
        set_session_cookie_if_needed(request, response, session_id)
        return response

    if host == "openplc" and port == 502:
        ok, err = ensure_openplc_runtime_started()
        if not ok:
            response = JSONResponse({"ok": False, "error": err or "OpenPLC runtime not ready"}, status_code=409)
            set_session_cookie_if_needed(request, response, session_id)
            return response

    try:
        read_res = modbus_read_coils(host=host, port=port, start=coil, quantity=1, unit_id=unit_id, timeout_s=2.0)
        value = int((read_res.get("values") or [0])[0])
    except Exception as exc:
        response = JSONResponse({"ok": False, "error": f"Read bool failed: {exc}"}, status_code=409)
        set_session_cookie_if_needed(request, response, session_id)
        return response

    response = JSONResponse(
        {
            "ok": True,
            "target": {"host": host, "port": port},
            "coil": int(coil),
            "unit_id": int(unit_id),
            "value": bool(value),
            "ts": int(time.time() * 1000),
        }
    )
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.post("/api/v2/lab/write-bool")
def api_v2_lab_write_bool(request: Request, payload: dict = Body(default={})):
    session_id, state = get_session_state_from_request(request)
    target = state.get("lab_target") or default_lab_target()
    host = str(target.get("host") or "openplc")
    port = int(target.get("port") or 502)

    try:
        coil = int(payload.get("coil", 0))
        unit_id = int(payload.get("unit_id", 1))
        raw_value = payload.get("value", False)
        value = bool(raw_value) if isinstance(raw_value, bool) else str(raw_value).strip().lower() in {"1", "true", "on", "yes"}
    except Exception:
        response = JSONResponse({"ok": False, "error": "Invalid payload"}, status_code=400)
        set_session_cookie_if_needed(request, response, session_id)
        return response

    if coil < 0 or coil > 65535:
        response = JSONResponse({"ok": False, "error": "Invalid coil address"}, status_code=400)
        set_session_cookie_if_needed(request, response, session_id)
        return response

    if host == "openplc" and port == 502:
        ok, err = ensure_openplc_runtime_started()
        if not ok:
            response = JSONResponse({"ok": False, "error": err or "OpenPLC runtime not ready"}, status_code=409)
            set_session_cookie_if_needed(request, response, session_id)
            return response

    try:
        modbus_write_single_coil(host=host, port=port, coil=coil, value=value, unit_id=unit_id, timeout_s=2.0)
    except Exception as exc:
        response = JSONResponse({"ok": False, "error": f"Write bool failed: {exc}"}, status_code=409)
        set_session_cookie_if_needed(request, response, session_id)
        return response

    response = JSONResponse(
        {
            "ok": True,
            "target": {"host": host, "port": port},
            "coil": int(coil),
            "unit_id": int(unit_id),
            "value": bool(value),
            "ts": int(time.time() * 1000),
        }
    )
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.post("/api/v2/lab/target")
def api_v2_lab_target(request: Request, payload: dict = Body(default={})):
    session_id, state = get_session_state_from_request(request)
    host = str(payload.get("host") or "").strip() or "openplc"
    try:
        port = int(payload.get("port") or 502)
    except Exception:
        port = 502
    if port < 1 or port > 65535:
        response = JSONResponse({"ok": False, "error": "Invalid port"}, status_code=400)
        set_session_cookie_if_needed(request, response, session_id)
        return response
    state["lab_target"] = {"host": host, "port": port}
    response = JSONResponse({"ok": True, "target": state["lab_target"]})
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.get("/api/v2/semantic-policy")
def api_v2_semantic_policy(request: Request, profile_id: str = "tank_v1"):
    session_id, _state = get_session_state_from_request(request)
    policy = SEMANTIC_POLICIES.get(profile_id) or SEMANTIC_POLICIES["tank_v1"]
    response = JSONResponse({"ok": True, "schemas": {"semantic_policy": "1.0.0"}, "profile_id": profile_id, "policy": policy})
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.get("/api/v2/attacks")
def api_v2_attacks(request: Request, profile_id: str | None = None):
    session_id, _state = get_session_state_from_request(request)
    attacks = list(ATTACK_LIBRARY.values())
    if profile_id:
        attacks = [a for a in attacks if str(a.get("profile")) == str(profile_id)]
    response = JSONResponse({"ok": True, "schemas": {"attack_scenario": "1.0.0"}, "attacks": attacks})
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.get("/api/v2/frameworks/traceability")
def api_v2_frameworks_traceability(request: Request):
    session_id, _state = get_session_state_from_request(request)
    rows = []
    for attack in ATTACK_LIBRARY.values():
        profile_id = attack.get("profile")
        policy = SEMANTIC_POLICIES.get(profile_id) or {}
        for rule in policy.get("rules") or []:
            rows.append(
                {
                    "scenario_id": attack.get("id"),
                    "scenario_name": attack.get("name"),
                    "attack_framework": attack.get("framework"),
                    "attack_technique": attack.get("technique"),
                    "policy_rule_id": rule.get("id"),
                    "policy_rule_name": rule.get("name"),
                    "purdue_zone": "Level 1/2 Control + Level 3 Operations",
                    "dmz_relevance": "Control-plane orchestration only, no direct process commands across DMZ",
                    "nist_reference": "NIST SP 800-82r3 (monitoring + control integrity)",
                }
            )
    response = JSONResponse({"ok": True, "matrix": rows})
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.get("/api/v2/policy-decisions")
def api_v2_policy_decisions(request: Request, decision: str | None = None):
    session_id, state = get_session_state_from_request(request)
    entries = list(state.get("policy_decisions") or [])
    if decision:
        decision_norm = str(decision).upper().strip()
        entries = [e for e in entries if str(e.get("decision")).upper() == decision_norm]
    response = JSONResponse({"ok": True, "entries": entries, "count": len(entries)})
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.get("/api/v2/execution-reports")
def api_v2_execution_reports(request: Request):
    session_id, state = get_session_state_from_request(request)
    response = JSONResponse({"ok": True, "schemas": {"execution_report": "1.0.0"}, "reports": list(state.get("execution_reports") or [])})
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.post("/api/v2/policy-decisions/export")
def api_v2_policy_decisions_export(request: Request):
    session_id, state = get_session_state_from_request(request)
    payload = {
        "session_id": session_id,
        "generated_at": time.time(),
        "entries": list(state.get("policy_decisions") or []),
    }
    response = JSONResponse({"ok": True, "export": payload})
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.post("/api/v2/scenarios/execute")
async def api_v2_scenarios_execute(request: Request):
    session_id, state = get_session_state_from_request(request)
    try:
        payload = await request.json()
        if not isinstance(payload, dict):
            payload = {}
    except Exception:
        payload = {}

    profile_id = str(payload.get("profile_id") or "tank_v1")
    attack_id = str(payload.get("attack_id") or "")
    mode = str(payload.get("mode") or "baseline").strip().lower()

    attack = ATTACK_LIBRARY.get(attack_id)
    if not attack:
        response = JSONResponse({"ok": False, "error": "Unknown attack_id"}, status_code=404)
        set_session_cookie_if_needed(request, response, session_id)
        return response
    if attack.get("profile") != profile_id:
        response = JSONResponse({"ok": False, "error": "Attack profile mismatch"}, status_code=400)
        set_session_cookie_if_needed(request, response, session_id)
        return response

    process_snapshot = state.get("process_sim") or process_sim.snapshot()
    use_external_lab = not bool(process_snapshot.get("running"))
    external_target = None
    process_running_override = None
    if use_external_lab:
        target = state.get("lab_target") or default_lab_target()
        external_target = (str(target.get("host") or "openplc"), int(target.get("port") or 502))
        process_running_override = True
        modbus_ready = False
        try:
            with socket.create_connection((external_target[0], external_target[1]), timeout=1.0):
                modbus_ready = True
        except Exception:
            modbus_ready = False
        if not modbus_ready:
            if external_target[0] == "openplc" and external_target[1] == 502:
                ok, err = ensure_openplc_runtime_started()
                if ok:
                    modbus_ready = True
                else:
                    response = JSONResponse(
                        {
                            "ok": False,
                            "error": err or (
                                "External PLC target openplc:502 is not accepting Modbus/TCP yet. "
                                "Open OpenPLC at http://localhost:8081 and ensure runtime is started."
                            ),
                        },
                        status_code=409,
                    )
                    set_session_cookie_if_needed(request, response, session_id)
                    return response
        if not modbus_ready:
            response = JSONResponse(
                {
                    "ok": False,
                    "error": (
                        f"External PLC target {external_target[0]}:{external_target[1]} is not accepting Modbus/TCP yet. "
                        "Open OpenPLC at http://localhost:8081 and ensure runtime is started."
                    ),
                },
                status_code=409,
            )
            set_session_cookie_if_needed(request, response, session_id)
            return response

    enforce = mode == "protected"
    trace = []
    for step in attack.get("steps") or []:
        address = int(step.get("address"))
        value = int(step.get("value"))
        delay_s = float(step.get("delay_s") or 0.0)
        try:
            res = apply_process_write_with_semantic_control(
                session_id=session_id,
                state=state,
                address=address,
                value=value,
                unit_id=1,
                enforce_defense=enforce,
                process_running_override=process_running_override,
                external_target=external_target,
            )
        except Exception as exc:
            trace.append({"ok": False, "address": address, "value": value, "error": str(exc)})
            break
        trace.append(res)
        if delay_s > 0:
            time.sleep(min(delay_s, 1.0))

    end_snapshot = state.get("process_sim") or process_sim.snapshot()
    trace_entries = [item.get("policy_decision") for item in trace if isinstance(item, dict) and item.get("policy_decision")]
    final_registers = get_process_register_values(end_snapshot)
    impact = evaluate_execution_impact(trace_entries, final_registers)
    effective_blocked = sum(1 for item in trace if isinstance(item, dict) and bool(item.get("blocked")))
    would_block = sum(1 for item in trace if isinstance(item, dict) and bool(item.get("would_block")) and not bool(item.get("blocked")))
    warnings = sum(
        1
        for item in trace_entries
        if isinstance(item, dict) and str(item.get("decision")) == "ALLOW_WITH_ALERT"
    )
    allowed_effective = max(0, len(trace) - effective_blocked - warnings)
    impact["blocked_effective"] = int(effective_blocked)
    impact["would_block"] = int(would_block)
    impact["alerts_effective"] = int(warnings + would_block)
    impact["allowed_effective"] = int(allowed_effective)
    report = {
        "id": f"rep_{uuid.uuid4().hex[:16]}",
        "timestamp": time.time(),
        "profile_id": profile_id,
        "attack_id": attack_id,
        "attack_name": attack.get("name"),
        "mode": mode,
        "framework": attack.get("framework"),
        "technique": attack.get("technique"),
        "execution_target": {
            "mode": "external_lab" if use_external_lab else "process_sim",
            "host": external_target[0] if external_target else ((end_snapshot.get("server") or {}).get("host")),
            "port": external_target[1] if external_target else ((end_snapshot.get("server") or {}).get("port")),
        },
        "trace": trace,
        "policy_trace": trace_entries,
        "impact": impact,
    }
    with lock:
        state["execution_reports"].append(report)

    push_log_for_session(
        session_id,
        f"Scenario executed ({attack_id}, mode={mode}) impact_score={impact.get('impact_score')}",
    )
    response = JSONResponse({"ok": True, "report": report, "session_id": session_id})
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.get("/api/actions/definitions")
def api_actions_definitions(request: Request):
    session_id, _state = get_session_state_from_request(request)
    response = JSONResponse({
        "ok": True,
        "protocols": [
            {
                "id": "modbus",
                "name": "Modbus",
                "functions": get_modbus_function_definitions(),
            }
        ],
    })
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.post("/api/actions/modbus/execute")
def api_execute_modbus_action(request: Request, payload: dict = Body(default={})):
    session_id, state = get_session_state_from_request(request)
    agent_info = state.get("agent_info") or {}
    if not agent_info.get("connected"):
        response = JSONResponse(
            {"ok": False, "error": "Agent is not connected. Connect the local agent first."},
            status_code=409,
        )
        set_session_cookie_if_needed(request, response, session_id)
        return response

    capabilities = set(agent_info.get("capabilities") or [])

    if "modbus_actions_v1" not in capabilities:
        response = JSONResponse(
            {
                "ok": False,
                "error": (
                    "Connected agent does not support Modbus Actions execution yet. "
                    "Please update/restart the local agent and reconnect."
                ),
                "required_capability": "modbus_actions_v1",
                "agent_capabilities": sorted(capabilities),
            },
            status_code=409,
        )
        set_session_cookie_if_needed(request, response, session_id)
        return response

    try:
        function_def, normalized = validate_modbus_action_payload(payload)
    except ModbusValidationError as exc:
        response = JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
        set_session_cookie_if_needed(request, response, session_id)
        return response

    transaction_id = int(time.time() * 1000) & 0xFFFF
    built = build_modbus_tcp_request(function_def, normalized, transaction_id=transaction_id)

    cmd_payload = {
        "host": normalized["host"],
        "port": normalized["port"],
        "function_id": normalized["function_id"],
        "function_name": function_def["name"],
        "code_label": function_def.get("code_label"),
        "values": normalized,
        "request_hex": built["request_hex"],
    }
    queued = queue_command(session_id, "RUN_MODBUS_ACTION", cmd_payload)

    response = JSONResponse({
        "ok": True,
        "command_id": queued["id"],
        "function": {
            "id": function_def["id"],
            "code": function_def["code"],
            "code_label": function_def.get("code_label"),
            "name": function_def["name"],
        },
        "preview": {
            "host": normalized["host"],
            "port": normalized["port"],
            "unit_id": built["unit_id"],
            "transaction_id": built["transaction_id"],
            "request_hex": built["request_hex"],
            "pdu_hex": built["pdu_hex"],
        },
    })
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.get("/api/actions/modbus/commands")
def api_modbus_action_commands(request: Request):
    session_id, state = get_session_state_from_request(request)
    history = list(state.get("action_commands") or [])
    response = JSONResponse({"ok": True, "commands": history, "session_id": session_id})
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.get("/api/agent/interfaces")
def get_agent_interfaces(request: Request):
    session_id, state = get_session_state_from_request(request)
    agent_info = state["agent_info"]

    response = JSONResponse({
        "ok": True,
        "connected": agent_info["connected"],
        "interfaces": agent_info.get("available_ifaces", []),
        "monitored_interfaces": agent_info.get("available_monitored_ifaces", []),
        "unmonitored_interfaces": agent_info.get("available_unmonitored_ifaces", []),
        "current": agent_info.get("iface"),
        "session_id": session_id,
    })
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.get("/api/agent/config")
def get_agent_config(request: Request, session_id: str = None):
    effective_session_id = session_id or get_or_create_session_id(request)
    state = ensure_session_state(effective_session_id)

    response = JSONResponse({
        "ok": True,
        "config": state["agent_config"],
        "instance_id": APP_INSTANCE_ID,
    })

    if session_id is None:
        set_session_cookie_if_needed(request, response, effective_session_id)

    return response


@app.post("/api/agent/config")
async def set_agent_config(request: Request):
    session_id, state = get_session_state_from_request(request)
    data = await request.json()

    iface = data.get("iface", state["agent_config"]["iface"])
    mode = data.get("mode", state["agent_config"]["mode"])
    port_mode = data.get("port_mode", state["agent_config"].get("port_mode", "MODBUS_PORTS"))

    if mode not in ["LEARNING", "MONITORING"]:
        return JSONResponse({"ok": False, "error": "Invalid mode"}, status_code=400)
    if port_mode not in ["ALL_PORTS", "MODBUS_PORTS", "CUSTOM"]:
        return JSONResponse({"ok": False, "error": "Invalid port_mode"}, status_code=400)

    try:
        custom_ports = normalize_custom_ports(data.get("custom_ports", state["agent_config"].get("custom_ports", [])))
    except ValueError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)

    if port_mode == "CUSTOM" and not custom_ports:
        return JSONResponse({"ok": False, "error": "CUSTOM port_mode requires at least one custom port"}, status_code=400)

    old_iface = state["agent_config"]["iface"]
    old_mode = state["agent_config"]["mode"]
    old_port_mode = state["agent_config"].get("port_mode", "MODBUS_PORTS")
    old_custom_ports = safe_normalize_custom_ports(state["agent_config"].get("custom_ports", []))
    iface_changed = old_iface != iface
    mode_changed = old_mode != mode
    port_mode_changed = old_port_mode != port_mode
    custom_ports_changed = old_custom_ports != custom_ports

    state["agent_config"]["iface"] = iface
    state["agent_config"]["mode"] = mode
    state["agent_config"]["port_mode"] = port_mode
    state["agent_config"]["custom_ports"] = custom_ports
    state["agent_config"]["updated_at"] = time.time()

    detection_scope_changed = iface_changed or port_mode_changed or custom_ports_changed

    if detection_scope_changed:
        state["modbus_summary"] = default_modbus_summary()
        if "event_log_signatures" in state:
            state["event_log_signatures"].clear()
        if "recent_event_signatures" in state:
            state["recent_event_signatures"].clear()
        if "recent_alert_signatures" in state:
            state["recent_alert_signatures"].clear()
        push_log_for_session(
            session_id,
            (
                f"Detection scope changed (iface: {old_iface}->{iface}, "
                f"port_mode: {old_port_mode}->{port_mode}, "
                f"custom_ports: {old_custom_ports}->{custom_ports}) - resetting detection"
            ),
        )
    else:
        changed_keys = []
        if mode_changed:
            changed_keys.append(f"mode={mode}")
        if not changed_keys:
            changed_keys.append("no-op")
        push_log_for_session(session_id, f"Monitor configuration updated ({', '.join(changed_keys)})")

    response = JSONResponse({
        "ok": True,
        "config": state["agent_config"],
    })
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.post("/api/agent/server/configure")
async def configure_server(request: Request):
    session_id, state = get_session_state_from_request(request)
    data = await request.json()

    host = data.get("host", state["remote_server"]["host"])
    port = int(data.get("port", state["remote_server"]["port"]))

    state["remote_server"]["host"] = host
    state["remote_server"]["port"] = port
    state["remote_server"]["updated_at"] = time.time()

    push_log_for_session(session_id, f"Server configuration updated (host={host}, port={port})")
    if is_agent_connected(state):
        queue_command(session_id, "CONFIGURE_SERVER", {"host": host, "port": port})

    response = JSONResponse({"ok": True, "server": state["remote_server"]})
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.post("/api/agent/client/configure")
async def configure_client(request: Request):
    session_id, state = get_session_state_from_request(request)
    data = await request.json()

    host = data.get("host", state["remote_client"]["host"])
    port = int(data.get("port", state["remote_client"]["port"]))
    poll_interval = float(data.get("poll_interval", state["remote_client"]["poll_interval"]))
    poll_start = int(data.get("poll_start", state["remote_client"]["poll_start"]))
    poll_quantity = int(data.get("poll_quantity", state["remote_client"]["poll_quantity"]))

    state["remote_client"]["host"] = host
    state["remote_client"]["port"] = port
    state["remote_client"]["poll_interval"] = poll_interval
    state["remote_client"]["poll_start"] = poll_start
    state["remote_client"]["poll_quantity"] = poll_quantity
    state["remote_client"]["updated_at"] = time.time()

    push_log_for_session(session_id, f"Client configuration updated (host={host}, port={port}, poll={poll_interval}s)")
    if is_agent_connected(state):
        queue_command(
            session_id,
            "CONFIGURE_CLIENT",
            {
                "host": host,
                "port": port,
                "poll_interval": poll_interval,
                "poll_start": poll_start,
                "poll_quantity": poll_quantity,
            },
        )

    response = JSONResponse({"ok": True, "client": state["remote_client"]})
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.post("/api/agent/server/start")
async def agent_server_start(request: Request):
    session_id, state = get_session_state_from_request(request)
    data = await request.json()

    host = data.get("host", state["remote_server"]["host"])
    port = int(data.get("port", state["remote_server"]["port"]))

    state["remote_server"]["host"] = host
    state["remote_server"]["port"] = port
    state["remote_server"]["updated_at"] = time.time()
    state["remote_server"]["running"] = True

    queue_command(session_id, "START_SERVER", {"host": host, "port": port})

    response = JSONResponse({"ok": True, "server": state["remote_server"]})
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.post("/api/agent/server/stop")
def agent_server_stop(request: Request):
    session_id, state = get_session_state_from_request(request)
    state["remote_server"]["running"] = False
    state["remote_server"]["updated_at"] = time.time()

    queue_command(session_id, "STOP_SERVER", {})

    response = JSONResponse({"ok": True, "server": state["remote_server"]})
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.post("/api/agent/client/start")
async def agent_client_start(request: Request):
    session_id, state = get_session_state_from_request(request)
    data = await request.json()

    host = data.get("host", state["remote_client"]["host"])
    port = int(data.get("port", state["remote_client"]["port"]))
    poll_interval = float(data.get("poll_interval", state["remote_client"]["poll_interval"]))
    poll_start = int(data.get("poll_start", state["remote_client"]["poll_start"]))
    poll_quantity = int(data.get("poll_quantity", state["remote_client"]["poll_quantity"]))

    state["remote_client"]["host"] = host
    state["remote_client"]["port"] = port
    state["remote_client"]["poll_interval"] = poll_interval
    state["remote_client"]["poll_start"] = poll_start
    state["remote_client"]["poll_quantity"] = poll_quantity
    state["remote_client"]["updated_at"] = time.time()
    state["remote_client"]["running"] = True

    queue_command(session_id, "START_CLIENT", {
        "host": host,
        "port": port,
        "poll_interval": poll_interval,
        "poll_start": poll_start,
        "poll_quantity": poll_quantity,
    })

    response = JSONResponse({"ok": True, "client": state["remote_client"]})
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.post("/api/agent/client/stop")
def agent_client_stop(request: Request):
    session_id, state = get_session_state_from_request(request)
    state["remote_client"]["running"] = False
    state["remote_client"]["updated_at"] = time.time()

    queue_command(session_id, "STOP_CLIENT", {})

    response = JSONResponse({"ok": True, "client": state["remote_client"]})
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.get("/api/agent/commands")
def get_agent_commands(session_id: str):
    state = ensure_session_state(session_id)
    now = time.time()
    runtime_entries_to_log = []
    with lock:
        commands = []
        retained = []
        for cmd in state["pending_commands"]:
            runtime_entry = (state.get("runtime_commands") or {}).get(cmd.get("id"))
            if runtime_entry and runtime_entry.get("status") in {"done", "error"}:
                continue

            cmd_type = cmd.get("type")
            dispatched_at = cmd.get("dispatched_at")
            dispatch_count = int(cmd.get("dispatch_count") or 0)

            # Retry window for runtime/process commands in case the poll reply timed out.
            retryable = cmd_type in {"START_PROCESS_SIM", "STOP_PROCESS_SIM", "WRITE_PROCESS_SIM"}
            min_redelivery_s = 8 if retryable else 60
            max_dispatches = 3 if retryable else 1

            should_send = False
            if dispatched_at is None:
                should_send = True
            elif retryable and dispatch_count < max_dispatches and (now - float(dispatched_at)) >= min_redelivery_s:
                should_send = True

            if should_send:
                cmd["dispatched_at"] = now
                cmd["dispatch_count"] = dispatch_count + 1
                commands.append(cmd)

            # Keep command until agent confirms via /api/agent/command_result.
            retained.append(cmd)

        state["pending_commands"] = retained
        for cmd in commands:
            if cmd.get("id") in (state.get("runtime_commands") or {}):
                runtime_entry = update_runtime_command_status(
                    state,
                    command_id=cmd.get("id"),
                    status="sent",
                    message="Delivered to runtime",
                )
                if runtime_entry:
                    runtime_entries_to_log.append(dict(runtime_entry))
            if cmd.get("type") == "RUN_MODBUS_ACTION":
                update_action_command_status(
                    state,
                    command_id=cmd.get("id"),
                    status="sent",
                    message="Delivered to agent",
                )
    for runtime_entry in runtime_entries_to_log:
        push_log_for_session(session_id, runtime_command_label(runtime_entry))
    if commands:
        print(
            f"[app:{APP_INSTANCE_ID}] command poll hit "
            f"session={session_id} drained={len(commands)}"
        )
    return {
        "ok": True,
        "commands": commands,
        "instance_id": APP_INSTANCE_ID,
        "pending_before_drain": len(commands),
    }


@app.post("/api/agent/command_result")
def agent_command_result(payload: dict = Body(...)):
    session_id = payload.get("session_id")
    command_id = payload.get("command_id")
    status = str(payload.get("status") or "").strip().lower()
    message = str(payload.get("message") or "").strip()

    if not session_id or not command_id:
        return JSONResponse({"ok": False, "error": "Missing session_id or command_id"}, status_code=400)

    if status not in {"done", "error"}:
        status = "done"

    state = ensure_session_state(session_id)
    with lock:
        state["pending_commands"] = [cmd for cmd in state.get("pending_commands", []) if cmd.get("id") != command_id]
        runtime_updated = update_runtime_command_status(
            state,
            command_id=command_id,
            status=status,
            message=message or ("Completed" if status == "done" else "Execution failed"),
        )
        updated = update_action_command_status(
            state,
            command_id=command_id,
            status=status,
            message=message or ("Completed" if status == "done" else "Execution failed"),
        )

    if runtime_updated:
        push_log_for_session(session_id, runtime_command_label(runtime_updated))
        command_type = runtime_updated.get("type")
        if command_type == "START_PROCESS_SIM" and status == "error":
            current = state.get("process_sim") or default_process_sim()
            current["running"] = False
            current["server"]["running"] = False
            current["client"]["running"] = False
            current["client"]["last_error"] = message or "Runtime failed to start process simulation"
            state["process_sim"] = current
            push_log_for_session(session_id, f"Process simulation failed to start on local runtime: {current['client']['last_error']}")
        elif command_type == "START_PROCESS_SIM" and status == "done":
            current = state.get("process_sim") or default_process_sim()
            current["running"] = True
            current["server"]["running"] = True
            current["client"]["running"] = True
            current.pop("last_error", None)
            if current.get("client"):
                current["client"].pop("last_error", None)
            state["process_sim"] = current
            push_log_for_session(session_id, "Process simulation start confirmed by local runtime")
        elif command_type == "STOP_PROCESS_SIM" and status == "done":
            push_log_for_session(session_id, "Process simulation stop confirmed by local runtime")

    if updated and status == "error":
        push_log_for_session(session_id, f"Modbus action failed: {updated.get('code_label', '-') } {updated.get('function_name', '-') } | {updated.get('message', '-')}")

    return {"ok": True}


@app.post("/api/agent/runtime")
def agent_runtime_update(payload: dict = Body(...)):
    session_id = payload.get("session_id")
    if not session_id:
        return JSONResponse({"ok": False, "error": "Missing session_id"}, status_code=400)

    state = ensure_session_state(session_id)

    server_data = payload.get("server") or {}
    client_data = payload.get("client") or {}
    process_data = payload.get("process_sim") or {}
    runtime_data = payload.get("runtime") or {}
    monitor_data = payload.get("monitor") or {}

    previous_server_running = state["remote_server"]["running"]
    previous_client_running = state["remote_client"]["running"]
    previous_process = state.get("process_sim") or default_process_sim()
    previous_process_running = bool(previous_process.get("running"))

    # Only update running status from agent; configuration is managed via /api/agent/server/configure and /api/agent/client/configure
    if server_data:
        state["remote_server"].update({
            "running": bool(server_data.get("running", state["remote_server"]["running"])),
            "updated_at": time.time(),
        })
        registers_preview = server_data.get("registers_preview")
        if isinstance(registers_preview, dict):
            values = registers_preview.get("values") or []
            if isinstance(values, list):
                safe_values = []
                for raw in values[:64]:
                    try:
                        safe_values.append(int(raw))
                    except Exception:
                        continue
                state["remote_server"]["registers_preview"] = {
                    "start": int(registers_preview.get("start", 0) or 0),
                    "quantity": int(registers_preview.get("quantity", len(safe_values)) or len(safe_values)),
                    "values": safe_values,
                }

    if client_data:
        state["remote_client"].update({
            "running": bool(client_data.get("running", state["remote_client"]["running"])),
            "updated_at": time.time(),
        })
        values = client_data.get("last_values")
        if isinstance(values, list):
            safe_values = []
            for raw in values[:64]:
                try:
                    safe_values.append(int(raw))
                except Exception:
                    continue
            state["remote_client"]["last_values"] = safe_values
        if "last_error" in client_data:
            state["remote_client"]["last_error"] = client_data.get("last_error")
        if "last_poll_at" in client_data:
            try:
                state["remote_client"]["last_poll_at"] = float(client_data.get("last_poll_at"))
            except Exception:
                pass
        if "last_success_at" in client_data:
            try:
                state["remote_client"]["last_success_at"] = float(client_data.get("last_success_at"))
            except Exception:
                pass

    if process_data:
        current = state.get("process_sim") or default_process_sim()
        server_block = process_data.get("server") or {}
        client_block = process_data.get("client") or {}

        process_snapshot = {
            "running": bool(process_data.get("running", current.get("running", False))),
            "process_type": str(process_data.get("process_type") or current.get("process_type") or "tank_v1"),
            "server": {
                "running": bool(server_block.get("running", current.get("server", {}).get("running", False))),
                "host": str(server_block.get("host") or current.get("server", {}).get("host") or "127.0.0.1"),
                "port": int(server_block.get("port") or current.get("server", {}).get("port") or 15020),
                "registers_preview": {
                    "start": 0,
                    "quantity": 0,
                    "values": [],
                },
            },
            "client": {
                "running": bool(client_block.get("running", current.get("client", {}).get("running", False))),
                "host": str(client_block.get("host") or current.get("client", {}).get("host") or "127.0.0.1"),
                "port": int(client_block.get("port") or current.get("client", {}).get("port") or 15020),
                "poll_interval": float(client_block.get("poll_interval") or current.get("client", {}).get("poll_interval") or 0.5),
                "poll_start": int(client_block.get("poll_start") or current.get("client", {}).get("poll_start") or 0),
                "poll_quantity": int(client_block.get("poll_quantity") or current.get("client", {}).get("poll_quantity") or 16),
                "last_values": [],
                "last_error": client_block.get("last_error", current.get("client", {}).get("last_error")),
                "last_poll_at": client_block.get("last_poll_at", current.get("client", {}).get("last_poll_at")),
                "last_success_at": client_block.get("last_success_at", current.get("client", {}).get("last_success_at")),
            },
        }

        registers_preview = server_block.get("registers_preview")
        if isinstance(registers_preview, dict):
            values = registers_preview.get("values") or []
            safe_values = []
            if isinstance(values, list):
                for raw in values[:64]:
                    try:
                        safe_values.append(int(raw))
                    except Exception:
                        continue
            process_snapshot["server"]["registers_preview"] = {
                "start": int(registers_preview.get("start", 0) or 0),
                "quantity": int(registers_preview.get("quantity", len(safe_values)) or len(safe_values)),
                "values": safe_values,
            }

        last_values = client_block.get("last_values")
        if isinstance(last_values, list):
            safe_values = []
            for raw in last_values[:64]:
                try:
                    safe_values.append(int(raw))
                except Exception:
                    continue
            process_snapshot["client"]["last_values"] = safe_values
        else:
            current_values = (current.get("client") or {}).get("last_values") or []
            process_snapshot["client"]["last_values"] = list(current_values)[:64]

        if not process_snapshot["running"] and current.get("running") and has_pending_process_start(state):
            process_snapshot["running"] = True
            process_snapshot["server"]["running"] = True
            process_snapshot["client"]["running"] = True
            process_snapshot["client"]["last_error"] = current.get("client", {}).get("last_error")
            process_snapshot["client"]["last_values"] = list((current.get("client") or {}).get("last_values") or [])[:64]

        state["process_sim"] = process_snapshot

        # Auto-confirm a pending START_PROCESS_SIM if the runtime reports running=True.
        # This handles cases where send_command_result failed but the process did start.
        if process_snapshot["running"]:
            commands = state.get("runtime_commands") or {}
            for cmd_entry in commands.values():
                if (
                    cmd_entry.get("type") == "START_PROCESS_SIM"
                    and cmd_entry.get("status") in {"queued", "sent"}
                ):
                    confirmed_id = None
                    for command_id, raw in commands.items():
                        if raw is cmd_entry:
                            confirmed_id = command_id
                            break
                    cmd_entry["status"] = "done"
                    cmd_entry["updated_at"] = time.time()
                    cmd_entry["message"] = "Confirmed via runtime update"
                    if confirmed_id:
                        state["pending_commands"] = [
                            cmd for cmd in state.get("pending_commands", [])
                            if cmd.get("id") != confirmed_id
                        ]
                    push_log_for_session(session_id, "Process simulation start confirmed by local runtime")
                    break

        current_process_running = bool(process_snapshot.get("running"))
        if not previous_process_running and current_process_running:
            push_log_for_session(
                session_id,
                "Process runtime reported RUNNING "
                f"(server={process_snapshot['server']['host']}:{process_snapshot['server']['port']}, "
                f"client={process_snapshot['client']['host']}:{process_snapshot['client']['port']}, "
                f"poll={process_snapshot['client']['poll_interval']}s)"
            )
        elif previous_process_running and not current_process_running:
            reason = process_snapshot.get("client", {}).get("last_error")
            if not reason:
                server_running = bool(process_snapshot.get("server", {}).get("running"))
                client_running = bool(process_snapshot.get("client", {}).get("running"))
                if (not server_running) and (not client_running):
                    reason = "process server and client are not running"
                elif not server_running:
                    reason = "process server is not running"
                elif not client_running:
                    reason = "process client is not running"
                else:
                    reason = "runtime reported stopped without explicit error"
            push_log_for_session(
                session_id,
                "Process runtime reported STOPPED "
                f"(server={process_snapshot['server']['host']}:{process_snapshot['server']['port']}, "
                f"client={process_snapshot['client']['host']}:{process_snapshot['client']['port']}, "
                f"reason={reason})"
            )

    current_server_running = state["remote_server"]["running"]
    current_client_running = state["remote_client"]["running"]

    if not previous_server_running and current_server_running:
        push_log_for_session(
            session_id,
            f"Modbus server running on {state['remote_server']['host']}:{state['remote_server']['port']}"
        )
    elif previous_server_running and not current_server_running:
        push_log_for_session(session_id, "Modbus server stopped")

    if not previous_client_running and current_client_running:
        push_log_for_session(
            session_id,
            f"Modbus client running on {state['remote_client']['host']}:{state['remote_client']['port']} "
            f"(poll={state['remote_client']['poll_interval']}s, start={state['remote_client']['poll_start']}, qty={state['remote_client']['poll_quantity']})"
        )
    elif previous_client_running and not current_client_running:
        push_log_for_session(session_id, "Modbus client stopped")

    runtime_state = state.get("runtime_state") or default_runtime_state()
    now = time.time()
    if runtime_data:
        runtime_state["runtime"]["running"] = bool(runtime_data.get("running", runtime_state["runtime"]["running"]))
        runtime_state["runtime"]["last_updated"] = now
    if monitor_data:
        runtime_state["monitor"]["running"] = bool(monitor_data.get("running", runtime_state["monitor"]["running"]))
        runtime_state["monitor"]["last_updated"] = now
    state["runtime_state"] = runtime_state
    refresh_runtime_state(state)

    return {"ok": True, "instance_id": APP_INSTANCE_ID}


@app.post("/api/reset")
def reset_system(request: Request):
    session_id, state = get_session_state_from_request(request)

    with lock:
        # Visual clean only: keep monitor/server/client configuration as-is.
        state["events"].clear()
        state["alerts"].clear()
        state["logs"].clear()
        state["agent_snapshot"] = default_agent_snapshot()
        state["modbus_summary"] = default_modbus_summary()
        if "connection_history" in state:
            state["connection_history"].clear()
        if "event_log_signatures" in state:
            state["event_log_signatures"].clear()
        if "recent_event_signatures" in state:
            state["recent_event_signatures"].clear()
        if "recent_alert_signatures" in state:
            state["recent_alert_signatures"].clear()
        state["pending_commands"].clear()
        if "runtime_commands" in state:
            state["runtime_commands"].clear()
        if "action_commands" in state:
            state["action_commands"].clear()

    response = JSONResponse({"ok": True, "session_id": session_id})
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.post("/api/alerts/clear")
def clear_alerts(request: Request):
    session_id, state = get_session_state_from_request(request)
    with lock:
        state["alerts"].clear()
    response = JSONResponse({"ok": True, "session_id": session_id})
    set_session_cookie_if_needed(request, response, session_id)
    return response


@app.post("/api/agent/register")
def agent_register(payload: dict = Body(...)):
    session_id = payload.get("session_id")
    if not session_id:
        return JSONResponse({"ok": False, "error": "Missing session_id"}, status_code=400)

    state = ensure_session_state(session_id)
    agent_info = state["agent_info"]
    recv_ts = time.time()

    agent_info["connected"] = True
    agent_info["agent_id"] = payload.get("agent_id")
    agent_info["hostname"] = payload.get("hostname")
    agent_info["iface"] = payload.get("iface")
    agent_info["mode"] = payload.get("mode")
    agent_info["port_mode"] = payload.get("port_mode")
    agent_info["custom_ports"] = safe_normalize_custom_ports(payload.get("custom_ports"))
    agent_info["running"] = payload.get("running", False)
    agent_info["last_seen"] = recv_ts
    agent_info["agent_timestamp"] = payload.get("timestamp")
    agent_info["available_ifaces"] = payload.get("available_ifaces", [])
    agent_info["available_monitored_ifaces"] = payload.get("available_monitored_ifaces", [])
    agent_info["available_unmonitored_ifaces"] = payload.get("available_unmonitored_ifaces", [])
    agent_info["capabilities"] = payload.get("capabilities", agent_info.get("capabilities", []))

    push_log_for_session(
        session_id,
        (
            "Agent connected "
            f"({payload.get('hostname', '-')}, interface={payload.get('iface', '-')}, "
            f"mode={payload.get('mode', '-')}, port_mode={payload.get('port_mode', '-')})"
        )
    )

    return {
        "ok": True,
        "config": state["agent_config"],
        "server": state["remote_server"],
        "client": state["remote_client"],
        "instance_id": APP_INSTANCE_ID,
    }


@app.post("/api/agent/heartbeat")
def agent_heartbeat(payload: dict = Body(...)):
    session_id = payload.get("session_id")
    if not session_id:
        return JSONResponse({"ok": False, "error": "Missing session_id"}, status_code=400)

    state = ensure_session_state(session_id)
    agent_info = state["agent_info"]
    recv_ts = time.time()

    agent_info["connected"] = True
    agent_info["agent_id"] = payload.get("agent_id")
    agent_info["hostname"] = payload.get("hostname")
    agent_info["iface"] = payload.get("iface")
    agent_info["mode"] = payload.get("mode")
    agent_info["port_mode"] = payload.get("port_mode")
    agent_info["custom_ports"] = safe_normalize_custom_ports(payload.get("custom_ports"))
    agent_info["running"] = payload.get("running", False)
    agent_info["last_seen"] = recv_ts
    agent_info["agent_timestamp"] = payload.get("timestamp")
    agent_info["available_ifaces"] = payload.get(
        "available_ifaces",
        agent_info.get("available_ifaces", [])
    )
    agent_info["available_monitored_ifaces"] = payload.get(
        "available_monitored_ifaces",
        agent_info.get("available_monitored_ifaces", []),
    )
    agent_info["available_unmonitored_ifaces"] = payload.get(
        "available_unmonitored_ifaces",
        agent_info.get("available_unmonitored_ifaces", []),
    )
    agent_info["capabilities"] = payload.get(
        "capabilities",
        agent_info.get("capabilities", [])
    )

    return {
        "ok": True,
        "config": state["agent_config"],
        "server": state["remote_server"],
        "client": state["remote_client"],
        "instance_id": APP_INSTANCE_ID,
    }


@app.post("/api/agent/disconnect")
def agent_disconnect(payload: dict = Body(...)):
    session_id = payload.get("session_id")
    if not session_id:
        return JSONResponse({"ok": False, "error": "Missing session_id"}, status_code=400)

    state = ensure_session_state(session_id)
    agent_info = state["agent_info"]
    agent_info["connected"] = False
    agent_info["running"] = False
    agent_info["last_seen"] = None
    push_log_for_session(session_id, "Agent disconnected")
    return {"ok": True, "instance_id": APP_INSTANCE_ID}


@app.post("/api/agent/snapshot")
def agent_snapshot_ingest(payload: dict = Body(...)):
    session_id = payload.get("session_id")
    if not session_id:
        return JSONResponse({"ok": False, "error": "Missing session_id"}, status_code=400)

    state = ensure_session_state(session_id)
    state["agent_snapshot"] = payload

    agent_info = state["agent_info"]
    agent_info["connected"] = True
    agent_info["agent_id"] = payload.get("agent_id")
    agent_info["hostname"] = payload.get("hostname")
    agent_info["iface"] = payload.get("iface")
    agent_info["mode"] = payload.get("mode")
    agent_info["port_mode"] = payload.get("port_mode")
    agent_info["custom_ports"] = safe_normalize_custom_ports(payload.get("custom_ports"))
    agent_info["running"] = True
    agent_info["last_seen"] = time.time()
    agent_info["agent_timestamp"] = payload.get("timestamp")
    agent_info["available_ifaces"] = payload.get(
        "available_ifaces",
        agent_info.get("available_ifaces", [])
    )
    agent_info["available_monitored_ifaces"] = payload.get(
        "available_monitored_ifaces",
        agent_info.get("available_monitored_ifaces", []),
    )
    agent_info["available_unmonitored_ifaces"] = payload.get(
        "available_unmonitored_ifaces",
        agent_info.get("available_unmonitored_ifaces", []),
    )
    agent_info["capabilities"] = payload.get(
        "capabilities",
        agent_info.get("capabilities", [])
    )

    modbus_summary = state.get("modbus_summary") or default_modbus_summary()
    if modbus_summary.get("detected") and modbus_summary.get("server_ip"):
        avg_polling = extract_avg_polling_from_snapshot(payload, modbus_summary.get("server_ip"))
        if avg_polling is not None:
            modbus_summary["avg_polling_s"] = avg_polling

    return {"ok": True}


@app.post("/api/agent/event")
def agent_event_ingest(payload: dict = Body(...)):
    session_id = payload.get("session_id")
    if not session_id:
        return JSONResponse({"ok": False, "error": "Missing session_id"}, status_code=400)

    state = ensure_session_state(session_id)
    ingest_agent_event_payload(state, session_id, payload)

    return {"ok": True}


@app.post("/api/agent/events_batch")
def agent_events_batch_ingest(payload: dict = Body(...)):
    session_id = payload.get("session_id")
    if not session_id:
        return JSONResponse({"ok": False, "error": "Missing session_id"}, status_code=400)

    events = payload.get("events")
    if not isinstance(events, list):
        return JSONResponse({"ok": False, "error": "events must be a list"}, status_code=400)

    state = ensure_session_state(session_id)
    accepted = 0
    for event in events:
        if not isinstance(event, dict):
            continue
        if not event.get("session_id"):
            event["session_id"] = session_id
        ingest_agent_event_payload(state, session_id, event)
        accepted += 1

    return {"ok": True, "accepted": accepted}


@app.post("/api/agent/alert")
def agent_alert_ingest(payload: dict = Body(...)):
    session_id = payload.get("session_id")
    if not session_id:
        return JSONResponse({"ok": False, "error": "Missing session_id"}, status_code=400)

    state = ensure_session_state(session_id)
    agent_info = state["agent_info"]
    agent_info["connected"] = True
    agent_info["last_seen"] = time.time()
    push_alert(state, payload)

    summary = payload.get("summary")
    if summary:
        push_log_for_session(session_id, f"Alert: {summary}")
    else:
        push_log_for_session(
            session_id,
            f"Alert generated: {payload.get('severity', 'INFO')} "
            f"{payload.get('event_type', 'UNKNOWN')}"
        )

    return {"ok": True}


@app.on_event("shutdown")
def stop_process_sim_on_shutdown():
    try:
        process_sim.stop()
    except Exception:
        pass
