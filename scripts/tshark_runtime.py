#!/usr/bin/env python3
from __future__ import annotations

import argparse
import collections
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import Any

import requests


MODBUS_DEFAULT_PORTS = {502, 5020, 15020}
WRITE_FUNCTIONS = {5, 6, 15, 16}


def _to_int(value: Any, default: int | None = None) -> int | None:
    if value is None:
        return default
    raw = str(value).strip()
    if raw == "":
        return default
    try:
        return int(raw, 0)
    except Exception:
        return default


def _parse_first_int(value: str | None) -> int | None:
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    # tshark fields may contain comma-separated entries.
    token = raw.split(",")[0].strip()
    return _to_int(token)


def _build_capture_filter(_port_mode: str, _custom_ports: list[int]) -> str:
    # Wireshark-like baseline for v2: capture broad TCP traffic and let dissectors
    # identify protocol layers. We still normalize to OT events later in parser.
    return "tcp"


def _event_type_for(func_code: int | None, dst_port: int | None) -> str:
    if func_code is None:
        return "UNKNOWN_REQUEST"
    base_fc = func_code & 0x7F if func_code > 127 else func_code
    if dst_port in MODBUS_DEFAULT_PORTS:
        return "WRITE_REQUEST" if base_fc in WRITE_FUNCTIONS else "READ_REQUEST"
    return "WRITE_RESPONSE" if base_fc in WRITE_FUNCTIONS else "READ_RESPONSE"


def _build_summary(event: dict) -> str:
    fc = event.get("function_code")
    src = f"{event.get('src_ip')}:{event.get('src_port')}"
    dst = f"{event.get('dst_ip')}:{event.get('dst_port')}"
    et = str(event.get("type") or "UNKNOWN")
    reg = event.get("register")
    val = event.get("value")
    start = event.get("start_addr")
    qty = event.get("quantity")
    if et.startswith("WRITE"):
        if reg is not None:
            return f"FC{fc} write from {src} to {dst} | register={reg} value={val}"
        return f"FC{fc} write from {src} to {dst}"
    return f"FC{fc} read from {src} to {dst} | start={start} qty={qty}"


@dataclass
class MonitorConfig:
    iface: str
    port_mode: str
    custom_ports: list[int]


class TsharkRuntime:
    def __init__(self, server: str, session_id: str, default_iface: str, poll_s: float = 2.0):
        self.server = server.rstrip("/")
        self.session_id = session_id
        self.default_iface = default_iface
        self.poll_s = poll_s
        self.agent_id = f"tshark-{os.getenv('HOSTNAME', 'runtime')}"
        self.hostname = os.getenv("HOSTNAME", "runtime")
        self.running = True
        self.proc: subprocess.Popen[str] | None = None
        self.proc_thread: threading.Thread | None = None
        self.current: MonitorConfig | None = None
        self.last_heartbeat = 0.0
        self.proxy_enabled = str(os.getenv("OTLAB_PROXY_ENABLED", "1")).strip().lower() in {"1", "true", "yes", "on"}
        self.proxy_listen_host = str(os.getenv("OTLAB_PROXY_LISTEN_HOST", "0.0.0.0")).strip() or "0.0.0.0"
        self.proxy_listen_port = _to_int(os.getenv("OTLAB_PROXY_LISTEN_PORT", "15020"), 15020) or 15020
        self.proxy_upstream_host = str(os.getenv("OTLAB_PROXY_UPSTREAM_HOST", "openplc")).strip() or "openplc"
        self.proxy_upstream_port = _to_int(os.getenv("OTLAB_PROXY_UPSTREAM_PORT", "502"), 502) or 502
        self.proxy_thread: threading.Thread | None = None
        self.proxy_sock: socket.socket | None = None
        self.stderr_thread: threading.Thread | None = None
        self.stderr_tail = collections.deque(maxlen=40)
        self.last_event_ts = 0.0
        self.capture_started_ts = 0.0
        self.fallback_to_any_done = False

        self.http = requests.Session()
        self.http.headers.update({"Content-Type": "application/json"})
        self._check_binary()

    def _check_binary(self) -> None:
        if not shutil.which("tshark"):
            raise RuntimeError("tshark binary not found in PATH")

    def _url(self, path: str) -> str:
        return f"{self.server}{path}"

    def _post(self, path: str, payload: dict, timeout: float = 3.0) -> dict:
        resp = self.http.post(self._url(path), data=json.dumps(payload), timeout=timeout)
        resp.raise_for_status()
        return resp.json()

    def _get(self, path: str, params: dict | None = None, timeout: float = 3.0) -> dict:
        resp = self.http.get(self._url(path), params=params, timeout=timeout)
        resp.raise_for_status()
        return resp.json()

    def register(self) -> None:
        payload = {
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "iface": self.current.iface if self.current else self.default_iface,
            "mode": "MONITORING",
            "port_mode": self.current.port_mode if self.current else "MODBUS_PORTS",
            "custom_ports": self.current.custom_ports if self.current else [],
            "running": True,
            "timestamp": time.time(),
            "available_ifaces": [],
            "available_monitored_ifaces": [],
            "available_unmonitored_ifaces": [],
            "capabilities": ["tshark_monitor"],
        }
        self._post("/api/agent/register", payload)

    def wait_for_server(self) -> None:
        while self.running:
            try:
                self._get("/api/status", params={"session_id": self.session_id}, timeout=2.0)
                print("[tshark-runtime] web API reachable", flush=True)
                return
            except Exception as exc:
                print(f"[tshark-runtime] waiting for web API: {exc}", flush=True)
                time.sleep(2.0)

    def _pipe(self, src: socket.socket, dst: socket.socket) -> None:
        try:
            while self.running:
                chunk = src.recv(65535)
                if not chunk:
                    break
                dst.sendall(chunk)
        except Exception:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except Exception:
                pass

    def _handle_proxy_conn(self, client_sock: socket.socket) -> None:
        upstream = None
        try:
            upstream = socket.create_connection((self.proxy_upstream_host, int(self.proxy_upstream_port)), timeout=3.0)
            upstream.settimeout(None)
            client_sock.settimeout(None)
            t1 = threading.Thread(target=self._pipe, args=(client_sock, upstream), daemon=True)
            t2 = threading.Thread(target=self._pipe, args=(upstream, client_sock), daemon=True)
            t1.start()
            t2.start()
            t1.join()
            t2.join()
        except Exception:
            pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass
            if upstream is not None:
                try:
                    upstream.close()
                except Exception:
                    pass

    def _proxy_loop(self) -> None:
        if not self.proxy_enabled:
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.proxy_listen_host, int(self.proxy_listen_port)))
        sock.listen(64)
        sock.settimeout(1.0)
        self.proxy_sock = sock
        print(
            f"[tshark-runtime] proxy listening on {self.proxy_listen_host}:{self.proxy_listen_port} "
            f"-> {self.proxy_upstream_host}:{self.proxy_upstream_port}",
            flush=True,
        )
        try:
            while self.running:
                try:
                    conn, _addr = sock.accept()
                except socket.timeout:
                    continue
                except Exception:
                    if self.running:
                        time.sleep(0.05)
                    continue
                threading.Thread(target=self._handle_proxy_conn, args=(conn,), daemon=True).start()
        finally:
            try:
                sock.close()
            except Exception:
                pass
            self.proxy_sock = None

    def start_proxy(self) -> None:
        if not self.proxy_enabled:
            print("[tshark-runtime] proxy disabled", flush=True)
            return
        if self.proxy_thread and self.proxy_thread.is_alive():
            return
        self.proxy_thread = threading.Thread(target=self._proxy_loop, daemon=True)
        self.proxy_thread.start()

    def heartbeat(self) -> None:
        now = time.time()
        if (now - self.last_heartbeat) < 5.0:
            return
        self.last_heartbeat = now
        payload = {
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "iface": self.current.iface if self.current else self.default_iface,
            "mode": "MONITORING",
            "port_mode": self.current.port_mode if self.current else "MODBUS_PORTS",
            "custom_ports": self.current.custom_ports if self.current else [],
            "running": True,
            "timestamp": now,
            "capabilities": ["tshark_monitor"],
        }
        try:
            self._post("/api/agent/heartbeat", payload)
        except Exception:
            pass

    def fetch_config(self) -> MonitorConfig:
        data = self._get("/api/agent/config", params={"session_id": self.session_id}, timeout=4.0)
        cfg = data.get("config") or {}
        iface = str(cfg.get("iface") or self.default_iface).strip()
        if iface.upper() == "ALL":
            iface = "any"
        port_mode = str(cfg.get("port_mode") or "MODBUS_PORTS").strip().upper()
        custom = []
        for p in cfg.get("custom_ports") or []:
            n = _to_int(p)
            if n and 1 <= n <= 65535:
                custom.append(n)
        return MonitorConfig(iface=iface or self.default_iface, port_mode=port_mode, custom_ports=sorted(set(custom)))

    def _build_cmd(self, cfg: MonitorConfig) -> list[str]:
        cap_filter = _build_capture_filter(cfg.port_mode, cfg.custom_ports)
        fields = [
            "frame.time_epoch",
            "frame.protocols",
            "ip.src",
            "tcp.srcport",
            "ip.dst",
            "tcp.dstport",
            "mbtcp.trans_id",
            "mbtcp.unit_id",
            "modbus.func_code",
            "modbus.reference_num",
            "modbus.read_reference_num",
            "modbus.word_cnt",
            "modbus.bit_cnt",
            "modbus.regval_uint16",
            "modbus.bitval",
            "modbus.exception_code",
        ]
        cmd = [
            "tshark",
            "-l",
            "-n",
            "-Q",
            "-i",
            cfg.iface,
            "-f",
            cap_filter,
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-E",
            "occurrence=f",
            "-E",
            "quote=n",
        ]
        for f in fields:
            cmd.extend(["-e", f])
        return cmd

    def _parse_line(self, line: str) -> dict | None:
        cols = line.rstrip("\n").split("\t")
        if len(cols) < 15:
            return None
        ts = float(cols[0]) if cols[0] else time.time()
        protocols = str(cols[1] or "").lower()
        src_ip = cols[2] or None
        src_port = _to_int(cols[3])
        dst_ip = cols[4] or None
        dst_port = _to_int(cols[5])
        tx_id = _parse_first_int(cols[6])
        unit_id = _parse_first_int(cols[7])
        func_code = _parse_first_int(cols[8])
        ref_write = _parse_first_int(cols[9])
        ref_read = _parse_first_int(cols[10])
        word_cnt = _parse_first_int(cols[11])
        bit_cnt = _parse_first_int(cols[12])
        reg_val = _parse_first_int(cols[13])
        bit_val = _parse_first_int(cols[14])
        exc = _parse_first_int(cols[15]) if len(cols) > 15 else None

        # For now we emit only Modbus events into current UI pipelines.
        # Detection is automatic by dissector (no hardcoded port filter).
        if "modbus" not in protocols:
            return None
        if not src_ip or not dst_ip or func_code is None:
            return None

        event_type = _event_type_for(func_code, dst_port)
        register = ref_write if ref_write is not None else ref_read
        quantity = word_cnt if word_cnt is not None else bit_cnt
        value = reg_val if reg_val is not None else bit_val

        is_req = event_type.endswith("REQUEST")
        client_ep = f"{src_ip}:{src_port}" if is_req else f"{dst_ip}:{dst_port}"
        server_ep = f"{dst_ip}:{dst_port}" if is_req else f"{src_ip}:{src_port}"

        event = {
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "timestamp": ts,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "client": client_ep,
            "server": server_ep,
            "direction": "request" if is_req else "response",
            "transaction_id": tx_id,
            "function_code": func_code,
            "unit_id": unit_id,
            "protocol": "MODBUS/TCP",
            "type": event_type,
            "register": register,
            "start_addr": register,
            "quantity": quantity,
            "value": value,
            "exception_code": exc,
            "iface": self.current.iface if self.current else self.default_iface,
        }
        event["summary"] = _build_summary(event)
        return event

    def _pump(self, proc: subprocess.Popen[str]) -> None:
        batch: list[dict] = []
        last_flush = time.time()
        assert proc.stdout is not None
        while self.running and proc.poll() is None:
            line = proc.stdout.readline()
            if not line:
                time.sleep(0.02)
                continue
            event = self._parse_line(line)
            if event:
                batch.append(event)
                self.last_event_ts = time.time()
            now = time.time()
            if batch and (len(batch) >= 20 or (now - last_flush) >= 0.35):
                self._flush(batch)
                batch = []
                last_flush = now
        if batch:
            self._flush(batch)

    def _drain_stderr(self, proc: subprocess.Popen[str]) -> None:
        if proc.stderr is None:
            return
        while self.running and proc.poll() is None:
            line = proc.stderr.readline()
            if not line:
                time.sleep(0.02)
                continue
            msg = line.rstrip("\n")
            if msg:
                self.stderr_tail.append(msg)
                print(f"[tshark-runtime][stderr] {msg}", flush=True)

    def _flush(self, batch: list[dict]) -> None:
        if not batch:
            return
        payload = {"session_id": self.session_id, "events": batch}
        try:
            self._post("/api/agent/events_batch", payload, timeout=4.0)
            print(f"[tshark-runtime] flushed {len(batch)} events", flush=True)
        except Exception:
            pass

    def stop_process(self) -> None:
        if self.proc is None:
            return
        try:
            self.proc.terminate()
            self.proc.wait(timeout=2.0)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass
        self.proc = None
        self.proc_thread = None

    def restart_process(self, cfg: MonitorConfig) -> None:
        self.stop_process()
        cmd = self._build_cmd(cfg)
        self.current = cfg
        self.capture_started_ts = time.time()
        self.last_event_ts = 0.0
        print(f"[tshark-runtime] starting tshark: {' '.join(cmd)}", flush=True)
        self.proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self.proc_thread = threading.Thread(target=self._pump, args=(self.proc,), daemon=True)
        self.proc_thread.start()
        self.stderr_thread = threading.Thread(target=self._drain_stderr, args=(self.proc,), daemon=True)
        self.stderr_thread.start()

    def run(self) -> None:
        self.wait_for_server()
        self.start_proxy()
        while self.running:
            try:
                self.register()
                print("[tshark-runtime] registered", flush=True)
                break
            except Exception as exc:
                print(f"[tshark-runtime] register failed, retrying: {exc}", flush=True)
                time.sleep(2.0)

        while self.running:
            try:
                cfg = self.fetch_config()
                crashed = self.proc is not None and self.proc.poll() is not None
                if crashed:
                    code = self.proc.returncode
                    tail = " | ".join(list(self.stderr_tail)[-3:]) if self.stderr_tail else "no stderr"
                    print(f"[tshark-runtime] tshark exited code={code} ({tail})", flush=True)
                if self.current != cfg or self.proc is None or crashed:
                    self.restart_process(cfg)
                    self.fallback_to_any_done = False
                    print(
                        f"[tshark-runtime] capture started iface={cfg.iface} "
                        f"port_mode={cfg.port_mode} custom_ports={cfg.custom_ports}",
                        flush=True,
                    )
                # If tshark is up but sees no packets, fallback once from eth0->any.
                if (
                    self.proc is not None
                    and self.proc.poll() is None
                    and not self.fallback_to_any_done
                    and str((self.current.iface if self.current else "")).strip().lower() == "eth0"
                ):
                    now = time.time()
                    silent_for = now - (self.last_event_ts or self.capture_started_ts or now)
                    if silent_for >= 12.0:
                        print("[tshark-runtime] no packets on eth0; switching capture iface to any", flush=True)
                        self.fallback_to_any_done = True
                        self.restart_process(
                            MonitorConfig(
                                iface="any",
                                port_mode=self.current.port_mode if self.current else "MODBUS_PORTS",
                                custom_ports=self.current.custom_ports if self.current else [],
                            )
                        )
            except Exception as exc:
                print(f"[tshark-runtime] loop warning: {exc}", flush=True)
                time.sleep(1.0)
            self.heartbeat()
            time.sleep(self.poll_s)

    def shutdown(self) -> None:
        self.running = False
        if self.proxy_sock is not None:
            try:
                self.proxy_sock.close()
            except Exception:
                pass
        self.stop_process()
        try:
            self._post(
                "/api/agent/disconnect",
                {"session_id": self.session_id, "agent_id": self.agent_id, "hostname": self.hostname},
                timeout=2.0,
            )
        except Exception:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description="OT Lab tshark monitor runtime")
    parser.add_argument("--server", default=os.getenv("OTLAB_SERVER", "http://web:8000"))
    parser.add_argument("--session-id", default=os.getenv("OTLAB_SESSION_ID", "sess_v2_docker_local"))
    parser.add_argument("--iface", default=os.getenv("RUNTIME_IFACE", "eth0"))
    args = parser.parse_args()

    runtime = TsharkRuntime(server=args.server, session_id=args.session_id, default_iface=args.iface)

    def _sig_handler(_signum, _frame):
        runtime.shutdown()
        raise SystemExit(0)

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    try:
        runtime.run()
    finally:
        runtime.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
