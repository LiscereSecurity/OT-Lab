#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
import socket
import statistics
import struct
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError("socket closed before full response")
        data += chunk
    return data


def build_fc03_request(tx_id: int, unit_id: int, start_addr: int, quantity: int) -> bytes:
    pdu = bytes([3]) + struct.pack(">HH", start_addr, quantity)
    mbap = struct.pack(">HHHB", tx_id, 0, len(pdu) + 1, unit_id)
    return mbap + pdu


def read_modbus_response(sock: socket.socket, tx_id: int, expected_fc: int) -> None:
    header = recv_exact(sock, 7)
    rx_tx, proto, length = struct.unpack(">HHH", header[:6])
    if rx_tx != tx_id:
        raise RuntimeError(f"transaction mismatch expected={tx_id} got={rx_tx}")
    if proto != 0:
        raise RuntimeError(f"invalid protocol id={proto}")

    body = recv_exact(sock, length - 1)
    if not body:
        raise RuntimeError("empty Modbus response")

    fc = body[0]
    if fc & 0x80:
        code = body[1] if len(body) > 1 else None
        raise RuntimeError(f"modbus exception function={fc} code={code}")
    if fc != expected_fc:
        raise RuntimeError(f"unexpected function expected={expected_fc} got={fc}")


def percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = math.ceil((pct / 100.0) * len(ordered)) - 1
    rank = max(0, min(rank, len(ordered) - 1))
    return ordered[rank]


def summarize_latencies(latencies_ms: list[float], failures: list[str], requests: int) -> dict[str, Any]:
    return {
        "requests": requests,
        "ok": len(latencies_ms),
        "failures": len(failures),
        "failure_rate": (len(failures) / requests) if requests else 0.0,
        "avg_ms": statistics.fmean(latencies_ms) if latencies_ms else None,
        "median_ms": statistics.median(latencies_ms) if latencies_ms else None,
        "p95_ms": percentile(latencies_ms, 95),
        "p99_ms": percentile(latencies_ms, 99),
        "min_ms": min(latencies_ms) if latencies_ms else None,
        "max_ms": max(latencies_ms) if latencies_ms else None,
        "failures_sample": failures[:10],
    }


def run_target(
    *,
    name: str,
    host: str,
    port: int,
    unit_id: int,
    start_addr: int,
    quantity: int,
    requests: int,
    warmup: int,
    timeout_s: float,
    delay_s: float,
    connection_mode: str,
) -> dict[str, Any]:
    latencies: list[float] = []
    failures: list[str] = []
    samples: list[dict[str, Any]] = []
    sock: socket.socket | None = None

    def connect() -> socket.socket:
        new_sock = socket.create_connection((host, port), timeout=timeout_s)
        new_sock.settimeout(timeout_s)
        return new_sock

    def close_current() -> None:
        nonlocal sock
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
            sock = None

    total = warmup + requests
    try:
        if connection_mode == "persistent":
            sock = connect()

        for i in range(total):
            measured = i >= warmup
            tx_id = (i + 1) % 65536 or 1
            started = time.perf_counter_ns()

            try:
                if connection_mode == "reconnect" or sock is None:
                    sock = connect()
                sock.sendall(build_fc03_request(tx_id, unit_id, start_addr, quantity))
                read_modbus_response(sock, tx_id, expected_fc=3)
                elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000.0

                if measured:
                    latencies.append(elapsed_ms)
                    samples.append({"index": i - warmup + 1, "latency_ms": elapsed_ms})

            except Exception as exc:
                if measured:
                    failures.append(str(exc))
                close_current()
                if connection_mode == "persistent":
                    try:
                        sock = connect()
                    except Exception as reconnect_exc:
                        if measured:
                            failures.append(f"reconnect failed: {reconnect_exc}")

            finally:
                if connection_mode == "reconnect":
                    close_current()
                if delay_s > 0:
                    time.sleep(delay_s)

    finally:
        close_current()

    return {
        "name": name,
        "target": {"host": host, "port": port},
        "summary": summarize_latencies(latencies, failures, requests),
        "latencies_ms": latencies,
        "samples": samples,
    }


def ms(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def print_result_table(results: dict[str, Any]) -> None:
    headers = ["path", "ok", "fail", "avg ms", "median", "p95", "p99", "min", "max"]
    rows = []
    for key in ("direct", "monitored"):
        summary = results[key]["summary"]
        rows.append(
            [
                key,
                str(summary["ok"]),
                str(summary["failures"]),
                ms(summary["avg_ms"]),
                ms(summary["median_ms"]),
                ms(summary["p95_ms"]),
                ms(summary["p99_ms"]),
                ms(summary["min_ms"]),
                ms(summary["max_ms"]),
            ]
        )

    widths = [len(h) for h in headers]
    for row in rows:
        for idx, value in enumerate(row):
            widths[idx] = max(widths[idx], len(value))

    print(" | ".join(h.ljust(widths[idx]) for idx, h in enumerate(headers)))
    print("-+-".join("-" * width for width in widths))
    for row in rows:
        print(" | ".join(value.ljust(widths[idx]) for idx, value in enumerate(row)))

    overhead = results["overhead"]
    print()
    print(f"avg overhead:    {ms(overhead['avg_ms'])} ms ({overhead['avg_pct']:.2f}% if direct avg is available)")
    print(f"median overhead: {ms(overhead['median_ms'])} ms")
    print(f"p95 overhead:    {ms(overhead['p95_ms'])} ms")
    print(f"p99 overhead:    {ms(overhead['p99_ms'])} ms")


def write_csv(path: Path, results: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["path", "index", "latency_ms"])
        writer.writeheader()
        for key in ("direct", "monitored"):
            for sample in results[key]["samples"]:
                writer.writerow({"path": key, **sample})


def compute_overhead(direct: dict[str, Any], monitored: dict[str, Any]) -> dict[str, Any]:
    direct_summary = direct["summary"]
    monitored_summary = monitored["summary"]

    def diff(metric: str) -> float | None:
        left = monitored_summary.get(metric)
        right = direct_summary.get(metric)
        if left is None or right is None:
            return None
        return left - right

    avg_diff = diff("avg_ms")
    direct_avg = direct_summary.get("avg_ms")
    return {
        "avg_ms": avg_diff,
        "avg_pct": (avg_diff / direct_avg * 100.0) if avg_diff is not None and direct_avg else 0.0,
        "median_ms": diff("median_ms"),
        "p95_ms": diff("p95_ms"),
        "p99_ms": diff("p99_ms"),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare Modbus/TCP latency for direct OpenPLC access and monitored runtime-proxy access."
    )
    parser.add_argument("--direct-host", default="127.0.0.1")
    parser.add_argument("--direct-port", type=int, default=1502)
    parser.add_argument("--monitored-host", default="127.0.0.1")
    parser.add_argument("--monitored-port", type=int, default=15020)
    parser.add_argument("--unit-id", type=int, default=1)
    parser.add_argument("--start-addr", type=int, default=1)
    parser.add_argument("--quantity", type=int, default=6)
    parser.add_argument("--requests", type=int, default=500)
    parser.add_argument("--warmup", type=int, default=25)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--delay-ms", type=float, default=0.0)
    parser.add_argument("--connection-mode", choices=["persistent", "reconnect"], default="persistent")
    parser.add_argument("--json-out", default="")
    parser.add_argument("--csv-out", default="")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    delay_s = max(0.0, args.delay_ms) / 1000.0

    params = {
        "unit_id": args.unit_id,
        "start_addr": args.start_addr,
        "quantity": args.quantity,
        "requests": args.requests,
        "warmup": args.warmup,
        "timeout_s": args.timeout,
        "delay_ms": args.delay_ms,
        "connection_mode": args.connection_mode,
    }

    print("[latency] running direct path: client -> OpenPLC")
    direct = run_target(
        name="direct",
        host=args.direct_host,
        port=args.direct_port,
        unit_id=args.unit_id,
        start_addr=args.start_addr,
        quantity=args.quantity,
        requests=args.requests,
        warmup=args.warmup,
        timeout_s=args.timeout,
        delay_s=delay_s,
        connection_mode=args.connection_mode,
    )

    print("[latency] running monitored path: client -> runtime proxy -> OpenPLC")
    monitored = run_target(
        name="monitored",
        host=args.monitored_host,
        port=args.monitored_port,
        unit_id=args.unit_id,
        start_addr=args.start_addr,
        quantity=args.quantity,
        requests=args.requests,
        warmup=args.warmup,
        timeout_s=args.timeout,
        delay_s=delay_s,
        connection_mode=args.connection_mode,
    )

    results = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "test": "modbus_tcp_latency_direct_vs_monitored",
        "params": params,
        "direct": direct,
        "monitored": monitored,
        "overhead": compute_overhead(direct, monitored),
        "notes": [
            "Direct path uses the host-published OpenPLC Modbus/TCP port.",
            "Monitored path uses the host-published runtime proxy port and forwards to OpenPLC.",
            "Persistent mode approximates an HMI or engineering workstation that keeps a TCP session open.",
        ],
    }

    print_result_table(results)

    if args.json_out:
        json_path = Path(args.json_out)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"[latency] JSON written to {json_path}")

    if args.csv_out:
        csv_path = Path(args.csv_out)
        write_csv(csv_path, results)
        print(f"[latency] CSV written to {csv_path}")

    return 0 if direct["summary"]["failures"] == 0 and monitored["summary"]["failures"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
