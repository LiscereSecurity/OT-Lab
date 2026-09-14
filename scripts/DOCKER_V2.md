# OT Lab (Docker) - Quick Start

This guide describes the current Docker-based OT Lab environment.

## 1) Start full lab (web + runtime + OpenPLC + HMI)

```bash
cd ot-lab-app
cp .env.example .env
docker compose up -d --build
```

Open:
- OT Lab: <http://localhost:8000/?session_id=sess_v2_docker_local>
- OpenPLC: <http://localhost:8081>
- FUXA HMI: <http://localhost:1881>

Inline monitor path for Modbus/TCP:
- HMI target host: `runtime`
- HMI target port: `15020`
- Monitor proxy forwards to OpenPLC `openplc:502`

## 1.1) Realistic OT lab addressing (optional but recommended)

The compose file now supports fixed OT/DMZ addressing and host-port mapping using `.env`.
Edit `.env` to simulate your target topology:

- `OT_SUBNET`, `DMZ_SUBNET`
- `OPENPLC_OT_IP`, `HMI_OT_IP`, `MONITOR_OT_IP`
- `WEB_DMZ_IP`, `MONITOR_DMZ_IP`
- `OPENPLC_WEB_PORT`, `OPENPLC_MODBUS_PORT`, `HMI_WEB_PORT`
- `RUNTIME_IFACE` (default `eth0`)

After changing network/subnet/IP values:

```bash
docker compose down -v
docker compose up -d --build
```

## 2) Logs

```bash
docker compose logs -f web
docker compose logs -f runtime
docker compose logs -f openplc
docker compose logs -f hmi
```

## 3) Stop

```bash
docker compose down
```

## Notes

- On macOS/Windows, Docker Desktop uses a VM. Packet-level behavior differs from Linux host mode.
- For full monitor/sniffer parity, Linux host deployments remain the closest match to a native OT capture environment.
- This Docker baseline is the main public OT Lab deployment path.
