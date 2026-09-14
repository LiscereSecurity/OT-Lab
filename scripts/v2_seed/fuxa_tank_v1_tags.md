# FUXA Tank v1 - Tag Map (OpenPLC Modbus/TCP)

Use this map after loading `openplc_tank_v1.st` in OpenPLC.

## Connection
- Name: `OpenPLC`
- Type: `ModbusTCP`
- Host: `openplc` (or monitor IP if routed through monitor)
- Port: `502` (or `15020` if routed through monitor)
- Slave ID: `1`

## Tags

### Coils (Read/Write + Status)
- `PUMP_CMD` -> Coil `00001` (`%QX0.0`) - Bool, Read/Write
- `VALVE_CMD` -> Coil `00002` (`%QX0.1`) - Bool, Read/Write
- `ALARM_HI_ACTIVE` -> Coil `00003` (`%QX0.2`) - Bool, Read
- `ALARM_LO_ACTIVE` -> Coil `00004` (`%QX0.3`) - Bool, Read

### Holding Registers (Setpoints)
- `PUMP_FLOW_SP` -> HR `40001` (`%QW0`) - Int 0..100, Read/Write
- `VALVE_FLOW_SP` -> HR `40002` (`%QW1`) - Int 0..100, Read/Write
- `ALARM_HI_SP` -> HR `40003` (`%QW2`) - Int 0..100, Read/Write
- `ALARM_LO_SP` -> HR `40004` (`%QW3`) - Int 0..100, Read/Write

### Input Registers (Process Feedback)
- `LEVEL_AI` -> IR `30001` (`%IW0`) - Int 0..100, Read
- `PUMP_RATE_AI` -> IR `30002` (`%IW1`) - Int 0..100, Read
- `VALVE_RATE_AI` -> IR `30003` (`%IW2`) - Int 0..100, Read

---

## Minimal HMI Layout (recommended)

1. Tank Level:
- Gauge/Bar bound to `LEVEL_AI` (0..100).

2. Pump:
- Switch bound to `PUMP_CMD`.
- Numeric input/slider bound to `PUMP_FLOW_SP` (0..100).
- Optional readback text bound to `PUMP_RATE_AI`.

3. Outlet Valve:
- Switch bound to `VALVE_CMD`.
- Numeric input/slider bound to `VALVE_FLOW_SP` (0..100).
- Optional readback text bound to `VALVE_RATE_AI`.

4. Alarms:
- Numeric input `ALARM_HI_SP`.
- Numeric input `ALARM_LO_SP`.
- Alarm indicators (lamp):
  - red lamp -> `ALARM_HI_ACTIVE`
  - yellow lamp -> `ALARM_LO_ACTIVE`

---

## Operator semantics to show in HMI
- Coil write in monitor: `%Q0.0` pump command, `%Q0.1` valve command.
- Setpoints persist in PLC memory while runtime is active.
- Alarm band is automatically validated in PLC (`HI > LO` always enforced).
