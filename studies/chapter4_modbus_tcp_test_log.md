# Chapter 4 Modbus/TCP Test Log

Date: 2026-06-08
Session: `sess_v2_docker_local`
Platform state: Docker-based OT Lab v2 with OpenPLC, FUXA HMI, tshark runtime monitor, and monitor proxy.

## Test 1 - Baseline Monitoring

Result: PASS

Goal: Confirm that the platform observes Modbus/TCP traffic.

Evidence:
- Protocol observed: Modbus/TCP.
- Traffic type: normal read traffic.
- Function codes observed: FC01 and FC03.
- Representative event: FC03 Read Holding Registers.
- Client: `10.20.0.31:58720`.
- Server: `10.20.0.11:502`.
- Interface reported by dashboard: `any`.
- Runtime/agent log interface: `eth0`.
- Events captured at evidence time: `2008`.
- Dashboard active traffic: yes.
- Writes detected: false.
- Exceptions detected: none.
- Screenshot: `studies/evidence/screenshots/chapter4_modbus_tcp/Screenshot 2026-06-08 at 14.41.21.png`.

Interpretation: the platform can observe live Modbus/TCP read traffic and maintain an active connection state.

## Test 2 - Write Action Detection

Result: PASS

Goal: Show that protocol-level write actions can be observed.

Command:

```bash
curl -s -X POST "http://localhost:8000/api/v2/lab/write-register?session_id=sess_v2_docker_local" \
  -H "Content-Type: application/json" \
  -d '{"register":1,"value":42,"unit_id":1}' | python3 -m json.tool
```

Evidence:
- Function code: FC06 Write Single Register.
- Target register/address: `1`.
- Mapped process tag: `PUMP_FLOW_SP`.
- Written value: `42`.
- Source observed: `10.20.0.31`.
- Target observed: PLC / `10.20.0.11:502`.
- Dashboard event generated: yes.
- Dashboard text: `Write register | 10.20.0.31 -> PLC | PUMP_FLOW_SP = 42`.
- Modbus summary `writes_detected`: true.
- Functions seen after test: FC01, FC03, FC06.
- Screenshot: `studies/evidence/screenshots/chapter4_modbus_tcp/Screenshot 2026-06-08 at 14.48.06.png`.

Interpretation: the platform can reconstruct a Modbus write as an operational action mapped to a process variable.

## Test 3 - Exception / Invalid Action

Result: PASS with implementation limitation.

Goal: Show that abnormal or unsupported protocol behaviour can be captured.

Command:

```bash
curl -s -X POST "http://localhost:8000/api/v2/lab/write-register?session_id=sess_v2_docker_local" \
  -H "Content-Type: application/json" \
  -d '{"register":65000,"value":123,"unit_id":1}' | python3 -m json.tool
```

Evidence:
- API result: `ok=false`.
- PLC response: `modbus exception code=2`.
- Meaning: Illegal Data Address.
- Function code: FC06 Write Single Register.
- Target register/address: `65000`.
- Value: `123`.
- Dashboard event generated: yes.
- Dashboard text: `Write register | 10.20.0.31 -> PLC | HR65000 = 123`.
- `exception_functions_seen`: not populated.
- Alerts: none at the time of the original run.
- Screenshot: `studies/evidence/screenshots/chapter4_modbus_tcp/Screenshot 2026-06-08 at 14.50.00.png`.

Interpretation: the invalid write attempt is visible and the PLC rejects it, but the initial monitor version did not yet promote the event to a semantic alert.

## Scenario A - Allowed Telemetry Read

Result: PASS

Goal: Connect observed protocol traffic to a policy-style interpretation.

Command:

```bash
curl -s "http://localhost:8000/api/v2/lab/read-register?session_id=sess_v2_docker_local&register=6&unit_id=1" | python3 -m json.tool
```

Evidence:
- Function code: FC03 Read Holding Registers.
- Target register: `6`.
- Mapped process tag: `LEVEL_AI`.
- Returned value: `0`.
- Policy idea: allowed telemetry read.
- Observed result: request succeeded and was logged.
- Alert generated: no.

Interpretation: normal telemetry reads are observed without being treated as incidents.

## Scenario B - Valid Setpoint Write

Result: PASS

Goal: Show that a valid process write can be observed and classified as normal.

Command:

```bash
curl -s -X POST "http://localhost:8000/api/v2/lab/write-register?session_id=sess_v2_docker_local" \
  -H "Content-Type: application/json" \
  -d '{"register":1,"value":50,"unit_id":1}' | python3 -m json.tool
```

Evidence:
- Function code: FC06 Write Single Register.
- Target register: `1`.
- Mapped process tag: `PUMP_FLOW_SP`.
- Written value: `50`.
- Policy idea: value within expected operational range.
- Observed result: write succeeded and was logged.
- Dashboard action: `Write register | 10.20.0.31 -> PLC | PUMP_FLOW_SP = 50`.
- Alert generated: no.
- Screenshot: `studies/evidence/screenshots/chapter4_modbus_tcp/Screenshot 2026-06-08 at 14.54.04.png`.

Interpretation: a valid operational setpoint write was observed and retained as evidence.

## Scenario C - Out-of-Range Setpoint Write

Result: PASS for observation; policy gap identified.

Goal: Show that a protocol-valid write may be operationally suspicious.

Command:

```bash
curl -s -X POST "http://localhost:8000/api/v2/lab/write-register?session_id=sess_v2_docker_local" \
  -H "Content-Type: application/json" \
  -d '{"register":1,"value":150,"unit_id":1}' | python3 -m json.tool
```

Evidence:
- Function code: FC06 Write Single Register.
- Target register: `1`.
- Mapped process tag: `PUMP_FLOW_SP`.
- Written value: `150`.
- Policy idea: setpoint range violation; expected range `0..100`.
- Observed result: write succeeded at protocol level and was logged.
- Dashboard action: `Write register | 10.20.0.31 -> PLC | PUMP_FLOW_SP = 150`.
- PLC behaviour: subsequent FC03 read returned `100`, indicating process-side saturation/clamping.
- Alert generated: no in the initial version.
- Screenshot: `studies/evidence/screenshots/chapter4_modbus_tcp/Screenshot 2026-06-08 at 14.57.40.png`.

Interpretation: the PLC constrains the final process value, but the initial monitor version did not yet flag the attempted out-of-range command as a semantic policy violation.

## Scenario D - Sensitive Configuration Write

Result: PASS for observation; policy gap identified.

Goal: Show that sensitive configuration targets can be observed.

Command:

```bash
curl -s -X POST "http://localhost:8000/api/v2/lab/write-register?session_id=sess_v2_docker_local" \
  -H "Content-Type: application/json" \
  -d '{"register":3,"value":5,"unit_id":1}' | python3 -m json.tool
```

Evidence:
- Function code: FC06 Write Single Register.
- Target register: `3`.
- Mapped process tag: `ALARM_HI_SP`.
- Written value: `5`.
- Policy idea: sensitive configuration target.
- Observed result: write succeeded and was logged.
- Dashboard action: `Write register | 10.20.0.31 -> PLC | ALARM_HI_SP = 5`.
- Alert generated: no in the initial version.
- Screenshot: `studies/evidence/screenshots/chapter4_modbus_tcp/Screenshot 2026-06-08 at 14.59.43.png`.

Interpretation: the monitor can observe writes to configuration variables, but the initial version did not yet classify them as sensitive changes.

## Interim Conclusion

The initial test package demonstrates that the platform observes Modbus/TCP traffic, reconstructs operational write actions, maps protocol addresses to process-level tags, and exposes the resulting events in the dashboard. The key limitation is semantic interpretation: out-of-range setpoints, unknown registers, and sensitive configuration writes are visible but were not yet classified as policy violations in the first test run.

The next implementation step is therefore a minimal declarative semantic policy layer for observed actions, producing `ALLOW` or `ALERT` decisions with traceable rule identifiers and reasons.

## Post-Policy Validation - Observed Semantic Decisions

Date: 2026-06-08

Result: PASS

Goal: Repeat the policy-style scenarios after adding the observed semantic policy layer.

Screenshot:
- `studies/evidence/screenshots/chapter4_modbus_tcp/Screenshot 2026-06-08 at 15.25.12.png`

### Scenario B - Valid Setpoint Write

Command:

```bash
curl -s -X POST "http://localhost:8000/api/v2/lab/write-register?session_id=sess_v2_docker_local" \
  -H "Content-Type: application/json" \
  -d '{"register":1,"value":50,"unit_id":1}' | python3 -m json.tool
```

API result:
- `ok=true`
- Register: `1`
- Value: `50`

Dashboard / Copy Log:

```text
Write register | 10.20.0.31 -> PLC | PUMP_FLOW_SP = 50 | ALLOW | OBS-R000 | Action is mapped to the process model and remains within the initial semantic policy.
```

Interpretation: the command is protocol-valid, process-mapped, and inside the declared operating envelope. The monitor therefore records it as an allowed operational action.

### Scenario C - Out-of-Range Setpoint Write

Command:

```bash
curl -s -X POST "http://localhost:8000/api/v2/lab/write-register?session_id=sess_v2_docker_local" \
  -H "Content-Type: application/json" \
  -d '{"register":1,"value":150,"unit_id":1}' | python3 -m json.tool
```

API result:
- `ok=true`
- Register: `1`
- Value: `150`

Dashboard / Copy Log:

```text
Write register | 10.20.0.31 -> PLC | PUMP_FLOW_SP = 150 | ALERT | OBS-R001 | PUMP_FLOW_SP=150 is outside the declared operational range 0..100.
```

Interpretation: the command is valid Modbus/TCP and may still be accepted by the communication path, but the monitor now classifies it as semantically abnormal because the setpoint exceeds the declared process envelope.

### Scenario D - Sensitive Configuration Write

Command:

```bash
curl -s -X POST "http://localhost:8000/api/v2/lab/write-register?session_id=sess_v2_docker_local" \
  -H "Content-Type: application/json" \
  -d '{"register":3,"value":5,"unit_id":1}' | python3 -m json.tool
```

API result:
- `ok=false`
- Error: `Write failed: timed out`

Dashboard / Copy Log:

```text
Write register | 10.20.0.31 -> PLC | ALARM_HI_SP = 5 | ALERT | OBS-R002 | ALARM_HI_SP is a process configuration parameter and should be changed only under authorised conditions.
```

Interpretation: even though the API call timed out, the monitor observed the attempted write and classified it as a sensitive configuration change. This is useful evidence for the thesis argument because detection is based on observed network/process intent rather than only API success/failure.

### Unknown / Unmapped Target

Command:

```bash
curl -s -X POST "http://localhost:8000/api/v2/lab/write-register?session_id=sess_v2_docker_local" \
  -H "Content-Type: application/json" \
  -d '{"register":65000,"value":123,"unit_id":1}' | python3 -m json.tool
```

API result:
- `ok=false`
- Error: `Write failed: modbus exception code=2`

Dashboard / Copy Log:

```text
Write register | 10.20.0.31 -> PLC | HR65000 = 123 | ALERT | OBS-R003 | Write targets an address that is not mapped to the declared process model (HR65000).
```

Interpretation: the PLC rejected the write with a Modbus exception, and the monitor independently flagged the address as outside the declared process model. This demonstrates a first link between protocol observation and process-aware interpretation.

## Updated Conclusion

The updated prototype now demonstrates three layers of evidence:

1. Protocol visibility: Modbus/TCP traffic is detected through `tshark`.
2. Operational reconstruction: FC06 writes are mapped to process-level variables such as `PUMP_FLOW_SP` and `ALARM_HI_SP`.
3. Semantic interpretation: observed actions receive traceable `ALLOW` or `ALERT` decisions with explicit rule identifiers.

This supports the Chapter 4 argument that the platform is no longer only a packet monitor. It can connect a protocol action to a declared process model and produce an explainable process-aware decision, while keeping the PLC safety logic responsible for physical constraints.

## Policy Decision Export Evidence

Date: 2026-06-08

Result: PASS

Goal: Confirm that the semantic decision layer can be exported as a structured artefact for thesis evidence.

Evidence files:
- Dashboard screenshot: `studies/evidence/screenshots/chapter4_modbus_tcp/Screenshot 2026-06-08 at 20.22.26.png`
- Exported policy decision JSON: `studies/evidence/otlab-policy-decisions-2026-06-08T18-22-31-770Z.json`

Export summary:
- Policy identifier: `observed_modbus_tank_v1`
- Policy version: `0.1.0`
- Total decisions: `4`
- ALLOW decisions: `1`
- ALERT decisions: `3`
- BLOCK decisions: `0`

Decision table:

| Scenario | Action | Asset | Value | Decision | Rule | Interpretation |
| --- | --- | --- | ---: | --- | --- | --- |
| Valid setpoint | FC06 write register | `PUMP_FLOW_SP` | 50 | ALLOW | `OBS-R000` | Mapped process action inside the declared envelope. |
| Out-of-range setpoint | FC06 write register | `PUMP_FLOW_SP` | 150 | ALERT | `OBS-R001` | Protocol-valid write outside the declared process envelope. |
| Sensitive configuration | FC06 write register | `ALARM_HI_SP` | 5 | ALERT | `OBS-R002` | Process configuration write requiring authorised conditions. |
| Unmapped address | FC06 write register | `HR65000` | 123 | ALERT | `OBS-R003` | Write to an address outside the declared process model. |

Interpretation: this exported result is the clearest Chapter 4 evidence produced so far. It shows the transition from network observation to process-aware semantic judgement: the same Modbus/TCP function code is interpreted differently depending on the declared process target, value, and policy rule.

## Latency Evidence: Direct Path vs Monitored Path

Date: 2026-06-09

Result: PASS

Goal: Estimate the communication overhead introduced by the monitoring/proxy path in the Docker-based OT lab.

Test design:

| Path | Route |
| --- | --- |
| Direct | client -> OpenPLC |
| Monitored | client -> runtime proxy -> OpenPLC |

Command:

```bash
python3 scripts/benchmark_modbus_latency.py \
  --requests 500 \
  --warmup 25 \
  --connection-mode persistent \
  --timeout 2 \
  --start-addr 1 \
  --quantity 6 \
  --json-out studies/evidence/modbus_latency_persistent_20260609T120706Z.json \
  --csv-out studies/evidence/modbus_latency_persistent_20260609T120706Z.csv
```

Evidence files:
- JSON: `studies/evidence/modbus_latency_persistent_20260609T120706Z.json`
- CSV: `studies/evidence/modbus_latency_persistent_20260609T120706Z.csv`

Measured result:

| Path | Requests | Failures | Average ms | Median ms | p95 ms | p99 ms | Min ms | Max ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Direct | 500 | 0 | 0.190 | 0.172 | 0.278 | 0.489 | 0.124 | 1.500 |
| Monitored | 500 | 0 | 0.296 | 0.219 | 0.713 | 1.420 | 0.178 | 2.478 |

Observed overhead:
- Average overhead: `0.106 ms`
- Median overhead: `0.047 ms`
- p95 overhead: `0.434 ms`
- p99 overhead: `0.931 ms`
- Failures/timeouts: `0` in both paths

Interpretation: in this local Docker setup, the monitored route introduces sub-millisecond median overhead and no observed request failures under the tested persistent-connection workload. This is suitable as preliminary feasibility evidence, but should be framed as a lab measurement rather than a deterministic real-time guarantee. Later evaluation should repeat the test under controlled load, with larger sample sizes, multiple rates, and protocol-specific traffic profiles.
