const SESSION_STORAGE_KEY = "otlab_session_id_v2";
const SESSION_ID_REGEX = /^sess_[A-Za-z0-9_-]{8,128}$/;

let pinnedSessionId = null;
let cachedAttacks = [];
let labLivePollHandle = null;
let labSwitchPollHandle = null;
let labSwitchValue = 0;
let plcServiceRunning = false;
let hmiServiceRunning = false;
let latestTopology = [];
let uiEndpoints = null;
let monitorRouteEnabled = true;
let latestNetworkHosts = [];
let selectedNetworkHostIp = null;
let latestNetworkArchitecture = null;
let latestAlertsClipboardText = "";
let latestPolicyDecisionRows = [];
let latestPolicyDecisionClipboardText = "";
let monitorTagRows = [];
const FLOW_ACTIVE_TTL_SEC = 3;
const MONITORED_PROTOCOLS = new Set(["MODBUS/TCP", "MODBUS"]);
const OT_EVENT_TYPES = new Set(["READ_REQUEST", "READ_RESPONSE", "WRITE_REQUEST", "WRITE_RESPONSE", "EXCEPTION_RESPONSE"]);
const LINK_EVENT_TYPES = new Set(["LINK_OPEN", "LINK_ERROR", "LINK_CLOSE"]);
let MODBUS_TAG_MAP = {
  coil: {
    0: "PUMP_CMD",
    1: "VALVE_CMD",
    2: "ALARM_HI_ACTIVE",
    3: "ALARM_LO_ACTIVE",
  },
  register: {
    1: "PUMP_FLOW_SP",
    2: "VALVE_FLOW_SP",
    3: "ALARM_HI_SP",
    4: "ALARM_LO_SP",
    6: "LEVEL_AI",
  },
};

function applyTagMap(payloadMap) {
  const incoming = payloadMap || {};
  const next = { coil: {}, register: {} };
  for (const bucket of ["coil", "register"]) {
    const src = incoming[bucket] || {};
    for (const [k, v] of Object.entries(src)) {
      const key = Number(k);
      if (!Number.isFinite(key)) continue;
      const val = String(v || "").trim();
      if (!val) continue;
      next[bucket][key] = val;
    }
  }
  MODBUS_TAG_MAP = next;
}

function normalizeTsSeconds(raw) {
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return 0;
  // Backends may emit seconds or milliseconds.
  return n > 1e12 ? n / 1000 : n;
}

function byId(id) { return document.getElementById(id); }
function setText(id, text) { const el = byId(id); if (el) el.textContent = text; }
function setHtml(id, html) { const el = byId(id); if (el) el.innerHTML = html; }
function flashButtonSaved(btn, label = "Saved", ms = 1000) {
  if (!btn) return;
  const prev = btn.textContent;
  btn.textContent = label;
  setTimeout(() => { btn.textContent = prev || "Save"; }, ms);
}

function isValidSessionId(value) {
  return SESSION_ID_REGEX.test(String(value || "").trim());
}

function loadPinnedSessionId() {
  try {
    const fromUrl = new URLSearchParams(window.location.search).get("session_id");
    if (isValidSessionId(fromUrl)) {
      pinnedSessionId = String(fromUrl).trim();
      localStorage.setItem(SESSION_STORAGE_KEY, pinnedSessionId);
      return;
    }
  } catch (_) {}
  try {
    const saved = localStorage.getItem(SESSION_STORAGE_KEY);
    if (isValidSessionId(saved)) pinnedSessionId = String(saved).trim();
  } catch (_) {}
}

function bindSessionToUrl(url) {
  if (!isValidSessionId(pinnedSessionId)) return url;
  try {
    const u = new URL(url, window.location.origin);
    if (!u.searchParams.get("session_id")) u.searchParams.set("session_id", pinnedSessionId);
    return u.origin === window.location.origin ? `${u.pathname}${u.search}${u.hash}` : u.toString();
  } catch (_) {
    return url;
  }
}

function captureSessionId(payload) {
  const candidate = payload?.session_id;
  if (!isValidSessionId(candidate)) return;
  pinnedSessionId = String(candidate).trim();
  try { localStorage.setItem(SESSION_STORAGE_KEY, pinnedSessionId); } catch (_) {}
}

async function apiGet(url) {
  const res = await fetch(bindSessionToUrl(url), { credentials: "same-origin" });
  const data = await res.json();
  captureSessionId(data);
  return data;
}

async function apiPost(url, data = {}) {
  const res = await fetch(bindSessionToUrl(url), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify(data),
  });
  const payload = await res.json();
  captureSessionId(payload);
  return payload;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function endpointHost(v) {
  const raw = String(v || "").trim();
  if (!raw) return raw;
  if (raw.includes(":") && raw.split(":").length === 2 && raw.includes(".")) return raw.split(":")[0];
  return raw;
}

function setBadge(id, label, running) {
  const el = byId(id);
  if (!el) return;
  el.textContent = `${label}: ${running ? "RUNNING" : "STOPPED"}`;
  el.style.color = running ? "var(--ok)" : "var(--muted)";
}

function openModal(id) { const el = byId(id); if (el) el.classList.remove("hidden"); }
function closeModal(id) { const el = byId(id); if (el) el.classList.add("hidden"); }
function openWindow(id) { const el = byId(id); if (el) el.classList.remove("hidden"); }
function closeWindow(id) {
  const el = byId(id);
  if (!el || el.classList.contains("hidden")) return;
  el.classList.add("closing");
  setTimeout(() => {
    el.classList.add("hidden");
    el.classList.remove("closing");
  }, 170);
}

function openQuickConfigWindow(windowId, anchorButtonId) {
  const win = byId(windowId);
  const btn = byId(anchorButtonId);
  if (!win) return;
  win.classList.remove("hidden");
  win.classList.remove("closing");
  if (!btn) return;
  const rect = btn.getBoundingClientRect();
  let preferredWidth = 360;
  if (windowId === "networkScanWindow") preferredWidth = 860;
  else if (windowId === "policyDecisionsWindow") preferredWidth = 980;
  else if (win.classList.contains("attack-config-window")) preferredWidth = 460;
  const w = Math.min(preferredWidth, Math.max(320, window.innerWidth - 24));
  const gap = 12;
  const measuredH = (windowId === "networkScanWindow" || windowId === "policyDecisionsWindow")
    ? Math.max(300, Math.min(560, win.offsetHeight || 420))
    : Math.max(220, Math.min(520, win.offsetHeight || 260));
  const spaceBelow = window.innerHeight - rect.bottom;
  const spaceAbove = rect.top;
  let top;
  if (windowId === "networkScanWindow" || windowId === "policyDecisionsWindow") {
    // Prefer opening above button for dock actions.
    if (spaceAbove >= (measuredH + gap)) {
      top = rect.top - measuredH - gap;
    } else if (spaceBelow >= (measuredH + gap)) {
      top = rect.bottom + gap;
    } else {
      top = Math.max(8, rect.top - measuredH - gap);
    }
  } else {
    if (spaceBelow >= (measuredH + gap) || spaceBelow >= spaceAbove) {
      top = rect.bottom + gap; // open below button
    } else {
      top = rect.top - measuredH - gap; // open above button
    }
  }
  const centeredLeft = rect.left + (rect.width / 2) - (w / 2);
  const left = Math.max(12, Math.min(window.innerWidth - w - 12, centeredLeft));
  top = Math.max(8, Math.min(window.innerHeight - measuredH - 8, top));
  win.style.width = `${w}px`;
  win.style.left = `${left}px`;
  win.style.top = `${top}px`;
  win.style.height = "auto";
}

function toggleQuickConfigWindow(windowId, anchorButtonId, beforeOpen) {
  const win = byId(windowId);
  if (!win) return;
  if (!win.classList.contains("hidden")) {
    closeWindow(windowId);
    return;
  }
  if (typeof beforeOpen === "function") beforeOpen();
  openQuickConfigWindow(windowId, anchorButtonId);
}

function enableWindowDragging() {
  let active = null;
  let startX = 0;
  let startY = 0;
  let startLeft = 0;
  let startTop = 0;

  const onMove = (ev) => {
    if (!active) return;
    const dx = ev.clientX - startX;
    const dy = ev.clientY - startY;
    const width = active.offsetWidth || 320;
    const height = active.offsetHeight || 220;
    const nextLeft = Math.max(8, Math.min(window.innerWidth - width - 8, startLeft + dx));
    const nextTop = Math.max(8, Math.min(window.innerHeight - height - 8, startTop + dy));
    active.style.left = `${nextLeft}px`;
    active.style.top = `${nextTop}px`;
  };

  const onUp = () => {
    active = null;
    document.removeEventListener("pointermove", onMove);
    document.removeEventListener("pointerup", onUp);
  };

  document.querySelectorAll(".floating-window .window-head").forEach((head) => {
    head.addEventListener("pointerdown", (ev) => {
      const target = ev.target;
      if (target && (target.closest(".window-close") || target.closest("button") || target.closest("input") || target.closest("select"))) {
        return;
      }
      const win = head.closest(".floating-window");
      if (!win) return;
      active = win;
      startX = ev.clientX;
      startY = ev.clientY;
      startLeft = parseFloat(win.style.left || "120") || 120;
      startTop = parseFloat(win.style.top || "120") || 120;
      document.addEventListener("pointermove", onMove);
      document.addEventListener("pointerup", onUp);
    });
  });
}

function renderList(containerId, items, formatter, emptyText = "No data available.") {
  const container = byId(containerId);
  if (!container) return;
  if (!items?.length) {
    container.innerHTML = `<div class="log-item">${escapeHtml(emptyText)}</div>`;
    return;
  }
  container.innerHTML = items.slice().reverse().map((item) =>
    `<div class="log-item">${String(formatter(item) || "").trim()}</div>`
  ).join("");
}

function formatAgentStatus(data) {
  const a = data?.agent || {};
  const opMode = String(data?.monitor_operating_mode || "observe").toUpperCase();
  const ports = a.port_mode === "CUSTOM" ? ((a.custom_ports || []).join(",") || "-") : String(a.port_mode || "-");
  return [
    `MODE: ${opMode}`,
    `INTERFACE: ${a.iface || "-"}`,
    `PORTS: ${ports}`,
  ].join("\n");
}

function formatEvent(item) {
  const rawTs = item?.ts_iso || item?.timestamp || "-";
  const ts = Number.isFinite(Number(rawTs)) ? new Date(Number(rawTs) * 1000).toLocaleTimeString() : String(rawTs);
  const type = String(item?.type || "EVENT");
  const summary = String(item?.summary || item?.message || item?.text || "").trim();
  return `<strong>[${escapeHtml(type)}] ${escapeHtml(ts)}</strong><br>${escapeHtml(summary || "Event detected")}`;
}

function formatAlert(item) {
  const severity = String(item?.severity || "info").toUpperCase();
  const title = String(item?.event_type || item?.event || "Alert");
  const rawSummary = String(item?.summary || item?.message || "-");
  const summary = rawSummary.replace(/\s*\|\s*rtt=[^|]+/gi, "").trim();

  const monitorPort = Number(uiEndpoints?.monitor_proxy?.port || 15020);
  const monitorAliasIps = new Set();
  const directMonIp = String(uiEndpoints?.monitor_proxy?.ip || "").trim();
  if (directMonIp) monitorAliasIps.add(directMonIp);
  (latestNetworkHosts || []).forEach((h) => {
    const ip = String(h?.ip || "").trim();
    const role = String(h?.role || "").toLowerCase();
    const ports = Array.isArray(h?.open_ports) ? h.open_ports.map((p) => Number(p)) : [];
    if (!ip) return;
    if (role === "monitor" || ports.includes(monitorPort)) monitorAliasIps.add(ip);
  });

  const resolveRoleByIp = (ipRaw) => {
    const ip = endpointHost(ipRaw);
    if (!ip) return "";
    const hmiIp = endpointHost(uiEndpoints?.hmi?.ip || "");
    const plcIp = endpointHost(uiEndpoints?.plc?.ip || "");
    const monIp = endpointHost(uiEndpoints?.monitor_proxy?.ip || "");
    if (ip === hmiIp) return "HMI";
    if (ip === plcIp) return "PLC";
    if (ip === monIp || monitorAliasIps.has(ip)) return "MONITOR";
    const fromScan = (latestNetworkHosts || []).find((h) => endpointHost(h?.ip || "") === ip);
    if (fromScan?.role) return String(fromScan.role).toUpperCase();
    return "";
  };
  const labelIp = (ip) => {
    const role = resolveRoleByIp(ip);
    return role || (ip || "-");
  };

  const m = summary.match(/from\s+([0-9.]+):(\d+)\s+to\s+([0-9.]+):(\d+)/i);
  const parts = summary
    .split("|")
    .map((p) => p.trim())
    .filter(Boolean)
    .filter((p) => !/^rtt=/i.test(p));
  const action = parts[1] || "";
  const details = parts.slice(2).join(" | ");

  if (!m) {
    return `<strong>[${escapeHtml(severity)}] ${escapeHtml(title)}</strong><br>${escapeHtml(summary)}`;
  }

  const srcIp = endpointHost(m[1]);
  const dstIp = endpointHost(m[3]);
  const srcRole = labelIp(srcIp);
  const dstRole = labelIp(dstIp);
  const cleanTitle = title.replace("WRITE_", "").replace("READ_", "");
  const actionLower = String(action || "").toLowerCase();

  let shortAction = action || cleanTitle;
  let shortDetail = details;
  if (actionLower.includes("write single coil")) {
    const regMatch = summary.match(/register\s*=\s*(\d+)/i);
    const valMatch = summary.match(/value\s*=\s*(ON|OFF|0|1)/i);
    const reg = Number(regMatch?.[1] || 0);
    const valueRaw = String(valMatch?.[1] || "0").toUpperCase();
    const bit = reg % 8;
    const byte = Math.floor(reg / 8);
    const valueNum = valueRaw === "ON" ? "1" : valueRaw === "OFF" ? "0" : valueRaw;
    shortAction = "Write single coil";
    shortDetail = `${MODBUS_TAG_MAP.coil[reg] || `%Q${byte}.${bit}`} = ${valueNum}`;
  } else if (actionLower.includes("write single register")) {
    const regMatch = summary.match(/register\s*=\s*(\d+)/i);
    const valMatch = summary.match(/value\s*=\s*(-?\d+)/i);
    const reg = Number(regMatch?.[1] || 0);
    const valueNum = Number(valMatch?.[1] || 0);
    shortAction = "Write register";
    shortDetail = `${MODBUS_TAG_MAP.register[reg] || `HR${reg}`} = ${valueNum}`;
  } else if (actionLower.includes("read coils")) {
    const startMatch = summary.match(/start\s*=\s*(\d+)/i);
    const qtyMatch = summary.match(/qty\s*=\s*(\d+)/i);
    const start = Number(startMatch?.[1] || 0);
    const qty = Number(qtyMatch?.[1] || 1);
    shortAction = "Read coils";
    shortDetail = `%Q${Math.floor(start / 8)}.${start % 8} .. qty=${qty}`;
  }

  return `
    <article class="alert-card">
      <div class="alert-top">
        <span class="alert-kind">${escapeHtml(cleanTitle)}</span>
        <span class="alert-level">${escapeHtml(severity === "NOTICE" ? "EVENT" : severity)}</span>
      </div>
      <div class="alert-line">${escapeHtml(srcRole)} (${escapeHtml(srcIp)}) → ${escapeHtml(dstRole)} (${escapeHtml(dstIp)}) | ${escapeHtml(shortAction)}: ${escapeHtml(shortDetail || "-")}</div>
    </article>
  `;
}

function compactOperationalAlerts(items) {
  const out = [];
  const source = Array.isArray(items) ? items : [];
  const decisionRank = (decision) => {
    const d = String(decision || "").toUpperCase();
    if (d === "BLOCK") return 3;
    if (d === "ALERT" || d === "ALLOW_WITH_ALERT") return 2;
    if (d === "ALLOW") return 1;
    return 0;
  };
  const strongerDecision = (a, b) => decisionRank(b?.decision) >= decisionRank(a?.decision) ? b : a;
  for (const item of source) {
    if (String(item?.kind || "") === "operational_action") {
      const ts = normalizeTsSeconds(item?.timestamp || Date.now() / 1000);
      const actionType = String(item?.action_type || "");
      const actionKey = actionType.includes("coil") ? "coil" : "register";
      const valueTo = item?.value_to;
      const mergeKey = actionKey === "coil"
        ? `${actionType}|${item?.asset}|${item?.target}|${valueTo}`
        : `${actionType}|${item?.asset}|${item?.target}`;
      const last = out.length ? out[out.length - 1] : null;
      if (last && last.key === mergeKey && (ts - last.lastTs) <= 0.5) {
        last.lastTs = ts;
        last.count += Number(item?.count || 1);
        last.lastValue = valueTo;
        last.policyDecision = strongerDecision(last.policyDecision, item?.policy_decision);
        if (last.firstValue === null || last.firstValue === undefined || last.firstValue === "") {
          last.firstValue = item?.value_from;
        }
        continue;
      }
      out.push({
        key: mergeKey,
        ts,
        lastTs: ts,
        count: Number(item?.count || 1),
        actionKey,
        reg: Number(item?.address || 0),
        firstValue: item?.value_from,
        lastValue: valueTo,
        src: String(item?.actor || ""),
        dst: String(item?.target || ""),
        asset: String(item?.asset || ""),
        policyDecision: item?.policy_decision || null,
        raw: item,
      });
      continue;
    }
    const eventType = String(item?.event_type || item?.event || "").toUpperCase();
    const summary = String(item?.summary || item?.message || "");
    const isWrite = /write single (coil|register)/i.test(summary);
    if (!isWrite) continue;

    const ts = normalizeTsSeconds(item?.timestamp || item?.ts_iso || Date.now() / 1000);
    const regMatch = summary.match(/register\s*=\s*(\d+)/i);
    const valMatch = summary.match(/value\s*=\s*(ON|OFF|0|1|-?\d+)/i);
    const srcMatch = summary.match(/from\s+([0-9.]+):\d+\s+to\s+([0-9.]+):\d+/i);
    const actionKey = /coil/i.test(summary) ? "coil" : "register";
    const reg = Number(regMatch?.[1] || 0);
    const valueRaw = String(valMatch?.[1] || "0").toUpperCase();
    const value = valueRaw === "ON" ? 1 : valueRaw === "OFF" ? 0 : Number(valueRaw || 0);
    const src = endpointHost(srcMatch?.[1] || "");
    const dst = endpointHost(srcMatch?.[2] || "");
    const key = `${actionKey}|${reg}|${src}|${dst}|${eventType.includes("REQUEST") ? "REQ" : "RESP"}`;

    const last = out.length ? out[out.length - 1] : null;
    if (last && last.key === key && (ts - last.lastTs) <= 2.0) {
      last.lastTs = ts;
      last.count += 1;
      last.lastValue = value;
      continue;
    }

    out.push({
      key,
      ts,
      lastTs: ts,
      count: 1,
      actionKey,
      reg,
      firstValue: value,
      lastValue: value,
      src,
      dst,
      raw: item,
    });
  }
  return out;
}

async function refreshStatus() {
  const data = await apiGet("/api/status");
  if (data?.tag_map) applyTagMap(data.tag_map);
  monitorRouteEnabled = !!data?.monitor_route_enabled;
  setText("agentStatus", formatAgentStatus(data));
  const monitorRuntime = !!data?.runtime_state?.monitor?.running;
  setBadge("globalMonitorBadge", "MONITOR", monitorRuntime && monitorRouteEnabled);
  const m = byId("globalMonitorBadge");
  if (m) m.textContent = `MONITOR: ${monitorRouteEnabled ? "ON" : "OFF"}`;
  setBadge("globalDefenseBadge", "DEFENSE", !!data?.runtime_state?.defense?.running);
  setBadge("globalPlcBadge", "PLC", plcServiceRunning);
  setBadge("globalHmiBadge", "HMI", hmiServiceRunning);
  const toggleBtn = byId("toggleMonitorRouteBtn");
  if (toggleBtn) {
    toggleBtn.textContent = monitorRouteEnabled ? "Monitor ON" : "Monitor OFF";
    toggleBtn.classList.toggle("secondary", !monitorRouteEnabled);
  }
}

async function refreshEvents() {
  const data = await apiGet("/api/events");
  if (data?.tag_map) applyTagMap(data.tag_map);
  const rawEvents = Array.isArray(data?.events) ? data.events : [];
  const plcIp = String(uiEndpoints?.plc?.ip || "").trim();
  const plcPort = Number(uiEndpoints?.plc?.port || 502);
  const hmiIp = String(uiEndpoints?.hmi?.ip || "").trim();
  const monIp = String(uiEndpoints?.monitor_proxy?.ip || "").trim();
  const monPort = Number(uiEndpoints?.monitor_proxy?.port || 15020);

  const healthEvents = rawEvents.filter((ev) => {
    const t = String(ev?.type || "");
    if (!LINK_EVENT_TYPES.has(t)) return false;
    const srcIp = String(ev?.src_ip || "");
    const dstIp = String(ev?.dst_ip || "");
    const dstPort = Number(ev?.dst_port || 0);
    if (!plcIp) return false;
    // Infra/system checks toward PLC endpoint but not from HMI/Monitor/PLC identities.
    const isInfraSrc = srcIp !== hmiIp && srcIp !== monIp && srcIp !== plcIp;
    return isInfraSrc && dstIp === plcIp && dstPort === plcPort;
  });

  const relevant = rawEvents.filter((ev) => {
    const t = String(ev?.type || "");
    if (!OT_EVENT_TYPES.has(t) && !LINK_EVENT_TYPES.has(t)) return false;
    const proto = String(ev?.protocol || "").toUpperCase();
    if (!MONITORED_PROTOCOLS.has(proto)) return false;
    const srcIp = String(ev?.src_ip || "");
    const dstIp = String(ev?.dst_ip || "");
    const srcPort = Number(ev?.src_port || 0);
    const dstPort = Number(ev?.dst_port || 0);
    if (!plcIp) return true;
    if (OT_EVENT_TYPES.has(t)) {
      // Real OT communication is defined by Modbus payload events touching PLC endpoint.
      return (srcIp === plcIp && srcPort === plcPort) || (dstIp === plcIp && dstPort === plcPort);
    }
    // Link events are useful for health context only.
    return false;
  });
  renderEventsPanel(relevant.slice(-50), healthEvents.slice(-20));
  renderAlertsPanel(data?.actions || data?.alerts || []);
}

function renderAlertsPanel(items) {
  const panel = byId("alertsPanel");
  if (!panel) return;
  const compacted = compactOperationalAlerts(items);
  if (!compacted.length) {
    latestAlertsClipboardText = "";
    panel.innerHTML = `<div class="log-item">No alerts.</div>`;
    return;
  }
  const roleByIp = (ipRaw) => {
    const roleRaw = String(ipRaw || "").trim().toUpperCase();
    if (["HMI", "PLC", "MONITOR"].includes(roleRaw)) return roleRaw;
    const ip = endpointHost(ipRaw);
    const hmiIp = endpointHost(uiEndpoints?.hmi?.ip || "");
    const plcIp = endpointHost(uiEndpoints?.plc?.ip || "");
    const monIp = endpointHost(uiEndpoints?.monitor_proxy?.ip || "");
    if (ip === hmiIp) return "HMI";
    if (ip === plcIp) return "PLC";
    if (ip === monIp) return "MONITOR";
    return ip || "-";
  };
  const ordered = compacted.slice().reverse();
  latestAlertsClipboardText = ordered.map((c) => {
    const src = roleByIp(c.src);
    const dst = roleByIp(c.dst);
    const tag = c.asset || (c.actionKey === "coil"
      ? (MODBUS_TAG_MAP.coil[c.reg] || `%Q${Math.floor(c.reg / 8)}.${c.reg % 8}`)
      : (MODBUS_TAG_MAP.register[c.reg] || `HR${c.reg}`));
    const valueText = c.count > 1
      ? `${c.firstValue} -> ${c.lastValue} (${c.count} changes)`
      : `${c.lastValue}`;
    const action = c.actionKey === "coil" ? "Write coil" : "Write register";
    const policy = c.policyDecision || {};
    const decision = String(policy.decision || "EVENT").toUpperCase();
    const rule = policy.rule_id ? ` | ${policy.rule_id}` : "";
    const reason = policy.reason ? ` | ${policy.reason}` : "";
    return `${action} | ${src} -> ${dst} | ${tag} = ${valueText} | ${decision}${rule}${reason}`;
  }).join("\n");

  panel.innerHTML = ordered.map((c) => {
    const src = roleByIp(c.src);
    const dst = roleByIp(c.dst);
    const tag = c.asset || (c.actionKey === "coil"
      ? (MODBUS_TAG_MAP.coil[c.reg] || `%Q${Math.floor(c.reg / 8)}.${c.reg % 8}`)
      : (MODBUS_TAG_MAP.register[c.reg] || `HR${c.reg}`));
    const hasFirst = c.firstValue !== null && c.firstValue !== undefined && c.firstValue !== "";
    const firstVal = hasFirst ? c.firstValue : c.lastValue;
    const valueText = c.count > 1
      ? (String(firstVal) === String(c.lastValue)
          ? `${c.lastValue} (${c.count} samples)`
          : `${firstVal} → ${c.lastValue} (${c.count} changes)`)
      : `${c.lastValue}`;
    const action = c.actionKey === "coil" ? "Write coil" : "Write register";
    const policy = c.policyDecision || {};
    const decision = String(policy.decision || "EVENT").toUpperCase();
    const rule = String(policy.rule_id || "").trim();
    const reason = String(policy.reason || "").trim();
    const policyLine = reason
      ? `<div class="alert-policy">${escapeHtml(rule ? `${rule}: ${reason}` : reason)}</div>`
      : "";
    return `
      <article class="alert-card policy-${escapeHtml(decision.toLowerCase())}">
        <div class="alert-top">
          <span class="alert-kind">${escapeHtml(action)}</span>
          <span class="alert-level">${escapeHtml(decision)}</span>
        </div>
        <div class="alert-line">${escapeHtml(src)} → ${escapeHtml(dst)} | ${escapeHtml(tag)} = ${escapeHtml(valueText)}</div>
        ${policyLine}
      </article>
    `;
  }).join("");
}

function renderEventsPanel(events, healthEvents = []) {
  const panel = byId("eventsPanel");
  if (!panel) return;

  if (!monitorRouteEnabled) {
    panel.innerHTML = `
      <article class="comm-state-card comm-off">
        <div class="comm-state-title">Monitor is OFF</div>
        <div class="comm-state-sub">Detection disabled. No traffic inspection is being performed.</div>
      </article>
    `;
    return;
  }

  const now = Date.now() / 1000;
  const recent = Array.isArray(events) ? events : [];
  const activeFlows = new Map();
  let latestPayload = null;
  let latestLink = null;

  for (const ev of recent) {
    const ts = normalizeTsSeconds(ev?.timestamp);
    if (!ts) continue;
    if ((now - ts) > FLOW_ACTIVE_TTL_SEC) continue;
    const type = String(ev?.type || "");
    const src = String(ev?.src_ip || "-");
    const dst = String(ev?.dst_ip || "-");
    const key = `${src}->${dst}`;
    const prev = activeFlows.get(key);
    if (!prev || ts > prev.ts) {
      activeFlows.set(key, {
        ts,
        type,
        src,
        dst,
      });
    }
    if (OT_EVENT_TYPES.has(type)) {
      if (!latestPayload || ts > latestPayload.ts) latestPayload = { ts, type, src, dst };
    }
    if (LINK_EVENT_TYPES.has(type)) {
      if (!latestLink || ts > latestLink.ts) latestLink = { ts, type, src, dst };
    }
  }

  if (activeFlows.size === 0) {
    panel.innerHTML = `
      <article class="comm-state-card comm-wait">
        <div class="comm-state-title">No communication detected</div>
        <div class="comm-state-sub">No Modbus packets detected on the monitored interface.</div>
      </article>
    `;
    return;
  }

  const latest = latestPayload || latestLink;
  const ts = new Date(latest.ts * 1000).toLocaleTimeString();
  const hmiIp = uiEndpoints?.hmi?.ip || "-";
  const plcIp = uiEndpoints?.plc?.ip || "-";
  const monIp = uiEndpoints?.monitor_proxy?.ip || "-";
  const hasPayload = !!latestPayload;

  let healthHtml = "";
  if (healthEvents.length) {
    const h = healthEvents[healthEvents.length - 1];
    const hts = new Date(normalizeTsSeconds(h?.timestamp) * 1000).toLocaleTimeString();
    const htype = String(h?.type || "LINK").replaceAll("_", " ");
    const ok = htype === "LINK OPEN";
    healthHtml = `<div class="comm-state-meta">Health check: ${ok ? "reachable" : "failing"} (${escapeHtml(htype)} at ${escapeHtml(hts)})</div>`;
  }

  panel.innerHTML = `
    <article class="comm-state-card ${hasPayload ? "comm-on" : "comm-stale"}">
      <div class="comm-state-title">${hasPayload ? "Communication active" : "Connection attempt detected"}</div>
      <div class="comm-state-sub">${escapeHtml(hmiIp)} → ${escapeHtml(monIp)} → ${escapeHtml(plcIp)} (Modbus/TCP)</div>
      <div class="comm-state-meta">Active conversations (last 3s): ${activeFlows.size} | Last packet: ${escapeHtml(latest.type.replaceAll("_", " "))} at ${escapeHtml(ts)}</div>
      ${healthHtml}
    </article>
  `;
}

async function refreshLabTopology() {
  const data = await apiGet("/api/v2/lab/topology");
  const target = data?.target || {};
  if (byId("labTargetHost") && document.activeElement !== byId("labTargetHost")) byId("labTargetHost").value = target.host || "runtime";
  if (byId("labTargetPort") && document.activeElement !== byId("labTargetPort")) byId("labTargetPort").value = target.port || 15020;

  const services = data?.services || [];
  latestTopology = services;
  uiEndpoints = data?.ui_endpoints || uiEndpoints;
  latestNetworkArchitecture = data?.architecture || latestNetworkArchitecture;
  monitorRouteEnabled = !!data?.monitor_route_enabled;
  const plc = services.find((s) => s.id === "plc");
  const hmi = services.find((s) => s.id === "hmi");
  plcServiceRunning = !!(plc?.reachable && plc?.modbus_ready);
  hmiServiceRunning = !!hmi?.reachable;

  if (!services.length) {
    setHtml("labTopologyPanel", `<div class="log-item">No lab services found.</div>`);
    return;
  }

  const html = services.map((s) => {
    const extra = s.id === "plc" ? ` | Modbus: ${s.modbus_ready ? "READY" : "NOT READY"}` : "";
    const err = s.error ? ` | ${s.error}` : "";
    const merr = s.modbus_error ? ` | ${s.modbus_error}` : "";
    return `<div class="log-item"><strong>${escapeHtml(s.name)}:</strong> ${s.reachable ? "RUNNING" : "UNREACHABLE"}${escapeHtml(extra)}<br>open: <a href="${escapeHtml(s.external_url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(s.external_url)}</a>${escapeHtml(err)}${escapeHtml(merr)}</div>`;
  }).join("");
  setHtml("labTopologyPanel", html);
  renderFlowPanel();
}

function renderFlowPanel() {
  const panel = byId("flowPanel");
  if (!panel) return;
  const plc = uiEndpoints?.plc || {};
  const hmi = uiEndpoints?.hmi || {};
  const mon = uiEndpoints?.monitor_proxy || {};
  const arch = latestNetworkArchitecture || {};
  const otSubnet = String(arch.ot_subnet || "10.20.0.0/24");
  const dmzSubnet = String(arch.dmz_subnet || "10.30.0.0/24");
  const monIps = Array.isArray(arch.monitor_alias_ips) ? arch.monitor_alias_ips : [];
  const webIps = Array.isArray(arch.web_alias_ips) ? arch.web_alias_ips : [];
  const monOtIp = monIps.find((ip) => ip.startsWith("10.20.")) || monIps[0] || String(mon.ip || "-");
  const monDmzIp = monIps.find((ip) => ip.startsWith("10.30.")) || monIps[0] || String(mon.ip || "-");
  const webIp = webIps.find((ip) => ip.startsWith("10.30.")) || webIps[0] || "-";
  panel.innerHTML = `
    <div class="flow-zones ${monitorRouteEnabled ? "route-on" : "route-off"}">
      <div class="flow-zone">
        <div class="flow-zone-head">OT subnet · ${escapeHtml(otSubnet)}</div>
        <div class="flow-zone-grid">
          <div class="flow-node ${monitorRouteEnabled ? "active" : "inactive"}">
            <div class="flow-icon">🖥</div>
            <div class="flow-label">HMI</div>
            <div class="flow-meta">${escapeHtml(hmi.ip || "-")}:${escapeHtml(hmi.port || 1881)}</div>
          </div>
          <div class="flow-node ${monitorRouteEnabled ? "active" : "inactive"}">
            <div class="flow-icon">🛡</div>
            <div class="flow-label">Monitor (OT)</div>
            <div class="flow-meta">${escapeHtml(monOtIp)}:${escapeHtml(mon.port || 15020)}</div>
          </div>
          <div class="flow-node">
            <div class="flow-icon">⚙</div>
            <div class="flow-label">PLC</div>
            <div class="flow-meta">${escapeHtml(plc.ip || "-")}:${escapeHtml(plc.port || 502)}</div>
          </div>
        </div>
      </div>
      <div class="flow-zone">
        <div class="flow-zone-head">DMZ subnet · ${escapeHtml(dmzSubnet)}</div>
        <div class="flow-zone-grid flow-zone-grid-dmz">
          <div class="flow-node ${monitorRouteEnabled ? "active" : "inactive"}">
            <div class="flow-icon">🛡</div>
            <div class="flow-label">Monitor (DMZ)</div>
            <div class="flow-meta">${escapeHtml(monDmzIp)}:${escapeHtml(mon.port || 15020)}</div>
          </div>
          <div class="flow-node">
            <div class="flow-icon">🌐</div>
            <div class="flow-label">Web Platform</div>
            <div class="flow-meta">${escapeHtml(webIp)}:8000</div>
          </div>
        </div>
      </div>
      <div class="flow-routing ${monitorRouteEnabled ? "active" : "inactive"}">
        ${monitorRouteEnabled ? "OT flow: HMI → Monitor(OT) → PLC · Telemetry/API: Monitor(DMZ) → Web" : "Bypass enabled: HMI → PLC (monitor path disabled)"}
      </div>
    </div>
  `;
}

async function toggleMonitorRoute() {
  const next = !monitorRouteEnabled;
  const res = await apiPost("/api/v2/monitor/route", { enabled: next });
  if (!res?.ok) return alert(res?.error || "Failed to change monitor route.");
  monitorRouteEnabled = !!res.enabled;
  if (monitorRouteEnabled) {
    await apiPost("/api/v2/lab/target", { host: "runtime", port: 15020 });
  } else {
    await apiPost("/api/v2/lab/target", { host: "openplc", port: 502 });
  }
  await refreshAll();
}

function fillEndpointConfigWindows() {
  const plc = uiEndpoints?.plc || {};
  const hmi = uiEndpoints?.hmi || {};
  if (byId("plcIpInput")) byId("plcIpInput").value = plc.ip || "";
  if (byId("plcPortInput")) byId("plcPortInput").value = plc.port || 502;
  if (byId("plcUiUrlInput")) byId("plcUiUrlInput").value = plc.ui_url || "http://localhost:8081";
  if (byId("hmiIpInput")) byId("hmiIpInput").value = hmi.ip || "";
  if (byId("hmiPortInput")) byId("hmiPortInput").value = hmi.port || 1881;
  if (byId("hmiUiUrlInput")) byId("hmiUiUrlInput").value = hmi.ui_url || "http://localhost:1881";
}

async function savePlcConfig() {
  const payload = {
    plc: {
      ip: String(byId("plcIpInput")?.value || "").trim(),
      port: Number(byId("plcPortInput")?.value || 502),
      ui_url: String(byId("plcUiUrlInput")?.value || "").trim(),
    },
  };
  const res = await apiPost("/api/v2/ui/endpoints", payload);
  if (!res?.ok) return alert(res?.error || "Failed to save PLC configuration.");
  uiEndpoints = res.ui_endpoints || uiEndpoints;
}

async function saveHmiConfig() {
  const payload = {
    hmi: {
      ip: String(byId("hmiIpInput")?.value || "").trim(),
      port: Number(byId("hmiPortInput")?.value || 1881),
      ui_url: String(byId("hmiUiUrlInput")?.value || "").trim(),
    },
  };
  const res = await apiPost("/api/v2/ui/endpoints", payload);
  if (!res?.ok) return alert(res?.error || "Failed to save HMI configuration.");
  uiEndpoints = res.ui_endpoints || uiEndpoints;
}

function openPlcFromConfig() {
  const url = String(uiEndpoints?.plc?.ui_url || "http://localhost:8081");
  window.open(url, "_blank", "noopener,noreferrer");
}

function openHmiFromConfig() {
  const url = String(uiEndpoints?.hmi?.ui_url || "http://localhost:1881");
  window.open(url, "_blank", "noopener,noreferrer");
}

async function saveLabTarget() {
  const host = byId("labTargetHost")?.value || "runtime";
  const port = Number(byId("labTargetPort")?.value || 15020);
  const res = await apiPost("/api/v2/lab/target", { host, port });
  if (!res?.ok) return alert(res?.error || "Failed to save target.");
  await refreshLabTopology();
}

async function startOpenPlcRuntime() {
  const res = await apiPost("/api/v2/lab/openplc/start");
  if (!res?.ok) return alert(res?.error || "Failed to start OpenPLC runtime.");
  await refreshLabTopology();
}

async function runLabSmokeTest() {
  setText("labSmokePanel", "Running smoke test...");
  const res = await apiPost("/api/v2/lab/smoke-test");
  if (!res?.ok) return setText("labSmokePanel", `Smoke test failed: ${res?.error || "unknown error"}`);
  setText("labSmokePanel", `OK: ${res?.target?.host}:${res?.target?.port} HR${res?.register} write=${res?.written} read=${res?.read_back}`);
  await refreshLabTopology();
}

async function pollLabLiveRegister() {
  const res = await apiGet("/api/v2/lab/read-register?register=0&unit_id=1");
  if (!res?.ok) return setText("labLivePanel", `Read failed: ${res?.error || "unknown error"}`);
  setText("labLivePanel", `HR0 = ${Number(res?.value ?? 0)}`);
}

async function toggleLabLive() {
  const btn = byId("toggleLabLiveBtn");
  if (!btn) return;
  if (labLivePollHandle) {
    clearInterval(labLivePollHandle);
    labLivePollHandle = null;
    btn.textContent = "Start Live";
    return setText("labLivePanel", "Live polling stopped");
  }
  btn.textContent = "Stop Live";
  setText("labLivePanel", "Connecting...");
  await pollLabLiveRegister();
  labLivePollHandle = setInterval(() => pollLabLiveRegister().catch(() => {}), 1000);
}

function renderLabSwitch(value) {
  labSwitchValue = value ? 1 : 0;
  const btn = byId("toggleLabSwitchBtn");
  if (btn) {
    btn.textContent = labSwitchValue ? "ON" : "OFF";
    btn.classList.toggle("danger", !!labSwitchValue);
  }
  setText("labSwitchPanel", `COIL0 = ${labSwitchValue ? "ON" : "OFF"}`);
}

async function pollLabSwitch() {
  const res = await apiGet("/api/v2/lab/read-bool?coil=0&unit_id=1");
  if (!res?.ok) return setText("labSwitchPanel", `Read failed: ${res?.error || "unknown error"}`);
  renderLabSwitch(!!res.value);
}

async function toggleLabSwitch() {
  const res = await apiPost("/api/v2/lab/write-bool", { coil: 0, value: !labSwitchValue, unit_id: 1 });
  if (!res?.ok) return setText("labSwitchPanel", `Write failed: ${res?.error || "unknown error"}`);
  renderLabSwitch(!!res.value);
}

function populateAttackSelect(profileId) {
  const select = byId("scenarioAttackSelect");
  if (!select) return;
  const list = (cachedAttacks || []).filter((a) => String(a.profile) === String(profileId));
  select.innerHTML = "";
  list.forEach((a) => {
    const opt = document.createElement("option");
    opt.value = a.id;
    opt.textContent = `${a.name} (${a.technique})`;
    select.appendChild(opt);
  });
}

async function loadAttacks() {
  const data = await apiGet("/api/v2/attacks");
  cachedAttacks = Array.isArray(data?.attacks) ? data.attacks : [];
  populateAttackSelect(byId("scenarioProfileSelect")?.value || "tank_v1");
}

async function executeScenario(mode) {
  const profile_id = byId("scenarioProfileSelect")?.value || "tank_v1";
  const attack_id = byId("scenarioAttackSelect")?.value;
  if (!attack_id) return alert("Select an attack scenario first.");
  const result = await apiPost("/api/v2/scenarios/execute", { profile_id, attack_id, mode });
  if (!result?.ok) return alert(result?.error || "Scenario execution failed");
  const report = result.report || {};
  const impact = report.impact || {};
  setText("scenarioResultPanel", [
    `Scenario: ${report.attack_name || report.attack_id}`,
    `Mode: ${report.mode}`,
    `Technique: ${report.technique || "-"}`,
    `Blocked: ${impact.blocked_effective ?? impact.blocked ?? 0}`,
    `Would Block (protected): ${impact.would_block ?? 0}`,
    `Alerts: ${impact.alerts_effective ?? impact.warned ?? 0}`,
    `Allowed: ${impact.allowed_effective ?? impact.allowed ?? 0}`,
    `Final Level: ${impact.final_level ?? "-"}`,
    `Impact Score: ${impact.impact_score ?? "-"}`,
  ].join("\n"));
  await refreshAll();
}

async function openMonitorConfig() {
  const configRes = await apiGet("/api/agent/config");
  const modeRes = await apiGet("/api/v2/monitor/mode");
  const contextRes = await apiGet("/api/v2/monitor/context");
  const cfg = configRes?.config || {};
  if (byId("monitorOperatingMode")) byId("monitorOperatingMode").value = modeRes?.mode || "observe";
  if (byId("portModeSelect")) byId("portModeSelect").value = cfg.port_mode || "MODBUS_PORTS";
  if (byId("customPortsInput")) byId("customPortsInput").value = (cfg.custom_ports || []).join(",");
  if (byId("monitorCtxHmiIpInput")) byId("monitorCtxHmiIpInput").value = contextRes?.hmi_ip || "";
  if (byId("monitorCtxPlcIpInput")) byId("monitorCtxPlcIpInput").value = contextRes?.plc_ip || "";
  if (byId("monitorCtxMonitorIpInput")) byId("monitorCtxMonitorIpInput").value = contextRes?.monitor_ip || "";
  if (byId("monitorCtxOtSubnetInput")) byId("monitorCtxOtSubnetInput").value = contextRes?.ot_subnet || "";
  if (byId("monitorCtxDmzSubnetInput")) byId("monitorCtxDmzSubnetInput").value = contextRes?.dmz_subnet || "";
  if (contextRes?.tag_map) applyTagMap(contextRes.tag_map);
  monitorTagRows = [];
  const coils = Object.entries((contextRes?.tag_map?.coil || MODBUS_TAG_MAP.coil)).map(([k, v]) => ({ location: `%QX0.${k}`, name: String(v || "") }));
  const regs = Object.entries((contextRes?.tag_map?.register || MODBUS_TAG_MAP.register)).map(([k, v]) => ({ location: `%QW${k}`, name: String(v || "") }));
  monitorTagRows.push(...coils, ...regs);
  renderTagMapRows();
  setText("monitorConfigStatus", "");
  updateCustomPortsVisibility();
  await scanInterfaces();
}

function updateCustomPortsVisibility() {
  const mode = byId("portModeSelect")?.value || "MODBUS_PORTS";
  byId("customPortsRow")?.classList.toggle("hidden", mode !== "CUSTOM");
}

async function scanInterfaces() {
  const data = await apiGet("/api/agent/interfaces");
  const interfaces = Array.isArray(data?.interfaces) ? data.interfaces : [];
  const select = byId("ifaceSelect");
  if (!select) return;
  select.innerHTML = interfaces.map((iface) => `<option value="${escapeHtml(iface)}">${escapeHtml(iface)}</option>`).join("");
  if (!interfaces.length) setText("monitorConfigStatus", "");
}

function buildTagMapPayloadFromRows() {
  const out = { coil: {}, register: {} };
  for (const row of monitorTagRows) {
    const location = String(row.location || "").trim().toUpperCase();
    const name = String(row.name || "").trim();
    if (!location || !name) continue;
    let m = location.match(/^%QX\d+\.(\d+)$/);
    if (m) {
      out.coil[Number(m[1])] = name;
      continue;
    }
    m = location.match(/^%QW(\d+)$/);
    if (m) {
      out.register[Number(m[1])] = name;
      continue;
    }
  }
  return out;
}

function renderTagMapRows() {
  const tbody = byId("tagsMapRows");
  if (!tbody) return;
  tbody.innerHTML = monitorTagRows.map((r, idx) => `
    <tr data-tag-idx="${idx}">
      <td><input data-tag-field="location" value="${escapeHtml(String(r.location || ""))}" placeholder="%QX0.0 or %QW1" /></td>
      <td><input data-tag-field="name" value="${escapeHtml(String(r.name || ""))}" placeholder="PUMP_CMD" /></td>
      <td><button type="button" class="secondary small" data-tag-del="${idx}">✕</button></td>
    </tr>
  `).join("");
  tbody.querySelectorAll("[data-tag-field]").forEach((el) => {
    el.addEventListener("input", (e) => {
      const tr = e.target.closest("tr[data-tag-idx]");
      if (!tr) return;
      const idx = Number(tr.getAttribute("data-tag-idx"));
      const field = e.target.getAttribute("data-tag-field");
      if (!Number.isFinite(idx) || !field) return;
      monitorTagRows[idx][field] = e.target.value;
    });
  });
  tbody.querySelectorAll("[data-tag-del]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const idx = Number(btn.getAttribute("data-tag-del"));
      if (!Number.isFinite(idx)) return;
      monitorTagRows.splice(idx, 1);
      renderTagMapRows();
    });
  });
}

function parseFuxaDevicesJsonToRows(content) {
  let payload;
  try {
    payload = JSON.parse(content);
  } catch (_) {
    return [];
  }
  const rows = [];
  const devices = Array.isArray(payload) ? payload : [];
  for (const dev of devices) {
    const tags = dev?.tags && typeof dev.tags === "object" ? dev.tags : {};
    for (const tag of Object.values(tags)) {
      const mem = String(tag?.memaddress || "").trim();
      const name = String(tag?.name || "").trim();
      const type = String(tag?.type || "").trim().toLowerCase();
      const addrNum = Number(tag?.address);
      if (!mem || !name) continue;
      // Prefer explicit location if already exported in IEC format.
      if (/^%QX\d+\.\d+$/i.test(mem) || /^%QW\d+$/i.test(mem)) {
        rows.push({ location: mem.toUpperCase(), name });
        continue;
      }
      // FUXA modbus export: Bool with address 1..N usually maps to coil N-1.
      if (type.includes("bool") && Number.isFinite(addrNum) && addrNum >= 1) {
        rows.push({ location: `%QX0.${Math.floor(addrNum - 1)}`, name });
        continue;
      }
      // FUXA holding register export: memaddress 4xxxxx + address 1..N -> %QW(address-1).
      if ((/^4\d{5}$/.test(mem) || type.includes("int") || type.includes("word") || type.includes("number")) && Number.isFinite(addrNum) && addrNum >= 1) {
        rows.push({ location: `%QW${Math.floor(addrNum - 1)}`, name });
        continue;
      }
      // Last fallback: if six-digit non-4xxxx and numeric, treat as coil bit index.
      if (/^\d{6}$/.test(mem)) {
        const addr = Number(mem);
        rows.push({ location: `%QX0.${addr}`, name });
      }
    }
  }
  const uniq = new Map();
  rows.forEach((r) => {
    const key = `${r.location}|${r.name}`;
    if (!uniq.has(key)) uniq.set(key, r);
  });
  return Array.from(uniq.values());
}

async function saveMonitorAll() {
  const btn = byId("saveMonitorAllBtn");
  const payload = {
    iface: byId("ifaceSelect")?.value || "ALL",
    mode: "MONITORING",
    port_mode: byId("portModeSelect")?.value || "MODBUS_PORTS",
    custom_ports: (byId("customPortsInput")?.value || "").trim(),
  };
  const res = await apiPost("/api/agent/config", payload);
  if (!res?.ok) {
    setText("monitorConfigStatus", `Save failed: ${res?.error || "unknown error"}`);
    return;
  }
  const opMode = byId("monitorOperatingMode")?.value || "observe";
  const modeRes = await apiPost("/api/v2/monitor/mode", { mode: opMode });
  if (!modeRes?.ok) {
    setText("monitorConfigStatus", `Operating mode save failed: ${modeRes?.error || "unknown error"}`);
    return;
  }
  const plcIp = String(byId("monitorCtxPlcIpInput")?.value || "").trim();
  const proxyRes = await apiPost("/api/v2/monitor/proxy-target", { host: plcIp || "openplc", port: 502 });
  if (!proxyRes?.ok) {
    setText("monitorConfigStatus", `Save failed on destination: ${proxyRes?.error || "unknown error"}`);
    return;
  }
  const contextPayload = {
    hmi_ip: String(byId("monitorCtxHmiIpInput")?.value || "").trim(),
    plc_ip: plcIp,
    monitor_ip: String(byId("monitorCtxMonitorIpInput")?.value || "").trim(),
    ot_subnet: String(byId("monitorCtxOtSubnetInput")?.value || "").trim(),
    dmz_subnet: String(byId("monitorCtxDmzSubnetInput")?.value || "").trim(),
    tag_map: buildTagMapPayloadFromRows(),
    tag_map_use_defaults: false,
  };
  const contextRes = await apiPost("/api/v2/monitor/context", contextPayload);
  if (!contextRes?.ok) {
    setText("monitorConfigStatus", `Save failed on context: ${contextRes?.error || "unknown error"}`);
    return;
  }
  if (contextRes?.tag_map) applyTagMap(contextRes.tag_map);
  setText("monitorConfigStatus", "");
  flashButtonSaved(btn);
  await refreshAll();
}

function renderNetworkScan(hosts = [], selectedIp = null) {
  const container = byId("networkScanHosts");
  const details = byId("networkScanDetails");
  if (!container || !details) return;
  if (!hosts.length) {
    container.innerHTML = "";
    details.textContent = "No devices found.";
    return;
  }
  const roleIcon = (role) => {
    const r = String(role || "unknown").toLowerCase();
    if (r === "plc") return "⚙";
    if (r === "hmi") return "🖥";
    if (r === "monitor") return "🛡";
    return "◉";
  };

  container.innerHTML = hosts.map((h) => {
    const ip = String(h.ip || "-");
    const role = String(h.role || "unknown").toUpperCase();
    const zones = Array.isArray(h.zones) && h.zones.length ? ` · ${h.zones.join("/")}` : "";
    const up = h.reachable ? "UP" : "DOWN";
    const active = ip === selectedIp ? "active" : "";
    const ports = (h.open_ports || []).slice(0, 4).map((p) => `<span class="port-chip">${escapeHtml(String(p))}</span>`).join("");
    return `
      <button type="button" class="network-host-item ${active}" data-host-ip="${escapeHtml(ip)}">
        <div class="host-top">
          <span class="host-icon">${roleIcon(role)}</span>
          <span class="host-ip">${escapeHtml(ip)}</span>
          <span class="host-state ${h.reachable ? "up" : "down"}">${escapeHtml(up)}</span>
        </div>
        <div class="host-sub">${escapeHtml(role)}${escapeHtml(zones)}</div>
        <div class="host-ports">${ports || '<span class="host-ports-empty">No open OT ports</span>'}</div>
      </button>
    `;
  }).join("");
  container.querySelectorAll("[data-host-ip]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const ip = btn.getAttribute("data-host-ip");
      selectedNetworkHostIp = ip;
      renderNetworkScan(latestNetworkHosts, selectedNetworkHostIp);
    });
  });
  if (!selectedIp) return;
  const selected = hosts.find((h) => String(h.ip) === String(selectedIp)) || hosts[0];
  selectedNetworkHostIp = String(selected.ip);
  const ports = (selected.open_ports || []).map((p) => String(p)).join(", ") || "none";
  details.textContent = `Selected: ${selected.ip} | ${String(selected.role || "unknown").toUpperCase()} | ${selected.reachable ? "UP" : "DOWN"} | Ports: ${ports}`;
}

function renderNetworkArchitecture(arch) {
  const panel = byId("networkArchitecturePanel");
  if (!panel) return;
  if (!arch) {
    panel.innerHTML = `
      <div class="network-arch-title">Architecture</div>
      <div class="network-arch-line">OT subnet: -</div>
      <div class="network-arch-line">DMZ subnet: -</div>
      <div class="network-arch-line">Monitor interfaces: -</div>
    `;
    return;
  }
  const monitorIps = Array.isArray(arch.monitor_alias_ips) && arch.monitor_alias_ips.length
    ? arch.monitor_alias_ips.join(", ")
    : "-";
  panel.innerHTML = `
    <div class="network-arch-title">Architecture (OT + DMZ)</div>
    <div class="network-arch-line">OT subnet: ${escapeHtml(String(arch.ot_subnet || "-"))}</div>
    <div class="network-arch-line">DMZ subnet: ${escapeHtml(String(arch.dmz_subnet || "-"))}</div>
    <div class="network-arch-line">Monitor interfaces: ${escapeHtml(monitorIps)}</div>
  `;
}

async function scanNetwork() {
  setText("networkScanDetails", "Scanning...");
  const data = await apiGet("/api/v2/network/scan");
  if (!data?.ok) {
    setText("networkScanDetails", `Scan failed: ${data?.error || "unknown error"}`);
    return;
  }
  const hosts = Array.isArray(data?.hosts) ? data.hosts : [];
  latestNetworkArchitecture = data?.architecture || null;
  latestNetworkHosts = hosts;
  selectedNetworkHostIp = null;
  setText("networkScanDetails", `Scan complete: ${hosts.length} device(s) found.`);
  renderNetworkArchitecture(latestNetworkArchitecture);
  renderNetworkScan(hosts, selectedNetworkHostIp);
}

function normalizePolicyDecisionEntry(entry) {
  const ts = normalizeTsSeconds(entry?.timestamp);
  return {
    timestamp: ts,
    timeText: ts ? new Date(ts * 1000).toLocaleTimeString() : "-",
    decision: String(entry?.decision || "EVENT").toUpperCase(),
    ruleId: String(entry?.rule_id || "-"),
    ruleName: String(entry?.rule_name || ""),
    asset: String(entry?.asset || entry?.address || "-"),
    value: entry?.value === null || entry?.value === undefined ? "-" : String(entry.value),
    reason: String(entry?.reason || ""),
    severity: String(entry?.severity || ""),
    actor: String(entry?.actor || "-"),
    target: String(entry?.target || "-"),
    actionType: String(entry?.action_type || "-"),
    protocol: String(entry?.protocol || "-"),
    raw: entry,
  };
}

function renderPolicyDecisions(entries) {
  const tbody = byId("policyDecisionRows");
  const summary = byId("policyDecisionSummary");
  if (!tbody || !summary) return;
  const rows = (Array.isArray(entries) ? entries : [])
    .map(normalizePolicyDecisionEntry)
    .sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
  latestPolicyDecisionRows = rows;
  const counts = rows.reduce((acc, row) => {
    acc[row.decision] = (acc[row.decision] || 0) + 1;
    return acc;
  }, {});
  summary.innerHTML = rows.length
    ? `Decisions: <strong>${rows.length}</strong> · ALLOW: <strong>${counts.ALLOW || 0}</strong> · ALERT: <strong>${counts.ALERT || 0}</strong> · BLOCK: <strong>${counts.BLOCK || 0}</strong>`
    : "No policy decisions recorded yet.";
  latestPolicyDecisionClipboardText = rows.map((row) => [
    row.timeText,
    row.decision,
    row.ruleId,
    row.asset,
    row.value,
    row.actor,
    row.target,
    row.reason,
  ].join(" | ")).join("\n");
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="6" class="policy-empty">No policy decisions recorded yet.</td></tr>`;
    return;
  }
  tbody.innerHTML = rows.slice(0, 80).map((row) => `
    <tr class="policy-row policy-row-${escapeHtml(row.decision.toLowerCase())}">
      <td>${escapeHtml(row.timeText)}</td>
      <td><span class="policy-pill">${escapeHtml(row.decision)}</span></td>
      <td>
        <div class="policy-rule-id">${escapeHtml(row.ruleId)}</div>
        <div class="policy-rule-name">${escapeHtml(row.ruleName)}</div>
      </td>
      <td>
        <div class="policy-asset">${escapeHtml(row.asset)}</div>
        <div class="policy-action">${escapeHtml(row.actionType)}</div>
      </td>
      <td>${escapeHtml(row.value)}</td>
      <td>${escapeHtml(row.reason)}</td>
    </tr>
  `).join("");
}

async function refreshPolicyDecisions(button = null) {
  const data = await apiGet("/api/v2/policy-decisions");
  renderPolicyDecisions(Array.isArray(data?.entries) ? data.entries : []);
  if (button) flashButtonSaved(button, "Updated", 900);
}

async function copyPolicyDecisions() {
  if (!latestPolicyDecisionRows.length) await refreshPolicyDecisions();
  const btn = byId("copyPolicyDecisionsBtn");
  const text = String(latestPolicyDecisionClipboardText || "").trim();
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
  } catch (_) {
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
  }
  flashButtonSaved(btn, "Copied", 1200);
}

async function exportPolicyDecisions() {
  const btn = byId("exportPolicyDecisionsBtn");
  const data = await apiPost("/api/v2/policy-decisions/export");
  const payload = data?.export || { entries: latestPolicyDecisionRows.map((r) => r.raw) };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  a.href = url;
  a.download = `otlab-policy-decisions-${stamp}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  flashButtonSaved(btn, "Exported", 1200);
}

async function refreshAll() {
  await refreshLabTopology();
  await Promise.all([refreshStatus(), refreshEvents()]);
}

loadPinnedSessionId();

window.addEventListener("DOMContentLoaded", () => {
  byId("saveMonitorAllBtn")?.addEventListener("click", () => saveMonitorAll().catch(console.error));
  byId("runNetworkScanBtn")?.addEventListener("click", () => scanNetwork().catch(console.error));
  byId("scanIfacesBtn")?.addEventListener("click", () => scanInterfaces().catch(console.error));
  byId("portModeSelect")?.addEventListener("change", updateCustomPortsVisibility);
  byId("openTagsMapBtn")?.addEventListener("click", () => toggleQuickConfigWindow("tagsMapWindow", "openTagsMapBtn"));
  byId("addTagMapRowBtn")?.addEventListener("click", () => {
    monitorTagRows.push({ location: "", name: "" });
    renderTagMapRows();
  });
  byId("saveTagMapBtn")?.addEventListener("click", async () => {
    const btn = byId("saveTagMapBtn");
    const payload = { tag_map: buildTagMapPayloadFromRows(), tag_map_use_defaults: false };
    const res = await apiPost("/api/v2/monitor/context", payload);
    if (!res?.ok) return;
    if (res?.tag_map) applyTagMap(res.tag_map);
    setText("tagsMapStatus", "");
    setText("monitorConfigStatus", "");
    flashButtonSaved(btn);
    await refreshEvents();
  });
  byId("uploadTagsJsonBtn")?.addEventListener("click", () => byId("tagsJsonInput")?.click());
  byId("tagsJsonInput")?.addEventListener("change", async (e) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    const txt = await file.text();
    const rows = parseFuxaDevicesJsonToRows(txt);
    if (!rows.length) {
      setText("tagsMapStatus", "");
      return;
    }
    monitorTagRows = rows;
    renderTagMapRows();
    setText("tagsMapStatus", "");
  });
  byId("saveLabTargetBtn")?.addEventListener("click", () => saveLabTarget().catch(console.error));
  byId("startOpenPlcBtn")?.addEventListener("click", () => startOpenPlcRuntime().catch(console.error));
  byId("runLabSmokeBtn")?.addEventListener("click", () => runLabSmokeTest().catch(console.error));
  byId("toggleLabLiveBtn")?.addEventListener("click", () => toggleLabLive().catch(console.error));
  byId("toggleLabSwitchBtn")?.addEventListener("click", () => toggleLabSwitch().catch(console.error));

  byId("scenarioProfileSelect")?.addEventListener("change", (e) => populateAttackSelect(e.target.value || "tank_v1"));
  byId("runBaselineScenarioBtn")?.addEventListener("click", () => executeScenario("baseline").catch(console.error));
  byId("runProtectedScenarioBtn")?.addEventListener("click", () => executeScenario("protected").catch(console.error));

  byId("clearAlertsBtn")?.addEventListener("click", async () => {
    await apiPost("/api/alerts/clear");
    await refreshEvents();
  });
  byId("copyAlertsBtn")?.addEventListener("click", async () => {
    const btn = byId("copyAlertsBtn");
    const text = String(latestAlertsClipboardText || "").trim();
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
    } catch (_) {
      const ta = document.createElement("textarea");
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
    }
    if (btn) {
      const prev = btn.textContent;
      btn.textContent = "Copied";
      setTimeout(() => { btn.textContent = prev || "Copy Log"; }, 1200);
    }
  });

  byId("openPlcUrlBtn")?.addEventListener("click", () => {
    toggleQuickConfigWindow("plcConfigWindow", "openPlcUrlBtn", fillEndpointConfigWindows);
  });
  byId("openHmiUrlBtn")?.addEventListener("click", () => {
    toggleQuickConfigWindow("hmiConfigWindow", "openHmiUrlBtn", fillEndpointConfigWindows);
  });
  byId("openMonitorConfigBtn")?.addEventListener("click", () => {
    toggleQuickConfigWindow("monitorConfigWindow", "openMonitorConfigBtn", () => openMonitorConfig().catch(console.error));
  });
  byId("openAttackBtn")?.addEventListener("click", () => {
    toggleQuickConfigWindow("scenarioWindow", "openAttackBtn");
  });
  byId("openNetworkScanBtn")?.addEventListener("click", () => {
    toggleQuickConfigWindow("networkScanWindow", "openNetworkScanBtn", () => {
      renderNetworkArchitecture(latestNetworkArchitecture);
      renderNetworkScan(latestNetworkHosts, selectedNetworkHostIp);
    });
  });
  byId("openPolicyDecisionsBtn")?.addEventListener("click", () => {
    toggleQuickConfigWindow("policyDecisionsWindow", "openPolicyDecisionsBtn", () => {
      refreshPolicyDecisions().catch(console.error);
    });
  });
  byId("refreshPolicyDecisionsBtn")?.addEventListener("click", (e) => refreshPolicyDecisions(e.currentTarget).catch(console.error));
  byId("copyPolicyDecisionsBtn")?.addEventListener("click", () => copyPolicyDecisions().catch(console.error));
  byId("exportPolicyDecisionsBtn")?.addEventListener("click", () => exportPolicyDecisions().catch(console.error));
  byId("savePlcConfigBtn")?.addEventListener("click", () => savePlcConfig().catch(console.error));
  byId("saveHmiConfigBtn")?.addEventListener("click", () => saveHmiConfig().catch(console.error));
  byId("openPlcFromConfigBtn")?.addEventListener("click", () => openPlcFromConfig());
  byId("openHmiFromConfigBtn")?.addEventListener("click", () => openHmiFromConfig());
  byId("toggleMonitorRouteBtn")?.addEventListener("click", () => toggleMonitorRoute().catch(console.error));
  

  document.querySelectorAll("[data-close]").forEach((btn) => {
    btn.addEventListener("click", () => closeModal(btn.dataset.close));
  });
  document.querySelectorAll("[data-close-window]").forEach((btn) => {
    btn.addEventListener("click", () => closeWindow(btn.dataset.closeWindow));
  });
  document.querySelectorAll(".modal").forEach((modal) => {
    modal.addEventListener("click", (e) => {
      if (e.target === modal) modal.classList.add("hidden");
    });
  });

  enableWindowDragging();
  loadAttacks().catch(console.error);
  // Do not generate synthetic background OT traffic from the web UI by default.
  refreshAll().catch(console.error);
  setInterval(() => refreshStatus().catch(() => {}), 1000);
  setInterval(() => refreshEvents().catch(() => {}), 1000);
  setInterval(() => refreshLabTopology().catch(() => {}), 2000);
});
