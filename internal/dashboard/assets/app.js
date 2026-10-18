"use strict";
/*
 * NetMerge Control Center dashboard.
 *
 * One rule shapes this file: it renders whatever the server says, including when the server says
 * "unknown". Nothing here synthesises a value, and every placeholder for a missing fact stays
 * visibly missing. Long operations (diagnostics runs, exports) are started as jobs and polled,
 * so no button ever freezes the page.
 */

const TOKEN = window.NETMERGE_TOKEN || "";
const HDR = "X-NetMerge-Token";

/* ---------- tiny DOM helpers (no innerHTML anywhere) ---------- */

const $ = (sel, root) => (root || document).querySelector(sel);

function h(tag, attrs) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") e.className = v;
    else if (k.startsWith("on") && typeof v === "function") e.addEventListener(k.slice(2), v);
    else if (k === "checked" || k === "disabled" || k === "selected" || k === "value") e[k] = v;
    else e.setAttribute(k, v === true ? "" : String(v));
  }
  for (let i = 2; i < arguments.length; i++) addKid(e, arguments[i]);
  return e;
}

function addKid(e, kid) {
  if (kid === null || kid === undefined || kid === false) return;
  if (Array.isArray(kid)) { kid.forEach((k) => addKid(e, k)); return; }
  e.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
}

function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

/* ---------- formatting ---------- */

const UNKNOWN = "unknown";

function rate(v) {
  if (v === null || v === undefined) return "—";
  const bps = Number(v);
  if (!isFinite(bps)) return "—";
  if (bps >= 1e9) return (bps / 1e9).toFixed(2) + " Gbit/s";
  if (bps >= 1e6) return (bps / 1e6).toFixed(1) + " Mbit/s";
  if (bps >= 1e3) return (bps / 1e3).toFixed(1) + " kbit/s";
  return bps.toFixed(0) + " bit/s";
}

function bytes(v) {
  if (v === null || v === undefined) return "—";
  const n = Number(v);
  if (!isFinite(n)) return "—";
  const u = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0, x = n;
  while (x >= 1024 && i < u.length - 1) { x /= 1024; i++; }
  return x.toFixed(i === 0 ? 0 : 1) + " " + u[i];
}

function clock(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d)) return String(iso);
  return d.toLocaleTimeString();
}

function stamp(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d)) return String(iso);
  return d.toLocaleString();
}

function dur(ms) {
  if (ms === null || ms === undefined) return "—";
  const s = Number(ms) / 1000;
  if (s < 1) return (s * 1000).toFixed(0) + " ms";
  if (s < 60) return s.toFixed(1) + " s";
  return Math.floor(s / 60) + "m " + (s % 60).toFixed(0) + "s";
}

/* Go marshals time.Duration as an integer number of nanoseconds, so anything that came out of a
   Go struct goes through here rather than through dur(), which takes milliseconds. */
function goDur(ns) {
  if (ns === null || ns === undefined) return "—";
  return dur(Number(ns) / 1e6);
}

function list(v) {
  if (!v || !v.length) return "—";
  return v.join(", ");
}

function val(v, suffix) {
  if (v === null || v === undefined || v === "") return "—";
  return v + (suffix || "");
}

/* ---------- api ---------- */

async function api(path, opts) {
  opts = opts || {};
  const res = await fetch(path, {
    method: opts.method || "GET",
    headers: Object.assign({ [HDR]: TOKEN }, opts.body ? { "Content-Type": "application/json" } : {}),
    body: opts.body ? JSON.stringify(opts.body) : undefined,
    cache: "no-store",
  });
  let payload = null;
  try { payload = await res.json(); } catch (e) { /* not JSON */ }
  if (!res.ok || !payload || payload.ok !== true) {
    const err = (payload && payload.error) || { code: "http_" + res.status, message: res.statusText || "request failed" };
    const e = new Error(err.message);
    e.code = err.code;
    e.details = err.details;
    throw e;
  }
  return payload.data;
}

function toast(kind, message, details, code) {
  const box = $("#toast");
  const info = code ? codeInfo(code) : null;
  const n = h("div", { class: "notice " + kind, onclick: () => n.remove() },
    code ? h("div", { class: "small mono dim" }, code) : null,
    h("strong", null, message),
    info ? h("div", { class: "small", style: "margin-top:4px" }, info.meaning) : null,
    info && info.fix ? h("div", { class: "small dim", style: "margin-top:4px" }, info.fix) : null,
    details ? h("div", { class: "small mono", style: "margin-top:4px" }, typeof details === "string" ? details : JSON.stringify(details, null, 2)) : null,
    h("div", { class: "row", style: "margin-top:6px" },
      h("button", {
        class: "btn secondary small", onclick: (ev) => {
          ev.stopPropagation();
          const body = ["code: " + (code || "(none)"), "message: " + message,
            info ? "meaning: " + info.meaning : "", info && info.fix ? "next step: " + info.fix : "",
            details ? "details: " + (typeof details === "string" ? details : JSON.stringify(details)) : ""].filter(Boolean).join("\n");
          navigator.clipboard.writeText(body).then(() => toast("ok", "Error details copied."), () => toast("warn", "Clipboard access was refused by the browser."));
        }
      }, "Copy error details"),
      h("span", { class: "small dim", style: "margin-left:8px" }, "click to dismiss")));
  box.append(n);
  setTimeout(() => n.remove(), 12000);
}

async function guard(fn, busy) {
  if (busy) busy.disabled = true;
  try { return await fn(); }
  catch (e) { toast("bad", e.message || "request failed", e.details ? JSON.stringify(e.details) : null, e.code); }
  finally { if (busy) busy.disabled = false; }
}

/* The application's error-code registry, so a code is never left unexplained. Loaded once at
   startup; until it arrives, toasts simply show the code without the prose. */
let codeRegistry = null;
function codeInfo(code) { return codeRegistry ? codeRegistry[code] : null; }
async function loadCodeRegistry() {
  try {
    const d = await api("/api/errcodes");
    codeRegistry = {};
    (d.codes || []).forEach((e) => { codeRegistry[e.code] = e; });
  } catch (e) { /* the dashboard works without it; only the prose is missing */ }
}

/* ---------- shared state ---------- */

let state = null;
let settingsView = null;
let ttlReport = null;
let openAdapters = new Set();
let logCursor = 0;
let logTimer = null;
let lastDiag = null;
let lastExport = null;
let exportJobId = null;
let diagJobId = null;

const STATUS_CLASS = { pass: "ok", warn: "warn", fail: "bad", error: "bad", skipped: "skip", info: "info" };
function tag(status) {
  const cls = STATUS_CLASS[status] || "info";
  return h("span", { class: "tag " + cls }, status || UNKNOWN);
}

/* ================= views ================= */

function showView(name) {
  document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
  document.querySelectorAll("#nav button").forEach((b) => b.classList.toggle("active", b.dataset.view === name));
  const view = $("#view-" + name);
  if (view) view.classList.add("active");
  if (name === "ttl" && !ttlReport) loadTTL();
  if (name === "diag") { ensureChecks(); }
  if (name === "logs") startLogs(); else stopLogs();
  if (name === "settings") loadSettings();
  if (name === "connections" || name === "routing" || name === "overview") renderAll();
}

/* ---------- overview ---------- */

function renderBadge() {
  const b = $("#engineBadge");
  clear(b);
  const on = state && state.engineOn;
  const st = state && state.engine;
  b.append(
    h("span", { class: "tag " + (on ? "ok" : "skip") }, on ? "engine ON" : "engine OFF"),
    h("span", { class: "small dim" }, st && st.mode ? st.mode : (on ? "" : "idle")));
}

function renderOverview() {
  const cards = $("#ovCards");
  clear(cards);
  const snap = state && state.snapshot;

  const inTot = snap ? snap.inPerSecTotal : null;
  const outTot = snap ? snap.outPerSecTotal : null;
  cards.append(
    card("Aggregate throughput", (rate(inTot) + " ↓ / " + rate(outTot) + " ↑"), "sum of measured per-link rates"),
    card("Links", snap ? String(snap.adapters ? snap.adapters.length : 0) : "—",
      snap ? (eligibleCount(snap) + " eligible") : "no snapshot yet"),
    card("Link speed total", snap && snap.linkSpeedTotalBps ? rate(snap.linkSpeedTotalBps) : "—",
      "negotiated speed, not throughput"),
    card("Engine", state && state.engineOn ? "ON" : "OFF",
      state && state.engine && state.engine.v6 ? "IPv6: " + state.engine.v6 : ""),
  );

  const warnings = $("#ovWarnings");
  clear(warnings);
  if (!state) return;
  if (state.collecting) {
    warnings.append(h("div", { class: "notice info" }, "The monitor has not completed its first adapter read yet."));
  }
  if (state.collectError) {
    warnings.append(h("div", { class: "notice bad" }, "The last adapter snapshot failed: " + state.collectError,
      h("div", { class: "small dim" }, "The view below is from the previous successful read.")));
  }
  if (snap) {
    (snap.warnings || []).forEach((w) => warnings.append(h("div", { class: "notice warn" }, w)));
    (snap.errors || []).forEach((w) => warnings.append(h("div", { class: "notice bad" }, w)));
    (snap.gaps || []).forEach((w) => warnings.append(h("div", { class: "notice info" }, w)));
  }

  const links = $("#ovLinks");
  clear(links);
  if (!snap || !snap.adapters || !snap.adapters.length) {
    links.append(h("div", { class: "dim" }, "No adapters in the current snapshot."));
  } else {
    links.append(linkTable(snap.adapters, false));
  }

  const eng = $("#ovEngine");
  clear(eng);
  eng.append(engineBlock());
}

function eligibleCount(snap) {
  return (snap.adapters || []).filter((a) => !a.exclusionCode).length;
}

function card(k, v, sub) {
  return h("div", { class: "card" },
    h("div", { class: "k" }, k),
    h("div", { class: "v" }, v, sub ? h("small", null, " " + sub) : null));
}

function linkTable(adapters, detailed) {
  const head = detailed
    ? ["Adapter", "Kind", "Status", "Link", "Engine", "Down", "Up", "Speed", "Exclusion"]
    : ["Adapter", "Kind", "Status", "Link", "Engine", "Down", "Up", "Exclusion"];
  const t = h("table", null, h("thead", null, h("tr", null, head.map((c, i) => h("th", { class: i >= 5 && i <= 8 ? "num" : "" }, c))))); 
  const body = h("tbody");
  adapters.forEach((a) => {
    const r = a.rates || {};
    body.append(h("tr", null,
      h("td", null, h("strong", null, a.name), a.description ? h("div", { class: "small dim" }, a.description) : null),
      h("td", null, a.kind || UNKNOWN),
      h("td", null, h("span", { class: "tag " + (a.status === "active" ? "ok" : a.status === "eligible" ? "info" : a.status === "unhealthy" ? "warn" : "skip") }, a.status || UNKNOWN)),
      h("td", null, a.link || UNKNOWN),
      h("td", null, a.engine ? h("span", { class: "tag ok" }, "in use") : h("span", { class: "dim small" }, "not used")),
      h("td", { class: "num" }, rate(r.inPerSec)),
      h("td", { class: "num" }, rate(r.outPerSec)),
      detailed ? h("td", { class: "num" }, a.speedBps ? rate(a.speedBps) : "—") : null,
      h("td", null, a.exclusionCode
        ? h("div", null, h("span", { class: "tag warn" }, a.exclusionCode), h("div", { class: "small dim" }, a.exclusion || ""))
        : h("span", { class: "tag ok" }, "eligible"))));
  });
  t.append(body);
  return t;
}

function engineBlock() {
  const wrap = h("div");
  if (!state || !state.engineOn) {
    wrap.append(
      h("div", { class: "dim" }, "The engine is off. Routes are normal: nothing is aggregated, and the adapter controls are idle."),
      h("div", { class: "row spread" },
        h("button", { class: "btn", onclick: (e) => engineAction("on", e.target) }, "Turn engine ON"),
        h("span", { class: "small dim" }, "Turning it on needs administrator rights; the engine will ask for elevation itself.")),
    );
    return wrap;
  }
  const st = state.engine;
  wrap.append(h("div", { class: "row spread" },
    h("div", null,
      h("div", null, "Mode: ", h("strong", null, st.mode || UNKNOWN), " · IPv6: ", st.v6 || UNKNOWN,
        " · pid ", st.pid, " · up ", st.since ? dur(Date.now() - Date.parse(st.since)) : "—"),
      h("div", { class: "small dim" }, "Status written by the engine at ", stamp(st.updated), ".")),
    h("button", { class: "btn danger", onclick: (e) => engineAction("off", e.target) }, "Turn engine OFF")));
  if (st.nics && st.nics.length) {
    const t = h("table", { class: "mt" }, h("thead", null, h("tr", null,
      ["Link", "State4", "State6", "Link ↓", "Link ↑", "via net-merge", "active", "total", "weight", "failed"].map((c, i) => h("th", { class: i >= 3 ? "num" : "" }, c)))));
    const body = h("tbody");
    st.nics.forEach((n) => body.append(h("tr", null,
      h("td", null, n.name, n.present === false ? h("span", { class: "tag warn" }, " gone") : null),
      h("td", null, n.state || "—"), h("td", null, n.state6 || "—"),
      h("td", { class: "num" }, rate((n.linkIn || 0) * 8)),
      h("td", { class: "num" }, rate((n.linkOut || 0) * 8)),
      h("td", { class: "num" }, rate(((n.rateIn || 0) + (n.rateOut || 0)) * 8)),
      h("td", { class: "num" }, n.active), h("td", { class: "num" }, n.total),
      h("td", { class: "num" }, (n.weight !== undefined ? n.weight : "—") + " / " + (n.weight6 !== undefined ? n.weight6 : "—")),
      h("td", { class: "num" }, n.failed))));
    t.append(body);
    wrap.append(t);
    wrap.append(h("div", { class: "small dim mt" },
      "\"Link\" is the adapter's total traffic read from the OS counters, including apps that bypass net-merge. \"via net-merge\" is the part the engine relayed."));
  }
  return wrap;
}

async function engineAction(action, btn) {
  if (action !== "on" && !confirm("Turn the bonding engine " + action.toUpperCase() + "? Existing connections are routed back to normal networking.")) return;
  await guard(async () => {
    await api("/api/engine", { method: "POST", body: { action } });
    toast("ok", "Engine " + (action === "on" ? "starting" : action === "quit" ? "quitting" : "stopping") + ".");
    await pollStateOnce();
  }, btn);
}

/* ---------- connections ---------- */

function renderConnections() {
  const body = $("#connBody");
  const snap = state && state.snapshot;
  const count = $("#connCount");
  const mon = state && state.monitor;
  clear(body);
  if (!snap) { clear(count); count.textContent = "No snapshot yet."; body.append(h("div", { class: "notice info" }, "Waiting for the first adapter read.")); return; }
  count.textContent = snap.adapters.length + " adapters · snapshot from " + stamp(snap.taken) + " · source " + (snap.source || UNKNOWN);
  if (mon) {
    count.textContent += mon.enabled
      ? " · reachability probe to " + (mon.endpoint || UNKNOWN) + " every " + dur(mon.intervalMs)
      : " · reachability probe off";
  }
  if (mon && !mon.enabled) {
    body.append(h("div", { class: "notice info" },
      "The reachability probe is off (dashboard.healthIntervalMs is negative in settings). ",
      h("strong", null, "“not tested” below means exactly that"), " — nothing here is a claim that a link does or does not work."));
  }
  snap.adapters.forEach((a) => body.append(adapterCard(a)));
}

// monitorLink finds the reachability monitor's view of one adapter, which carries the state
// the per-adapter health snapshot does not: since when, and how many changes it has seen.
function monitorLink(name) {
  const links = (state && state.monitor && state.monitor.links) || [];
  for (let i = 0; i < links.length; i++) if (links[i].name === name) return links[i];
  return null;
}

// healthText renders one adapter's reachability. Every part that is unknown is said to be
// unknown; an untested adapter never renders as a healthy one.
function healthText(a) {
  const link = monitorLink(a.name);
  const parts = [];
  if (link) {
    parts.push(link.state === "reachable" ? "reachable"
      : link.state === "unreachable" ? "not answering"
      : link.state === "absent" ? "gone from the last check"
      : "not checked yet");
  } else if (a.health) {
    parts.push(a.health.ok ? "reachable" : "did not answer");
  }
  if (a.health) {
    if (a.health.rttMs) parts.push(a.health.rttMs.toFixed(1) + " ms");
    if (a.health.lossPct) parts.push("loss " + a.health.lossPct.toFixed(0) + "% in the recent window");
    if (a.health.jitterMs) parts.push("jitter " + a.health.jitterMs.toFixed(1) + " ms");
    if (a.health.endpoint) parts.push("via " + a.health.endpoint);
    if (a.health.detail) parts.push(a.health.detail);
    if (a.health.at) parts.push("at " + stamp(a.health.at));
  }
  if (link && link.changes) parts.push("state changed " + link.changes + "× — last " + stamp(link.since));
  return parts.length ? parts.join(" · ") : "— not tested";
}

function adapterCard(a) {
  const open = openAdapters.has(a.name);
  const det = h("details", open ? { open: true } : {},
    h("summary", null,
      h("strong", null, a.name), " ",
      h("span", { class: "tag " + (a.status === "active" ? "ok" : a.status === "eligible" ? "info" : a.status === "unhealthy" ? "warn" : "skip") }, a.status || UNKNOWN),
      a.exclusionCode ? h("span", { class: "tag warn", style: "margin-left:6px" }, a.exclusionCode) : null,
      a.engine ? h("span", { class: "tag ok", style: "margin-left:6px" }, "engine") : null),
    h("div", { class: "small", style: "margin:8px 0 0" }));

  det.addEventListener("toggle", () => {
    if (det.open) openAdapters.add(a.name); else openAdapters.delete(a.name);
  });

  const grid = det.lastChild;
  const rows = [
    ["Interface GUID", a.guid || "— (this platform has no per-interface GUID)"],
    ["Interface index", "IPv4 " + a.index + (a.indexV6 ? " · IPv6 " + a.indexV6 : "")],
    ["Alias / description", (a.ifAlias || "—") + " · " + (a.description || "—")],
    ["Kind", (a.kind || UNKNOWN) + (a.hardware === false ? " (virtual: " + (a.virtualReason || "marked virtual") + ")" : "")],
    ["Operational state", (a.status || UNKNOWN) + " · admin " + (a.admin || UNKNOWN) + " · media " + (a.media || UNKNOWN)],
    ["Media / link speed", (a.mediaType || "—") + " · " + (a.speedBps ? rate(a.speedBps) : "speed unknown")],
    ["MAC", a.mac || "—"],
    ["MTU", val(a.mtu) + (a.mtu4 || a.mtu6 ? " (v4 " + (a.mtu4 || "—") + ", v6 " + (a.mtu6 || "—") + ")" : "")],
    ["IPv4", addrList(a.ipv4)],
    ["IPv6", addrList(a.ipv6)],
    ["Default gateways", "v4: " + list(a.gateways4) + " · v6: " + list(a.gateways6)],
    ["Default route", (a.defaultRoute4 ? "v4 yes" : "v4 none") + " · " + (a.defaultRoute6 ? "v6 yes" : "v6 none")],
    ["DNS", "v4: " + list(a.dns4) + " · v6: " + list(a.dns6)],
    ["DHCP", "v4: " + tri(a.dhcp4) + " · v6: " + tri(a.dhcp6)],
    ["Interface metric", "v4: " + ival(a.metric4) + " · v6: " + ival(a.metric6)],
    ["Routes", (a.routeCount || (a.routes || []).length) + " in the table" + (a.defaultRoutes && a.defaultRoutes.length ? " · " + a.defaultRoutes.length + " default" : "")],
    ["Counters", a.counters ? ("received " + bytes(a.counters.in) + " · sent " + bytes(a.counters.out)) : "— not available on this platform"],
    ["Rates", a.rates ? (rate(a.rates.inPerSec) + " ↓ / " + rate(a.rates.outPerSec) + " ↑ over " + (a.rates.spanSeconds ? a.rates.spanSeconds.toFixed(1) + "s" : "one interval")) : "— no rate yet (this is not zero: it means the counters have not been observed twice)"],
    ["Health probe", healthText(a)],
    ["Engine use", a.engine ? "yes" : "no" + (a.exclusionCode ? " (excluded)" : "")],
    ["Connections assigned by engine", a.engineAssigned === null || a.engineAssigned === undefined ? "— the engine does not report this" : String(a.engineAssigned)],
  ];
  const t = h("table");
  rows.forEach(([k, v]) => t.append(h("tr", null, h("td", { class: "dim", style: "width:210px" }, k), h("td", null, v))));
  grid.append(t);

  if (a.exclusion || a.exclusionCode) {
    grid.append(h("div", { class: "notice warn" }, h("strong", null, "Excluded: " + (a.exclusionCode || "")), " ", a.exclusion || ""));
  }
  if (a.gaps && a.gaps.length) grid.append(h("div", { class: "notice info" }, h("strong", null, "Not known for this adapter: "), a.gaps.join("; ")));
  if (a.warnings && a.warnings.length) grid.append(h("div", { class: "notice warn" }, h("strong", null, "Warnings: "), a.warnings.join("; ")));
  if (a.defaultRoutes && a.defaultRoutes.length) {
    const rt = h("table", { class: "mt" }, h("thead", null, h("tr", null, ["Destination", "Gateway", "Metric", "Family"].map((c) => h("th", null, c)))));
    const rb = h("tbody");
    a.defaultRoutes.forEach((r) => rb.append(h("tr", null, h("td", null, r.destination), h("td", null, r.gateway || "on-link"), h("td", null, ival(r.metric)), h("td", null, r.family || ""))));
    rt.append(rb);
    grid.append(h("div", { class: "small dim mt" }, "Default routes"), rt);
  }
  return h("div", { class: "panel" }, det);
}

function addrList(addrs) {
  if (!addrs || !addrs.length) return "—";
  return addrs.map((a) => a.address + "/" + a.prefix + (a.tentative ? " (tentative)" : "") + (a.origin ? " [" + a.origin + "]" : "")).join(", ");
}
function tri(v) {
  if (v === true) return "yes";
  if (v === false) return "no";
  return "not known";
}
function ival(v) { return v === null || v === undefined ? "—" : String(v); }

/* ---------- routing ---------- */

function renderRouting() {
  const prof = $("#routeProfile");
  clear(prof);
  const cfg = state && state.settings;
  if (!cfg) { prof.append(h("div", { class: "dim" }, "Settings are not readable, so the active profile is unknown.")); }
  else {
    const p = (cfg.profiles || {})[cfg.activeProfile];
    if (!p) {
      prof.append(h("div", { class: "notice warn" }, "The active profile id \"" + cfg.activeProfile + "\" is not among the stored profiles."));
    } else {
      prof.append(h("div", null,
        h("h4", { style: "margin:0 0 4px" }, p.name, " ", h("span", { class: "tag info" }, p.id)),
        h("div", { class: "dim small" }, p.description || "")));
      const t = h("table", { class: "mt" });
      const e = p.engine || {};
      t.append(h("tr", null, h("td", { class: "dim" }, "Requested engine flags"), h("td", { class: "mono" }, requestedFlags(p))));
      t.append(h("tr", null, h("td", { class: "dim" }, "Include / exclude"), h("td", null, list(e.include) + " / " + list(e.exclude))));
      t.append(h("tr", null, h("td", { class: "dim" }, "Weights"), h("td", null, weightText(e.weights))));
      t.append(h("tr", null, h("td", { class: "dim" }, "IPv6 mode"), h("td", null, e.ipv6 || "auto")));
      t.append(h("tr", null, h("td", { class: "dim" }, "Monitor"), h("td", null,
        "latency budget " + (p.monitor && p.monitor.latencyBudgetMs ? p.monitor.latencyBudgetMs + " ms" : "none") +
        " · probe latency " + (p.monitor && p.monitor.probeLinkLatency ? "on" : "off") +
        " · prefers lower latency " + (p.monitor && p.monitor.preferLowerLatency ? "yes" : "no"))));
      prof.append(t);
      prof.append(h("div", { class: "small dim mt" },
        "Profile selection changes how the engine is started (via the flags above); it cannot make one TCP connection use several links — that is the engine's per-connection scheduler."));
      prof.append(h("div", { class: "row spread" }, h("button", { class: "btn secondary", onclick: () => showView("settings") }, "Change in Settings")));
    }
  }

  const eng = $("#routeEngine");
  clear(eng);
  eng.append(engineBlock());

  const cross = $("#routeCross");
  clear(cross);
  const snap = state && state.snapshot;
  if (!snap) cross.append(h("div", { class: "dim" }, "No snapshot yet."));
  else {
    const items = [].concat(
      (snap.warnings || []).map((w) => ["warn", w]),
      (snap.gaps || []).map((w) => ["info", w]),
      (snap.errors || []).map((w) => ["bad", w]));
    if (!items.length) cross.append(h("div", { class: "dim" }, "No cross-adapter observations were reported."));
    items.forEach(([kind, text]) => cross.append(h("div", { class: "notice " + kind }, text)));
  }

  const def = $("#routeDefaults");
  clear(def);
  if (!snap) def.append(h("div", { class: "dim" }, "No snapshot yet."));
  else {
    const t = h("table", null, h("thead", null, h("tr", null, ["Adapter", "Destination", "Gateway", "Metric", "Interface index"].map((c) => h("th", null, c)))));
    const b = h("tbody");
    let any = false;
    snap.adapters.forEach((a) => (a.defaultRoutes || []).forEach((r) => {
      any = true;
      b.append(h("tr", null, h("td", null, a.name), h("td", null, r.destination), h("td", null, r.gateway || "on-link"), h("td", null, ival(r.metric)), h("td", null, r.index)));
    }));
    t.append(b);
    def.append(any ? t : h("div", { class: "dim" }, "No default routes were attributed to an adapter."));
  }
}

function requestedFlags(p) {
  const e = p.engine || {};
  const parts = [];
  if (e.include && e.include.length) parts.push("-include " + e.include.join(","));
  if (e.exclude && e.exclude.length) parts.push("(avoid: " + e.exclude.join(",") + ")");
  Object.keys(e.weights || {}).sort().forEach((k) => parts.push("-weight " + k + "=" + e.weights[k]));
  if (e.autoWeight === false) parts.push("-auto-weight=false");
  if (e.ipv6 && e.ipv6 !== "auto") parts.push("-ipv6 " + e.ipv6);
  if (e.mtu) parts.push("-mtu " + e.mtu);
  return parts.length ? parts.join(" ") : "engine defaults";
}
function weightText(w) {
  if (!w || !Object.keys(w).length) return "— automatic (weighted by measured throughput)";
  return Object.keys(w).sort().map((k) => k + "=" + w[k]).join(", ");
}

/* ---------- TTL ---------- */

async function loadTTL(btn) {
  await guard(async () => {
    const d = await api("/api/ttl");
    ttlReport = d;
    renderTTL();
    const hist = await api("/api/ttl/history?limit=100");
    renderTTLHistory(hist.events || []);
  }, btn);
  if (!ttlReport) {
    const s = $("#ttlState");
    clear(s);
    s.textContent = "TTL values could not be loaded.";
  }
}

function renderTTL() {
  const s = $("#ttlState");
  clear(s);
  const body = $("#ttlBody");
  clear(body);
  if (!ttlReport) return;
  const rep = ttlReport.report;
  s.textContent = "read at " + stamp(rep.at) + " · " + (ttlReport.elevated ? "elevated" : "not elevated");

  const cap = rep.capabilities || {};
  if (!cap.supported) {
    body.append(h("div", { class: "notice info" },
      h("strong", null, "This host has no supported mechanism for these values. "),
      (cap.notes || []).join(" ")));
  } else {
    if (!ttlReport.elevated) {
      body.append(h("div", { class: "notice warn" },
        "This process is not elevated: values can be inspected, and writes that need administrator rights will be refused by the platform rather than silently failing."));
    }
    (cap.notes || []).forEach((n) => body.append(h("div", { class: "notice info" }, n)));
  }

  const t = h("table", null, h("thead", null, h("tr", null, ["Setting", "Concept", "Family", "Scope", "Interface", "Current value", "Read from", "Writable"].map((c) => h("th", null, c)))));
  const tb = h("tbody");
  (rep.settings || []).forEach((x) => tb.append(h("tr", null,
    h("td", { class: "mono" }, x.id),
    h("td", null, x.kind || ""),
    h("td", null, x.family || ""),
    h("td", null, x.scope || ""),
    h("td", null, x.interface || "—"),
    h("td", { class: "num" }, x.value === null || x.value === undefined
      ? h("span", { class: "dim" }, "not configured (the platform default applies)")
      : String(x.value)),
    h("td", null, x.valueOrigin || "—"),
    h("td", null, x.writable ? h("span", { class: "tag ok" }, "yes") : h("span", { class: "tag warn" }, x.writableReason || "no")))));
  t.append(tb);
  if (!(rep.settings || []).length) body.append(h("div", { class: "dim" }, "No packet-header settings were reported."));
  else body.append(h("div", { class: "panel" }, h("h3", null, "Packet-header settings", h("span", { class: "hint" }, "IPv4 TTL and IPv6 hop limit")), t));

  const cap2 = rep.captured || {};
  const keys = Object.keys(cap2);
  const cp = h("div", { class: "panel" }, h("h3", null, "Captured originals", h("span", { class: "hint" }, "what Restore puts back")));
  if (!keys.length) cp.append(h("div", { class: "notice info" }, "Nothing has been captured yet, so there is nothing to restore. A capture happens automatically before the first change to a setting."));
  else {
    const t2 = h("table", null, h("thead", null, h("tr", null, ["Setting", "Original value", "Explicit", "Captured at", "Read from"].map((c) => h("th", null, c)))));
    const b2 = h("tbody");
    keys.forEach((k) => {
      const o = cap2[k];
      b2.append(h("tr", null, h("td", { class: "mono" }, k),
        h("td", { class: "num" }, o.value === null || o.value === undefined ? "— (was not set)" : o.value),
        h("td", null, o.explicit ? "yes" : "no (platform default was in effect)"),
        h("td", null, stamp(o.capturedAt)), h("td", null, o.origin || "—")));
    });
    t2.append(b2);
    cp.append(t2);
  }
  body.append(cp);

  if (rep.notSettings && rep.notSettings.length) {
    const ns = h("div", { class: "panel" }, h("h3", null, "Related but different concepts", h("span", { class: "hint" }, "reported so they are not confused with the settings above")));
    const t3 = h("table", null, h("thead", null, h("tr", null, ["Concept", "Why it is not a packet-header setting"].map((c) => h("th", null, c)))));
    const b3 = h("tbody");
    rep.notSettings.forEach((x) => b3.append(h("tr", null, h("td", { class: "mono" }, x.id + " (" + (x.kind || "") + ")"), h("td", null, x.writableReason || "not a packet-header value"))));
    t3.append(b3);
    ns.append(t3);
    body.append(ns);
  }

  if (rep.readErrors && rep.readErrors.length) {
    const re = h("div", { class: "panel" }, h("h3", null, "Could not be read"));
    rep.readErrors.forEach((e) => re.append(h("div", { class: "notice warn" }, h("strong", null, e.code + " — " + (e.setting && e.setting.id ? e.setting.id : "")), " ", e.message)));
    body.append(re);
  }
  if (rep.warnings && rep.warnings.length) {
    const w = h("div", { class: "panel" }, h("h3", null, "Warnings"));
    rep.warnings.forEach((x) => w.append(h("div", { class: "notice warn" }, x)));
    body.append(w);
  }

  renderTTLConfig(rep.config);
  renderTTLActions(rep);
}

function renderTTLConfig(cfg) {
  const box = $("#ttlConfig");
  clear(box);
  const c = Object.assign({}, cfg); // keep unknown fields when saving back
  const fields = {};

  const chk = (name, label) => {
    const i = h("input", { type: "checkbox", checked: !!c[name], onchange: () => { c[name] = i.checked; } });
    fields[name] = i;
    return h("label", { class: "field" }, h("span", null, label), i);
  };
  const num = (name, label) => {
    const i = h("input", { type: "number", value: c[name] ?? 0, onchange: () => { c[name] = Number(i.value); } });
    fields[name] = i;
    return h("label", { class: "field" }, h("span", null, label), i);
  };
  const text = (name, label) => {
    const i = h("input", { type: "text", value: (c[name] || []).join(", "), onchange: () => { c[name] = i.value.split(",").map((s) => s.trim()).filter(Boolean); } });
    fields[name] = i;
    return h("label", { class: "field" }, h("span", null, label), i);
  };
  const pol = h("select", null,
    ["none", "list", "all-except"].map((p) => h("option", p === c.interfacePolicy ? { selected: true } : {}, p)));
  pol.addEventListener("change", () => { c.interfacePolicy = pol.value; });

  box.append(h("div", { class: "grid2" },
    chk("enabled", "Management enabled (records intent only; never acted on by itself)"),
    num("bumpIPv4", "IPv4 TTL to write"),
    num("bumpIPv6", "IPv6 hop limit to write"),
    h("label", { class: "field" }, h("span", null, "Per-interface policy"), pol),
    text("includeIfaces", "Include adapters (list policy)"),
    text("excludeIfaces", "Exclude adapters (all-except policy)")));
  box.append(h("div", { class: "small dim mt" },
    "The per-interface mechanism is Windows' " , h("code", null, "Set-NetIPInterface -CurrentHopLimit"), ". Whether it can be applied is verified by reading the value back after each write; a write that cannot be confirmed is reported as unverified, never as success."));
  box.append(h("div", { class: "row spread" },
    h("button", { class: "btn", onclick: (e) => guard(async () => {
      await api("/api/ttl/config", { method: "POST", body: c });
      toast("ok", "TTL configuration saved. Nothing was changed on the system.");
      loadTTL();
    }, e.target) }, "Save configuration")));
}

function renderTTLActions(rep) {
  const body = $("#ttlBody");
  const box = h("div", { class: "panel" }, h("h3", null, "Preview, apply, restore", h("span", { class: "hint" }, "preview first; a real change always asks for confirmation")));
  const out = h("div", { class: "mt" });
  const preview = (restore, btn) => guard(async () => {
    const d = await api(restore ? "/api/ttl/restore" : "/api/ttl/apply", { method: "POST", body: { dryRun: true, reason: "dashboard preview" } });
    renderOutcome(out, d, true);
  }, btn);
  const real = (restore, btn) => {
    const what = restore
      ? "Restore the captured original TTL/hop-limit values? This writes to system settings."
      : "Apply the configured TTL/hop-limit changes now? This writes to system settings.";
    if (!confirm(what + "\n\nPreview first if you have not, so you know exactly what will change.")) return;
    return guard(async () => {
      const d = await api(restore ? "/api/ttl/restore" : "/api/ttl/apply", { method: "POST", body: { dryRun: false, confirm: true, reason: "confirmed in dashboard" } });
      renderOutcome(out, d, false);
      toast(d.failed ? "warn" : "ok", restore ? "Restore finished." : "Apply finished.", d.failed ? d.failed + " change(s) failed" : undefined);
      loadTTL();
    }, btn);
  };
  box.append(h("div", { class: "row" },
    h("button", { class: "btn secondary", onclick: (e) => preview(false, e.target) }, "Preview planned changes"),
    h("button", { class: "btn", onclick: (e) => real(false, e.target) }, "Apply changes…"),
    h("button", { class: "btn secondary", onclick: (e) => preview(true, e.target) }, "Preview restore"),
    h("button", { class: "btn danger", onclick: (e) => real(true, e.target) }, "Restore originals…")));
  box.append(out);
  body.append(box);
}

function renderOutcome(container, d, dry) {
  clear(container);
  const kind = d.rollbackIncomplete ? "bad" : d.failed ? "warn" : "ok";
  const head = dry ? "Preview (nothing was written)" : "Result";
  container.append(h("div", { class: "notice " + kind },
    h("strong", null, head + ": "),
    d.applied + " change(s) " + (dry ? "planned" : "applied") + ", " + d.failed + " failed",
    d.rolledBack ? " · rolled back completely" : "",
    d.rollbackIncomplete ? " · ROLLBACK INCOMPLETE" : ""));
  (d.rollbackDetail || []).forEach((x) => container.append(h("div", { class: "notice bad" }, x)));
  (d.notes || []).forEach((x) => container.append(h("div", { class: "notice info" }, x)));
  if (d.changes && d.changes.length) {
    const t = h("table", null, h("thead", null, h("tr", null, ["Setting", "From", "To", "Outcome", "Verified"].map((c) => h("th", null, c)))));
    const b = h("tbody");
    d.changes.forEach((ch) => b.append(h("tr", null,
      h("td", { class: "mono" }, ch.setting.id),
      h("td", { class: "num" }, ch.from === null || ch.from === undefined ? "— (unread)" : ch.from),
      h("td", { class: "num" }, ch.to),
      h("td", null, h("span", { class: "tag " + (ch.outcome === "applied" || ch.outcome === "planned" ? "ok" : "warn") }, ch.outcome)),
      h("td", null, ch.verified ? h("span", { class: "tag ok" }, "read back") : h("span", { class: "tag warn" }, "not confirmed")))));
    t.append(b);
    container.append(t);
  }
}

function renderTTLHistory(events) {
  const box = $("#ttlHistory");
  clear(box);
  if (!events.length) { box.append(h("div", { class: "dim" }, "No changes have been recorded.")); return; }
  const t = h("table", null, h("thead", null, h("tr", null, ["When", "Setting", "From", "To", "Outcome", "Reason", "Error"].map((c) => h("th", null, c)))));
  const b = h("tbody");
  events.forEach((e) => b.append(h("tr", null,
    h("td", null, stamp(e.at)),
    h("td", { class: "mono" }, e.id + (e.interface ? " @ " + e.interface : "")),
    h("td", { class: "num" }, e.old === null || e.old === undefined ? "—" : e.old),
    h("td", { class: "num" }, e.new === null || e.new === undefined ? "—" : e.new),
    h("td", null, h("span", { class: "tag " + (e.outcome === "applied" || e.outcome === "restored" ? "ok" : "warn") }, e.outcome)),
    h("td", null, e.reason || ""),
    h("td", null, e.error || ""))));
  t.append(b);
  box.append(t);
}

/* ---------- diagnostics ---------- */

let checkMetas = null;

async function ensureChecks() {
  if (checkMetas) return;
  await guard(async () => {
    const d = await api("/api/diag/checks");
    checkMetas = d;
    renderChecks();
  });
}

function renderChecks() {
  const box = $("#diagChecks");
  clear(box);
  if (!checkMetas) return;
  const disabled = new Set(checkMetas.disabledChecks || []);
  const t = h("table", null, h("thead", null, h("tr", null, ["", "Check", "Category", "What it establishes"].map((c) => h("th", null, c)))));
  const b = h("tbody");
  (checkMetas.checks || []).forEach((m) => {
    const cb = h("input", { type: "checkbox", "data-id": m.id, checked: !disabled.has(m.id) });
    if (disabled.has(m.id)) cb.disabled = true;
    b.append(h("tr", null,
      h("td", null, cb),
      h("td", null, h("strong", null, m.id), h("div", { class: "small dim" }, m.title)),
      h("td", null, h("span", { class: "tag info" }, m.category)),
      h("td", null,
        h("div", { class: "small" }, m.purpose || ""),
        h("details", { class: "mt" }, h("summary", null, "establishes / does not establish"),
          h("div", { class: "small mt" }, h("strong", null, "Establishes:")),
          h("ul", { class: "small est" }, (m.establishes || []).map((x) => h("li", null, x))),
          h("div", { class: "small mt" }, h("strong", null, "Does not establish:")),
          h("ul", { class: "small est" }, (m.doesNotEstablish || []).map((x) => h("li", null, x)))))));
  });
  t.append(b);
  box.append(t);
  if (disabled.size) box.append(h("div", { class: "notice info mt" }, disabled.size + " check(s) are disabled in Settings and will be skipped."));
}

async function runDiag(all, btn) {
  const ids = [];
  document.querySelectorAll("#diagChecks input[type=checkbox]").forEach((cb) => { if (cb.checked) ids.push(cb.dataset.id); });
  if (!all && !ids.length) { toast("warn", "No checks are selected."); return; }
  const body = all ? { all: true } : { ids };
  await guard(async () => {
    const j = await api("/api/diag/run", { method: "POST", body });
    diagJobId = j.id;
    $("#diagCancel").disabled = false;
    pollDiagJob();
  }, btn);
}

async function pollDiagJob() {
  if (!diagJobId) return;
  let j;
  try { j = await api("/api/diag/runs/" + encodeURIComponent(diagJobId)); }
  catch (e) { $("#diagProgress").textContent = "Could not read the run: " + e.message; return; }
  const prog = $("#diagProgress");
  clear(prog);
  if (j.status === "running") {
    prog.append(h("div", { class: "notice info spin" }, "Run " + j.id + " is in progress since " + clock(j.started) + ". The page stays responsive; results appear when the run finishes."));
    setTimeout(pollDiagJob, 1200);
    return;
  }
  $("#diagCancel").disabled = true;
  if (j.status !== "done") {
    prog.append(h("div", { class: "notice bad" }, "Run " + j.id + " ended as " + j.status + (j.error ? ": " + j.error : ".")));
    // A stopped run keeps the checks that had finished. Show them, clearly labelled: a check with
    // no result here did not pass, it did not run, and the two must not look alike.
    const partial = j.diag && j.diag.result;
    const partialResults = (partial && partial.results) || [];
    if (partialResults.length) {
      prog.append(h("div", { class: "notice warn" },
        "What follows is the partial set: the " + partialResults.length + " check(s) that had already finished when the run stopped. Every other check has no result - not a pass - and can be run again."));
      renderDiagResults(partial);
    }
    return;
  }
  lastDiag = j.diag.result;
  prog.append(h("div", { class: "notice ok" }, lastDiag.summary + " · took " + goDur(lastDiag.duration) + " · " + lastDiag.results.length + " checks"));
  renderDiagResults(lastDiag);
}

function renderDiagResults(run) {
  const box = $("#diagResults");
  clear(box);
  if (!run) return;
  if (run.skipped && Object.keys(run.skipped).length) {
    const sk = h("div", { class: "panel" }, h("h3", null, "Skipped checks"));
    Object.entries(run.skipped).forEach(([id, why]) => sk.append(h("div", { class: "small" }, h("span", { class: "mono" }, id), " — ", why)));
    box.append(sk);
  }
  (run.results || []).forEach((res) => {
    const panel = h("div", { class: "panel" },
      h("div", { class: "row between" },
        h("h3", { style: "margin:0" }, res.title, " ", h("span", { class: "mono small dim" }, res.id)),
        h("div", null, tag(res.status), " ", h("span", { class: "small dim" }, goDur(res.duration)))),
      h("div", { class: "mt" }, res.summary || ""));
    if (res.established && res.established.length) {
      panel.append(h("div", { class: "small mt" }, h("strong", null, "Established:")), h("ul", { class: "small est" }, res.established.map((x) => h("li", null, x))));
    }
    if (res.inconclusive && res.inconclusive.length) {
      panel.append(h("div", { class: "small mt" }, h("strong", null, "Could not establish:")), h("ul", { class: "small est" }, res.inconclusive.map((x) => h("li", null, x))));
    }
    if (res.errorCodes && res.errorCodes.length) {
      const codes = h("div", { class: "mt" });
      res.errorCodes.forEach((c) => {
        const info = codeInfo(c);
        codes.append(h("span", { class: "tag warn", style: "margin-right:6px", title: info ? info.meaning : c }, c));
      });
      panel.append(codes);
      res.errorCodes.forEach((c) => {
        const info = codeInfo(c);
        if (!info) return;
        panel.append(h("div", { class: "small", style: "margin-top:2px" },
          h("span", { class: "mono" }, c), " — ", info.meaning,
          info.fix ? h("span", { class: "dim" }, " " + info.fix) : null));
      });
    }
    if (res.nextSteps && res.nextSteps.length) {
      panel.append(h("div", { class: "small mt" }, h("strong", null, "Next steps:")), h("ul", { class: "small est" }, res.nextSteps.map((x) => h("li", null, x))));
    }
    (res.evidence || []).forEach((ev) => {
      const det = h("details", { class: "mt" }, h("summary", null,
        "evidence: " + ev.label + (ev.command && ev.command.length ? " — " + ev.command.join(" ") : "")));
      let meta = [];
      if (ev.exitCode !== null && ev.exitCode !== undefined) meta.push("exit " + ev.exitCode);
      if (ev.timedOut) meta.push("timed out");
      if (ev.truncated) meta.push("output truncated");
      if (ev.err) meta.push("error: " + ev.err);
      if (ev.note) meta.push(ev.note);
      if (meta.length) det.append(h("div", { class: "small dim" }, meta.join(" · ")));
      if (ev.output && ev.output.length) det.append(h("pre", null, ev.output.join("\n")));
      panel.append(det);
    });
    if (res.notes && res.notes.length) panel.append(h("div", { class: "notice info mt" }, res.notes.join(" ")));
    box.append(panel);
  });
}

/* ---------- export ---------- */

async function startExport(btn) {
  await guard(async () => {
    const j = await api("/api/export", { method: "POST", body: {} });
    exportJobId = j.id;
    $("#exportPanel").classList.remove("hidden");
    $("#exportMeta").textContent = "Export " + j.id + " is being assembled…";
    pollExportJob();
  }, btn);
}

async function pollExportJob() {
  if (!exportJobId) return;
  let j;
  try { j = await api("/api/export/" + encodeURIComponent(exportJobId)); }
  catch (e) { $("#exportMeta").textContent = "Could not read the export: " + e.message; return; }
  if (j.status === "running") {
    $("#exportMeta").textContent = "Export " + j.id + " is being assembled and redacted…";
    setTimeout(pollExportJob, 1000);
    return;
  }
  if (j.status !== "done") {
    $("#exportMeta").textContent = "Export ended as " + j.status + (j.error ? ": " + j.error : ".");
    return;
  }
  lastExport = j.export;
  renderExport(j.export);
}

function renderExport(e) {
  const meta = $("#exportMeta");
  clear(meta);
  const c = e.redactionCounts || {};
  meta.append(
    h("div", null, h("strong", null, e.baseName)),
    h("div", { class: "small dim" },
      "redacted: " + (c.total || 0) + " value(s) — addresses " + (c.publicAddresses || 0) +
      ", MACs " + (c.macAddresses || 0) + ", user paths " + (c.userPaths || 0) +
      ", serials " + (c.serials || 0) + ", credentials " + (c.credentials || 0) +
      ", names " + (c.accountAndHostNames || 0)),
    h("div", { class: "small dim" }, "Nothing has been uploaded. Saving writes two files into your outputs directory."));

  const vis = $("#exportVisibility");
  clear(vis);
  const entries = e.redactionEntries || [];
  if (entries.length) {
    vis.append(h("div", { class: "notice warn" },
      h("strong", null, "What the placeholders stand for "),
      "— this mapping is shown only here and is never written into the report files."));
    const t = h("table", null, h("thead", null, h("tr", null, ["Placeholder", "Category", "Actual value"].map((x) => h("th", null, x)))));
    const b = h("tbody");
    entries.forEach((en) => b.append(h("tr", null, h("td", { class: "mono" }, en.placeholder), h("td", null, en.category), h("td", { class: "mono" }, en.value))));
    t.append(b);
    vis.append(t);
  } else {
    vis.append(h("div", { class: "notice ok" }, "Nothing needed redacting in this report."));
  }
  $("#exportText").textContent = e.text;
}

async function saveExport(btn) {
  if (!exportJobId) return;
  await guard(async () => {
    const d = await api("/api/export/save", { method: "POST", body: { id: exportJobId } });
    toast("ok", "Saved.", d.saved.join("\n"));
  }, btn);
}

/* ---------- logs ---------- */

function startLogs() {
  if (logTimer) return;
  pollLogs();
  logTimer = setInterval(pollLogs, 2500);
}
function stopLogs() { if (logTimer) { clearInterval(logTimer); logTimer = null; } }

async function pollLogs() {
  const q = $("#logQuery").value.trim();
  const level = $("#logLevel").value;
  try {
    let d;
    if (q) d = await api("/api/logs?level=" + encodeURIComponent(level) + "&limit=400&q=" + encodeURIComponent(q));
    else d = await api("/api/logs?level=" + encodeURIComponent(level) + "&limit=300&since=" + logCursor);
    renderLogs(d, !!q);
    if (!q && typeof d.cursor === "number") logCursor = d.cursor;
  } catch (e) {
    $("#logBody").textContent = "Could not read logs: " + e.message;
  }
}

function renderLogs(d, isSearch) {
  const box = $("#logBody");
  clear(box);
  const evs = d.events || [];
  if (!evs.length) { box.append(h("div", { class: "dim" }, isSearch ? "No events match the search." : "No new events.")); return; }
  const t = h("table", null, h("thead", null, h("tr", null, ["Time", "Level", "Code", "Message"].map((c) => h("th", null, c)))));
  const b = h("tbody");
  evs.forEach((e) => {
    const row = h("tr", null,
      h("td", { class: "num" }, stamp(e.at)),
      h("td", null, h("span", { class: "tag " + (e.levelName === "error" ? "bad" : e.levelName === "warn" ? "warn" : "info") }, e.levelName)),
      h("td", { class: "mono" }, e.code || ""),
      h("td", null, e.message, e.detail ? h("details", null, h("summary", null, "details"), h("pre", null, e.detail)) : null));
    b.append(row);
  });
  t.append(b);
  box.append(t);
  box.append(h("div", { class: "small dim mt" }, evs.length + " event(s) · newest first? order shown is as stored"));
}

/* ---------- settings ---------- */

let settingsCfg = null;

async function loadSettings() {
  await guard(async () => {
    settingsView = await api("/api/settings");
    settingsCfg = settingsView.config;
    renderSettings();
  });
}

function renderSettings() {
  const box = $("#settingsBody");
  clear(box);
  if (!settingsCfg) { box.append(h("div", { class: "dim" }, "Loading…")); return; }

  if (settingsView.loadError) {
    box.append(h("div", { class: "notice bad" },
      h("strong", null, "The settings file could not be read. "),
      settingsView.loadError,
      h("div", { class: "small" }, "The defaults are shown; the file on disk has not been changed. Fix the problem and reload.")));
  }
  if (settingsView.stale) {
    box.append(h("div", { class: "notice info" },
      h("strong", null, "This settings file was written by a different build. "),
      settingsView.staleReason));
  }
  box.append(h("div", { class: "small dim" }, "File: ", h("span", { class: "mono" }, settingsView.path), settingsView.existed ? "" : " (not created yet — defaults are in use)"));

  /* profiles */
  const prof = h("div", { class: "panel" }, h("h3", null, "Quality profile"));
  const sel = h("select");
  (settingsView.profileOrder || Object.keys(settingsCfg.profiles)).forEach((id) => {
    const p = settingsCfg.profiles[id] || { name: id };
    sel.append(h("option", id === settingsCfg.activeProfile ? { value: id, selected: true } : { value: id }, p.name + " (" + id + ")"));
  });
  sel.addEventListener("change", () => {
    settingsCfg.activeProfile = sel.value;
    renderSettings();
  });
  prof.append(h("div", { class: "grid2" }, h("label", { class: "field" }, h("span", null, "Active profile"), sel)));

  const p = settingsCfg.profiles[settingsCfg.activeProfile];
  if (p) {
    prof.append(h("div", { class: "small dim mt" }, p.description || ""));
    const e = p.engine || (p.engine = {});
    const inc = h("input", { type: "text", value: (e.include || []).join(", "), onchange: () => { e.include = inc.value.split(",").map((s) => s.trim()).filter(Boolean); } });
    const exc = h("input", { type: "text", value: (e.exclude || []).join(", "), onchange: () => { e.exclude = exc.value.split(",").map((s) => s.trim()).filter(Boolean); } });
    const wt = h("input", { type: "text", value: Object.keys(e.weights || {}).map((k) => k + "=" + e.weights[k]).join(", "), onchange: () => {
      const w = {};
      wt.value.split(",").forEach((part) => {
        const i = part.lastIndexOf("=");
        if (i > 0) { const n = parseFloat(part.slice(i + 1)); if (isFinite(n) && n > 0) w[part.slice(0, i).trim()] = n; }
      });
      e.weights = w;
    } });
    const ipv6 = h("select", null, ["auto", "on", "off"].map((v) => h("option", v === (e.ipv6 || "auto") ? { value: v, selected: true } : { value: v }, v)));
    ipv6.addEventListener("change", () => { e.ipv6 = ipv6.value; });
    const mtu = h("input", { type: "number", value: e.mtu || 0, onchange: () => { e.mtu = Number(mtu.value); } });
    const auto = h("input", { type: "checkbox", checked: e.autoWeight !== false, onchange: () => { e.autoWeight = auto.checked; } });
    const lat = h("input", { type: "number", value: (p.monitor && p.monitor.latencyBudgetMs) || 0, onchange: () => { p.monitor = p.monitor || {}; p.monitor.latencyBudgetMs = Number(lat.value); } });
    const probe = h("input", { type: "checkbox", checked: !!(p.monitor && p.monitor.probeLinkLatency), onchange: () => { p.monitor = p.monitor || {}; p.monitor.probeLinkLatency = probe.checked; } });
    const prefer = h("input", { type: "checkbox", checked: !!(p.monitor && p.monitor.preferLowerLatency), onchange: () => { p.monitor = p.monitor || {}; p.monitor.preferLowerLatency = prefer.checked; } });
    prof.append(h("div", { class: "grid2 mt" },
      h("label", { class: "field" }, h("span", null, "Include adapters"), inc),
      h("label", { class: "field" }, h("span", null, "Exclude adapters"), exc),
      h("label", { class: "field" }, h("span", null, "Weights (Name=value)"), wt),
      h("label", { class: "field" }, h("span", null, "IPv6 mode"), ipv6),
      h("label", { class: "field" }, h("span", null, "Engine MTU"), mtu),
      h("label", { class: "field" }, h("span", null, "Weight by measured throughput"), auto),
      h("label", { class: "field" }, h("span", null, "Latency budget (ms, 0 = none)"), lat),
      h("label", { class: "field" }, h("span", null, "Probe per-link latency"), probe),
      h("label", { class: "field" }, h("span", null, "Prefer lower-latency link (advice)"), prefer)));
    prof.append(h("div", { class: "small dim mt" }, "Requested engine flags: ", h("span", { class: "mono" }, requestedFlags(p))));
  }
  box.append(prof);

  /* dashboard + logging */
  const d = settingsCfg.dashboard, lg = settingsCfg.logging, pv = settingsCfg.privacy, dx = settingsCfg.diagnostics;
  const dash = h("div", { class: "panel" }, h("h3", null, "Dashboard and logs"));
  const listen = h("input", { type: "text", value: d.listen || "", onchange: () => { d.listen = listen.value; } });
  const interval = h("input", { type: "number", value: d.intervalMs, onchange: () => { d.intervalMs = Number(interval.value); } });
  const open = h("input", { type: "checkbox", checked: !!d.openBrowser, onchange: () => { d.openBrowser = open.checked; } });
  const lvl = h("select", null, ["debug", "info", "warn", "error"].map((v) => h("option", v === lg.level ? { value: v, selected: true } : { value: v }, v)));
  lvl.addEventListener("change", () => { lg.level = lvl.value; });
  const maxBytes = h("input", { type: "number", value: lg.maxBytes, onchange: () => { lg.maxBytes = Number(maxBytes.value); } });
  const maxFiles = h("input", { type: "number", value: lg.maxFiles, onchange: () => { lg.maxFiles = Number(maxFiles.value); } });
  const ring = h("input", { type: "number", value: lg.ringEvents, onchange: () => { lg.ringEvents = Number(ring.value); } });
  dash.append(h("div", { class: "grid2" },
    h("label", { class: "field" }, h("span", null, "Listen address (loopback only)"), listen),
    h("label", { class: "field" }, h("span", null, "Monitor interval (ms)"), interval),
    h("label", { class: "field" }, h("span", null, "Open browser on start"), open),
    h("label", { class: "field" }, h("span", null, "Log level"), lvl),
    h("label", { class: "field" }, h("span", null, "Log file max bytes"), maxBytes),
    h("label", { class: "field" }, h("span", null, "Log files kept"), maxFiles),
    h("label", { class: "field" }, h("span", null, "In-memory events kept"), ring)));
  box.append(dash);

  /* privacy */
  const priv = h("div", { class: "panel" }, h("h3", null, "Export privacy", h("span", { class: "hint" }, "credentials are always redacted")));
  const pChecks = [
    ["redactPublicIPs", "Redact public IP addresses"],
    ["keepWellKnownPublicIPs", "Keep well-known public resolvers readable"],
    ["redactMACs", "Redact MAC addresses (vendor prefix kept)"],
    ["redactSerials", "Redact serial numbers, IMEIs, USB instance paths"],
    ["redactPaths", "Redact the account name in paths"],
    ["redactHostNames", "Redact the machine and account names"],
    ["includeHostname", "Include the machine name in the report"],
    ["redactAdapterNames", "Redact adapter names"],
  ];
  const grid = h("div", { class: "grid2" });
  pChecks.forEach(([k, label]) => {
    const i = h("input", { type: "checkbox", checked: !!pv[k], onchange: () => { pv[k] = i.checked; } });
    grid.append(h("label", { class: "field" }, h("span", null, label), i));
  });
  priv.append(grid);
  box.append(priv);

  /* diagnostics targets */
  const diagP = h("div", { class: "panel" }, h("h3", null, "Diagnostic targets"));
  const f = (name, label) => {
    const i = h("input", { type: "text", value: dx[name] || "", onchange: () => { dx[name] = i.value.trim(); } });
    return h("label", { class: "field" }, h("span", null, label), i);
  };
  const nf = (name, label) => {
    const i = h("input", { type: "number", value: dx[name] || 0, onchange: () => { dx[name] = Number(i.value); } });
    return h("label", { class: "field" }, h("span", null, label), i);
  };
  diagP.append(h("div", { class: "grid2" },
    f("endpoint", "TCP / latency endpoint (host:port)"),
    f("dnsServer", "DNS server to target (optional)"),
    f("dnsName", "DNS name to resolve"),
    f("tracerouteTarget", "Traceroute target"),
    f("udpTarget", "UDP probe target (host:port)"),
    f("mtuHost", "Path-MTU host"),
    nf("timeoutMs", "Per-command timeout (ms)"),
    nf("tracerouteTimeoutMs", "Traceroute timeout (ms)")));
  box.append(diagP);

  const actions = h("div", { class: "row spread" }, h("button", { class: "btn", onclick: (e) => guard(async () => {
    const d2 = await api("/api/settings", { method: "PUT", body: settingsCfg });
    toast("ok", "Settings saved.", d2.path);
    loadSettings();
  }, e.target) }, "Save settings"));
  box.append(actions);
}

/* ---------- boot ---------- */

async function pollStateOnce() {
  state = await api("/api/state");
  renderBadge(); renderOverview(); renderConnections(); renderRouting();
}

async function stateLoop() {
  try { await pollStateOnce(); }
  catch (e) {
    const b = $("#engineBadge");
    clear(b);
    b.append(h("span", { class: "tag bad" }, "disconnected"), h("span", { class: "small dim" }, e.message));
  }
  setTimeout(stateLoop, 2000);
}

document.querySelectorAll("#nav button").forEach((b) => b.addEventListener("click", () => showView(b.dataset.view)));
$("#connRefresh").addEventListener("click", (e) => guard(async () => { state = await api("/api/refresh", { method: "POST", body: {} }); renderBadge(); renderOverview(); renderConnections(); renderRouting(); toast("ok", "Snapshot refreshed."); }, e.target));
$("#ttlReload").addEventListener("click", (e) => loadTTL(e.target));
$("#diagRunAll").addEventListener("click", (e) => runDiag(true, e.target));
$("#diagRunSel").addEventListener("click", (e) => runDiag(false, e.target));
$("#diagCancel").addEventListener("click", (e) => guard(async () => {
  if (!diagJobId) return;
  const j = await api("/api/diag/cancel", { method: "POST", body: { id: diagJobId } });
  toast("warn", "Cancellation requested for " + j.id + ".");
}, e.target));
$("#exportStart").addEventListener("click", (e) => startExport(e.target));
$("#exportSave").addEventListener("click", (e) => saveExport(e.target));
$("#exportCopy").addEventListener("click", () => {
  if (!lastExport) return;
  navigator.clipboard.writeText(lastExport.json).then(() => toast("ok", "The redacted JSON is on the clipboard."), () => toast("warn", "Clipboard access was refused by the browser."));
});
$("#logClearSearch").addEventListener("click", () => { $("#logQuery").value = ""; logCursor = 0; pollLogs(); });
let logDebounce = null;
$("#logQuery").addEventListener("input", () => { clearTimeout(logDebounce); logDebounce = setTimeout(() => { logCursor = 0; pollLogs(); }, 300); });
$("#logLevel").addEventListener("change", () => { logCursor = 0; pollLogs(); });

stateLoop();
loadCodeRegistry();
