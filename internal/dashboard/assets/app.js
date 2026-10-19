"use strict";
/*
 * NetMerge Control Center dashboard.
 *
 * One rule shapes this file: it renders whatever the server says, including when the server says
 * "unknown". Nothing here synthesises a value, and every placeholder for a missing fact stays
 * visibly missing. Long operations (diagnostics runs, exports) are started as jobs and polled,
 * so no button ever freezes the page. Charts and meters are built from real collected samples
 * only; an unavailable sample is drawn as a gap, never as a zero.
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

function setAll(node, kids) { clear(node); addKid(node, kids); return node; }

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

function rateShort(v) {
  if (v === null || v === undefined) return "—";
  const bps = Number(v);
  if (!isFinite(bps)) return "—";
  if (bps >= 1e9) return (bps / 1e9).toFixed(1) + "G";
  if (bps >= 1e6) return (bps / 1e6).toFixed(1) + "M";
  if (bps >= 1e3) return (bps / 1e3).toFixed(0) + "k";
  return bps.toFixed(0);
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

function nfmt(v) {
  if (v === null || v === undefined) return "—";
  const n = Number(v);
  if (!isFinite(n)) return "—";
  return n.toLocaleString();
}

function pct(v) {
  if (v === null || v === undefined) return "—";
  const n = Number(v);
  if (!isFinite(n)) return "—";
  return n.toFixed(1) + "%";
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
    details ? h("div", { class: "small mono", style: "margin-top:4px;white-space:pre-wrap" }, typeof details === "string" ? details : JSON.stringify(details, null, 2)) : null,
    h("div", { class: "row", style: "margin-top:6px" },
      h("button", {
        class: "btn secondary small", onclick: (ev) => {
          ev.stopPropagation();
          const body = ["code: " + (code || "(none)"), "message: " + message,
            info ? "meaning: " + info.meaning : "", info && info.fix ? "next step: " + info.fix : "",
            details ? "details: " + (typeof details === "string" ? details : JSON.stringify(details)) : ""].filter(Boolean).join("\n");
          copyText(body, "Error details copied.");
        }
      }, "Copy error details"),
      h("span", { class: "small dim", style: "margin-left:8px" }, "click to dismiss")));
  box.append(n);
  setTimeout(() => n.remove(), 12000);
}

function copyText(text, okMsg) {
  navigator.clipboard.writeText(text).then(
    () => toast("ok", okMsg || "Copied to clipboard."),
    () => toast("warn", "Clipboard access was refused by the browser."),
  );
}

async function guard(fn, busy) {
  if (busy) busy.disabled = true;
  try { return await fn(); }
  catch (e) { toast("bad", e.message || "request failed", e.details ? JSON.stringify(e.details) : null, e.code); }
  finally { if (busy) busy.disabled = false; }
}

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
// publicIP is the last opt-in public-IP check: {endpoint, at, results, skipped}. It stays null
// until the user clicks "Check public IPs" — nothing here runs on load or on a poll.
let publicIP = null;
// publicIPMasked hides the addresses behind a placeholder. It is persisted so a page reload
// mid-recording does not silently reveal them again.
let publicIPMasked = false;
try { publicIPMasked = localStorage.getItem("netmerge.pubip.masked") === "1"; } catch (e) { publicIPMasked = false; }
let logCursor = 0;
let logTimer = null;
let logSelected = new Set();
let lastDiag = null;
let lastExport = null;
let exportJobId = null;
let diagJobId = null;
let currentView = "overview";
// rolling throughput history, keyed by adapter index, so charts read real samples only
let history = [];
const HISTORY_MAX = 60;

const STATUS_CLASS = { pass: "ok", warn: "warn", fail: "bad", error: "bad", skipped: "skip", info: "info" };
function statusTag(status) {
  const cls = STATUS_CLASS[status] || "info";
  return h("span", { class: "tag " + cls }, h("span", { class: "dot" }), status || UNKNOWN);
}

/* ---------- shared small components ---------- */

// card(k, v, sub, opts) renders a metric card. sub is a short caption shown inline beside the
// value; opts takes sub (a caption on its own line below), tone, spark, icon, small, onclick.
// Passing an object where the caption is expected must never stringify into the card as
// "[object Object]".
function card(k, v, sub, opts) {
  if (typeof sub === "object" && sub !== null) { opts = sub; sub = opts.inline || null; }
  opts = opts || {};
  const kids = [h("span", { class: "accent" }), h("div", { class: "k" }, k,
    opts.icon ? h("span", null, opts.icon) : null)];
  const vcls = "v" + (opts.tone ? " " + opts.tone : "") + (opts.small ? " sm" : "");
  kids.push(h("div", { class: vcls }, v === null || v === undefined ? "—" : v,
    sub ? h("small", null, " " + sub) : null));
  if (opts.sub) kids.push(h("div", { class: "sub" }, opts.sub));
  if (opts.spark) kids.push(h("div", { class: "spark" }, opts.spark));
  return h("div", { class: "card" + (opts.tone ? " is-" + opts.tone : "") + (opts.onclick ? " clickable" : ""), onclick: opts.onclick }, kids);
}

function meter(value, max, tone) {
  const frac = (value === null || value === undefined || !max) ? 0 : Math.max(0, Math.min(1, value / max));
  return h("div", { class: "meter" + (tone ? " " + tone : "") }, h("span", { style: "width:" + (frac * 100).toFixed(1) + "%" }));
}

// A bar chart from a real series. null entries are drawn as gaps so "unknown" never looks like 0.
// When opts.second is given, every slot carries two bars side by side (the primary series and the
// second one), so a legend that names two series always describes two that are actually drawn.
function chart(series, opts) {
  opts = opts || {};
  const second = opts.second || null;
  const all = second ? series.concat(second) : series;
  const max = Math.max(1e-6, ...all.filter((v) => v !== null && v !== undefined).map(Number));
  const barFor = (v, out) => {
    if (v === null || v === undefined) return h("div", { class: "bar", style: "height:0;background:var(--line2)", title: "no sample" });
    const frac = Math.max(0.04, Number(v) / max);
    return h("div", { class: "bar" + (out ? " out" : ""), style: "height:" + (frac * 100).toFixed(1) + "%", title: opts.fmt ? opts.fmt(v) : String(v) });
  };
  const bars = series.map((v, i) => {
    if (!second) return barFor(v, opts.out);
    // A paired slot: the two bars share one column so the eye compares them directly.
    return h("div", { class: "pair" }, barFor(v, false), barFor(second[i], true));
  });
  return h("div", { class: "chart" + (opts.tall ? " tall" : "") }, bars);
}

function legend(items) {
  return h("div", { class: "chart-legend" }, items.map(([color, label]) =>
    h("span", null, h("span", { class: "sw", style: "background:" + color }), label)));
}

function emptyState(icon, big, small) {
  return h("div", { class: "empty" }, h("div", { class: "ic" }, icon),
    h("div", { class: "big" }, big), small ? h("div", { class: "small" }, small) : null);
}

function kvList(pairs) {
  const dl = h("dl", { class: "kv" });
  pairs.forEach(([k, v]) => { dl.append(h("dt", null, k), h("dd", null, v === null || v === undefined || v === "" ? "—" : v)); });
  return dl;
}

function section(title, hint, body, opts) {
  opts = opts || {};
  return h("div", { class: "panel" }, h("h3", null, title, hint ? h("span", { class: "hint" }, hint) : null, opts.actions ? h("span", { class: "grow" }) : null, opts.actions || null), body);
}

function exp(summaryText, body, hint) {
  return h("details", { class: "exp" },
    h("summary", null, summaryText, hint ? h("span", { class: "hint dim small" }, hint) : null),
    h("div", { class: "exp-body" }, body));
}

function badge(text, tone) { return h("span", { class: "tag " + (tone || "") }, text); }

// The confirm modal used for anything that changes a live system setting.
function confirmModal(opts) {
  return new Promise((resolve) => {
    const back = h("div", { class: "modal-back" });
    const done = (v) => { back.remove(); resolve(v); };
    const body = h("div", { class: "mbody" });
    addKid(body, opts.body);
    const m = h("div", { class: "modal" },
      h("div", { class: "mhead" }, h("h3", null, opts.title || "Confirm")),
      body,
      h("div", { class: "mfoot" },
        h("button", { class: "btn secondary", onclick: () => done(false) }, opts.cancel || "Cancel"),
        h("button", { class: "btn " + (opts.danger ? "danger" : "primary"), onclick: () => done(true) }, opts.confirm || "Confirm")));
    back.append(m);
    back.addEventListener("click", (e) => { if (e.target === back) done(false); });
    document.body.append(back);
  });
}

/* ---------- view switching ---------- */

const VIEW_TITLES = {
  overview: "Overview", connections: "Connections", routing: "Routing",
  ttl: "TTL / Hop limit", diag: "Diagnostics", logs: "Logs", settings: "Profiles & Settings",
};

function showView(name) {
  currentView = name;
  document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
  document.querySelectorAll("#nav button, #nav2 button").forEach((b) => b.classList.toggle("active", b.dataset.view === name));
  const view = $("#view-" + name);
  if (view) view.classList.add("active");
  document.title = (VIEW_TITLES[name] || "NetMerge") + " · NetMerge Control Center";
  if (name === "ttl" && !ttlReport) loadTTL();
  if (name === "diag") { ensureChecks(); }
  if (name === "logs") startLogs(); else stopLogs();
  if (name === "settings") loadSettings();
  if (name === "overview" || name === "connections" || name === "routing") renderAll();
}

/* ---------- overview ---------- */

function renderBadge() {
  const b = $("#engineBadge");
  clear(b);
  const on = state && state.engineOn;
  const st = state && state.engine;
  b.className = on ? "on" : "";
  b.append(
    h("span", { class: "pill" }, h("span", { class: "dot" }), on ? "Engine ON" : "Engine OFF"),
    h("span", { class: "small dim" }, st && st.mode ? st.mode : (on ? "" : "idle")));
}

// record real samples for the traffic chart
function pushHistory(snap) {
  if (!snap) return;
  history.push({ at: Date.now(), inRate: snap.inPerSecTotal || 0, outRate: snap.outPerSecTotal || 0 });
  if (history.length > HISTORY_MAX) history.shift();
}

function renderOverview() {
  const snap = state && state.snapshot;
  pushHistory(snap);

  // summary strip
  const strip = $("#ovSummary");
  const adapters = (snap && snap.adapters) || [];
  const eligible = adapters.filter((a) => !a.exclusionCode);
  const inUse = adapters.filter((a) => a.engine);
  const healthy = adapters.filter((a) => a.health && a.health.checked && a.health.ok);
  clear(strip);
  strip.append(
    seg("Eligible links", eligible.length + " / " + adapters.length, eligible.length ? "ok" : "dim"),
    seg("In engine", inUse.length ? String(inUse.length) : (state && state.engineOn ? "0" : "off"), inUse.length ? "ok" : "dim"),
    seg("Reachable", healthy.length ? String(healthy.length) : "—", healthy.length ? "ok" : "dim"),
    seg("Engine", state && state.engineOn ? "ON" : "OFF", state && state.engineOn ? "ok" : "dim"),
  );

  // warnings / gaps / errors
  const warnings = $("#ovWarnings");
  clear(warnings);
  if (state) {
    if (state.collecting) warnings.append(h("div", { class: "notice info" }, "The monitor has not completed its first adapter read yet."));
    if (state.collectError) warnings.append(h("div", { class: "notice bad" }, "The last adapter snapshot failed: " + state.collectError,
      h("div", { class: "small dim" }, "The view below is from the previous successful read.")));
    if (snap) {
      (snap.warnings || []).forEach((w) => warnings.append(h("div", { class: "notice warn" }, w)));
      (snap.errors || []).forEach((w) => warnings.append(h("div", { class: "notice bad" }, w)));
      (snap.gaps || []).forEach((w) => warnings.append(h("div", { class: "notice info" }, w)));
    }
  }

  // headline cards
  const cards = $("#ovCards");
  clear(cards);
  const inTot = snap ? snap.inPerSecTotal : null;
  const outTot = snap ? snap.outPerSecTotal : null;
  cards.append(
    card("Throughput ↓ down", rate(inTot), { sub: "sum of measured per-link rates", tone: "info", spark: sparkline("in") }),
    card("Throughput ↑ up", rate(outTot), { sub: "sum of measured per-link rates", tone: "cyan", spark: sparkline("out", true) }),
    card("Negotiated link speed", snap && snap.linkSpeedTotalBps ? rate(snap.linkSpeedTotalBps) : "—", { sub: "hardware speed, not achievable throughput" }),
  );

  // traffic panel with a shared dual chart
  const traffic = $("#ovTraffic");
  clear(traffic);
  if (history.length < 2) {
    traffic.append(emptyState("📶", "Collecting samples…", "Throughput history builds from the monitor's real counter reads; a gap or two will fill in shortly."));
  } else {
    const inSeries = history.map((p) => p.inRate || 0);
    const outSeries = history.map((p) => p.outRate || 0);
    traffic.append(
      chart(inSeries, { tall: true, fmt: rate, second: outSeries }),
      legend([["var(--accent)", "download (in)"], ["var(--cyan)", "upload (out)"], ["var(--line2)", "window ≈ " + (HISTORY_MAX * (state && state.monitor && state.monitor.intervalMs ? state.monitor.intervalMs : 2000) / 1000) + "s"]]),
      h("div", { class: "small dim mt" }, "Each bar is one monitor interval's measured aggregate rate across eligible adapters. This is measured movement, not a claim about maximum achievable bandwidth."),
    );
  }

  // engine
  const eng = $("#ovEngine");
  clear(eng);
  eng.append(engineBlock());

  renderNavCounts();
}

function seg(k, v, tone) {
  return h("div", { class: "seg" }, h("div", { class: "sk" }, k),
    h("div", { class: "sv " + (tone === "ok" ? "" : "dim"), style: tone === "ok" ? "color:var(--ok)" : "" }, v));
}

function sparkline(dir, out) {
  const series = history.slice(-40).map((p) => (out ? p.outRate : p.inRate) || 0);
  if (series.length < 2) return h("div", { class: "tiny faint" }, "collecting…");
  return chart(series, { out: !!out });
}

function renderNavCounts() {
  const c = $("#navConnCount");
  const adapters = (state && state.snapshot && state.snapshot.adapters) || [];
  if (c) c.textContent = adapters.length ? String(adapters.length) : "";
}

function eligibleCount(snap) {
  return (snap.adapters || []).filter((a) => !a.exclusionCode).length;
}

function engineBlock() {
  const wrap = h("div");
  if (!state || !state.engineOn) {
    wrap.append(
      h("div", { class: "dim" }, "The engine is off. Routes are normal: nothing is aggregated, and the adapter controls are idle."),
      h("div", { class: "row spread" },
        h("button", { class: "btn primary", onclick: (e) => engineAction("on", e.target) }, "Turn engine ON"),
        h("span", { class: "small dim" }, "Turning it on needs administrator rights; the engine will ask for elevation itself.")),
    );
    return wrap;
  }
  const st = state.engine;
  wrap.append(h("div", { class: "row between" },
    h("div", null,
      h("div", null, "Mode: ", h("strong", null, st.mode || UNKNOWN), " · IPv6: ", st.v6 || UNKNOWN,
        " · pid ", st.pid, " · up ", st.since ? dur(Date.now() - Date.parse(st.since)) : "—"),
      h("div", { class: "small dim mt" }, "Status written by the engine at ", stamp(st.updated), ".")),
    h("div", { class: "row tight" },
      h("button", { class: "btn secondary", onclick: (e) => engineAction("off", e.target) }, "Pause"),
      h("button", { class: "btn danger", onclick: (e) => engineAction("quit", e.target) }, "Quit engine"))));
  if (st.nics && st.nics.length) {
    wrap.append(h("div", { class: "mt" }, engineNicTable(st.nics)));
  }
  return wrap;
}

function engineNicTable(nics) {
  const t = h("table", { class: "compact" },
    h("thead", null, h("tr", null, ["Adapter", "IPv4", "IPv6", "Weight", "State", "Active", "Failed", "Bytes in", "Bytes out"].map((c, i) =>
      h("th", { class: i >= 4 ? "num" : "" }, c)))));
  const body = h("tbody");
  nics.forEach((l) => {
    body.append(h("tr", null,
      h("td", null, h("strong", null, l.name), l.present === false ? h("span", { class: "tag warn", style: "margin-left:6px" }, "absent") : null),
      h("td", { class: "mono small" }, l.ip || "—"),
      h("td", { class: "mono small" }, l.ip6 || "—"),
      h("td", { class: "num" }, l.weight ? l.weight.toFixed(2) : "—"),
      h("td", { class: "num small" }, (l.state || "") + (l.state6 && l.state6 !== "-" ? " / " + l.state6 : "")),
      h("td", { class: "num" }, nfmt(l.active)),
      h("td", { class: "num" }, l.failed ? nfmt(l.failed) : "0"),
      h("td", { class: "num" }, bytes(l.bytesIn)),
      h("td", { class: "num" }, bytes(l.bytesOut))));
  });
  t.append(body);
  return t;
}

async function engineAction(action, btn) {
  await guard(async () => {
    const d = await api("/api/engine", { method: "POST", body: { action: action } });
    toast("ok", d.message || ("Engine " + action + " requested."), d.detail);
    // give the marker a moment, then refresh
    setTimeout(pollStateOnce, 400);
  }, btn);
}

/* ---------- connections ---------- */

const KIND_ICON = {
  ethernet: ["Ethernet", "⇅", "ethernet"], wifi: ["Wi-Fi", "📶", "wifi"],
  "usb-tether": ["USB tether", "📱", "tether"], modem: ["Modem", "📡", "tether"],
  vpn: ["VPN", "🔒", "vpn"], other: ["Other", "•", ""],
};

function kindChip(a) {
  const [label, ic, cls] = KIND_ICON[a.kind] || KIND_ICON.other;
  return h("span", { class: "kind-ic " + cls, title: label }, ic);
}

/* ---------- public IPs (opt-in, masked for recording) ---------- */

// maskIP replaces the host part of an address with a placeholder so a screen recording shows
// that a public IP exists without showing the address itself. The network prefix is kept so the
// card still reads as a real answer; only the routable host is hidden.
function maskIP(ip) {
  if (!publicIPMasked || !ip) return ip;
  if (ip.indexOf(".") >= 0) {
    const p = ip.split(".");
    if (p.length === 4) return p[0] + "." + p[1] + "." + p[2] + ".•••";
    return "•••.•••.•••.•••";
  }
  if (ip.indexOf(":") >= 0) {
    const parts = ip.split(":");
    return parts.slice(0, 3).join(":") + ":•••";
  }
  return "•••";
}

// publicIPFor returns the last check's result for one adapter, or null when the adapter was
// not asked (or no check has run yet).
function publicIPFor(name) {
  if (!publicIP || !publicIP.results) return null;
  return publicIP.results.find((r) => r.name === name) || null;
}

// checkPublicIPs is the opt-in action. It makes one HTTPS request per uplink to a disclosed
// echo service, pinned to that uplink's socket, and only ever runs when this button is clicked.
async function checkPublicIPs(btn) {
  const d = await guard(() => api("/api/uplinks/publicip", { method: "POST" }), btn);
  if (!d) return;
  publicIP = d;
  renderConnections();
  const bad = (d.results || []).filter((r) => r.error).length;
  if (bad) toast("warn", "Checked. " + bad + " uplink(s) could not reach the echo service.");
  else toast("ok", "Public IPs resolved for " + ((d.results || []).length) + " uplink(s).");
}

// togglePublicIPMask flips the placeholder view and persists it across reloads.
function togglePublicIPMask() {
  publicIPMasked = !publicIPMasked;
  try { localStorage.setItem("netmerge.pubip.masked", publicIPMasked ? "1" : "0"); } catch (e) { /* storage may be blocked */ }
  syncMaskButton();
  renderConnections();
}

function syncMaskButton() {
  const b = $("#pubIPMask");
  if (!b) return;
  // The label states what clicking does, so the choice is never ambiguous on a recording.
  b.textContent = publicIPMasked ? "Show public IPs" : "Mask public IPs";
  b.setAttribute("aria-pressed", publicIPMasked ? "true" : "false");
}

function renderConnections() {
  const body = $("#connBody");
  const snap = state && state.snapshot;
  const adapters = (snap && snap.adapters) || [];
  const cc = $("#connCount");
  if (cc) cc.textContent = adapters.length
    ? adapters.length + " adapter" + (adapters.length === 1 ? "" : "s") + " · " + eligibleCount(snap) + " eligible for bonding"
    : "";

  const note = $("#pubIPNote");
  clear(note);
  if (publicIP) {
    const failed = (publicIP.results || []).filter((r) => r.error);
    note.append(h("div", { class: "notice info small", style: "margin-bottom:12px" },
      "Public IPs from ", h("b", {}, publicIP.endpoint),
      " — asked once when you clicked the button, over a socket pinned to each uplink.",
      publicIPMasked ? " Currently masked for recording." : "",
      failed.length ? h("div", { class: "small", style: "color:var(--warn);margin-top:4px" },
        failed.length + " uplink(s) did not answer: " + failed.map((r) => r.name).join(", ")) : null));
  }

  clear(body);
  if (!adapters.length) {
    body.append(emptyState("🔌", "No adapters in the current snapshot.",
      state && state.collecting ? "The monitor is still reading interfaces for the first time." : "Nothing was reported by the platform's interface reader."));
    return;
  }
  const grid = h("div", { class: "adapters" });
  adapters.forEach((a) => grid.append(adapterCard(a)));
  body.append(grid);
}

function adapterCard(a) {
  const excluded = !!a.exclusionCode;
  const open = openAdapters.has(a.name);
  const [kindLabel] = KIND_ICON[a.kind] || KIND_ICON.other;
  const r = a.rates || {};

  const chips = h("div", { class: "achips" });
  chips.append(badge(a.status || UNKNOWN, a.status === "active" ? "ok" : a.status === "eligible" ? "info" : a.status === "unhealthy" ? "warn" : "skip"));
  chips.append(badge(kindLabel, "skip"));
  if (a.engine) chips.append(badge("in engine", "ok"));
  if (a.hardware === false) chips.append(badge("virtual", "skip"));
  if (a.health) {
    if (!a.health.checked) chips.append(badge("not probed", "skip"));
    else if (a.health.ok) chips.append(badge("reachable" + (a.health.rttMs ? " " + a.health.rttMs.toFixed(0) + "ms" : ""), "ok"));
    else chips.append(badge("unreachable", "bad"));
  }
  if (excluded) chips.append(badge(a.exclusionCode, "warn"));

  const rates = h("div", { class: "arates" },
    h("div", { class: "arate" }, h("div", { class: "rk" }, "↓ down"), h("div", { class: "rv in" }, rateShort(r.inPerSec), h("span", { class: "tiny dim" }, " bit/s"))),
    h("div", { class: "arate" }, h("div", { class: "rk" }, "↑ up"), h("div", { class: "rv out" }, rateShort(r.outPerSec), h("span", { class: "tiny dim" }, " bit/s"))),
    h("div", { class: "arate" }, h("div", { class: "rk" }, "link speed"), h("div", { class: "rv" }, a.speedBps ? rateShort(a.speedBps) : "—", a.speedBps ? h("span", { class: "tiny dim" }, " bit/s") : null)),
  );

  const pub = publicIPFor(a.name);

  const cardEl = h("div", { class: "acard" + (excluded ? " excluded" : "") },
    h("div", { class: "ahead" },
      h("div", { class: "grow" },
        h("div", { class: "aname" }, kindChip(a), a.name),
        a.description ? h("div", { class: "adesc" }, a.description) : null),
      h("button", { class: "btn ghost sm", onclick: () => { toggleAdapter(a.name); } }, open ? "▾ Hide" : "▸ Detail")),
    chips,
    rates,
    pub ? h("div", { class: "small", style: "margin-top:8px" },
      h("span", { class: "dim" }, "Public IP "),
      pub.error
        ? h("span", { style: "color:var(--warn)" }, "unreachable over this uplink")
        : h("b", { style: publicIPMasked ? "letter-spacing:1px" : "" }, maskIP(pub.ip))) : null,
    h("div", { class: "small dim mt" }, a.link || "link state unknown",
      a.exclusion ? h("div", { class: "small", style: "color:var(--warn);margin-top:3px" }, a.exclusion) : null),
    open ? adapterDetail(a) : null,
  );
  return cardEl;
}

function toggleAdapter(name) {
  if (openAdapters.has(name)) openAdapters.delete(name); else openAdapters.add(name);
  renderConnections();
}

function adapterDetail(a) {
  const d = h("div", { class: "adetail" });
  const pairs = [];
  pairs.push(["IPv4", a.ipv4 && a.ipv4.length ? a.ipv4.map((x) => x.address + (x.prefixLength ? "/" + x.prefixLength : "")).join(", ") : "—"]);
  pairs.push(["IPv6", a.ipv6 && a.ipv6.length ? a.ipv6.map((x) => x.address + (x.prefixLength ? "/" + x.prefixLength : "")).join(", ") : "—"]);
  const pub = publicIPFor(a.name);
  if (pub) {
    pairs.push(["Public IP", pub.error
      ? h("span", { style: "color:var(--warn)" }, "not reachable over this uplink")
      : h("b", { style: publicIPMasked ? "letter-spacing:1px" : "" }, maskIP(pub.ip))]);
  }
  if (a.gateways4 && a.gateways4.length) pairs.push(["Gateway v4", a.gateways4.join(", ")]);
  if (a.gateways6 && a.gateways6.length) pairs.push(["Gateway v6", a.gateways6.join(", ")]);
  if (a.dns4 && a.dns4.length) pairs.push(["DNS v4", a.dns4.join(", ")]);
  if (a.dns6 && a.dns6.length) pairs.push(["DNS v6", a.dns6.join(", ")]);
  // tri() returns a real element, so the pieces are passed as separate children rather than
  // concatenated into a string - which would stringify the element as "[object HTMLSpanElement]".
  pairs.push(["DHCP", ["v4: ", tri(a.dhcp4), " \u00b7 v6: ", tri(a.dhcp6)]]);
  if (a.mtu) pairs.push(["MTU", String(a.mtu)]);
  if (a.mac) pairs.push(["MAC", a.mac]);
  if (a.driverProvider) pairs.push(["Driver", a.driverProvider + (a.driverVersion ? " " + a.driverVersion : "")]);
  if (a.counters) pairs.push(["Totals", "in " + bytes(a.counters.in) + " · out " + bytes(a.counters.out)]);
  if (a.engineAssigned !== null && a.engineAssigned !== undefined) pairs.push(["Engine assigned", String(a.engineAssigned)]);
  d.append(kvList(pairs));
  if (a.health && a.health.checked) {
    d.append(h("div", { class: "small mt" }, "Probe: ", a.health.ok ? statusTag("pass") : statusTag("fail"),
      " ", h("span", { class: "dim" }, (a.health.rttMs ? "rtt " + a.health.rttMs.toFixed(1) + "ms · " : "") +
        (a.health.lossPct !== undefined ? "loss " + pct(a.health.lossPct) + " · " : "") +
        (a.health.endpoint ? "to " + a.health.endpoint : ""))));
  }
  (a.warnings || []).forEach((w) => d.append(h("div", { class: "notice warn small" }, w)));
  (a.gaps || []).forEach((g) => d.append(h("div", { class: "notice info small" }, g)));
  return d;
}

function tri(v) {
  if (v === "yes") return h("span", { class: "tag ok" }, "yes");
  if (v === "no") return h("span", { class: "tag skip" }, "no");
  return h("span", { class: "tag skip" }, "unknown");
}

/* ---------- routing ---------- */

function renderRouting() {
  // active profile summary
  const rp = $("#routeProfile");
  clear(rp);
  const cfg = state && state.settings;
  const prof = cfg && cfg.profiles && cfg.profiles[cfg.activeProfile];
  rp.append(section("Active profile",
    "a profile is a request expressed in real engine flags; the engine's status file is the truth about what happened",
    profileSummary(cfg, prof)));

  // topology
  const topo = $("#routeTopo");
  clear(topo);
  topo.append(topology());

  // cross-adapter observations
  const cross = $("#routeCross");
  clear(cross);
  const snap = state && state.snapshot;
  if (snap && ((snap.warnings || []).length || (snap.errors || []).length)) {
    const list = h("div");
    (snap.warnings || []).forEach((w) => list.append(h("div", { class: "notice warn small" }, w)));
    (snap.errors || []).forEach((e) => list.append(h("div", { class: "notice bad small" }, e)));
    cross.append(list);
  } else {
    cross.append(h("div", { class: "dim small" }, "No cross-adapter warnings. The last snapshot found a consistent picture across links."));
  }

  // default routes (compact) + full table (expandable)
  const rd = $("#routeDefaults");
  clear(rd);
  rd.append(defaultRouteTable(snap));
  const rf = $("#routeFull");
  clear(rf);
  rf.append(fullRouteTable(snap));
}

function profileSummary(cfg, prof) {
  const wrap = h("div");
  if (!cfg || !cfg.profiles) { wrap.append(h("div", { class: "dim" }, "No profiles are loaded.")); return wrap; }
  const activeName = cfg.activeProfile;
  wrap.append(h("div", { class: "row between" },
    h("div", null, "Selected: ", h("strong", null, activeName || "(none)")),
    h("span", { class: "tag info" }, "selection does not change the running engine")));
  if (prof) {
    if (prof.description) wrap.append(h("div", { class: "small dim mt" }, prof.description));
    wrap.append(h("div", { class: "small mt" }, "Requested engine flags: ", h("span", { class: "mono" }, requestedFlags(prof))));
  }
  const st = state && state.engine;
  wrap.append(h("div", { class: "small dim mt" }, st
    ? "The engine is currently running with mode " + (st.mode || UNKNOWN) + " and IPv6 " + (st.v6 || UNKNOWN) + "."
    : "The engine is not running, so no profile's flags are in effect right now."));
  wrap.append(h("div", { class: "small faint mt" }, "Selecting or editing a profile changes only what the engine would be asked for next time it starts. It never restarts or reconfigures a running engine on its own."));
  return wrap;
}

function requestedFlags(p) {
  if (!p || !p.engine) return "(no engine overrides)";
  const e = p.engine;
  const bits = [];
  if (e.include && e.include.length) bits.push("--include=" + e.include.join(","));
  if (e.exclude && e.exclude.length) bits.push("--exclude=" + e.exclude.join(","));
  if (e.ipv6 && e.ipv6 !== "auto") bits.push("--ipv6=" + e.ipv6);
  if (e.mtu) bits.push("--mtu=" + e.mtu);
  if (e.autoWeight === false) bits.push("--no-auto-weight");
  return bits.length ? bits.join(" ") : "(defaults)";
}

function topology() {
  const snap = state && state.snapshot;
  const adapters = ((snap && snap.adapters) || []).filter((a) => !a.exclusionCode);
  const on = state && state.engineOn;
  const wrap = h("div", { class: "topo" });
  const linksCol = h("div", { style: "display:flex;flex-direction:column;gap:8px" });
  adapters.forEach((a) => {
    const inEngine = a.engine;
    linksCol.append(h("div", { class: "node" },
      h("div", { class: "nlabel" }, (KIND_ICON[a.kind] || KIND_ICON.other)[0]),
      h("div", { class: "nval" }, a.name),
      h("div", { class: "tiny " + (inEngine ? "" : "faint"), style: inEngine ? "color:var(--ok)" : "" },
        inEngine ? "in use · " + rateShort((a.rates || {}).inPerSec) + "↓" : (on ? "not used" : "idle"))));
  });
  const core = h("div", { class: "link" },
    h("div", { style: "display:flex;flex-direction:column;gap:6px;align-items:center" },
      adapters.map(() => h("div", { class: "wire" + (on ? " on" : "") })),
      h("div", { class: "node core", style: "margin-top:6px" },
        h("div", { class: "nlabel" }, "net-merge engine"),
        h("div", { class: "nval" }, on ? "ON" : "OFF"))));
  const out = h("div", { class: "link" }, h("div", { class: "wire" + (on ? " on" : "") }));
  const internet = h("div", { class: "node" },
    h("div", { class: "nlabel" }, "internet"),
    h("div", { class: "nval" }, on ? "via bonded links" : "via default route"));
  wrap.append(linksCol, core, out, internet);
  if (!adapters.length) wrap.append(h("div", { class: "dim small", style: "align-self:center" }, "No eligible adapters to show."));
  return wrap;
}

function defaultRouteTable(snap) {
  const routes = ((snap && snap.adapters) || []).flatMap((a) =>
    ((a.defaultRoutes || []).map((r) => Object.assign({ iface: a.name }, r))));
  if (!routes.length) return h("div", { class: "dim small" }, "No default routes reported by the platform.");
  const t = h("table", { class: "compact" },
    h("thead", null, h("tr", null, ["Family", "Destination", "Next hop", "Interface", "Protocol", "Metric"].map((c, i) => h("th", { class: i === 5 ? "num" : "" }, c)))));
  const body = h("tbody");
  routes.forEach((r) => body.append(h("tr", null,
    h("td", null, r.family || "—"), h("td", { class: "mono small" }, r.destination || "—"),
    h("td", { class: "mono small" }, r.nextHop || "(on-link)"), h("td", null, r.iface || r.name || "—"),
    h("td", null, r.protocol || "—"), h("td", { class: "num" }, r.metric || "—"))));
  t.append(body);
  return t;
}

function fullRouteTable(snap) {
  const routes = (snap && snap.routes) || [];
  if (!routes.length) return h("div", { class: "dim small" }, "The platform did not expose a full routing table for this snapshot.");
  const t = h("table", { class: "compact" },
    h("thead", null, h("tr", null, ["Family", "Destination", "Next hop", "Interface", "Protocol", "Metric"].map((c, i) => h("th", { class: i === 5 ? "num" : "" }, c)))));
  const body = h("tbody");
  routes.forEach((r) => body.append(h("tr", null,
    h("td", null, r.family || "—"), h("td", { class: "mono small" }, r.destination || "—"),
    h("td", { class: "mono small" }, r.nextHop || "(on-link)"), h("td", null, r.interfaceName || "—"),
    h("td", null, r.protocol || "—"), h("td", { class: "num" }, r.metric || "—"))));
  t.append(body);
  return t;
}

/* ---------- TTL / hop limit ---------- */

const TTL_PRESETS = [
  { key: "64", label: "64", note: "Common desktop default. Neutral — matches what most OSes ship." },
  { key: "65", label: "65", note: "Sits just above the usual 64 to survive one extra hop while staying unremarkable." },
  { key: "128", label: "128", note: "Windows default. Higher headroom; still a normal value." },
  { key: "255", label: "255", note: "Maximum. Some carriers/networks treat unusually high values differently — use knowingly." },
];
// The staged targets are keyed by the same "ipv4"/"ipv6" identifiers the control cards use.
// A mismatch here is silent in the worst way: the value looks staged but the preview/apply
// buttons never enable.
let ttlStaged = { ipv4: null, ipv6: null };

async function loadTTL(btn) {
  await guard(async () => {
    const d = await api("/api/ttl");
    ttlReport = d.report || d;
    ttlStaged = { ipv4: null, ipv6: null };
    renderTTL();
    renderTTLHistory([]);
    loadTTLHistory();
  }, btn);
}

async function loadTTLHistory() {
  try {
    const d = await api("/api/ttl/history");
    renderTTLHistory(d.events || []);
  } catch (e) { /* history is optional */ }
}

function renderTTL() {
  const body = $("#ttlBody");
  const st = $("#ttlState");
  clear(body);
  if (!ttlReport) { body.append(emptyState("⏱", "Loading current TTL / hop-limit values…")); return; }

  const rep = ttlReport;
  if (st) {
    const caps = rep.capabilities || {};
    st.textContent = caps.platform ? (caps.platform + " · " + (caps.supported ? "changes supported here" : (caps.readable ? "read-only: values are live, but no write mechanism on this host" : "no readable source on this host"))) : "";
  }

  if (rep.warnings && rep.warnings.length) {
    rep.warnings.forEach((w) => body.append(h("div", { class: "notice warn" }, w)));
  }
  if (!rep.capabilities || !rep.capabilities.readable) {
    body.append(h("div", { class: "notice info" }, "This host exposes no readable source for packet TTL / hop limit, so no current values are shown.",
      rep.capabilities && rep.capabilities.notes ? h("ul", null, rep.capabilities.notes.map((n) => h("li", null, n))) : null));
  } else if (!rep.capabilities.supported) {
    body.append(h("div", { class: "notice info" }, "Current values are read live from this host and shown below. Changing packet TTL / hop limit is a Windows feature in this build, so the controls here are read-only and nothing on this host is modified.",
      rep.capabilities && rep.capabilities.notes ? h("ul", null, rep.capabilities.notes.map((n) => h("li", null, n))) : null));
  }

  // elevation banner
  body.append(h("div", { class: "notice " + (rep.elevated ? "ok" : "info") }, rep.elevationNote ||
    (rep.elevated ? "This process is elevated, so it can change system settings." : "This process is not elevated. Inspection works without it; a change will request elevation when you confirm it.")));

  // ---- header controls ----
  const header = h("div", { class: "panel" });
  const caps = rep.capabilities || {};
  const canWriteAny = (rep.settings || []).some((s) => s.writable);
  // On a host with no write mechanism the section must not promise an action it cannot perform:
  // the heading says what is actually being shown instead of "Apply a change".
  header.append(canWriteAny
    ? h("h3", null, "Apply a change", h("span", { class: "hint" }, "preview with a dry run first; nothing is written without confirmation"))
    : h("h3", null, "Current values", h("span", { class: "hint" }, "read live from this host; changing them is not available here")));

  // v4 card
  const v4sys = (rep.settings || []).find((s) => s.family === "ipv4" && s.scope === "system-global");
  const v6sys = (rep.settings || []).find((s) => s.family === "ipv6" && s.scope === "system-global");
  header.append(ttlControlCard("IPv4 TTL", "ipv4", v4sys, caps));
  header.append(ttlControlCard("IPv6 hop limit", "ipv6", v6sys, caps));

  // preview / confirm / restore actions — hidden entirely on a read-only host, since staging a
  // value there would be a dead end (the manager refuses every write).
  if (canWriteAny) {
    const actions = h("div", { class: "row spread mt" });
    const stagedAny = ttlStaged.ipv4 !== null || ttlStaged.ipv6 !== null;
    actions.append(
      h("div", { class: "small dim" }, stagedAny ? "You have unsaved, unapplied target values." : "No change staged. Pick a preset or type a custom value above."),
      h("div", { class: "row tight" },
        h("button", { class: "btn", disabled: !stagedAny, onclick: (e) => ttlApply(e.target, true) }, "Preview (dry run)"),
        h("button", { class: "btn primary", disabled: !stagedAny, onclick: (e) => ttlApply(e.target, false) }, "Apply change"),
        h("button", { class: "btn secondary", onclick: (e) => ttlRestore(e.target, false) }, "Restore captured originals")));
    header.append(actions);
  }
  body.append(header);

  // ---- read-back: per-interface + non-settings ----
  const perIface = (rep.settings || []).filter((s) => s.scope === "per-interface");
  if (perIface.length) {
    body.append(section("Per-interface values", "these override the system-global value for packets leaving on that adapter", perIfaceTable(perIface)));
  }
  const notSettings = rep.notSettings || [];
  if (notSettings.length) {
    body.append(section("Not host-level settings", "shown so they are never confused with the packet-header values above", notSettingsTable(notSettings)));
  }
  if (rep.readErrors && rep.readErrors.length) {
    const el = h("div", { class: "panel" }, h("h3", null, "Read errors"));
    rep.readErrors.forEach((f) => el.append(h("div", { class: "notice bad small" },
      h("strong", null, f.setting && f.setting.id ? f.setting.id : "setting"), ": ", f.message,
      f.details && f.details.length ? h("ul", null, f.details.map((d) => h("li", null, d))) : null)));
    body.append(el);
  }

  renderTTLConfig(rep.config);
}

function ttlControlCard(title, key, setting, caps) {
  const card = h("div", { class: "ttl-card", style: "margin-top:12px" });
  const readable = !!(caps && caps.readable);
  const supported = readable && !!(caps && caps.supported) && !!(setting && setting.writable);
  const cur = setting ? setting.value : null;
  const origin = setting ? setting.valueOrigin : null;
  const staged = ttlStaged[key];

  // What to show for "current" when there is no number. A readable host with no value means the
  // OS's built-in default applies; a host with no read source must not claim that, because we
  // never actually looked.
  const curText = cur !== null && cur !== undefined ? String(cur)
    : (readable ? "default" : "unknown");
  const curIsUnknown = cur === null || cur === undefined;

  card.append(h("div", { class: "tt" },
    h("div", { class: "tname" }, title, " ", h("span", { class: "scope-badge system" }, "system-wide")),
    !readable ? badge("not readable here", "warn")
      : (setting && !setting.writable ? badge("read-only", "warn") : null)));

  const vals = h("div", { class: "ttl-vals" });
  vals.append(
    h("div", null, h("div", { class: "lbl" }, "current"),
      h("div", { class: "cur" + (curIsUnknown ? " def" : "") }, curText)),
    h("div", null, h("div", { class: "lbl" }, "target"),
      h("div", { class: "cur" + (staged === null ? " def" : ""), style: staged !== null ? "color:var(--accent2)" : "" }, staged === null ? "—" : String(staged))),
  );
  if (staged !== null && staged !== cur) {
    vals.append(h("div", { class: "ttl-diff" }, h("span", { class: "from" }, curIsUnknown ? "default" : String(cur)),
      h("span", { class: "arrow" }, "→"), h("span", { class: "to" }, String(staged))));
  }
  card.append(vals);
  card.append(h("div", { class: "tiny faint" },
    origin ? ("source: " + origin)
      : (readable ? "not explicitly configured — the OS built-in default is in use" : "no readable source on this host, so the current value was not shown")));

  // presets + custom — only when this value can actually be changed, so a read-only host never
  // offers staging controls that would go nowhere.
  if (supported) {
    const presetRow = h("div", { class: "preset-row" });
    TTL_PRESETS.forEach((p) => {
      const on = String(staged) === p.key || (staged === null && String(cur) === p.key);
      presetRow.append(h("button", { class: "preset" + (on ? " active" : ""), title: p.note, onclick: () => { ttlStaged[key] = Number(p.key); renderTTL(); } }, p.label));
    });
    const custom = h("input", { type: "number", min: 1, max: 255, value: staged !== null ? staged : "", placeholder: "custom", style: "width:80px", onchange: (e) => { const n = Number(e.target.value); ttlStaged[key] = isFinite(n) && n >= 1 && n <= 255 ? n : null; renderTTL(); } });
    presetRow.append(h("span", { class: "tiny faint", style: "align-self:center" }, "or"), custom, h("span", { class: "tiny faint", style: "align-self:center" }, "1–255"));
    card.append(presetRow);
  } else {
    card.append(h("div", { class: "tiny", style: "color:var(--warn);margin-top:8px" },
      setting && setting.writableReason ? setting.writableReason
        : (readable ? "This value cannot be changed on this host." : "This value could not be read on this host.")));
  }
  return card;
}

function perIfaceTable(rows) {
  const t = h("table", { class: "compact" },
    h("thead", null, h("tr", null, ["Interface", "Family", "Current", "Source", "Writable"].map((c) => h("th", null, c)))));
  const body = h("tbody");
  rows.forEach((s) => body.append(h("tr", null,
    h("td", null, s.interface || "—"), h("td", null, s.family || "—"),
    h("td", { class: "num" }, s.value === null || s.value === undefined
      ? h("span", { class: "dim" }, s.writable ? "default" : "unknown")
      : String(s.value)),
    h("td", { class: "small dim" }, s.valueOrigin || "—"),
    h("td", null, s.writable ? badge("yes", "ok") : badge("no", "warn")))));
  t.append(body);
  return t;
}

function notSettingsTable(rows) {
  const t = h("table", { class: "compact" },
    h("thead", null, h("tr", null, ["Kind", "Family", "Scope", "Why it is here"].map((c) => h("th", null, c)))));
  const body = h("tbody");
  rows.forEach((s) => body.append(h("tr", null,
    h("td", null, s.kind || "—"), h("td", null, s.family || "—"),
    h("td", null, h("span", { class: "scope-badge per" }, s.scope || "—")),
    h("td", { class: "small dim" }, s.writableReason || "shown for completeness"))));
  t.append(body);
  return t;
}

async function ttlApply(btn, dry) {
  // The preview must describe the values the user staged on screen, not whatever was last
  // saved to the config file. Staged values ride along as an override that lives for this
  // one operation, so the manager reports the real from/to for exactly what they chose.
  const cfg = buildTTLOverride();
  const body = { dryRun: dry, confirm: !dry, config: cfg };
  const preview = await guard(() => api("/api/ttl/apply", { method: "POST", body }), btn);
  if (!preview) return;
  if (dry) { renderOutcomeModal("Dry-run preview", preview, true, () => ttlApply(btn, false)); return; }
  // a real apply: reload and show read-back
  await loadTTL();
  renderOutcomeModal("Applied", preview, false);
}

// buildTTLOverride returns the config this operation should act on: the stored configuration
// with the staged values substituted in. A family with no staged value keeps the stored target,
// so applying after staging only one family does not silently reset the other.
function buildTTLOverride() {
  const base = (ttlReport && ttlReport.config) || {};
  const cfg = Object.assign({}, base);
  // Fill in anything the stored config is missing. An unsaved configuration arrives as an
  // empty object and Validate() rejects that outright, so the scaffolding around the staged
  // values must never be the reason this operation fails.
  cfg.schema = cfg.schema || "netmerge-ttl/1";
  cfg.version = cfg.version || 1;
  cfg.enabled = true;
  if (ttlStaged.ipv4 !== null) cfg.bumpIPv4 = ttlStaged.ipv4;
  if (ttlStaged.ipv6 !== null) cfg.bumpIPv6 = ttlStaged.ipv6;
  if (cfg.bumpIPv4 == null || cfg.bumpIPv4 < 1 || cfg.bumpIPv4 > 255) cfg.bumpIPv4 = 64;
  if (cfg.bumpIPv6 == null || cfg.bumpIPv6 < 1 || cfg.bumpIPv6 > 255) cfg.bumpIPv6 = 64;
  if (!cfg.interfacePolicy || (cfg.interfacePolicy === "list" && !(cfg.includeIfaces || []).length)) {
    cfg.interfacePolicy = "none";
  }
  return cfg;
}

async function ttlRestore(btn, dry) {
  const out = await guard(() => api("/api/ttl/restore", { method: "POST", body: { dryRun: false, confirm: true } }), btn);
  if (!out) return;
  await loadTTL();
  renderOutcomeModal("Restore", out, false);
}

function renderOutcomeModal(title, out, dry, onConfirm) {
  const body = h("div");
  body.append(h("div", { class: "small dim" }, (out.applied || 0) + " applied, " + (out.failed || 0) + " failed" + (out.dryRun ? " (nothing was written)" : "")));
  if (out.changes && out.changes.length) {
    const t = h("table", { class: "compact", style: "margin-top:8px" },
      h("thead", null, h("tr", null, ["Setting", "From", "To", "Result"].map((c, i) => h("th", { class: i === 1 || i === 2 ? "num" : "" }, c)))));
    const tb = h("tbody");
    out.changes.forEach((c) => {
      const r = c.outcome;
      tb.append(h("tr", null,
        h("td", { class: "small mono" }, c.setting && c.setting.id ? c.setting.id : "—"),
        h("td", { class: "num" }, c.from === null || c.from === undefined ? h("span", { class: "dim" }, "—") : String(c.from)),
        h("td", { class: "num" }, String(c.to)),
        h("td", null, outcomeTag(r, c.verified), c.detail ? h("div", { class: "tiny dim" }, c.detail) : null)));
    });
    t.append(tb);
    body.append(t);
  }
  if (out.notes && out.notes.length) out.notes.forEach((n) => body.append(h("div", { class: "notice info small mt" }, n)));
  if (out.rollbackIncomplete) {
    body.append(h("div", { class: "notice bad" }, h("strong", null, "Rollback was incomplete."),
      out.rollbackDetail && out.rollbackDetail.length ? h("ul", null, out.rollbackDetail.map((d) => h("li", null, d))) : h("div", { class: "small" }, "Some values could not be returned to their originals. Inspect the per-interface table and restore manually if needed.")));
  } else if (out.rolledBack) {
    body.append(h("div", { class: "notice warn" }, "A failure occurred and the change was rolled back — no partial state was left in place."));
  }

  const back = h("div", { class: "modal-back" });
  const close = () => back.remove();
  const foot = h("div", { class: "mfoot" }, h("button", { class: "btn secondary", onclick: close }, "Close"));
  if (dry && onConfirm) {
    foot.append(h("button", { class: "btn primary", onclick: () => { close(); onConfirm(); } }, "Confirm & apply"));
  }
  back.append(h("div", { class: "modal" }, h("div", { class: "mhead" }, h("h3", null, title + (dry ? " (dry run)" : ""))), h("div", { class: "mbody" }, body), foot));
  back.addEventListener("click", (e) => { if (e.target === back) close(); });
  document.body.append(back);
}

function outcomeTag(r, verified) {
  if (r === "applied") return verified ? badge("applied · verified", "ok") : badge("applied · unverified", "warn");
  if (r === "unchanged") return badge("unchanged", "skip");
  if (r === "failed") return badge("failed", "bad");
  if (r === "rolled-back") return badge("rolled-back", "warn");
  if (r === "rollback-incomplete") return badge("rollback incomplete", "bad");
  if (r === "dry-run") return badge("dry-run", "info");
  return badge(r || UNKNOWN, "skip");
}

function renderTTLConfig(cfg) {
  const el = $("#ttlConfig");
  clear(el);
  if (!cfg) { el.append(h("div", { class: "dim small" }, "No stored configuration.")); return; }
  el.append(h("div", { class: "small", style: "margin-bottom:10px" },
    "This configuration records what you would <em>like</em> written. It is saved here and never applied by itself — a change only happens when you explicitly confirm one on this page.",
    cfg.enabled ? null : h("span", { class: "tag warn", style: "margin-left:8px" }, "management is off")));
  el.append(kvList([
    ["Opted in to management", cfg.enabled ? "yes" : "no"],
    ["IPv4 target", String(cfg.bumpIPv4)],
    ["IPv6 target", String(cfg.bumpIPv6)],
    ["Per-interface policy", cfg.interfacePolicy || "—"],
    ["Include interfaces", cfg.includeIfaces && cfg.includeIfaces.length ? cfg.includeIfaces.join(", ") : "(all)"],
    ["Exclude interfaces", cfg.excludeIfaces && cfg.excludeIfaces.length ? cfg.excludeIfaces.join(", ") : "(none)"],
    ["Last saved", stamp(cfg.updated)],
  ]));
}

function renderTTLHistory(events) {
  const el = $("#ttlHistory");
  clear(el);
  if (!events || !events.length) { el.append(h("div", { class: "dim small" }, "No TTL/hop-limit changes have been attempted yet.")); return; }
  const t = h("table", { class: "compact" },
    h("thead", null, h("tr", null, ["When", "Setting", "Old", "New", "Result", "Reason"].map((c, i) => h("th", { class: i === 2 || i === 3 ? "num" : "" }, c)))));
  const tb = h("tbody");
  events.forEach((e) => tb.append(h("tr", null,
    h("td", { class: "small" }, stamp(e.at)),
    h("td", { class: "small mono" }, e.interface ? (e.family + " per-iface " + e.interface) : e.id),
    h("td", { class: "num" }, e.old === null || e.old === undefined ? h("span", { class: "dim" }, "—") : String(e.old)),
    h("td", { class: "num" }, e.new === null || e.new === undefined ? h("span", { class: "dim" }, "—") : String(e.new)),
    h("td", null, outcomeTag(e.outcome), e.error ? h("div", { class: "tiny", style: "color:var(--bad)" }, e.error) : null),
    h("td", { class: "small dim" }, e.reason || "—"))));
  t.append(tb);
  el.append(t);
}

/* ---------- diagnostics ---------- */

let diagChecks = null;   // { checks, categories, disabledChecks }
let diagSelected = new Set();

async function ensureChecks() {
  if (diagChecks) return;
  try {
    diagChecks = await api("/api/diag/checks");
    renderChecks();
  } catch (e) { /* registry unavailable; the run buttons explain why */ }
}

function renderChecks() {
  const el = $("#diagChecks");
  clear(el);
  if (!diagChecks) { el.append(h("div", { class: "dim small" }, "The diagnostics registry is not available in this environment.")); return; }
  const disabled = new Set(diagChecks.disabledChecks || []);
  const grid = h("div", { class: "grid2" });
  (diagChecks.checks || []).forEach((c) => {
    const off = disabled.has(c.id);
    const box = h("input", { type: "checkbox", checked: !off && diagSelected.has(c.id), onchange: (e) => { if (e.target.checked) diagSelected.add(c.id); else diagSelected.delete(c.id); } });
    grid.append(h("label", { class: "inline", style: "align-items:flex-start;flex-direction:column;gap:4px" },
      h("div", { class: "row tight" }, box, h("strong", null, c.title),
        c.category ? badge(c.category, "skip") : null,
        c.needsAdmin ? badge("needs admin", "warn") : null,
        c.slow ? badge("slow", "skip") : null,
        off ? badge("disabled", "skip") : null),
      c.purpose ? h("div", { class: "help" }, c.purpose) : null,
      (c.establishes && c.establishes.length) ? h("div", { class: "tiny faint" }, "proves: " + c.establishes.join("; ")) : null,
      (c.doesNotEstablish && c.doesNotEstablish.length) ? h("div", { class: "tiny", style: "color:var(--warn)" }, "does not prove: " + c.doesNotEstablish.join("; ")) : null));
  });
  el.append(grid);
}

async function runDiag(all, btn) {
  const ids = all ? [] : Array.from(diagSelected);
  if (!all && !ids.length) { toast("warn", "Select at least one check, or use Run all."); return; }
  await guard(async () => {
    const d = await api("/api/diag/run", { method: "POST", body: { all: !!all, ids: ids } });
    diagJobId = d.id;
    $("#diagCancel").disabled = false;
    showProgress("diag", "Running diagnostics…");
    pollDiagJob();
  }, btn);
}

function showProgress(kind, label) {
  const p = $("#diagProgress");
  p.classList.remove("hidden");
  setAll(p, [h("div", { class: "panel" }, h("h3", null, label),
    h("div", { class: "progress indet" }, h("span")))]);
}

function hideProgress() { $("#diagProgress").classList.add("hidden"); }

async function pollDiagJob() {
  if (!diagJobId) return;
  try {
    const d = await api("/api/diag/runs/" + diagJobId);
    if (d.status === "running") { showProgress("diag", d.progress || "Running diagnostics…"); setTimeout(pollDiagJob, 700); return; }
    hideProgress();
    $("#diagCancel").disabled = true;
    lastDiag = d.diag || null;
    renderDiagResults(lastDiag, d);
  } catch (e) { hideProgress(); toast("bad", "Could not poll the diagnostics job.", e.message, e.code); }
}

async function cancelDiag(btn) {
  if (!diagJobId) return;
  await guard(() => api("/api/diag/cancel", { method: "POST", body: { id: diagJobId } }), btn);
  toast("info", "Cancellation requested.");
}

function renderDiagResults(dv, job) {
  const el = $("#diagResults");
  clear(el);
  if (job && job.status === "failed") { el.append(h("div", { class: "notice bad" }, job.error || "The diagnostics run failed.")); return; }
  if (job && job.status === "cancelled") { el.append(h("div", { class: "notice warn" }, "The run was cancelled. Results below are partial.")); }
  if (!dv || !dv.result) { el.append(emptyState("🩺", "No diagnostics run yet.", "Run all supported checks, or select specific ones and run them.")); return; }
  const r = dv.result;
  const panel = h("div", { class: "panel" });
  panel.append(h("h3", null, "Results", h("span", { class: "hint" }, r.summary || "")));
  panel.append(h("div", { class: "small dim" }, "Started " + stamp(r.started) + (r.duration ? " · took " + goDur(r.duration) : "") + (r.platform ? " · " + r.platform : "")));
  (r.results || []).forEach((res) => panel.append(diagResultCard(res)));
  if (r.skipped && Object.keys(r.skipped).length) {
    const sk = h("div", { class: "notice info" }, h("strong", null, "Skipped checks"));
    const ul = h("ul");
    Object.entries(r.skipped).forEach(([id, reason]) => ul.append(h("li", null, h("span", { class: "mono" }, id), ": ", reason)));
    sk.append(ul); panel.append(sk);
  }
  el.append(panel);
}

function diagResultCard(res) {
  const st = res.status;
  const tone = st === "pass" ? "ok" : st === "warn" ? "warn" : st === "fail" || st === "error" ? "bad" : "skip";
  const body = h("div", { class: "mt" });
  if (res.summary) body.append(h("div", null, res.summary));
  if (res.established && res.established.length) {
    body.append(h("div", { class: "small mt" }, h("strong", null, "This run proved:")));
    const ul = h("ul", { class: "est" }); res.established.forEach((x) => ul.append(h("li", null, x))); body.append(ul);
  }
  if (res.inconclusive && res.inconclusive.length) {
    body.append(h("div", { class: "small mt" }, h("strong", null, "Inconclusive:")));
    const ul = h("ul"); res.inconclusive.forEach((x) => ul.append(h("li", null, x))); body.append(ul);
  }
  if (res.nextSteps && res.nextSteps.length) {
    body.append(h("div", { class: "small mt" }, h("strong", null, "Supported next steps:")));
    const ul = h("ul"); res.nextSteps.forEach((x) => ul.append(h("li", null, x))); body.append(ul);
  }
  if (res.measure) {
    body.append(h("div", { class: "small mt" }, "Measure: ", h("span", { class: "mono" }, (res.measure.value != null ? res.measure.value : "—") + (res.measure.unit ? " " + res.measure.unit : ""))));
  }
  if (res.errorCodes && res.errorCodes.length) {
    body.append(h("div", { class: "row tight mt" }, res.errorCodes.map((c) => badge(c, "info"))));
  }
  if (res.evidence && res.evidence.length) {
    body.append(h("details", { class: "exp inline mt" }, h("summary", null, "Evidence (" + res.evidence.length + ")"),
      h("div", { class: "exp-body" }, res.evidence.map((ev) => h("pre", null, typeof ev === "string" ? ev : (ev.output || JSON.stringify(ev)))))));
  }
  if (res.notes && res.notes.length) res.notes.forEach((n) => body.append(h("div", { class: "tiny faint mt" }, n)));
  return h("div", { class: "notice " + tone + " mt", style: "border-width:1px" },
    h("div", { class: "row between" }, h("strong", null, res.title || res.id), statusTag(st)),
    body);
}

/* ---------- export ---------- */

async function startExport(btn) {
  await guard(async () => {
    const d = await api("/api/export", { method: "POST", body: {} });
    exportJobId = d.id;
    $("#exportPanel").classList.remove("hidden");
    showProgress("export", "Assembling & redacting the report…");
    pollExportJob();
  }, btn);
}

async function pollExportJob() {
  if (!exportJobId) return;
  try {
    const d = await api("/api/export/" + exportJobId);
    if (d.status === "running") { showProgress("export", d.progress || "Assembling the report…"); setTimeout(pollExportJob, 700); return; }
    hideProgress();
    if (d.status === "failed") { toast("bad", d.error || "The export failed."); return; }
    lastExport = d.export || null;
    renderExport(lastExport);
  } catch (e) { hideProgress(); toast("bad", "Could not poll the export job.", e.message, e.code); }
}

function renderExport(e) {
  if (!e) return;
  const meta = $("#exportMeta");
  clear(meta);
  meta.append(h("div", { class: "small" }, "Report base name: ", h("span", { class: "mono" }, e.baseName)));
  const counts = e.redactionCounts || {};
  const nRed = Object.values(counts).reduce((a, b) => a + (Number(b) || 0), 0);
  meta.append(h("div", { class: "small dim" }, nRed > 0
    ? "Redaction applied (" + nRed + " values replaced). The mapping is NOT included below."
    : "No redaction was triggered by the current privacy settings."));
  const vis = $("#exportVisibility");
  clear(vis);
  vis.append(h("div", { class: "notice info" }, h("strong", null, "Inspect before sharing. "),
    "Nothing is uploaded — this is a local file. Review the preview below for anything you do not want to send, then save.", e.entries && e.entries.length ? h("div", { class: "small dim mt" }, "Placeholders hide real values; the key is not shown in the artifact.") : null));
  const t = $("#exportText");
  t.textContent = (e.text || "").slice(0, 200000);
  $("#exportPanel").classList.remove("hidden");
}

async function saveExport(btn) {
  if (!exportJobId) return;
  await guard(async () => {
    const d = await api("/api/export/save", { method: "POST", body: { id: exportJobId } });
    toast("ok", "Export saved.", (d.saved || []).join("\n"));
  }, btn);
}

function copyExport(btn) {
  if (!lastExport) return;
  copyText(lastExport.json || lastExport.text || "", "Export JSON copied to clipboard.");
}

/* ---------- logs ---------- */

// The tail is kept in memory, not re-derivered from each response: a "since" poll that brings
// nothing new must not blank the lines already on screen, because those lines are still the log.
let logBuf = [];          // newest first
let logLastKey = "";      // what level+query the buffer currently reflects

function startLogs() { stopLogs(); resetLogBuf(); pollLogs(); logTimer = setInterval(pollLogs, 1500); }
function stopLogs() { if (logTimer) { clearInterval(logTimer); logTimer = null; } }

function logFilterKey() { return $("#logLevel").value + "\u0000" + $("#logQuery").value.trim(); }

// The API sends level as a number (logx iota) and levelName as the text; the page only ever
// wants the text.
function logLevelName(e) { return e.levelName || "info"; }

// Dropping the buffer means the next poll must re-read from the beginning, not from the old
// cursor - otherwise a level change would silently keep showing the previous level's events.
function resetLogBuf() { logBuf = []; logLastKey = logFilterKey(); logSelected.clear(); logCursor = 0; }

async function pollLogs() {
  // A changed level or search invalidates the buffer: the next poll re-reads from scratch.
  if (logFilterKey() !== logLastKey) resetLogBuf();
  const lvl = $("#logLevel").value;
  const q = $("#logQuery").value.trim();
  const since = q ? 0 : logCursor;
  const path = "/api/logs?level=" + encodeURIComponent(lvl) + "&limit=400" + (q ? "&q=" + encodeURIComponent(q) : "") + (since ? "&since=" + since : "");
  try {
    const d = await api(path);
    if (d.cursor) logCursor = d.cursor;
    const incoming = (d && d.events) || [];
    if (incoming.length) {
      // Responses are newest first; merging keeps that order and drops repeats by seq.
      const seen = new Set(logBuf.map((e) => e.seq));
      const fresh = incoming.filter((e) => !e.seq || !seen.has(e.seq));
      logBuf = fresh.concat(logBuf).slice(0, 400);
    } else if (since) {
      // Nothing new since the last cursor: the lines on screen are still correct, so leave
      // them alone rather than flashing an empty state.
      return;
    }
    renderLogs();
  } catch (e) { /* transient; keep the last good view */ }
}

function renderLogs() {
  const body = $("#logBody");
  const isSearch = !!$("#logQuery").value.trim();
  const events = logBuf;
  clear(body);
  if (!events.length) {
    body.append(emptyState(isSearch ? "🔍" : "≡", isSearch ? "No events match that search." : "No events captured yet.",
      isSearch ? "Try a shorter query, or clear the search to return to the live tail." : "Events appear here as the application runs."));
    return;
  }
  const stream = h("div", { class: "logstream" });
  events.forEach((e) => {
    const id = e.seq || (e.at + "|" + e.code);
    const sel = logSelected.has(id);
    const line = h("div", { class: "logline" + (sel ? " sel" : "") },
      h("input", { type: "checkbox", checked: sel, style: "margin-top:3px", onchange: (ev) => { if (ev.target.checked) logSelected.add(id); else logSelected.delete(id); } }),
      h("span", { class: "lt" }, clock(e.at)),
      h("span", { class: "lv " + logLevelName(e) }, logLevelName(e)),
      h("span", { class: "lc" }, e.code || ""),
      h("span", { class: "lm" }, e.message || ""),
      h("button", { class: "btn ghost sm copybtn", title: "copy this entry", onclick: () => copyText(logLineText(e), "Entry copied.") }, "⧉"));
    stream.append(line);
  });
  body.append(h("div", { class: "row between", style: "margin-bottom:8px" },
    h("span", { class: "small dim" }, (isSearch ? "Search results: " : "Live tail: ") + events.length + " event" + (events.length === 1 ? "" : "s") + (logSelected.size ? " · " + logSelected.size + " selected" : "")),
    h("span", { class: "tiny faint" }, "Newest first")));
  body.append(stream);
}

function logLineText(e) {
  return [e.at, (e.levelName || "info").toUpperCase(), e.code || "", e.message || ""].join("  ");
}

function visibleLogEvents() {
  return Array.from(document.querySelectorAll("#logBody .logline")).map((n) => n.querySelector(".lm").textContent);
}

function logsAs(kind, events) {
  if (kind === "json") return JSON.stringify(events.map((e) => ({ at: e.at, level: e.levelName, code: e.code, message: e.message })), null, 2);
  if (kind === "md") {
    const lines = ["# NetMerge log export", "", "Exported " + new Date().toISOString() + ". Public IPs, MACs, serials, hostnames and paths are redacted per the current privacy settings.", "", "| Time | Level | Code | Message |", "|---|---|---|---|"];
    events.forEach((e) => lines.push("| " + [e.at, (e.levelName || "info"), e.code || "", (e.message || "").replace(/\|/g, "\\|")].join(" | ") + " |"));
    return lines.join("\n");
  }
  // txt
  return events.map(logLineText).join("\n");
}

function currentLogEvents() {
  // Pull a fresh copy for export so it respects the current level/search rather than the DOM text.
  const lvl = $("#logLevel").value;
  const q = $("#logQuery").value.trim();
  return api("/api/logs?level=" + encodeURIComponent(lvl) + "&limit=1000" + (q ? "&q=" + encodeURIComponent(q) : "")).then((d) => d.events || []);
}

async function exportLogs(kind, btn) {
  await guard(async () => {
    const events = await currentLogEvents();
    if (!events.length) { toast("warn", "No log events to export."); return; }
    const text = logsAs(kind, events);
    const name = "net-merge-logs." + (kind === "md" ? "md" : kind === "json" ? "json" : "txt");
    downloadText(name, text);
    toast("ok", "Log exported as " + name + " (" + events.length + " events).", "Secrets and personal data are redacted per your privacy settings.");
  }, btn);
}

function downloadText(filename, text) {
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = h("a", { href: url, download: filename });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

function copyLogs(kind) {
  currentLogEvents().then((events) => {
    if (!events.length) { toast("warn", "No log events to copy."); return; }
    copyText(logsAs(kind, events), events.length + " events copied as " + (kind === "md" ? "Markdown" : kind === "json" ? "JSON" : "text") + ".");
  }, (e) => toast("bad", "Could not read logs.", e.message, e.code));
}

/* ---------- profiles & settings ---------- */

let settingsCfg = null;
let editingProfile = null;   // profile id being edited inline
let profileDirty = false;

async function loadSettings(btn) {
  await guard(async () => {
    const d = await api("/api/settings");
    settingsCfg = d.config;
    settingsView = d;
    profileDirty = false;
    renderSettings();
  }, btn);
}

const PROFILE_FIELD_HELP = {
  include: "Adapter names to use. Empty means every adapter the engine considers usable.",
  exclude: "Adapter names to leave out. The Control Center turns this into the inclusion list handed to the engine.",
  weights: "Fixed per-adapter weights. Present only when the profile pins weights.",
  autoWeight: "Weight adapters by measured throughput (engine -auto-weight).",
  ipv6: "IPv6 handling: auto (use only if every adapter has it), on, or off (push apps to IPv4 so every adapter is used).",
  mtu: "Engine MTU. 0 leaves the engine default.",
  latencyBudgetMs: "Round-trip time above which a link is marked over budget for this profile. 0 = no budget.",
  probeLinkLatency: "Enable the per-link TCP latency probe (the most expensive thing the monitor does).",
  preferLowerLatency: "Advice flag: prefer the lower-latency link. Shown as advice, never enforced as a scheduler rule.",
};

function renderSettings() {
  const body = $("#settingsBody");
  clear(body);
  if (!settingsCfg) { body.append(emptyState("⚙", "Loading settings…")); return; }
  if (settingsView && settingsView.loadError) body.append(h("div", { class: "notice warn" }, "The settings file could not be loaded cleanly: " + settingsView.loadError));
  if (settingsView && settingsView.stale) body.append(h("div", { class: "notice info" }, settingsView.staleReason || "These settings are not yet saved to disk."));

  /* ---- profiles ---- */
  const profPanel = h("div", { class: "panel" });
  profPanel.append(h("h3", null, "Profiles", h("span", { class: "hint" }, "named configurations; selecting one never changes the running engine on its own")));
  profPanel.append(profileToolbar());
  profPanel.append(profileList());
  body.append(profPanel);

  /* ---- app settings tabs ---- */
  const tabs = h("div", { class: "tabs" });
  const panels = {};
  const groups = [["dashboard", "Dashboard"], ["logging", "Logging"], ["privacy", "Privacy & redaction"], ["diagnostics", "Diagnostics targets"]];
  groups.forEach(([key, label], i) => {
    const p = h("div", { class: "panel" });
    panels[key] = p;
    tabs.append(h("button", { class: i === 0 ? "active" : "", onclick: (e) => {
      Object.values(panels).forEach((x) => x.classList.add("hidden"));
      tabs.querySelectorAll("button").forEach((b) => b.classList.remove("active"));
      e.target.classList.add("active"); p.classList.remove("hidden");
    } }, label));
  });
  body.append(tabs);
  groups.forEach(([key], i) => { if (i > 0) panels[key].classList.add("hidden"); });

  // dashboard
  const d = settingsCfg.dashboard;
  panels.dashboard.append(h("div", { class: "grid2" },
    field("Listen address (loopback only)", d.listen, (v) => d.listen = v, "The dashboard refuses a routable address — this is what keeps it private."),
    fieldNum("Monitor interval (ms)", d.intervalMs, (v) => d.intervalMs = v, "How often the shared adapter snapshot is refreshed."),
    fieldNum("Health probe interval (ms, negative = off)", d.healthIntervalMs, (v) => d.healthIntervalMs = v, "One TCP connect per eligible adapter per round."),
    check("Open browser on start", !!d.openBrowser, (v) => d.openBrowser = v)));
  body.append(panels.dashboard);

  // logging
  const lg = settingsCfg.logging;
  panels.logging.append(h("div", { class: "grid2" },
    selectField("Log level", ["debug", "info", "warn", "error"], lg.level, (v) => lg.level = v, "Written to the rotating files on disk."),
    fieldNum("Log file max bytes", lg.maxBytes, (v) => lg.maxBytes = v),
    fieldNum("Log files kept", lg.maxFiles, (v) => lg.maxFiles = v),
    fieldNum("In-memory events kept", lg.ringEvents, (v) => lg.ringEvents = v, "Shown in the Logs section.")));
  body.append(panels.logging);

  // privacy
  const pv = settingsCfg.privacy;
  const pg = h("div", { class: "grid2" });
  [["redactPublicIPs", "Redact public IP addresses"], ["keepWellKnownPublicIPs", "Keep well-known public resolvers readable"],
   ["redactMACs", "Redact MAC addresses (vendor prefix kept)"], ["redactSerials", "Redact serials, IMEIs, USB instance paths"],
   ["redactPaths", "Redact the account name in paths"], ["redactHostNames", "Redact machine and account names"],
   ["includeHostname", "Include the machine name in the report"], ["redactAdapterNames", "Redact adapter names"]]
    .forEach(([k, label]) => pg.append(check(label, !!pv[k], (v) => pv[k] = v)));
  panels.privacy.append(pg);
  panels.privacy.append(h("div", { class: "notice info mt" }, "These apply to the diagnostics export and log export. Credentials are always redacted regardless of these switches."));
  body.append(panels.privacy);

  // diagnostics
  const dx = settingsCfg.diagnostics;
  panels.diagnostics.append(h("div", { class: "grid2" },
    field("TCP / latency endpoint", dx.endpoint, (v) => dx.endpoint = v),
    field("DNS server (optional)", dx.dnsServer, (v) => dx.dnsServer = v),
    field("DNS name to resolve", dx.dnsName, (v) => dx.dnsName = v),
    field("Traceroute target", dx.tracerouteTarget, (v) => dx.tracerouteTarget = v),
    field("UDP probe target", dx.udpTarget, (v) => dx.udpTarget = v),
    field("Path-MTU host", dx.mtuHost, (v) => dx.mtuHost = v),
    fieldNum("Per-command timeout (ms)", dx.timeoutMs, (v) => dx.timeoutMs = v),
    fieldNum("Traceroute timeout (ms)", dx.tracerouteTimeoutMs, (v) => dx.tracerouteTimeoutMs = v)));
  body.append(panels.diagnostics);

  if (profileDirty) body.append(h("div", { class: "notice warn mt" }, "You have unsaved profile edits. Nothing is on disk until you press “Save settings”."));
}

function field(label, value, onInput, help) {
  const i = h("input", { type: "text", value: value || "", oninput: (e) => onInput(e.target.value) });
  return h("label", { class: "field" }, h("span", null, label), i, help ? h("span", { class: "help" }, help) : null);
}
function fieldNum(label, value, onInput, help) {
  const i = h("input", { type: "number", value: value || 0, oninput: (e) => onInput(Number(e.target.value)) });
  return h("label", { class: "field" }, h("span", null, label), i, help ? h("span", { class: "help" }, help) : null);
}
function check(label, value, onInput, help) {
  const i = h("input", { type: "checkbox", checked: !!value, onchange: (e) => onInput(e.target.checked) });
  return h("label", { class: "field" }, h("span", null, label), i, help ? h("span", { class: "help" }, help) : null);
}
function selectField(label, options, value, onInput, help) {
  const s = h("select", null, options.map((o) => h("option", o === value ? { value: o, selected: true } : { value: o }, o)));
  s.addEventListener("change", (e) => onInput(e.target.value));
  return h("label", { class: "field" }, h("span", null, label), s, help ? h("span", { class: "help" }, help) : null);
}

function profileToolbar() {
  const ids = settingsView && settingsView.profileOrder ? settingsView.profileOrder : Object.keys(settingsCfg.profiles || {});
  const sel = h("select", null, ids.map((id) => h("option", id === settingsCfg.activeProfile ? { value: id, selected: true } : { value: id }, (settingsCfg.profiles[id] || {}).name || id)));
  sel.addEventListener("change", () => { settingsCfg.activeProfile = sel.value; editingProfile = null; renderSettings(); });
  return h("div", { class: "row between spread" },
    h("div", { class: "row" }, h("span", { class: "small dim" }, "Selected profile:"), sel,
      h("span", { class: "tag info" }, "selection only — no live change")),
    h("div", { class: "row tight" },
      h("button", { class: "btn secondary sm", onclick: () => duplicateProfile() }, "Duplicate"),
      h("button", { class: "btn secondary sm", onclick: () => renameProfile() }, "Rename"),
      h("button", { class: "btn danger sm", onclick: () => deleteProfile() }, "Delete")));
}

function profileList() {
  const wrap = h("div");
  const ids = settingsView && settingsView.profileOrder ? settingsView.profileOrder : Object.keys(settingsCfg.profiles || {});
  const grid = h("div", { class: "grid2 mt" });
  ids.forEach((id) => {
    const p = settingsCfg.profiles[id];
    if (!p) return;
    const isActive = id === settingsCfg.activeProfile;
    const editing = editingProfile === id;
    const cardEl = h("div", { class: "card", style: "padding:14px" },
      h("div", { class: "row between" },
        h("div", { class: "row tight" }, h("strong", null, p.name || id), isActive ? badge("selected", "ok") : null),
        h("button", { class: "btn ghost sm", onclick: () => { editingProfile = editing ? null : id; renderSettings(); } }, editing ? "Done" : "Edit")),
      p.description ? h("div", { class: "small dim", style: "margin-top:4px" }, p.description) : null,
      h("div", { class: "small mt" }, "Engine flags: ", h("span", { class: "mono" }, requestedFlags(p))),
      editing ? profileEditor(id, p) : null);
    grid.append(cardEl);
  });
  wrap.append(grid);
  wrap.append(h("div", { class: "small dim mt" }, "A profile is a request expressed in real engine flags. It is stored in the settings file and shown to the engine the next time it starts. Editing or selecting one here does not restart or reconfigure a running engine."));
  return wrap;
}

function profileEditor(id, p) {
  const e = p.engine || (p.engine = {});
  const m = p.monitor || (p.monitor = {});
  const mark = () => { profileDirty = true; };
  const inc = h("input", { type: "text", value: (e.include || []).join(", "), oninput: (ev) => { e.include = ev.target.value.split(",").map((s) => s.trim()).filter(Boolean); mark(); } });
  const exc = h("input", { type: "text", value: (e.exclude || []).join(", "), oninput: (ev) => { e.exclude = ev.target.value.split(",").map((s) => s.trim()).filter(Boolean); mark(); } });
  const wt = h("input", { type: "text", value: Object.keys(e.weights || {}).map((k) => k + "=" + e.weights[k]).join(", "), oninput: (ev) => {
    const w = {}; ev.target.value.split(",").forEach((part) => { const i = part.lastIndexOf("="); if (i > 0) { const n = parseFloat(part.slice(i + 1)); if (isFinite(n) && n > 0) w[part.slice(0, i).trim()] = n; } }); e.weights = w; mark();
  } });
  const ipv6 = selectField("IPv6 mode", ["auto", "on", "off"], e.ipv6 || "auto", (v) => { e.ipv6 = v; mark(); }, PROFILE_FIELD_HELP.ipv6);
  const mtu = h("input", { type: "number", value: e.mtu || 0, oninput: (ev) => { e.mtu = Number(ev.target.value); mark(); } });
  const auto = check("Weight by measured throughput", e.autoWeight !== false, (v) => { e.autoWeight = v; mark(); }, PROFILE_FIELD_HELP.autoWeight);
  const lat = h("input", { type: "number", value: m.latencyBudgetMs || 0, oninput: (ev) => { m.latencyBudgetMs = Number(ev.target.value); mark(); } });
  const probe = check("Probe per-link latency", !!m.probeLinkLatency, (v) => { m.probeLinkLatency = v; mark(); });
  const prefer = check("Prefer lower-latency link (advice)", !!m.preferLowerLatency, (v) => { m.preferLowerLatency = v; mark(); });
  const g = h("div", { class: "grid2 mt" },
    fieldHelp("Include adapters", inc, PROFILE_FIELD_HELP.include),
    fieldHelp("Exclude adapters", exc, PROFILE_FIELD_HELP.exclude),
    fieldHelp("Weights (Name=value)", wt, PROFILE_FIELD_HELP.weights),
    ipv6,
    fieldHelp("Engine MTU", mtu, PROFILE_FIELD_HELP.mtu),
    auto, probe, prefer);
  return h("div", { class: "mt", style: "border-top:1px solid var(--line);padding-top:10px" }, g);
}

function fieldHelp(label, input, help) {
  return h("label", { class: "field" }, h("span", null, label), input, help ? h("span", { class: "help" }, help) : null);
}

function newProfileId(base) {
  const ids = new Set(Object.keys(settingsCfg.profiles || {}));
  let n = 1, id = base;
  while (ids.has(id)) { id = base + "-" + (++n); }
  return id;
}

function duplicateProfile() {
  const srcId = settingsCfg.activeProfile;
  const src = settingsCfg.profiles[srcId];
  if (!src) return;
  const id = newProfileId(srcId + "-copy");
  const copy = JSON.parse(JSON.stringify(src));
  copy.id = id; copy.name = (src.name || srcId) + " (copy)";
  settingsCfg.profiles[id] = copy;
  if (settingsView && settingsView.profileOrder) settingsView.profileOrder.push(id);
  settingsCfg.activeProfile = id; editingProfile = id; profileDirty = true;
  renderSettings();
  toast("info", "Duplicated “" + (src.name || srcId) + "”. Press Save settings to persist it.");
}

function renameProfile() {
  const id = settingsCfg.activeProfile;
  const p = settingsCfg.profiles[id];
  if (!p) return;
  const name = prompt("Rename profile", p.name || id);
  if (name === null) return;
  p.name = name.trim() || id;
  profileDirty = true; renderSettings();
}

function deleteProfile() {
  const id = settingsCfg.activeProfile;
  const ids = Object.keys(settingsCfg.profiles || {});
  if (ids.length <= 1) { toast("warn", "At least one profile must remain."); return; }
  const p = settingsCfg.profiles[id];
  confirmModal({
    title: "Delete profile", danger: true, confirm: "Delete",
    body: h("div", null, "Delete the profile ", h("strong", null, (p && p.name) || id), "? This only removes it from the settings file — it never touches the running engine."),
  }).then((ok) => {
    if (!ok) return;
    delete settingsCfg.profiles[id];
    if (settingsView && settingsView.profileOrder) settingsView.profileOrder = settingsView.profileOrder.filter((x) => x !== id);
    settingsCfg.activeProfile = Object.keys(settingsCfg.profiles)[0];
    editingProfile = null; profileDirty = true; renderSettings();
  });
}

async function saveSettings(btn) {
  await guard(async () => {
    const d = await api("/api/settings", { method: "PUT", body: settingsCfg });
    profileDirty = false;
    toast("ok", "Settings saved.", d.path);
    // reload to get the server's normalized view (validation, ordering)
    await loadSettings();
  }, btn);
}

/* ---------- boot ---------- */

async function pollStateOnce() {
  state = await api("/api/state");
  renderBadge();
  if (currentView === "overview") renderOverview();
  else if (currentView === "connections") renderConnections();
  else if (currentView === "routing") renderRouting();
  else { renderOverview(); renderConnections(); renderRouting(); }
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

function renderAll() { renderOverview(); renderConnections(); renderRouting(); }

function renderFooter() {
  const f = $("#foot");
  if (!state || !state.app) { clear(f); return; }
  const a = state.app;
  clear(f);
  f.append(h("div", null, "v", a.version || "?", " · ", a.platform || "?", "/", a.arch || "?"),
    h("div", { class: "mono tiny", style: "word-break:break-all" }, a.dashboard || ""),
    a.elevated ? h("div", { style: "color:var(--ok)" }, "elevated") : h("div", null, "not elevated"));
}

/* ---------- wiring ---------- */

document.querySelectorAll("#nav button, #nav2 button").forEach((b) => b.addEventListener("click", () => showView(b.dataset.view)));

$("#ovRefresh").addEventListener("click", (e) => guard(async () => { state = await api("/api/refresh", { method: "POST", body: {} }); renderAll(); toast("ok", "Snapshot refreshed."); }, e.target));
$("#connRefresh").addEventListener("click", (e) => guard(async () => { state = await api("/api/refresh", { method: "POST", body: {} }); renderAll(); toast("ok", "Snapshot refreshed."); }, e.target));
$("#pubIPCheck").addEventListener("click", (e) => checkPublicIPs(e.target));
$("#pubIPMask").addEventListener("click", () => togglePublicIPMask());
$("#ttlReload").addEventListener("click", (e) => loadTTL(e.target));
$("#diagRunAll").addEventListener("click", (e) => runDiag(true, e.target));
$("#diagRunSel").addEventListener("click", (e) => runDiag(false, e.target));
$("#diagCancel").addEventListener("click", (e) => cancelDiag(e.target));
$("#exportStart").addEventListener("click", (e) => startExport(e.target));
$("#exportSave").addEventListener("click", (e) => saveExport(e.target));
$("#exportCopy").addEventListener("click", () => copyExport());
$("#logLevel").addEventListener("change", () => { logCursor = 0; pollLogs(); });
$("#logQuery").addEventListener("input", () => { clearTimeout(window.__logq); window.__logq = setTimeout(() => { logCursor = 0; pollLogs(); }, 300); });
$("#logClearSearch").addEventListener("click", () => { $("#logQuery").value = ""; logCursor = 0; pollLogs(); });
$("#logCopySel").addEventListener("click", () => {
  const sel = Array.from(document.querySelectorAll("#logBody .logline.sel")).map((n) => n.querySelector(".lm").textContent);
  if (!sel.length) { toast("warn", "No entries selected."); return; }
  copyText(sel.join("\n"), sel.length + " selected entries copied.");
});
$("#logCopyAll").addEventListener("click", () => {
  const all = Array.from(document.querySelectorAll("#logBody .logline .lm")).map((n) => n.textContent);
  if (!all.length) { toast("warn", "No visible entries."); return; }
  copyText(all.join("\n"), all.length + " visible entries copied.");
});
$("#logExportMd").addEventListener("click", (e) => exportLogs("md", e.target));
$("#logExportTxt").addEventListener("click", (e) => exportLogs("txt", e.target));
$("#logExportJson").addEventListener("click", (e) => exportLogs("json", e.target));
$("#settingsSave").addEventListener("click", (e) => saveSettings(e.target));

// original boot
(async function boot() {
  await loadCodeRegistry();
  syncMaskButton(); // reflect the persisted mask choice before anything renders
  renderFooter();
  stateLoop();
  const footTimer = setInterval(() => { if (state) { renderFooter(); } }, 5000);
  // initial view content
  renderAll();
})();




