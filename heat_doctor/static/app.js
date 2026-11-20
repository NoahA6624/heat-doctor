/* Heat Doctor dashboard - plain JS, no dependencies, works in any modern browser. */
"use strict";

const TOKEN = document.querySelector('meta[name="hd-token"]').content;
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => Array.from(el.querySelectorAll(s));

let windowS = 300;
let S = null;               // last /api/state payload
let pollTimer = null;
let stopped = false;
const chatHistory = [];
const openDetails = new Set();
const sigs = {};            // render signatures for slow-changing panels

/* ------------------------------------------------------------------ utils */
function esc(v) {
  return String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function fmtBytes(n) {
  n = Number(n) || 0;
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (Math.abs(n) >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return i === 0 ? `${n.toFixed(0)} B` : `${n.toFixed(n >= 100 ? 0 : 1)} ${u[i]}`;
}
const fmtRate = n => fmtBytes(n) + "/s";
const pct = (n, d = 0) => (n == null || isNaN(n) ? "–" : `${Number(n).toFixed(d)}%`);
function fmtClock(t, withSec) {
  const d = new Date(t * 1000);
  return d.toLocaleTimeString([], withSec ? { hour: "2-digit", minute: "2-digit", second: "2-digit" } : { hour: "2-digit", minute: "2-digit" });
}
function ago(t) {
  if (!t) return "never";
  const s = Math.max(0, Date.now() / 1000 - t);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  return `${Math.round(s / 3600)} h ago`;
}

async function api(path, body) {
  const opts = { headers: { "X-HD-Token": TOKEN } };
  if (body !== undefined) {
    opts.method = "POST";
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r;
}

/* ------------------------------------------------------------------ icons */
const ICON = {
  critical: '<svg viewBox="0 0 16 16" aria-hidden="true"><path class="fill" d="M5 1h6l4 4v6l-4 4H5l-4-4V5z"/><path d="M8 4.2v4.6" stroke="#fff" stroke-width="1.8" stroke-linecap="round"/><circle cx="8" cy="11.4" r="1.05" fill="#fff"/></svg>',
  serious: '<svg viewBox="0 0 16 16" aria-hidden="true"><path class="fill" d="M8 1.2l7.2 13.2H.8z"/><path d="M8 5.6v4" stroke="#fff" stroke-width="1.8" stroke-linecap="round"/><circle cx="8" cy="12.2" r="1" fill="#fff"/></svg>',
  warning: '<svg viewBox="0 0 16 16" aria-hidden="true"><path class="fill" d="M8 1.2l7.2 13.2H.8z"/><path d="M8 5.6v4" stroke="#0b0b0b" stroke-width="1.8" stroke-linecap="round"/><circle cx="8" cy="12.2" r="1" fill="#0b0b0b"/></svg>',
  info: '<svg viewBox="0 0 16 16" aria-hidden="true"><circle class="fill" cx="8" cy="8" r="7"/><path d="M8 7.2v4.4" stroke="#fff" stroke-width="1.8" stroke-linecap="round"/><circle cx="8" cy="4.8" r="1.05" fill="#fff"/></svg>',
  good: '<svg viewBox="0 0 16 16" aria-hidden="true"><circle class="fill" cx="8" cy="8" r="7"/><path d="M4.8 8.3l2.2 2.2 4.2-4.6" stroke="#fff" stroke-width="1.8" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>',
};
const SEV_LABEL = { critical: "Critical", serious: "Serious", warning: "Warning", info: "Note", good: "Good" };
const SEV_RANK = { critical: 4, serious: 3, warning: 2, info: 1, good: 0 };
const chip = (sev, label) => `<span class="chip sev-${sev}">${ICON[sev] || ICON.info}${esc(label || SEV_LABEL[sev] || sev)}</span>`;

/* ------------------------------------------------------------------ toast */
function toast(msg, sev = "good") {
  const t = document.createElement("div");
  t.className = `toast sev-${sev}`;
  t.innerHTML = (ICON[sev] || ICON.info) + `<div>${esc(msg)}</div>`;
  $("#toasts").appendChild(t);
  setTimeout(() => t.remove(), 6000);
}

/* ------------------------------------------------------------------ actions */
function actionBtn(id, params, extraClass = "") {
  const a = S && S.actions[id];
  if (!a) return "";
  const cls = id === "end_process" ? "danger" : "";
  return `<button class="btn small ${cls} ${extraClass}" data-act="${esc(id)}" data-params="${esc(JSON.stringify(params || {}))}">${esc(a.label)}</button>`;
}
function findingActions(f) {
  const out = [];
  const seen = new Set();
  for (const id of f.actions || []) {
    if (seen.has(id)) continue;
    seen.add(id);
    let params = {};
    if (id === "end_process") params = { pids: f.pids || (f.pid ? [f.pid] : []) };
    if (id === "open_file_location" || id === "defender_scan_file") params = { path: f.path };
    if (id === "end_process" && !params.pids.length) continue;
    out.push(actionBtn(id, params));
  }
  return out.join("");
}
document.addEventListener("click", async e => {
  const b = e.target.closest("[data-act]");
  if (!b) return;
  if (!S) return;
  let params = {};
  try { params = JSON.parse(b.dataset.params || "{}"); } catch (err) { /* ignore */ }
  const entry = { id: b.dataset.act, params };
  const meta = S.actions[entry.id];
  if (meta && meta.confirm && !window.confirm(meta.confirm)) return;
  b.disabled = true;
  const old = b.innerHTML;
  b.innerHTML = `<span class="spin"></span> ${esc(meta ? meta.label : "Working")}`;
  try {
    const r = await (await api("/api/action", { action: entry.id, params: entry.params })).json();
    toast(r.message, r.severity || (r.ok ? "good" : "serious"));
  } catch (err) {
    toast("Couldn't reach Heat Doctor: " + err.message, "serious");
  } finally {
    b.disabled = false;
    b.innerHTML = old;
  }
});

/* ------------------------------------------------------------------ findings */
function renderFindings(el, list, emptyText) {
  if (!list.length) { el.innerHTML = `<p class="empty">${esc(emptyText || "Nothing to report.")}</p>`; return; }
  el.innerHTML = list.map(f => `
    <article class="finding sev-${esc(f.severity)}">
      <div class="f-head">${chip(f.severity)}<h3>${esc(f.title)}</h3></div>
      ${f.detail ? `<p>${esc(f.detail)}</p>` : ""}
      ${(f.evidence || []).length ? `<ul class="evidence">${f.evidence.map(x => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}
      ${(f.fixes || []).length ? `<ul class="fixes">${f.fixes.map(x => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}
      ${(f.actions || []).length ? `<div class="f-actions">${findingActions(f)}</div>` : ""}
    </article>`).join("");
}

/* ------------------------------------------------------------------ charts */
function niceStep(range, count) {
  const raw = range / Math.max(1, count);
  const mag = Math.pow(10, Math.floor(Math.log10(raw || 1)));
  for (const m of [1, 2, 2.5, 5, 10]) if (raw <= m * mag) return m * mag;
  return 10 * mag;
}
function lineChart(el, cfg) {
  const W = el.clientWidth, H = el.clientHeight;
  if (!W || !H) return;
  const m = { l: 46, r: 10, t: 8, b: 22 };
  const iw = W - m.l - m.r, ih = H - m.t - m.b;
  const now = S.now, t0 = now - windowS;
  const x = t => m.l + ((t - t0) / windowS) * iw;
  const all = cfg.series.flatMap(s => s.pts.map(p => p[1]).filter(v => v != null));
  let yMax = Math.max(cfg.yMaxMin || 1, ...all);
  let step;
  if (cfg.bytes) {  // clean binary ticks: 0 / 512 KB / 1 MB ...
    const unit = Math.pow(1024, Math.max(0, Math.floor(Math.log(yMax) / Math.log(1024))));
    step = niceStep(yMax / unit, 4) * unit;
  } else step = niceStep(yMax, 4);
  yMax = Math.ceil(yMax / step) * step;
  const yMin = cfg.yMin || 0;
  const y = v => m.t + ih - ((v - yMin) / (yMax - yMin)) * ih;

  let g = `<g class="grid">`;
  for (let v = yMin; v <= yMax + 1e-9; v += step) g += `<line x1="${m.l}" x2="${W - m.r}" y1="${y(v)}" y2="${y(v)}"/>`;
  g += `</g>`;
  let labels = "";
  for (let v = yMin; v <= yMax + 1e-9; v += step) labels += `<text x="${m.l - 6}" y="${y(v) + 4}" text-anchor="end">${esc(cfg.fmt(v, true))}</text>`;
  const xticks = 4;
  for (let i = 0; i <= xticks; i++) {
    const t = t0 + (windowS * i) / xticks;
    const anchor = i === 0 ? "start" : i === xticks ? "end" : "middle";
    labels += `<text x="${x(t)}" y="${H - 4}" text-anchor="${anchor}">${esc(i === xticks ? "now" : fmtClock(t, windowS <= 120))}</text>`;
  }
  let paths = "";
  const hasData = all.length > 0;
  for (const s of cfg.series) {
    let d = "", area = "", seg = [];
    const flush = () => {
      if (seg.length) {
        d += "M" + seg.map(p => `${x(p[0]).toFixed(1)},${y(p[1]).toFixed(1)}`).join("L");
        if (cfg.area) area += `M${x(seg[0][0]).toFixed(1)},${y(yMin)}L` + seg.map(p => `${x(p[0]).toFixed(1)},${y(p[1]).toFixed(1)}`).join("L") + `L${x(seg[seg.length - 1][0]).toFixed(1)},${y(yMin)}Z`;
      }
      seg = [];
    };
    for (const p of s.pts) { if (p[1] == null) flush(); else seg.push(p); }
    flush();
    if (area) paths += `<path class="area" d="${area}" style="fill:${s.color}"/>`;
    paths += `<path class="line" d="${d}" style="stroke:${s.color}"/>`;
  }
  const nodata = hasData ? "" : `<text class="nodata" x="${m.l + iw / 2}" y="${m.t + ih / 2}" text-anchor="middle">${esc(cfg.empty || "No data yet")}</text>`;
  el.innerHTML = `<svg role="img" aria-label="${esc(cfg.label || "")}">${g}<line class="baseline" x1="${m.l}" x2="${W - m.r}" y1="${y(yMin)}" y2="${y(yMin)}"/>${labels}${paths}${nodata}<g class="hover"></g><rect class="hit" x="${m.l}" y="${m.t}" width="${iw}" height="${ih}" fill="transparent"/></svg><div class="tooltip"></div>`;

  const svg = $("svg", el), hov = $(".hover", el), tip = $(".tooltip", el);
  const show = px => {
    const t = t0 + ((px - m.l) / iw) * windowS;
    const ref = cfg.series[0].pts;
    if (!ref.length) return;
    let best = 0, bd = Infinity;
    for (let i = 0; i < ref.length; i++) { const dd = Math.abs(ref[i][0] - t); if (dd < bd) { bd = dd; best = i; } }
    const tt = ref[best][0];
    let dots = `<line class="cross" x1="${x(tt)}" x2="${x(tt)}" y1="${m.t}" y2="${m.t + ih}"/>`;
    let rows = "";
    for (const s of cfg.series) {
      const p = s.pts[best];
      if (!p) continue;
      if (p[1] != null) dots += `<circle class="dot" cx="${x(tt)}" cy="${y(p[1])}" r="4.5" style="fill:${s.color}"/>`;
      rows += `<div class="tt-row"><span class="key line" style="background:${s.color}"></span>${esc(s.name)}: <b>${esc(p[1] == null ? "n/a" : cfg.fmt(p[1]))}</b></div>`;
    }
    hov.innerHTML = dots;
    tip.innerHTML = `<div class="tt-time">${esc(fmtClock(tt, true))}</div>${rows}`;
    tip.style.display = "block";
    const tw = tip.offsetWidth;
    let left = x(tt) + 12;
    if (left + tw > W) left = x(tt) - tw - 12;
    tip.style.left = `${Math.max(0, left)}px`;
    tip.style.top = `${m.t}px`;
  };
  svg.addEventListener("pointermove", e => { const r = svg.getBoundingClientRect(); el._hx = e.clientX - r.left; show(el._hx); });
  svg.addEventListener("pointerleave", () => { el._hx = null; hov.innerHTML = ""; tip.style.display = "none"; });
  if (el._hx != null) show(el._hx);
}
function legend(el, series) {
  el.innerHTML = series.length < 2 ? "" : series.map(s => `<span><span class="key line" style="background:${s.color}"></span>${esc(s.name)}</span>`).join("");
}
const pts = key => S.history.map(h => [h.t, h[key]]);

/* ------------------------------------------------------------------ header */
function renderTop() {
  const m = S.meta;
  const me = m.self || {};
  $("#topMeta").innerHTML = `
    <span>${chip("good", "Live")}</span>
    <span>Sampling every ${m.interval.toFixed(0)} s</span>
    <span title="Heat Doctor's own footprint">Uses ${(me.cpu_pct || 0).toFixed(1)}% CPU · ${fmtBytes(me.rss)}</span>
    <span>${m.admin ? "Administrator" : "Standard user"}</span>`;
  const sc = S.security.counts || {};
  const n = (sc.critical || 0) + (sc.serious || 0);
  const b = $("#secBadge");
  b.hidden = !n;
  b.textContent = n;
}

/* ------------------------------------------------------------------ overview */
function tempSev(t) { return t == null ? "info" : t >= 75 ? "critical" : t >= 65 ? "serious" : t >= 55 ? "warning" : "good"; }
function renderOverview() {
  const d = S.diag;
  $("#vChip").outerHTML = `<span class="chip sev-${esc(d.status)}" id="vChip">${ICON[d.status]}${esc(d.status === "good" ? "Looking good" : SEV_LABEL[d.status])}</span>`;
  $("#vHeadline").textContent = d.headline;
  $("#vSummary").textContent = d.summary;
  const t = d.stats.drive_temp;
  $("#hero").innerHTML = t != null
    ? `<div class="label">Hottest drive</div><div class="value">${t.toFixed(0)}<small>°C</small></div>${chip(tempSev(t), tempSev(t) === "good" ? "Normal" : SEV_LABEL[tempSev(t)])}`
    : `<div class="label">Drive temperature</div><div class="value">–</div><div class="note">Start with run_as_admin to read the drive's own sensor.${
        d.stats.zone_temp != null ? ` ACPI system sensor: ${d.stats.zone_temp.toFixed(0)} °C.` : ""}</div>`;

  const L = S.latest || {};
  const mem = S.memory || {};
  const worst = (S.partitions || []).slice().sort((a, b) => b.percent - a.percent)[0];
  const memCls = mem.percent >= 90 ? "crit" : mem.percent >= 80 ? "warn" : "";
  const partCls = worst && worst.percent >= 90 ? "crit" : worst && worst.percent >= 80 ? "warn" : "";
  const cpuCls = L.cpu >= 80 ? "serious" : L.cpu >= 50 ? "warn" : "";
  $("#tiles").innerHTML = `
    <div class="card tile"><div class="t-label">Drive temperature</div>
      <div class="t-value">${t != null ? `${t.toFixed(0)}<small> °C</small>` : "–"}</div>
      <div class="t-foot">${t != null ? esc(SEV_LABEL[tempSev(t)] === "Good" ? "Normal range" : SEV_LABEL[tempSev(t)]) : "Needs admin for the drive sensor"}</div></div>
    <div class="card tile"><div class="t-label">CPU</div>
      <div class="t-value">${pct(L.cpu)}</div><div class="meter thin ${cpuCls}"><i style="width:${Math.min(100, L.cpu || 0)}%"></i></div>
      <div class="t-foot">${pct(d.stats.cpu_avg)} average</div></div>
    <div class="card tile"><div class="t-label">RAM</div>
      <div class="t-value">${pct(mem.percent)}</div><div class="meter thin ${memCls}"><i style="width:${mem.percent || 0}%"></i></div>
      <div class="t-foot">${fmtBytes(mem.used)} of ${fmtBytes(mem.total)}</div></div>
    <div class="card tile"><div class="t-label">Disk activity</div>
      <div class="t-value">${fmtRate((L.read_bps || 0) + (L.write_bps || 0))}</div>
      <div class="t-foot">Busy ${pct(d.stats.busy_frac * 100)} of the time</div></div>
    <div class="card tile"><div class="t-label">Storage ${worst ? esc(worst.mount) : ""}</div>
      <div class="t-value">${worst ? `${fmtBytes(worst.free)}<small> free</small>` : "–"}</div>
      ${worst ? `<div class="meter thin ${partCls}"><i style="width:${worst.percent}%"></i></div>` : ""}
      <div class="t-foot">${worst ? `${worst.percent.toFixed(0)}% used` : ""}</div></div>`;

  const top = d.findings.filter(f => f.severity !== "good").slice(0, 6);
  renderFindings($("#topFindings"), top, "No problems found right now.");

  const sus = d.suspects.slice(0, 6);
  $("#miniSuspects").innerHTML = sus.length ? sus.map(s => `
    <div class="bar-row">
      <div><div class="name">${esc(s.kb ? s.kb.label : s.name)}</div><div class="muted" style="font-size:12px">${esc(s.key)}</div></div>
      <div class="size">${(s.share * 100).toFixed(0)}%</div>
      <div class="meter"><i style="width:${(s.share * 100).toFixed(1)}%"></i></div>
    </div>`).join("") : `<p class="empty">Collecting data…</p>`;
}

/* ------------------------------------------------------------------ heat */
function renderHeat() {
  const tSeries = [];
  if (S.history.some(h => h.drive_temp != null)) tSeries.push({ name: "Drive", color: "var(--series-1)", pts: pts("drive_temp") });
  if (S.history.some(h => h.zone_temp != null)) tSeries.push({ name: "System sensor", color: tSeries.length ? "var(--series-2)" : "var(--series-1)", pts: pts("zone_temp") });
  $("#tempSub").textContent = (tSeries.length === 1 ? `°C · ${tSeries[0].name}` : "°C") +
    (tSeries.some(s => s.name === "System sensor") ? " (ACPI zone; some laptops report a fixed value)" : "");
  legend($("#tempLegend"), tSeries);
  lineChart($("#chartTemp"), { series: tSeries.length ? tSeries : [{ name: "Drive", color: "var(--series-1)", pts: [] }],
    fmt: (v, axis) => axis ? v.toFixed(0) : `${v.toFixed(1)} °C`, yMaxMin: 60, label: "Temperature over time",
    empty: S.meta.admin ? "No temperature sensors found" : "Run as administrator for drive temperature" });

  const dSeries = [{ name: "Read", color: "var(--series-1)", pts: pts("read_bps") }, { name: "Write", color: "var(--series-2)", pts: pts("write_bps") }];
  legend($("#diskLegend"), dSeries);
  lineChart($("#chartDisk"), { series: dSeries, fmt: (v, axis) => axis ? fmtBytes(v).replace(".0 ", " ") : fmtRate(v), yMaxMin: 1024 * 1024, bytes: true, label: "Disk throughput" });
  lineChart($("#chartCpu"), { series: [{ name: "CPU", color: "var(--series-1)", pts: pts("cpu") }], area: true,
    fmt: (v, axis) => axis ? `${v.toFixed(0)}%` : `${v.toFixed(1)}%`, yMaxMin: 100, label: "CPU load" });

  const rows = S.diag.suspects.map(s => {
    const key = "s:" + s.key;
    const why = s.kb ? `<details class="why" data-key="${esc(key)}" ${openDetails.has(key) ? "open" : ""}><summary>What is this?</summary><div>${esc(s.kb.about)}<ul>${s.kb.fixes.map(f => `<li>${esc(f)}</li>`).join("")}</ul></div></details>` : "";
    const canEnd = !["system", "registry", "memcompression", "memory compression", "svchost.exe"].includes(s.name.toLowerCase());
    return `<tr>
      <td><div class="pname">${esc(s.key)}</div>${s.kb ? `<div class="what">${esc(s.kb.label)}</div>` : ""}${why}</td>
      <td class="num">${fmtRate(s.read_bps)}</td><td class="num">${fmtRate(s.write_bps)}</td>
      <td class="num">${pct(s.cpu_pct, 1)}</td><td class="num">${fmtBytes(s.private || s.rss)}</td>
      <td><div class="share"><div class="meter"><i style="width:${(s.share * 100).toFixed(1)}%"></i></div><span>${(s.share * 100).toFixed(0)}%</span></div></td>
      <td class="num">${canEnd && s.pids.length ? actionBtn("end_process", { pids: s.pids }) : ""}</td></tr>`;
  }).join("");
  $("#suspectTable").innerHTML = `<thead><tr><th>Process</th><th class="num">Read</th><th class="num">Write</th><th class="num">CPU</th><th class="num">RAM</th><th>Heat share</th><th></th></tr></thead>
    <tbody>${rows || `<tr><td colspan="7" class="empty">Collecting data…</td></tr>`}</tbody>`;

  $("#drivesBox").innerHTML = (S.drives.length ? S.drives.map(dv => `
    <div class="bar-row">
      <div><div class="name">${esc(dv.name)}</div><div class="muted" style="font-size:12px">${esc([dv.media, dv.bus, dv.size ? fmtBytes(dv.size) : ""].filter(Boolean).join(" · "))}</div></div>
      <div class="size">${dv.temp != null ? `${dv.temp.toFixed(0)} °C` : "–"}</div>
      <div class="tip">${[dv.temp != null ? chip(tempSev(dv.temp), `${dv.temp.toFixed(0)} °C`) : chip("info", "Temp needs admin"),
        dv.temp_max ? `Max rated ${esc(dv.temp_max)} °C` : "", dv.wear != null ? `Wear ${esc(dv.wear)}%` : "",
        dv.hours ? `${Number(dv.hours).toLocaleString()} power-on hours` : "", dv.health ? `Health: ${esc(dv.health)}` : ""].filter(Boolean).join(" · ")}</div>
    </div>`).join("") : `<p class="empty">No drive information available.</p>`)
    + (!S.meta.admin && S.meta.windows ? `<p class="sub mt">Windows only lets administrator programs read the drive's own temperature. Close Heat Doctor and start it with <b>run_as_admin.bat</b> to see it.</p>` : "");
  renderFindings($("#heatFindings"), S.diag.findings.filter(f => ["heat", "disk", "cpu", "suspect", "health"].includes(f.area) && f.severity !== "good").slice(0, 8), "No heat problems found right now.");
}

/* ------------------------------------------------------------------ memory */
function renderMemory() {
  const m = S.memory || {};
  $("#memHero").innerHTML = `${(m.percent || 0).toFixed(0)}<small>%</small>`;
  $("#memSub").textContent = `${fmtBytes(m.used)} used of ${fmtBytes(m.total)}`;
  const mm = $("#memMeter");
  mm.className = "meter " + (m.percent >= 90 ? "crit" : m.percent >= 80 ? "warn" : "");
  mm.firstElementChild.style.width = `${m.percent || 0}%`;
  $("#memLegend").innerHTML = `<span>Available: <b>${fmtBytes(m.available)}</b></span><span>Page file in use: <b>${fmtBytes(m.swap_used)}</b> of ${fmtBytes(m.swap_total)}</span>${S.diag.stats.pages_avg != null ? `<span>Paging: <b>${S.diag.stats.pages_avg.toFixed(0)}</b> pages/s</span>` : ""}`;
  lineChart($("#chartMem"), { series: [{ name: "RAM used", color: "var(--series-1)", pts: pts("mem") }], area: true,
    fmt: (v, axis) => axis ? `${v.toFixed(0)}%` : `${v.toFixed(1)}%`, yMaxMin: 100, label: "RAM over time" });
  const total = S.meta.ram_total || 1;
  $("#memTable").innerHTML = `<thead><tr><th>App</th><th class="num">Memory</th><th class="num">Processes</th><th>Share of RAM</th><th></th></tr></thead><tbody>` +
    S.diag.memory_top.map(r => {
      const canEnd = !["system", "registry", "memcompression", "memory compression", "svchost.exe", "explorer.exe", "dwm.exe"].includes(r.name.toLowerCase());
      const share = Math.min(100, (r.bytes / total) * 100);
      return `<tr><td><div class="pname">${esc(r.name)}</div>${r.kb ? `<div class="what">${esc(r.kb.label)}</div>` : ""}</td>
        <td class="num">${fmtBytes(r.bytes)}</td><td class="num">${r.instances}</td>
        <td><div class="share"><div class="meter"><i style="width:${share.toFixed(1)}%"></i></div><span>${share.toFixed(0)}%</span></div></td>
        <td class="num">${canEnd ? actionBtn("end_process", { pids: r.pids }) : ""}</td></tr>`;
    }).join("") + "</tbody>";
  renderFindings($("#memFindings"), S.diag.findings.filter(f => f.area === "memory"), "Memory looks fine.");
}

/* ------------------------------------------------------------------ storage */
function renderStorage() {
  $("#partBox").innerHTML = (S.partitions || []).map(p => {
    const cls = p.percent >= 90 ? "crit" : p.percent >= 80 ? "warn" : "";
    return `<div class="bar-row"><div><div class="name">${esc(p.mount)}</div><div class="muted" style="font-size:12px">${esc(p.fstype)} · ${fmtBytes(p.total)}</div></div>
      <div class="size">${fmtBytes(p.free)} free</div><div class="meter ${cls}"><i style="width:${p.percent}%"></i></div>
      <div class="tip">${p.percent.toFixed(0)}% used</div></div>`;
  }).join("") || `<p class="empty">No partitions found.</p>`;

  const st = S.storage;
  const sig = `${st.status}|${st.finished}|${st.hogs.length}|${st.folders.length}`;
  const btn = $("#scanStorageBtn");
  btn.disabled = st.status === "running";
  btn.innerHTML = st.status === "running" ? `<span class="spin"></span> Scanning…` : (st.finished ? "Scan again" : "Scan storage");
  if (st.finished) $("#scanSub").textContent = `Last scan ${ago(st.finished)}${st.partial ? " (stopped early to stay light; numbers are a lower bound)" : ""}.`;
  if (sigs.storage !== sig) {
    sigs.storage = sig;
    if (st.hogs.length) {
      const max = st.hogs[0].size || 1;
      $("#hogsBox").innerHTML = st.hogs.map(h => `<div class="bar-row"><div class="name">${esc(h.label)}</div><div class="size">${h.partial ? "≥ " : ""}${fmtBytes(h.size)}</div>
        <div class="meter"><i style="width:${(h.size / max * 100).toFixed(1)}%"></i></div>
        <div class="tip"><span>${esc(h.tip)}</span>${h.action ? actionBtn(h.action) : ""}</div></div>`).join("");
    } else if (st.status === "running") $("#hogsBox").innerHTML = `<p class="empty"><span class="spin"></span> Measuring…</p>`;
    if (st.folders.length) {
      const max = st.folders[0].size || 1;
      $("#foldersBox").innerHTML = st.folders.map(f => `<div class="bar-row"><div class="name">${esc(f.name)}</div><div class="size">${f.partial ? "≥ " : ""}${fmtBytes(f.size)}</div>
          <div class="meter"><i style="width:${(f.size / max * 100).toFixed(1)}%"></i></div>
          <div class="tip"><span class="muted">${Number(f.files).toLocaleString()} files</span>${actionBtn("open_file_location", { path: f.path })}</div></div>` +
        (f.children || []).map(c => `<div class="bar-row child"><div class="name">↳ ${esc(c.name)}</div><div class="size">${fmtBytes(c.size)}</div>
          <div class="meter"><i style="width:${(c.size / max * 100).toFixed(1)}%"></i></div></div>`).join("")).join("");
    } else if (st.status === "running") $("#foldersBox").innerHTML = `<p class="empty"><span class="spin"></span> Waiting for the first part of the scan…</p>`;
  }
  renderFindings($("#storageFindings"), S.diag.findings.filter(f => f.area === "storage"), "Storage looks fine.");
}
$("#scanStorageBtn").addEventListener("click", async () => { await api("/api/storage/scan", {}); poll(); });

/* ------------------------------------------------------------------ security */
function renderSecurity() {
  const sec = S.security;
  const btn = $("#scanSecBtn");
  btn.disabled = sec.status === "running";
  btn.innerHTML = sec.status === "running" ? `<span class="spin"></span> Scanning…` : "Scan now";
  const sig = `${sec.status}|${sec.finished}`;
  if (sigs.security === sig) return;
  sigs.security = sig;
  const dfd = sec.defender;
  const c = sec.counts || {};
  const issues = (c.critical || 0) + (c.serious || 0) + (c.warning || 0);
  const rtp = dfd ? dfd.realtime : null;
  const third = (sec.av || []).filter(a => !/defender/i.test(a));
  $("#secSummary").innerHTML = `
    <div class="card tile"><div class="t-label">Real-time protection</div><div class="t-value" style="font-size:18px">${
      rtp === true ? chip("good", "On") : rtp === false ? (third.length ? chip("info", `Handled by ${third[0]}`) : chip("critical", "Off")) : chip("info", sec.finished ? "Unknown" : "Not checked yet")}</div>
      <div class="t-foot">${esc((sec.av || []).join(", ") || "")}</div></div>
    <div class="card tile"><div class="t-label">Definitions · last quick scan</div><div class="t-value" style="font-size:18px">${dfd && dfd.sig_age != null ? `${esc(dfd.sig_age)} day(s) old` : "–"}</div>
      <div class="t-foot">${dfd && dfd.quick_age != null ? `Quick scan ${esc(dfd.quick_age)} day(s) ago` : ""} ${actionBtn("defender_quick_scan")}</div></div>
    <div class="card tile"><div class="t-label">Heuristic scan</div><div class="t-value" style="font-size:18px">${sec.finished ? (issues ? chip(c.critical ? "critical" : c.serious ? "serious" : "warning", `${issues} to review`) : chip("good", "Nothing suspicious")) : (sec.status === "running" ? '<span class="spin"></span>' : "–")}</div>
      <div class="t-foot">${sec.finished ? `${sec.scanned_processes} processes checked ${ago(sec.finished)}` : "Runs automatically every 30 min"}</div></div>`;
  $("#secSub").textContent = sec.finished ? "Signed software from known vendors is shown as a note, not a threat. Use 'Scan this file' to get Microsoft Defender's verdict." : "";
  renderFindings($("#secFindings"), sec.findings || [], sec.finished ? "No suspicious activity found." : "Scan in progress…");
  const startup = sec.startup || [];
  $("#startupTable").innerHTML = startup.length ? `<thead><tr><th>Name</th><th>Where</th><th>Command</th><th></th></tr></thead><tbody>` +
    startup.map(s => `<tr><td><div class="pname">${esc(s.name)}</div>${s.suspicious ? chip("warning", "Review") : ""}${s.missing ? chip("info", "File missing") : ""}</td>
      <td class="muted">${esc(s.where)}</td><td style="font-size:12px;overflow-wrap:anywhere;max-width:520px">${esc(s.command)}</td>
      <td class="num">${actionBtn("open_startup_apps")}</td></tr>`).join("") + "</tbody>"
    : `<tbody><tr><td class="empty">${sec.finished ? "No startup entries found." : "Scan in progress…"}</td></tr></tbody>`;
}
$("#scanSecBtn").addEventListener("click", async () => { sigs.security = null; await api("/api/security/scan", {}); poll(); });

/* ------------------------------------------------------------------ ask claude */
function renderKeyStatus() {
  const a = S.assistant;
  const sig = JSON.stringify(a);
  if (sigs.key === sig) return;
  sigs.key = sig;
  let html;
  if (!a.sdk) html = `${chip("warning", "SDK missing")} Install it with <code>pip install anthropic</code>, then restart Heat Doctor.`;
  else if (a.key_source === "app") html = `${chip("good", "Key set")} ${a.saved ? "Saved on this computer." : "For this session only."}`;
  else if (a.key_source === "env") html = `${chip("good", "Using ANTHROPIC_API_KEY")} from your environment.`;
  else html = `${chip("info", "No key yet")} Paste an Anthropic API key to enable Ask Claude.`;
  $("#keyStatus").innerHTML = html + ` <span class="muted">Model: ${esc(a.model)}</span>`;
}
$("#keyForm").addEventListener("submit", async e => {
  e.preventDefault();
  const r = await (await api("/api/key", { key: $("#keyInput").value, remember: $("#keyRemember").checked })).json();
  toast(r.message, r.ok ? "good" : "serious");
  if (r.ok) $("#keyInput").value = "";
  poll();
});
$("#keyClear").addEventListener("click", async () => {
  const r = await (await api("/api/key", { key: "", remember: false })).json();
  toast(r.message, "info");
  poll();
});

function inlineMd(s) {
  return s
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>")
    .replace(/(^|[^*])\*([^*\s][^*]*)\*/g, "$1<i>$2</i>")
    .replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
}
function md(src) {
  // Escape first, then add a small, safe subset of Markdown.
  const lines = esc(src).split("\n");
  let html = "", list = null, code = false, para = [];
  const flushPara = () => { if (para.length) { html += `<p>${inlineMd(para.join(" "))}</p>`; para = []; } };
  const closeList = () => { if (list) { html += `</${list}>`; list = null; } };
  for (const raw of lines) {
    const line = raw.trimEnd();
    if (line.startsWith("```")) { flushPara(); closeList(); html += code ? "</code></pre>" : "<pre><code>"; code = !code; continue; }
    if (code) { html += line + "\n"; continue; }
    let m;
    if ((m = line.match(/^(#{1,4})\s+(.*)/))) { flushPara(); closeList(); const lv = Math.min(3, m[1].length + 1); html += `<h${lv}>${inlineMd(m[2])}</h${lv}>`; continue; }
    if ((m = line.match(/^\s*[-*•]\s+(.*)/))) { flushPara(); if (list !== "ul") { closeList(); html += "<ul>"; list = "ul"; } html += `<li>${inlineMd(m[1])}</li>`; continue; }
    if ((m = line.match(/^\s*\d+[.)]\s+(.*)/))) { flushPara(); if (list !== "ol") { closeList(); html += "<ol>"; list = "ol"; } html += `<li>${inlineMd(m[1])}</li>`; continue; }
    if (!line.trim()) { flushPara(); closeList(); continue; }
    closeList();
    para.push(line);
  }
  flushPara(); closeList();
  if (code) html += "</code></pre>";
  return html;
}

async function ask(question) {
  const chat = $("#chat");
  const u = document.createElement("div");
  u.className = "msg user";
  u.textContent = question;
  chat.appendChild(u);
  const b = document.createElement("div");
  b.className = "msg bot typing";
  chat.appendChild(b);
  b.scrollIntoView({ block: "nearest", behavior: "smooth" });
  $("#askBtn").disabled = true;
  let text = "", raf = 0, failed = false;
  const paint = () => { raf = 0; b.innerHTML = md(text); };
  try {
    const r = await api("/api/ask", { question, history: chatHistory.slice(-4), window: Math.max(windowS, 300) });
    const reader = r.body.getReader();
    const dec = new TextDecoder();
    let buf = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let i;
      while ((i = buf.indexOf("\n\n")) >= 0) {
        const chunk = buf.slice(0, i); buf = buf.slice(i + 2);
        if (!chunk.startsWith("data: ")) continue;
        const ev = JSON.parse(chunk.slice(6));
        if (ev.type === "text") { text += ev.data; if (!raf) raf = requestAnimationFrame(paint); }
        else if (ev.type === "error") { failed = true; b.className = "msg bot err"; b.innerHTML = chip("serious", "Couldn't get an answer") + `<p>${esc(ev.data)}</p>`; }
      }
    }
  } catch (err) {
    failed = true;
    b.className = "msg bot err";
    b.innerHTML = chip("serious", "Connection problem") + `<p>${esc(err.message)}</p>`;
  }
  if (!failed) { paint(); b.classList.remove("typing"); chatHistory.push({ q: question, a: text }); }
  $("#askBtn").disabled = false;
}
$("#askForm").addEventListener("submit", e => {
  e.preventDefault();
  const q = $("#askInput").value.trim();
  if (!q) return;
  $("#askInput").value = "";
  ask(q);
});
$("#askInput").addEventListener("keydown", e => {
  if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); $("#askForm").requestSubmit ? $("#askForm").requestSubmit() : $("#askBtn").click(); }
});
$("#suggest").addEventListener("click", e => { if (e.target.tagName === "BUTTON") ask(e.target.textContent); });

/* ------------------------------------------------------------------ router */
const VIEWS = ["overview", "heat", "memory", "storage", "security", "ask"];
function currentView() { const h = location.hash.slice(1); return VIEWS.includes(h) ? h : "overview"; }
function route() {
  const v = currentView();
  for (const id of VIEWS) $(`#view-${id}`).classList.toggle("active", id === v);
  $$("nav.tabs a").forEach(a => a.setAttribute("aria-current", a.getAttribute("href") === `#${v}` ? "page" : "false"));
  if (S) render();
}
window.addEventListener("hashchange", route);
document.addEventListener("toggle", e => {
  const d = e.target;
  if (d.matches && d.matches("details[data-key]")) { d.open ? openDetails.add(d.dataset.key) : openDetails.delete(d.dataset.key); }
}, true);

/* ------------------------------------------------------------------ main loop */
function render() {
  renderTop();
  const v = currentView();
  if (v === "overview") renderOverview();
  else if (v === "heat") renderHeat();
  else if (v === "memory") renderMemory();
  else if (v === "storage") renderStorage();
  else if (v === "security") renderSecurity();
  else if (v === "ask") renderKeyStatus();
}

async function poll() {
  if (stopped) return;
  clearTimeout(pollTimer);
  try {
    const r = await api(`/api/state?window=${windowS}`);
    S = await r.json();
    render();
  } catch (err) {
    $("#topMeta").innerHTML = `<span>${chip("serious", "Disconnected")}</span><span>Is Heat Doctor still running?</span>`;
  }
  const fast = S && (S.storage.status === "running" || S.security.status === "running");
  pollTimer = setTimeout(poll, document.hidden ? 10000 : fast ? 1500 : 2000);
}
document.addEventListener("visibilitychange", () => { if (!document.hidden) poll(); });

$("#windowSeg").addEventListener("click", e => {
  const b = e.target.closest("button");
  if (!b) return;
  windowS = Number(b.dataset.w);
  $$("#windowSeg button").forEach(x => x.setAttribute("aria-pressed", String(x === b)));
  poll();
});

/* theme: auto -> light -> dark */
const THEMES = ["auto", "light", "dark"];
function applyTheme(t) {
  if (t === "auto") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", t);
  $("#themeBtn").textContent = `Theme: ${t[0].toUpperCase()}${t.slice(1)}`;
  try { localStorage.setItem("hd-theme", t); } catch (e) { /* storage blocked */ }
  if (S) render();
}
let theme = "auto";
try { theme = localStorage.getItem("hd-theme") || "auto"; } catch (e) { /* ignore */ }
applyTheme(THEMES.includes(theme) ? theme : "auto");
$("#themeBtn").addEventListener("click", () => { theme = THEMES[(THEMES.indexOf(theme) + 1) % 3]; applyTheme(theme); });

$("#quitBtn").addEventListener("click", async () => {
  if (!window.confirm("Stop Heat Doctor? Monitoring stops until you start it again.")) return;
  stopped = true;
  try { await api("/api/quit", {}); } catch (e) { /* server is going away */ }
  document.body.innerHTML = '<main class="wrap" style="padding-top:80px;text-align:center"><h1>Heat Doctor has stopped</h1><p class="muted">You can close this window.</p></main>';
});

let resizeT = 0;
window.addEventListener("resize", () => { clearTimeout(resizeT); resizeT = setTimeout(() => S && render(), 150); });

route();
poll();
