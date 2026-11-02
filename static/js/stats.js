import { initWidgets } from "./console/widgets.js";
import {
  actionColors,
  actionLabels,
  finite,
  formatNumber,
  milliseconds,
  bytes,
  summary,
  metricValues,
  nodeLabel,
  chartPosition,
} from "./management/stats-core.js";
const $ = (id) => document.getElementById(id),
  ns = "http://www.w3.org/2000/svg";
const text = (id, value) => {
  const el = $(id);
  if (el) el.textContent = value;
};
const element = (tag, value, cls) => {
  const el = document.createElement(tag);
  if (value !== undefined) el.textContent = value;
  if (cls) el.className = cls;
  return el;
};
const svg = (tag, attrs = {}) => {
  const el = document.createElementNS(ns, tag);
  for (const [key, value] of Object.entries(attrs))
    el.setAttribute(key, String(value));
  return el;
};
const time = (value) => {
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date.toLocaleString() : "Unknown";
};
const form = $("statsFilters");
let source = null,
  paused = false,
  generation = 0,
  abort = null,
  nextBefore = 0,
  mapShapes = [],
  latest = null;
let extra = {};
function query() {
  const q = new URLSearchParams(new FormData(form));
  for (const [key, value] of Object.entries(extra))
    if (value) q.set(key, value);
  for (const [key, value] of [...q]) if (!value) q.delete(key);
  return q;
}
function option(select, value, label) {
  if (!value) return;
  let opt = [...select.options].find((o) => o.value === value);
  if (!opt) {
    opt = element("option", label);
    opt.value = value;
    select.append(opt);
  } else opt.textContent = label;
}
function filter(key, value) {
  if (form.elements[key]) form.elements[key].value = value;
  else extra[key] = value;
  connect();
}
function ranking(id, rows, key) {
  const box = $(id);
  box.replaceChildren();
  if (!rows?.length) {
    box.append(element("p", "No decisions in this view.", "stats-empty"));
    return;
  }
  const list = element("div", undefined, "stats-ranking");
  for (const row of rows.slice(0, 250)) {
    const button = element("button", undefined, "stats-rank");
    button.type = "button";
    button.append(
      element("span", row.key || "Not recorded"),
      element("strong", formatNumber(row.count)),
    );
    if (key && row.key)
      button.addEventListener("click", () => filter(key, row.key));
    else button.disabled = true;
    list.append(button);
  }
  box.append(list);
}
function legend(box, items) {
  box.replaceChildren();
  for (const [key, label] of items) {
    const span = element("span");
    const dot = element("i", undefined, "stats-dot");
    dot.style.backgroundColor = actionColors[key] || key;
    span.append(dot, document.createTextNode(label));
    box.append(span);
  }
}
function axes(chart, width, height, start, end) {
  chart.replaceChildren();
  chart.append(
    svg("path", {
      d: `M40 10V${height - 25}H${width - 10}`,
      class: "stats-chart-axis",
      fill: "none",
    }),
  );
  for (const [value, x] of [
    [start, 40],
    [end, width - 130],
  ]) {
    const label = svg("text", { x, y: height - 5, class: "stats-chart-text" });
    label.textContent = time(value);
    chart.append(label);
  }
}
function traffic(data) {
  const chart = $("statsTraffic");
  axes(chart, 960, 230, data.start, data.end);
  const points = (data.timeline || []).slice(0, 3606),
    max = Math.max(1, ...points.map((p) => finite(p.count) || 0));
  const duration = (Date.parse(data.end) - Date.parse(data.start)) / 1000;
  const barWidth = Math.max(
    0.5,
    (880 * data.bucket_seconds) / Math.max(1, duration) / 6,
  );
  const actions = Object.keys(actionColors);
  for (const point of points) {
    const x = chartPosition(point.time, data.start, data.end, 880);
    if (x === null) continue;
    const height = ((finite(point.count) || 0) / max) * 165;
    const bar = svg("rect", {
      x: 40 + x + actions.indexOf(point.action) * barWidth,
      y: 190 - height,
      width: barWidth,
      height,
      fill: actionColors[point.action] || "#888",
    });
    const title = svg("title");
    title.textContent = `${time(point.time)} · ${actionLabels[point.action] || point.action}: ${formatNumber(point.count)}`;
    bar.append(title);
    chart.append(bar);
  }
  legend($("statsLegend"), Object.entries(actionLabels));
  const body = $("statsTrafficRows");
  body.replaceChildren();
  for (const point of points) {
    const row = element("tr");
    for (const value of [
      time(point.time),
      actionLabels[point.action] || point.action,
      formatNumber(point.count),
    ])
      row.append(element("td", value));
    body.append(row);
  }
}
function latency(data) {
  const p = data.latency || {};
  text("statLatency", milliseconds(p.p95_ms));
  text(
    "statsLatencySummary",
    `p50 ${milliseconds(p.p50_ms)} · p95 ${milliseconds(p.p95_ms)} · p99 ${milliseconds(p.p99_ms)} · ${formatNumber(p.samples)} timed / ${formatNumber(p.unknown)} unknown`,
  );
  const chart = $("statsLatencyChart");
  axes(chart, 600, 200, data.start, data.end);
  const points = (data.latency_timeline || []).slice(0, 601);
  const max = Math.max(
    1,
    ...points.flatMap((p) =>
      [p.p50_ms, p.p95_ms, p.p99_ms].filter((v) => finite(v) !== null),
    ),
  );
  for (const [key, color] of [
    ["p50_ms", "#22c55e"],
    ["p95_ms", "#38bdf8"],
    ["p99_ms", "#c084fc"],
  ]) {
    let path = "",
      previous = 0;
    for (const point of points) {
      const x = chartPosition(point.time, data.start, data.end, 540),
        value = finite(point[key]),
        at = Date.parse(point.time);
      if (x === null || value === null) continue;
      const command =
        !path || at - previous > data.bucket_seconds * 1500 ? "M" : "L";
      path += `${command}${40 + x},${160 - (value / max) * 140}`;
      previous = at;
    }
    chart.append(
      svg("path", { d: path, fill: "none", stroke: color, "stroke-width": 2 }),
    );
  }
}
function drawMap(data) {
  const counts = new Map((data.countries || []).map((r) => [r.key, r.count])),
    max = Math.max(1, ...counts.values());
  for (const { el, code, name } of mapShapes) {
    const count = counts.get(code) || 0;
    el.setAttribute(
      "fill",
      count
        ? `hsl(195 80% ${Math.round(35 + 25 * Math.sqrt(count / max))}%)`
        : "var(--rc-surface-3)",
    );
    el.style.fill = count
      ? `hsl(195 80% ${Math.round(35 + 25 * Math.sqrt(count / max))}%)`
      : "var(--rc-surface-3)";
    el.setAttribute("aria-label", `${name}: ${formatNumber(count)} decisions`);
    el.setAttribute("tabindex", count ? "0" : "-1");
    el.querySelector("title").textContent = `${name}: ${formatNumber(count)}`;
  }
}
async function loadMap() {
  try {
    const response = await fetch("/static/data/countries-110m.json", {
      credentials: "same-origin",
    });
    if (!response.ok) throw new Error("map unavailable");
    const countries = await response.json();
    for (const c of countries.slice(0, 250)) {
      if (
        !/^[A-Z]{2}$/.test(c.code) ||
        typeof c.path !== "string" ||
        !/^[MLZ0-9., -]+$/.test(c.path)
      )
        continue;
      const path = svg("path", {
        d: c.path,
        class: "stats-country-shape",
        role: "button",
        tabindex: "-1",
      });
      path.append(svg("title"));
      path.addEventListener("click", () => filter("country", c.code));
      path.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          filter("country", c.code);
        }
      });
      $("statsMap").append(path);
      mapShapes.push({ el: path, code: c.code, name: c.name });
    }
    if (latest) drawMap(latest);
  } catch {
    text(
      "statsMapStatus",
      "Map unavailable. Country counts remain available below.",
    );
  }
}
function nodes(data) {
  const box = $("statsNodes");
  box.replaceChildren();
  if (!data.nodes?.length) {
    box.append(
      element(
        "p",
        "No retained node observations. Missing samples are not zero.",
        "stats-empty",
      ),
    );
    return;
  }
  for (const node of data.nodes) {
    option($("statsNode"), node.node_id, nodeLabel(node));
    option($("statsDiagnosticNode"), node.node_id, nodeLabel(node));
    const p = node.snapshot || {},
      values = metricValues(p),
      health = p.health || {};
    const card = element("article", undefined, "stats-node");
    card.append(
      element("h3", nodeLabel(node)),
      element("div", node.node_id, "mono small text-muted"),
    );
    const state = node.stale ? "Stale" : health.ready ? "Ready" : "Not ready";
    card.append(
      element(
        "span",
        state,
        `chip ${node.stale ? "warn" : health.ready ? "ok" : "warn"}`,
      ),
    );
    const list = element("dl");
    const add = (label, value) =>
      list.append(element("dt", label), element("dd", value));
    add("Observed", time(node.time));
    add("Process started", time(p.started_at));
    add("Build", p.build_revision?.slice(0, 12) || p.go_version || "Unknown");
    add(
      "CPU rate",
      node.interval_covered &&
        finite(node.rates?.process_cpu_seconds_total) !== null
        ? `${formatNumber(node.rates.process_cpu_seconds_total * 100)}% of one core`
        : "No covered interval",
    );
    add(
      "RSS / heap",
      `${bytes(values.process_resident_memory_bytes)} / ${bytes(values.go_heap_alloc_bytes)}`,
    );
    add(
      "Goroutines / GC",
      `${formatNumber(values.go_goroutines)} / ${formatNumber(values.go_gc_cycles_total)}`,
    );
    add(
      "Auth / enrollment",
      p.health
        ? `${health.auth_ready ? "Ready" : "Unavailable"} / ${health.enrollment_ready ? "Ready" : "Unavailable"}`
        : "Not observed",
    );
    add(
      "Policy applied / desired",
      p.health ? `${health.applied} / ${health.desired}` : "Not observed",
    );
    add(
      "Policy lease",
      p.health ? time(health.lease_expires_at) : "Not observed",
    );
    add(
      "Local buffer",
      p.health
        ? `${health.local_ready ? "Ready" : "Unavailable"} · ${formatNumber(health.pending)} pending`
        : "Not observed",
    );
    add("Buffer disk", bytes(health.disk_bytes));
    add(
      "Known drops / restarts",
      p.health
        ? `${formatNumber(health.dropped)} / ${formatNumber(health.unclean_restarts)}`
        : "Not observed",
    );
    add(
      "Delivery",
      p.health
        ? `${health.delivery_ready ? "Available" : "Unavailable"} · ${time(health.last_delivered)}`
        : "Not observed",
    );
    add(
      "GeoIP database",
      values.rauth_geoip_db_build_timestamp
        ? time(values.rauth_geoip_db_build_timestamp * 1000)
        : "Not observed",
    );
    add(
      "Login success / failed",
      `${formatNumber(values.rauth_login_success_total)} / ${formatNumber(values.rauth_login_failed_total)}`,
    );
    add(
      "Rate limit / 2FA outcomes",
      `${formatNumber(values.rauth_rate_limit_hits_total)} / ${formatNumber(values.rauth_second_factor_total)}`,
    );
    add(
      "Snapshot coverage",
      p.partial
        ? "Partial"
        : node.interval_covered
          ? "Recent same-process interval"
          : "No covered rate interval",
    );
    card.append(list);
    box.append(card);
  }
}
function render(data) {
  latest = data;
  for (const [key, value] of Object.entries(summary(data)))
    text("stat" + key, formatNumber(value));
  latency(data);
  traffic(data);
  nodes(data);
  for (const row of data.countries || [])
    option($("statsCountry"), row.key, row.key);
  ranking("statsCountries", data.countries, "country");
  for (const [key, filterKey] of Object.entries({
    urls: "url",
    domains: "domain",
    ips: "source",
    reasons: "reason",
    feeds: null,
  })) {
    ranking("statsTop" + key, data.top?.[key], filterKey);
    const note = element(
      "p",
      data.top_unavailable
        ? "Top list unavailable; aggregate charts remain available."
        : data.top_scope || "",
      "text-muted small",
    );
    $("statsTop" + key).prepend(note);
  }
  drawMap(data);
  text("statsUpdated", `Updated ${time(data.generated_at)}`);
  text("statsConnection", paused ? "Paused" : "Live");
  text(
    "statsResolution",
    `${formatNumber(data.bucket_seconds)} second buckets`,
  );
  text(
    "statsScope",
    Object.keys(extra).length
      ? `Traffic drilldown: ${Object.entries(extra)
          .map(([k, v]) => `${k} = ${v}`)
          .join(" · ")}. Node/time scope applies to system panels.`
      : "Node/time scope applies to system panels. Action/country scope applies to traffic.",
  );
  text(
    "statsCoverage",
    `${data.coverage}. Retained since ${time(data.retained_since)} · ${formatNumber(data.expired)} expired history records · ${formatNumber(data.loss_markers)} loss markers in window. Latency values are histogram estimates.`,
  );
}
async function history(before = 0) {
  const current = generation,
    q = query();
  if (before) q.set("before", String(before));
  text("statsHistoryState", "Loading…");
  try {
    const r = await fetch("/rauthmgmt/stats/history?" + q, {
      signal: abort.signal,
      headers: { Accept: "application/json" },
    });
    if (current !== generation) return;
    if (!r.ok) throw new Error("unavailable");
    const data = await r.json();
    if (current !== generation) return;
    const body = $("statsHistory");
    body.replaceChildren();
    for (const event of (data.events || []).slice(0, 100)) {
      const row = element("tr"),
        cells = [
          ["Time", time(event.time)],
          ["URL", event.url || "Not recorded"],
          ["Original client IP", event.source],
          ["Country", event.country],
          ["Action", actionLabels[event.action] || event.action],
          ["Processing node", event.node_name || event.node_id],
          [
            "Processing",
            event.processing_us
              ? milliseconds(event.processing_us / 1000)
              : "Unknown",
          ],
        ];
      for (const [label, value] of cells) {
        const td = element("td", value);
        td.dataset.label = label;
        if (label === "Action")
          td.style.color = actionColors[event.action] || "inherit";
        if (label === "Processing node") td.title = event.node_id || "";
        row.append(td);
      }
      body.append(row);
    }
    nextBefore = data.before || 0;
    $("statsOlder").disabled = !nextBefore;
    text(
      "statsHistoryState",
      data.events?.length
        ? `${data.events.length} decisions shown`
        : "No decisions in this view.",
    );
  } catch (error) {
    if (error.name !== "AbortError")
      text("statsHistoryState", "Decision history unavailable.");
  }
}

let lastHAView = null;
function renderHA(view) {
  const members = $("statsHAMembers");
  if (!members) return;
  members.replaceChildren();
  if (!view || typeof view !== "object" || !view.configured) {
    lastHAView = null;
    text("statsHAState", "Not configured");
    text("statsHASummary", "No HA observation source is configured.");
    text(
      "statsHACoverage",
      "Authentication readiness is checked independently.",
    );
    return;
  }
  if (view.report) lastHAView = view;
  else if (lastHAView?.report) view = { ...view, report: lastHAView.report };
  const fresh = view.available === true && view.stale !== true;
  const state = fresh
    ? view.state === "healthy"
      ? "Observed services healthy"
      : "Degraded"
    : view.stale
      ? "Stale"
      : "Unavailable";
  text("statsHAState", state);
  text(
    "statsHASummary",
    fresh
      ? `Quorum ${view.healthy_voters}/3 · Running databases ${view.running_data_members}/3 · Verified primary ${view.verified_leaders} · Synchronous replicas ${view.synchronous_replicas}`
      : "Current HA status is unknown. Last observations are retained below.",
  );
  text(
    "statsHACoverage",
    `${view.report?.mode === "isolated-test" ? "Isolated test cluster · " : ""}All state members · Current observation ${time(view.report?.checked_at)} · Fencing not observed · Authentication readiness is independent`,
  );
  for (const member of view.report?.members || []) {
    const databaseIdentity =
      member.system_id === view.report.expected_system_id;
    const dcsIdentity =
      member.dcs_cluster_id === view.report.expected_dcs_cluster_id;
    const card = element("article", "", "stats-ha-member");
    card.append(element("h3", member.name));
    const add = (label, value) => {
      const row = element("p");
      row.append(element("strong", label + ": "), element("span", value));
      card.append(row);
    };
    add(
      "PostgreSQL",
      fresh
        ? member.database_ready
          ? databaseIdentity
            ? member.role
            : "Identity mismatch"
          : "Unavailable"
        : "Last known: " + member.role,
    );
    add(
      "Primary lease",
      fresh
        ? member.leader_verified
          ? "Verified"
          : "Not primary / unavailable"
        : "Not observed",
    );
    add(
      "Replication lag",
      fresh && member.lag_bytes != null
        ? bytes(member.lag_bytes)
        : "Not observed",
    );
    add("Timeline", member.timeline || "Not observed");
    add(
      "Server version",
      member.server_version
        ? `${Math.floor(member.server_version / 10000)}.${member.server_version % 10000}`
        : "Not observed",
    );
    add(
      "Quorum voter",
      fresh
        ? member.dcs_ready
          ? dcsIdentity
            ? "Healthy"
            : "Identity mismatch"
          : "Unavailable"
        : "Not observed",
    );
    add(
      "DCS database",
      fresh && member.dcs_quota_bytes
        ? `${bytes(member.dcs_bytes)} / ${bytes(member.dcs_quota_bytes)}`
        : "Not observed",
    );
    add("TLS leaf expires", time(member.certificate_expires_at));
    if (member.issue) add("Observation", member.issue.replaceAll("_", " "));
    members.append(card);
  }
}

async function operations() {
  if (paused) return;
  const current = generation;
  try {
    const r = await fetch("/rauthmgmt/stats/operations", {
      signal: abort.signal,
      headers: { Accept: "application/json" },
    });
    if (!r.ok) throw new Error();
    const data = await r.json();
    if (current !== generation) return;
    text(
      "statsSessions",
      `Active sessions: ${formatNumber(data.active_sessions)} · ${data.session_scope}`,
    );
    text("statsOperations", JSON.stringify(data, null, 2));
    renderHA(data.ha_observation);
    text("statsOperationsState", `Observed ${time(data.checked_at)}`);
    const feeds = $("statsFeedHealth");
    feeds.replaceChildren();
    for (const feed of data.feeds || []) {
      feeds.append(
        element(
          "p",
          `${feed.name} · ${feed.ready ? "Ready" : "Not ready"}${feed.stale ? " / stale" : ""}${feed.refresh_failed ? " / refresh failed" : ""} · version ${feed.version} · ${formatNumber(feed.entries)} entries · last success ${time(feed.last_success * 1000)}`,
        ),
      );
    }
  } catch (error) {
    if (error.name !== "AbortError") {
      if (lastHAView)
        renderHA({ configured: true, available: false, stale: true });
      text(
        "statsOperationsState",
        "Operations unavailable; previous observation is stale",
      );
    }
  }
}
function connect() {
  generation++;
  source?.close();
  source = null;
  abort?.abort();
  abort = new AbortController();
  if (paused) {
    text("statsConnection", "Paused · observations are frozen");
    return;
  }
  text("statsConnection", "Connecting…");
  const current = generation;
  source = new EventSource("/rauthmgmt/stats/stream?" + query());
  source.addEventListener("stats", (event) => {
    if (current !== generation || paused) return;
    try {
      render(JSON.parse(event.data));
    } catch {
      text("statsConnection", "Invalid statistics snapshot");
    }
  });
  source.addEventListener("unavailable", () => {
    if (current === generation)
      text(
        "statsConnection",
        "Statistics unavailable · last snapshot is stale",
      );
  });
  source.addEventListener("session-ended", () => {
    if (current !== generation) return;
    source.close();
    text("statsConnection", "Administrator access ended. Sign in again.");
  });
  source.onerror = () => {
    if (current === generation && !paused)
      text(
        "statsConnection",
        "Disconnected · reconnecting; last snapshot is stale",
      );
  };
  history();
  operations();
}
async function diagnostics() {
  const node = $("statsDiagnosticNode").value;
  if (!node) {
    text("statsDiagnosticsState", "Select a processing node.");
    return;
  }
  text("statsDiagnosticsState", "Loading…");
  try {
    const r = await fetch(
      "/rauthmgmt/stats/diagnostics?" + new URLSearchParams({ node }),
      { headers: { Accept: "application/json" } },
    );
    if (!r.ok) throw new Error();
    const data = await r.json();
    text("statsDiagnostics", JSON.stringify(data, null, 2));
    text(
      "statsDiagnosticsState",
      `${data.complete ? "Complete capture" : "Incomplete or missing capture"} · ${time(data.time)}${data.parts?.some((p) => p.partial) ? " · some series were unavailable or exceeded bounds" : ""}`,
    );
    const link = $("statsDownloadDiagnostics");
    link.href =
      "/rauthmgmt/stats/diagnostics?" +
      new URLSearchParams({ node, download: "1" });
    link.hidden = false;
  } catch {
    text("statsDiagnosticsState", "Metric diagnostics unavailable.");
  }
}
if (form) {
  initWidgets();
  text("pageTitle", "Stats");
  form.addEventListener("submit", (event) => event.preventDefault());
  form.addEventListener("change", connect);
  $("statsPause").addEventListener("click", () => {
    paused = !paused;
    $("statsPause").textContent = paused ? "Resume" : "Pause";
    $("statsPause").setAttribute("aria-pressed", String(paused));
    connect();
  });
  $("statsClear").addEventListener("click", () => {
    form.reset();
    extra = {};
    connect();
  });
  $("statsOlder").addEventListener("click", () => history(nextBefore));
  $("statsHistoryRefresh").addEventListener("click", () => history());
  $("statsLoadDiagnostics").addEventListener("click", diagnostics);
  loadMap();
  connect();
  const timer = setInterval(operations, 15000);
  window.addEventListener(
    "pagehide",
    () => {
      generation++;
      source?.close();
      abort?.abort();
      clearInterval(timer);
    },
    { once: true },
  );
}
