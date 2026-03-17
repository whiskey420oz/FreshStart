const ALERTS_BODY = document.getElementById("alerts-body");
const ERROR_BANNER = document.getElementById("error-banner");
const STREAM_STATUS = document.getElementById("stream-status");
const METRIC_TOTAL = document.getElementById("metric-total");
const METRIC_CRITICAL = document.getElementById("metric-critical");
const METRIC_HIGH = document.getElementById("metric-high");
const METRIC_AGENTS = document.getElementById("metric-agents");
const METRIC_SUSPICIOUS = document.getElementById("metric-suspicious");
const METRIC_EVENTS = document.getElementById("metric-events");
const METRIC_OPEN_CASES = document.getElementById("metric-open-cases");
const METRIC_RESOLVED_TODAY = document.getElementById("metric-resolved-today");
const METRIC_MTTR = document.getElementById("metric-mttr");
const METRIC_ANALYSTS = document.getElementById("metric-analysts");
const TOP_RULES_BODY = document.getElementById("top-rules-body");
const TOP_ATTACKERS_BODY = document.getElementById("top-attackers-body");
const HOSTS_BODY = document.getElementById("hosts-body");
const ATTACK_TIMELINE = document.getElementById("attack-timeline");
const ACTIVITY_FEED = document.getElementById("soc-activity");
const PULSE_INDICATORS = document.getElementById("pulse-indicators");
const PULSE_MALWARE = document.getElementById("pulse-malware");
const PULSE_BLOCKED = document.getElementById("pulse-blocked");
const LOCK_BUTTON = document.getElementById("lock-button");
const LOCK_OVERLAY = document.getElementById("lock-overlay");
const LOCK_PASSWORD = document.getElementById("lock-password");
const UNLOCK_BUTTON = document.getElementById("unlock-button");
const LOCK_ERROR = document.getElementById("lock-error");
const APP_CONTENT = document.getElementById("app-content");

const UPDATED_SEVERITY = document.getElementById("updated-severity");
const UPDATED_TIMELINE = document.getElementById("updated-timeline");
const UPDATED_MAP = document.getElementById("updated-map");
const UPDATED_ATTACKERS = document.getElementById("updated-attackers");
const UPDATED_RULES = document.getElementById("updated-rules");
const UPDATED_LIVE = document.getElementById("updated-live");
const UPDATED_HOSTS = document.getElementById("updated-hosts");
const UPDATED_STREAM = document.getElementById("updated-stream");
const UPDATED_ACTIVITY = document.getElementById("updated-activity");

let severityChart;
let timelineChart;
let map;
let markersLayer;
let isLocked = false;

const SOC_PASSWORD = "freshstart";
const MAX_RECENT_ALERTS = 200;
let recentAlerts = [];

const lastUpdated = {
  severity: null,
  timeline: null,
  map: null,
  attackers: null,
  rules: null,
  live: null,
  hosts: null,
  stream: null,
  activity: null,
};

const updatedLabels = {
  severity: UPDATED_SEVERITY,
  timeline: UPDATED_TIMELINE,
  map: UPDATED_MAP,
  attackers: UPDATED_ATTACKERS,
  rules: UPDATED_RULES,
  live: UPDATED_LIVE,
  hosts: UPDATED_HOSTS,
  stream: UPDATED_STREAM,
  activity: UPDATED_ACTIVITY,
};

function markUpdated(key) {
  if (!lastUpdated[key]) {
    lastUpdated[key] = Date.now();
  } else {
    lastUpdated[key] = Date.now();
  }
}

function renderFreshness() {
  Object.keys(updatedLabels).forEach((key) => {
    const label = updatedLabels[key];
    if (!label) return;
    const timestamp = lastUpdated[key];
    if (!timestamp) {
      label.textContent = "Last updated: —";
      return;
    }
    const seconds = Math.max(0, Math.floor((Date.now() - timestamp) / 1000));
    label.textContent = `Last updated: ${seconds}s ago`;
  });
}

function setStatus(text, isOffline = false) {
  STREAM_STATUS.textContent = text;
  STREAM_STATUS.classList.toggle("offline", isOffline);
}

function showError(message) {
  ERROR_BANNER.textContent = message;
  ERROR_BANNER.classList.remove("hidden");
}

function clearError() {
  ERROR_BANNER.textContent = "";
  ERROR_BANNER.classList.add("hidden");
}

function lockConsole() {
  if (isLocked) return;
  isLocked = true;
  localStorage.setItem("socLocked", "true");
  LOCK_OVERLAY.classList.remove("hidden");
  APP_CONTENT.classList.add("app-locked");
  LOCK_ERROR.classList.add("hidden");
  LOCK_PASSWORD.value = "";
  LOCK_PASSWORD.focus();
}

function unlockConsole() {
  if (LOCK_PASSWORD.value === SOC_PASSWORD) {
    isLocked = false;
    localStorage.removeItem("socLocked");
    LOCK_OVERLAY.classList.add("hidden");
    APP_CONTENT.classList.remove("app-locked");
    LOCK_ERROR.classList.add("hidden");
    LOCK_PASSWORD.value = "";
  } else {
    LOCK_ERROR.classList.remove("hidden");
  }
}

function severityBucket(level) {
  if (level <= 3) return "low";
  if (level <= 6) return "medium";
  if (level <= 9) return "high";
  return "critical";
}

function severityColor(level) {
  const bucket = severityBucket(level);
  return {
    low: "#2dd4bf",
    medium: "#facc15",
    high: "#fb923c",
    critical: "#f87171",
  }[bucket];
}

function formatTimestamp(value) {
  if (!value) return "Unknown";
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) return String(value);
  const date = new Date(parsed);
  const formatted = date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
  return formatted.replace(",", "");
}

function isPrivateIp(ip) {
  if (!ip) return true;
  if (ip.startsWith("10.")) return true;
  if (ip.startsWith("192.168.")) return true;
  if (ip.startsWith("127.")) return true;
  if (ip.startsWith("169.254.")) return true;
  if (ip.startsWith("172.")) {
    const parts = ip.split(".");
    if (parts.length > 1) {
      const second = Number(parts[1]);
      return second >= 16 && second <= 31;
    }
  }
  return false;
}

function updateMetrics(metrics) {
  if (!metrics) return;
  METRIC_TOTAL.textContent = metrics.total_alerts ?? 0;
  METRIC_CRITICAL.textContent = metrics.critical_alerts ?? 0;
  METRIC_HIGH.textContent = metrics.high_alerts ?? 0;
  METRIC_AGENTS.textContent = metrics.active_agents ?? 0;
  METRIC_SUSPICIOUS.textContent = metrics.suspicious_ips ?? 0;
  METRIC_EVENTS.textContent = metrics.events_processed ?? 0;

  const cases = loadCases();
  METRIC_OPEN_CASES.textContent = cases.filter((item) => item.status !== "Resolved").length;
  METRIC_RESOLVED_TODAY.textContent = countResolvedToday();
  METRIC_MTTR.textContent = "—";
  METRIC_ANALYSTS.textContent = "1";

  PULSE_INDICATORS.textContent = metrics.suspicious_ips ?? "—";
  PULSE_MALWARE.textContent = metrics.critical_alerts ?? "—";
  PULSE_BLOCKED.textContent = metrics.high_alerts ?? "—";
}

function updateTopRules(rules) {
  TOP_RULES_BODY.innerHTML = (rules || [])
    .map((rule) => {
      const severity = rule.severity || "medium";
      const description = rule.rule_description || rule.rule_id || "Unknown rule";
      return `
        <tr>
          <td>${description}</td>
          <td>${rule.count}</td>
          <td><span class="severity ${severity}">${severity.toUpperCase()}</span></td>
        </tr>
      `;
    })
    .join("");
}

function updateTopAttackers(attackers) {
  TOP_ATTACKERS_BODY.innerHTML = (attackers || [])
    .map((attacker) => {
      const severity = severityBucket(attacker.severity || 5);
      return `
        <tr>
          <td>${attacker.src_ip}</td>
          <td>${attacker.count}</td>
          <td><span class="severity ${severity}">${severity.toUpperCase()}</span></td>
        </tr>
      `;
    })
    .join("");
}

function updateHosts(hosts) {
  HOSTS_BODY.innerHTML = (hosts || [])
    .map(
      (host) => `
        <tr>
          <td>${host.host}</td>
          <td>${host.count}</td>
          <td>${host.highest_severity}</td>
          <td>${host.last_activity || "—"}</td>
        </tr>
      `
    )
    .join("");
}

function initCharts() {
  const severityCtx = document.getElementById("severity-chart");
  const timelineCtx = document.getElementById("timeline-chart");

  severityChart = new Chart(severityCtx, {
    type: "bar",
    data: {
      labels: ["Critical", "High", "Medium", "Low"],
      datasets: [
        {
          label: "Alerts",
          data: [0, 0, 0, 0],
          backgroundColor: ["#f87171", "#fb923c", "#facc15", "#2dd4bf"],
          borderRadius: 8,
          barThickness: 18,
        },
      ],
    },
    options: {
      indexAxis: "y",
      plugins: {
        legend: { display: false },
        tooltip: { enabled: true, intersect: false },
      },
      animation: { duration: 700, easing: "easeOutQuart" },
      scales: {
        x: { ticks: { color: "#94a3b8" }, grid: { color: "rgba(148,163,184,0.2)" } },
        y: { ticks: { color: "#e2e8f0" }, grid: { display: false } },
      },
    },
  });

  timelineChart = new Chart(timelineCtx, {
    type: "line",
    data: {
      labels: [],
      datasets: [
        { label: "Critical", data: [], borderColor: "#f87171", tension: 0.35, pointRadius: 0 },
        { label: "High", data: [], borderColor: "#fb923c", tension: 0.35, pointRadius: 0 },
        { label: "Medium", data: [], borderColor: "#facc15", tension: 0.35, pointRadius: 0 },
        { label: "Low", data: [], borderColor: "#2dd4bf", tension: 0.35, pointRadius: 0 },
      ],
    },
    options: {
      plugins: {
        legend: { labels: { color: "#e2e8f0" } },
        tooltip: { enabled: true, intersect: false },
      },
      interaction: { mode: "index", intersect: false },
      animation: { duration: 700, easing: "easeOutQuart" },
      scales: {
        x: { ticks: { color: "#94a3b8" }, grid: { color: "rgba(148,163,184,0.2)" } },
        y: { ticks: { color: "#94a3b8" }, grid: { color: "rgba(148,163,184,0.2)" } },
      },
    },
  });
}

function updateCharts(timeline) {
  if (!timeline || !timeline.labels) return;
  const counts = timeline.series || {};
  timelineChart.data.labels = timeline.labels;
  timelineChart.data.datasets[0].data = counts.critical || [];
  timelineChart.data.datasets[1].data = counts.high || [];
  timelineChart.data.datasets[2].data = counts.medium || [];
  timelineChart.data.datasets[3].data = counts.low || [];
  timelineChart.update();

  const totals = [
    (counts.critical || []).reduce((a, b) => a + b, 0),
    (counts.high || []).reduce((a, b) => a + b, 0),
    (counts.medium || []).reduce((a, b) => a + b, 0),
    (counts.low || []).reduce((a, b) => a + b, 0),
  ];
  severityChart.data.datasets[0].data = totals;
  severityChart.update();
}

function initMap() {
  map = L.map("attack-map", { zoomControl: false }).setView([20, 0], 2);
  L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
    attribution: "",
  }).addTo(map);
  markersLayer = L.layerGroup().addTo(map);
}

function addMapMarker(alert) {
  if (!alert.src_ip || isPrivateIp(alert.src_ip)) return;
  const color = severityColor(alert.rule_level);
  const marker = L.circleMarker([20 + Math.random() * 40 - 20, Math.random() * 80 - 40], {
    radius: 6,
    color,
    fillColor: color,
    fillOpacity: 0.8,
    className: "map-marker",
  });
  marker.bindTooltip(
    `${alert.src_ip || "Unknown"}<br>${alert.rule_description}<br>Target: ${alert.agent_name}`,
    { direction: "top", opacity: 0.9 }
  );
  marker.addTo(markersLayer);
  markUpdated("map");
}

function renderRow(alert, prepend = false) {
  const level = Number.isFinite(alert.rule_level) ? alert.rule_level : 0;
  const bucket = severityBucket(level);
  const row = document.createElement("tr");
  row.classList.add("row-new");
  if (level >= 10) row.classList.add("row-critical");
  if (level >= 8 && level < 10) row.classList.add("row-high");

  const ipClass = !isPrivateIp(alert.src_ip) ? "ip-attacker" : "";

  row.innerHTML = `
    <td>${formatTimestamp(alert.timestamp)}</td>
    <td>${alert.rule_id}</td>
    <td>${alert.rule_description}</td>
    <td><span class="severity ${bucket}">${level}</span></td>
    <td>${alert.agent_name}</td>
    <td class="${ipClass}">${alert.src_ip || "N/A"}</td>
  `;

  if (prepend) {
    ALERTS_BODY.prepend(row);
  } else {
    ALERTS_BODY.appendChild(row);
  }

  setTimeout(() => row.classList.remove("row-new"), 1300);
}

function renderTimelineEntry(alert) {
  if (!ATTACK_TIMELINE) return;
  const level = Number.isFinite(alert.rule_level) ? alert.rule_level : 0;
  const bucket = severityBucket(level);

  const card = document.createElement("div");
  card.className = "timeline-card";
  card.innerHTML = `
    <div class="timeline-header">
      <span class="timeline-severity ${bucket}">${bucket.toUpperCase()}</span>
      <span class="timeline-meta">${formatTimestamp(alert.timestamp)}</span>
    </div>
    <div>${alert.rule_description}</div>
    <div class="timeline-meta">Source IP: ${alert.src_ip || "N/A"}</div>
  `;

  if (ATTACK_TIMELINE.querySelector(".timeline-empty")) {
    ATTACK_TIMELINE.innerHTML = "";
  }

  ATTACK_TIMELINE.prepend(card);
  if (ATTACK_TIMELINE.children.length > 100) {
    ATTACK_TIMELINE.removeChild(ATTACK_TIMELINE.lastElementChild);
  }
  markUpdated("live");
}

function renderInitial(alerts) {
  ALERTS_BODY.innerHTML = "";
  if (!alerts.length) {
    ALERTS_BODY.innerHTML = `
      <tr>
        <td colspan="6" class="muted">No alerts received yet.</td>
      </tr>
    `;
    return;
  }

  alerts.forEach((alert) => renderRow(alert));
  alerts.slice(0, 100).forEach((alert) => renderTimelineEntry(alert));
  recentAlerts = alerts.slice(0, MAX_RECENT_ALERTS);

  alerts.slice(0, 20).forEach((alert) => addMapMarker(alert));
  markUpdated("stream");
  markUpdated("live");
}

async function loadInitial() {
  try {
    const response = await fetch("/alerts");
    const payload = await response.json();
    if (!response.ok) throw new Error(payload?.error || "Failed to load alerts.");
    renderInitial(payload.alerts || []);
  } catch (error) {
    showError(error.message || "Unable to load alerts.");
  }
}

async function loadAnalytics() {
  try {
    const [metricsRes, attackersRes, timelineRes, rulesRes, hostsRes] = await Promise.all([
      fetch("/metrics"),
      fetch("/top_attackers"),
      fetch("/alerts_over_time"),
      fetch("/rule_statistics"),
      fetch("/risky_hosts"),
    ]);

    const metrics = await metricsRes.json();
    const attackers = await attackersRes.json();
    const timeline = await timelineRes.json();
    const rules = await rulesRes.json();
    const hosts = await hostsRes.json();

    updateMetrics(metrics.metrics);
    updateTopAttackers(attachSeverityToAttackers(attackers.attackers));
    updateCharts(timeline.timeline);
    updateTopRules(attachSeverityToRules(rules.rules));
    updateHosts(hosts.hosts);

    markUpdated("severity");
    markUpdated("timeline");
    markUpdated("attackers");
    markUpdated("rules");
    markUpdated("hosts");
  } catch (error) {
    showError(error.message || "Unable to load analytics.");
  }
}

function connectStream() {
  const source = new EventSource("/stream");

  source.onopen = () => {
    setStatus("Live", false);
    clearError();
  };

  source.onerror = () => {
    setStatus("Offline", true);
    showError("Live stream disconnected. Retrying...");
  };

  source.onmessage = (event) => {
    if (!event.data) return;
    const payload = JSON.parse(event.data);
    if (payload.type === "alert" && payload.alert) {
      if (ALERTS_BODY.querySelector(".muted")) {
        ALERTS_BODY.innerHTML = "";
      }
      renderRow(payload.alert, true);
      renderTimelineEntry(payload.alert);
      recentAlerts.unshift(payload.alert);
      if (recentAlerts.length > MAX_RECENT_ALERTS) {
        recentAlerts.pop();
      }
      updateMetrics(payload.metrics);
      updateTopAttackers(attachSeverityToAttackers(payload.attackers));
      updateCharts(payload.timeline);
      updateTopRules(attachSeverityToRules(payload.rules));
      updateHosts(payload.hosts);
      addMapMarker(payload.alert);
      addActivityEntry(`Alert ${payload.alert.rule_id} received`);
      markUpdated("stream");
    }
  };
}

function attachSeverityToAttackers(attackers) {
  if (!attackers) return [];
  const byIp = {};
  recentAlerts.forEach((alert) => {
    if (!alert.src_ip) return;
    const level = alert.rule_level || 0;
    byIp[alert.src_ip] = Math.max(byIp[alert.src_ip] || 0, level);
  });
  return attackers.map((attacker) => ({
    ...attacker,
    severity: byIp[attacker.src_ip] || 5,
  }));
}

function attachSeverityToRules(rules) {
  if (!rules) return [];
  const byRule = {};
  recentAlerts.forEach((alert) => {
    const key = alert.rule_id;
    if (!key) return;
    const level = alert.rule_level || 0;
    byRule[key] = Math.max(byRule[key] || 0, level);
  });
  return rules.map((rule) => ({
    ...rule,
    severity: severityBucket(byRule[rule.rule_id] || 5),
  }));
}

function loadCases() {
  const index = JSON.parse(localStorage.getItem("cases_index") || "[]");
  return index.map((id) => JSON.parse(localStorage.getItem(`case_${id}`) || "{}")).filter(Boolean);
}

function countResolvedToday() {
  const today = new Date().toDateString();
  return recentAlerts.filter((alert) => {
    const status = localStorage.getItem(`alertStatus_${alertKey(alert)}`) || "New";
    const date = new Date(alert.timestamp).toDateString();
    return status === "Resolved" && date === today;
  }).length;
}

function alertKey(alert) {
  const timestamp = alert.timestamp || "unknown";
  const ruleId = alert.rule_id || "unknown";
  return `alert_${timestamp}_${ruleId}`;
}

function addActivityEntry(text) {
  if (!ACTIVITY_FEED) return;
  if (ACTIVITY_FEED.querySelector(".muted")) {
    ACTIVITY_FEED.innerHTML = "";
  }
  const item = document.createElement("li");
  item.textContent = `${formatTimestamp(new Date().toISOString())} ${text}`;
  ACTIVITY_FEED.prepend(item);
  if (ACTIVITY_FEED.children.length > 8) {
    ACTIVITY_FEED.removeChild(ACTIVITY_FEED.lastElementChild);
  }
  markUpdated("activity");
}

window.addEventListener("beforeunload", (event) => {
  event.preventDefault();
  event.returnValue = "";
});

LOCK_BUTTON.addEventListener("click", lockConsole);
UNLOCK_BUTTON.addEventListener("click", unlockConsole);
LOCK_PASSWORD.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    unlockConsole();
  }
});

if (localStorage.getItem("socLocked") === "true") {
  lockConsole();
}

initCharts();
initMap();
loadInitial();
loadAnalytics();
connectStream();
setInterval(loadAnalytics, 5000);
setInterval(renderFreshness, 1000);
