const ALERTS_BODY = document.getElementById("alerts-body");
const ERROR_BANNER = document.getElementById("error-banner");
const STREAM_STATUS = document.getElementById("stream-status");
const METRIC_TOTAL = document.getElementById("metric-total");
const METRIC_CRITICAL = document.getElementById("metric-critical");
const METRIC_HIGH = document.getElementById("metric-high");
const METRIC_SUSPICIOUS = document.getElementById("metric-suspicious");
const METRIC_EVENTS = document.getElementById("metric-events");
const METRIC_AGENTS_ACTIVE = document.getElementById("metric-agents-active");
const METRIC_AGENTS_DISCONNECTED = document.getElementById("metric-agents-disconnected");
const METRIC_AGENTS_NEVER = document.getElementById("metric-agents-never");
const WAZUH_VERSION = document.getElementById("wazuh-version");
const WAZUH_HEALTH = document.getElementById("wazuh-health");
const WAZUH_TOTAL_AGENTS = document.getElementById("wazuh-total-agents");
const WAZUH_API_STATUS = document.getElementById("wazuh-api-status");
const WAZUH_ERROR = document.getElementById("wazuh-error");
const WAZUH_API_CONNECTIVITY = document.getElementById("wazuh-api-connectivity");
const WAZUH_SUMMARY_ACTIVE = document.getElementById("wazuh-summary-active");
const WAZUH_SUMMARY_DISCONNECTED = document.getElementById("wazuh-summary-disconnected");
const WAZUH_SUMMARY_NEVER = document.getElementById("wazuh-summary-never");
const WAZUH_SUMMARY_TOTAL = document.getElementById("wazuh-summary-total");
const WAZUH_ALERTS_BODY = document.getElementById("wazuh-alerts-body");
const WAZUH_ALERTS_UPDATED = document.getElementById("wazuh-alerts-updated");
const WAZUH_VULN_BODY = document.getElementById("wazuh-vuln-body");
const WAZUH_VULN_UPDATED = document.getElementById("wazuh-vuln-updated");
const WAZUH_FIM_BODY = document.getElementById("wazuh-fim-body");
const WAZUH_FIM_UPDATED = document.getElementById("wazuh-fim-updated");
const METRIC_OPEN_CASES = document.getElementById("metric-open-cases");
const METRIC_RESOLVED_TODAY = document.getElementById("metric-resolved-today");
const METRIC_MTTR = document.getElementById("metric-mttr");
const METRIC_ANALYSTS = document.getElementById("metric-analysts");
const METRIC_INCIDENTS_OPEN = document.getElementById("metric-incidents-open");
const METRIC_INCIDENTS_CONTAINED = document.getElementById("metric-incidents-contained");
const TOP_RULES_BODY = document.getElementById("top-rules-body");
const TOP_ATTACKERS_BODY = document.getElementById("top-attackers-body");
const ATTACKERS_BODY = document.getElementById("attackers-body");
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
const UPDATED_RISK = document.getElementById("updated-risk");
const UPDATED_MITRE = document.getElementById("updated-mitre");
const UPDATED_INCIDENT_TIMELINE = document.getElementById("updated-incident-timeline");
const UPDATED_LIVE = document.getElementById("updated-live");
const UPDATED_HOSTS = document.getElementById("updated-hosts");
const UPDATED_INCIDENTS = document.getElementById("updated-incidents");
const UPDATED_STREAM = document.getElementById("updated-stream");
const UPDATED_ACTIVITY = document.getElementById("updated-activity");
const INCIDENTS_BODY = document.getElementById("incidents-body");
const RISK_BODY = document.getElementById("risk-body");
const MITRE_BODY = document.getElementById("mitre-body");
const MITRE_CHART = document.getElementById("mitre-chart");

let severityChart;
let timelineChart;
let rulesChart;
let mitreChart;
let incidentTimelineChart;
let map;
let markersLayer;
let heatLayer;
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
  incidents: null,
  risk: null,
  mitre: null,
  incidentTimeline: null,
  stream: null,
  activity: null,
};

const updatedLabels = {
  severity: UPDATED_SEVERITY,
  timeline: UPDATED_TIMELINE,
  map: UPDATED_MAP,
  attackers: UPDATED_ATTACKERS,
  rules: UPDATED_RULES,
  risk: UPDATED_RISK,
  mitre: UPDATED_MITRE,
  incidentTimeline: UPDATED_INCIDENT_TIMELINE,
  live: UPDATED_LIVE,
  hosts: UPDATED_HOSTS,
  incidents: UPDATED_INCIDENTS,
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
  const text =
    typeof message === "string"
      ? message
      : message?.message || message?.textContent || "An unexpected error occurred.";
  ERROR_BANNER.textContent = text;
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
  METRIC_SUSPICIOUS.textContent = metrics.suspicious_ips ?? 0;
  METRIC_EVENTS.textContent = metrics.events_processed ?? 0;

  PULSE_INDICATORS.textContent = metrics.suspicious_ips ?? "—";
  PULSE_MALWARE.textContent = metrics.critical_alerts ?? "—";
  PULSE_BLOCKED.textContent = metrics.high_alerts ?? "—";
}

function setWazuhUnavailable(message) {
  if (WAZUH_API_STATUS) {
    WAZUH_API_STATUS.textContent = "Unavailable";
    WAZUH_API_STATUS.classList.remove("active");
    WAZUH_API_STATUS.classList.add("disconnected");
  }
  if (WAZUH_VERSION) WAZUH_VERSION.textContent = "—";
  if (WAZUH_HEALTH) WAZUH_HEALTH.textContent = "—";
  if (WAZUH_TOTAL_AGENTS) WAZUH_TOTAL_AGENTS.textContent = "0";
  if (WAZUH_API_CONNECTIVITY) WAZUH_API_CONNECTIVITY.textContent = "Unavailable";
  if (WAZUH_ERROR) WAZUH_ERROR.textContent = message || "Wazuh API unavailable.";
}

function setWazuhConnected() {
  if (WAZUH_API_STATUS) {
    WAZUH_API_STATUS.textContent = "Connected";
    WAZUH_API_STATUS.classList.add("active");
    WAZUH_API_STATUS.classList.remove("disconnected");
  }
  if (WAZUH_API_CONNECTIVITY) WAZUH_API_CONNECTIVITY.textContent = "Connected";
  if (WAZUH_ERROR) WAZUH_ERROR.textContent = "";
}

async function loadWazuhManager() {
  try {
    const response = await fetch("/wazuh/manager");
    const payload = await response.json();
    if (!response.ok) throw new Error(payload?.error || "Wazuh API unavailable.");
    const info =
      payload?.data?.affected_items?.[0] ||
      payload?.affected_items?.[0] ||
      payload?.data ||
      payload ||
      {};

    const version = info.version || info?.manager?.version || info?.data?.version || "Unknown";
    const health =
      info?.manager_status?.data?.affected_items?.[0]?.status ||
      info?.manager_status?.affected_items?.[0]?.status ||
      info.status ||
      info?.manager?.status ||
      "Running";
    if (WAZUH_VERSION) WAZUH_VERSION.textContent = version;
    if (WAZUH_HEALTH) WAZUH_HEALTH.textContent = String(health);
    setWazuhConnected();
  } catch (error) {
    setWazuhUnavailable(error.message);
  }
}

async function loadWazuhAgents() {
  try {
    const response = await fetch("/wazuh/agents");
    const payload = await response.json();
    if (!response.ok) throw new Error(payload?.message || "Wazuh API unavailable.");
    const items = payload?.agents || [];
    if (WAZUH_TOTAL_AGENTS) WAZUH_TOTAL_AGENTS.textContent = String(items.length);
    setWazuhConnected();
  } catch (error) {
    setWazuhUnavailable(error.message);
  }
}

async function loadWazuhSummary() {
  try {
    const response = await fetch("/wazuh/agents/summary");
    const payload = await response.json();
    if (!response.ok) throw new Error(payload?.message || "Wazuh API unavailable.");
    if (METRIC_AGENTS_ACTIVE) METRIC_AGENTS_ACTIVE.textContent = payload.active ?? 0;
    if (METRIC_AGENTS_DISCONNECTED) METRIC_AGENTS_DISCONNECTED.textContent = payload.disconnected ?? 0;
    if (METRIC_AGENTS_NEVER) METRIC_AGENTS_NEVER.textContent = payload.never_connected ?? 0;
    if (WAZUH_SUMMARY_ACTIVE) WAZUH_SUMMARY_ACTIVE.textContent = payload.active ?? 0;
    if (WAZUH_SUMMARY_DISCONNECTED) WAZUH_SUMMARY_DISCONNECTED.textContent = payload.disconnected ?? 0;
    if (WAZUH_SUMMARY_NEVER) WAZUH_SUMMARY_NEVER.textContent = payload.never_connected ?? 0;
    if (WAZUH_SUMMARY_TOTAL) WAZUH_SUMMARY_TOTAL.textContent = payload.total ?? 0;
    if (WAZUH_TOTAL_AGENTS && payload.total !== undefined) {
      WAZUH_TOTAL_AGENTS.textContent = String(payload.total);
    }
    setWazuhConnected();
  } catch (error) {
    setWazuhUnavailable(error.message);
    if (METRIC_AGENTS_ACTIVE) METRIC_AGENTS_ACTIVE.textContent = "0";
    if (METRIC_AGENTS_DISCONNECTED) METRIC_AGENTS_DISCONNECTED.textContent = "0";
    if (METRIC_AGENTS_NEVER) METRIC_AGENTS_NEVER.textContent = "0";
    if (WAZUH_SUMMARY_ACTIVE) WAZUH_SUMMARY_ACTIVE.textContent = "0";
    if (WAZUH_SUMMARY_DISCONNECTED) WAZUH_SUMMARY_DISCONNECTED.textContent = "0";
    if (WAZUH_SUMMARY_NEVER) WAZUH_SUMMARY_NEVER.textContent = "0";
    if (WAZUH_SUMMARY_TOTAL) WAZUH_SUMMARY_TOTAL.textContent = "0";
  }
}

function renderWazuhAlerts(alerts) {
  if (!WAZUH_ALERTS_BODY) return;
  if (!alerts || !alerts.length) {
    WAZUH_ALERTS_BODY.innerHTML = `
      <tr>
        <td colspan="5" class="muted">No Wazuh alerts available.</td>
      </tr>
    `;
    return;
  }
  WAZUH_ALERTS_BODY.innerHTML = alerts
    .map((alert) => {
      const level = alert.rule_level ?? alert.severity_level ?? alert.severity ?? 0;
      const bucket = severityBucket(Number(level));
      return `
        <tr>
          <td>${formatTimestamp(alert.timestamp)}</td>
          <td>${alert.agent_name || "—"}</td>
          <td>${alert.rule_description || alert.rule_id || "—"}</td>
          <td><span class="severity ${bucket}">${bucket.toUpperCase()}</span></td>
          <td class="${!isPrivateIp(alert.source_ip) ? "ip-attacker" : ""}">${alert.source_ip || "—"}</td>
        </tr>
      `;
    })
    .join("");
}

function renderVulnerabilities(entries) {
  if (!WAZUH_VULN_BODY) return;
  if (!entries || !entries.length) {
    WAZUH_VULN_BODY.innerHTML = `
      <tr>
        <td colspan="4" class="muted">No vulnerabilities reported.</td>
      </tr>
    `;
    return;
  }
  WAZUH_VULN_BODY.innerHTML = entries
    .map(
      (item) => `
        <tr>
          <td>${item.agent_name || "—"}</td>
          <td>${item.package_name || "—"}</td>
          <td>${item.cve || "—"}</td>
          <td>${item.severity || "—"}</td>
        </tr>
      `
    )
    .join("");
}

function renderFileIntegrity(entries) {
  if (!WAZUH_FIM_BODY) return;
  if (!entries || !entries.length) {
    WAZUH_FIM_BODY.innerHTML = `
      <tr>
        <td colspan="4" class="muted">No recent file integrity changes.</td>
      </tr>
    `;
    return;
  }
  WAZUH_FIM_BODY.innerHTML = entries
    .map(
      (item) => `
        <tr>
          <td>${item.agent || "—"}</td>
          <td class="mono">${item.file_path || "—"}</td>
          <td>${item.event_type || "—"}</td>
          <td>${formatTimestamp(item.timestamp)}</td>
        </tr>
      `
    )
    .join("");
}

async function loadWazuhAlerts() {
  try {
    const response = await fetch("/alerts?limit=6&offset=0");
    const payload = await response.json();
    if (!response.ok) throw new Error(payload?.error || "Unable to load alerts.");
    renderWazuhAlerts(payload.alerts || []);
    if (WAZUH_ALERTS_UPDATED) {
      WAZUH_ALERTS_UPDATED.textContent = `Last updated: ${new Date().toLocaleTimeString()}`;
    }
  } catch (error) {
    if (WAZUH_ALERTS_BODY) {
      WAZUH_ALERTS_BODY.innerHTML = `
        <tr>
          <td colspan="5" class="muted">${error.message || "Unable to load alerts."}</td>
        </tr>
      `;
    }
  }
}

async function loadWazuhVulnerabilities() {
  try {
    const response = await fetch("/wazuh/vulnerabilities?limit=6");
    const payload = await response.json();
    if (!response.ok) throw new Error(payload?.message || "Wazuh API unavailable.");
    renderVulnerabilities(payload.vulnerabilities || []);
    if (WAZUH_VULN_UPDATED) {
      WAZUH_VULN_UPDATED.textContent = `Last updated: ${new Date().toLocaleTimeString()}`;
    }
  } catch (error) {
    if (WAZUH_VULN_BODY) {
      WAZUH_VULN_BODY.innerHTML = `
        <tr>
          <td colspan="4" class="muted">Wazuh API unavailable.</td>
        </tr>
      `;
    }
  }
}

async function loadWazuhFileIntegrity() {
  try {
    const response = await fetch("/wazuh/file-integrity?limit=8");
    const payload = await response.json();
    if (!response.ok) throw new Error(payload?.message || "Wazuh API unavailable.");
    renderFileIntegrity(payload.changes || []);
    if (WAZUH_FIM_UPDATED) {
      WAZUH_FIM_UPDATED.textContent = `Last updated: ${new Date().toLocaleTimeString()}`;
    }
  } catch (error) {
    if (WAZUH_FIM_BODY) {
      WAZUH_FIM_BODY.innerHTML = `
        <tr>
          <td colspan="4" class="muted">Wazuh API unavailable.</td>
        </tr>
      `;
    }
  }
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

  if (rulesChart && rules) {
    rulesChart.data.labels = rules.map((rule) => rule.rule_id || "Rule");
    rulesChart.data.datasets[0].data = rules.map((rule) => rule.count || 0);
    rulesChart.update();
  }
}

function updateTopAttackers(attackers) {
  if (!TOP_ATTACKERS_BODY) return;
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

function renderAttackerProfiles(attackers) {
  if (!ATTACKERS_BODY) return;
  if (!attackers || !attackers.length) {
    ATTACKERS_BODY.innerHTML = `
      <tr>
        <td colspan="6" class="muted">No attacker profiles yet.</td>
      </tr>
    `;
    return;
  }
  ATTACKERS_BODY.innerHTML = attackers
    .map(
      (attacker) => `
        <tr>
          <td class="mono">${attacker.src_ip}</td>
          <td>${attacker.country || "Unknown"}</td>
          <td>${attacker.count}</td>
          <td>${attacker.targets}</td>
          <td>${(attacker.attack_types || []).slice(0, 2).join(", ") || "—"}</td>
          <td>${formatTimestamp(attacker.last_seen)}</td>
        </tr>
      `
    )
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

function renderRiskScores(items) {
  if (!RISK_BODY) return;
  if (!items || !items.length) {
    RISK_BODY.innerHTML = `
      <tr>
        <td colspan="6" class="muted">No risk scores yet.</td>
      </tr>
    `;
    return;
  }
  RISK_BODY.innerHTML = items
    .map(
      (item) => `
        <tr>
          <td>${item.host}</td>
          <td>${item.risk_score}</td>
          <td>${item.critical}</td>
          <td>${item.high}</td>
          <td>${item.medium}</td>
          <td>${formatTimestamp(item.last_seen)}</td>
        </tr>
      `
    )
    .join("");
}

function renderMitre(techniques) {
  if (!MITRE_BODY) return;
  if (!techniques || !techniques.length) {
    MITRE_BODY.innerHTML = `
      <tr>
        <td colspan="3" class="muted">No MITRE data yet.</td>
      </tr>
    `;
    return;
  }
  MITRE_BODY.innerHTML = techniques
    .map(
      (item) => `
        <tr>
          <td>${item.technique}</td>
          <td>${item.count}</td>
          <td>${(item.tactics || []).join(", ") || "—"}</td>
        </tr>
      `
    )
    .join("");

  if (mitreChart && techniques) {
    mitreChart.data.labels = techniques.map((item) => item.technique);
    mitreChart.data.datasets[0].data = techniques.map((item) => item.count || 0);
    mitreChart.update();
  }
}

function renderIncidents(incidents) {
  if (!INCIDENTS_BODY) return;
  if (!incidents || !incidents.length) {
    INCIDENTS_BODY.innerHTML = `
      <tr>
        <td colspan="5" class="muted">No incidents yet.</td>
      </tr>
    `;
    return;
  }
  INCIDENTS_BODY.innerHTML = incidents
    .slice(0, 6)
    .map(
      (incident) => `
        <tr>
          <td>${incident.incident_id}</td>
          <td>${incident.incident_type}</td>
          <td><span class="severity ${incident.severity || "low"}">${(incident.severity || "low").toUpperCase()}</span></td>
          <td class="mono">${incident.src_ip || "—"}</td>
          <td>${incident.status || "open"}</td>
        </tr>
      `
    )
    .join("");
}

function initCharts() {
  const severityCtx = document.getElementById("severity-chart");
  const timelineCtx = document.getElementById("timeline-chart");
  const rulesCtx = document.getElementById("rules-chart");

  severityChart = new Chart(severityCtx, {
    type: "bar",
    data: {
      labels: ["Severity Mix"],
      datasets: [
        { label: "Critical", data: [0], backgroundColor: "#f87171" },
        { label: "High", data: [0], backgroundColor: "#fb923c" },
        { label: "Medium", data: [0], backgroundColor: "#facc15" },
        { label: "Low", data: [0], backgroundColor: "#2dd4bf" },
      ],
    },
    options: {
      plugins: {
        legend: { labels: { color: "#e2e8f0" } },
        tooltip: { enabled: true, intersect: false },
      },
      animation: { duration: 700, easing: "easeOutQuart" },
      scales: {
        x: { stacked: true, ticks: { color: "#94a3b8" }, grid: { color: "rgba(148,163,184,0.2)" } },
        y: { stacked: true, ticks: { color: "#e2e8f0" }, grid: { display: false } },
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

  if (rulesCtx) {
    rulesChart = new Chart(rulesCtx, {
      type: "bar",
      data: {
        labels: [],
        datasets: [
          {
            label: "Alerts",
            data: [],
            backgroundColor: "#38bdf8",
            borderRadius: 6,
          },
        ],
      },
      options: {
        indexAxis: "y",
        plugins: {
          legend: { display: false },
          tooltip: { enabled: true, intersect: false },
        },
        scales: {
          x: { ticks: { color: "#94a3b8" }, grid: { color: "rgba(148,163,184,0.2)" } },
          y: { ticks: { color: "#e2e8f0" }, grid: { display: false } },
        },
      },
    });
  }

  if (MITRE_CHART) {
    mitreChart = new Chart(MITRE_CHART, {
      type: "bar",
      data: {
        labels: [],
        datasets: [
          {
            label: "Detections",
            data: [],
            backgroundColor: "#38bdf8",
            borderRadius: 6,
          },
        ],
      },
      options: {
        indexAxis: "y",
        plugins: {
          legend: { display: false },
          tooltip: { enabled: true, intersect: false },
        },
        scales: {
          x: { ticks: { color: "#94a3b8" }, grid: { color: "rgba(148,163,184,0.2)" } },
          y: { ticks: { color: "#e2e8f0" }, grid: { display: false } },
        },
      },
    });
  }

  const incidentCtx = document.getElementById("incident-timeline-chart");
  if (incidentCtx) {
    incidentTimelineChart = new Chart(incidentCtx, {
      type: "line",
      data: {
        labels: [],
        datasets: [
          {
            label: "Incidents",
            data: [],
            borderColor: "#38bdf8",
            tension: 0.35,
            pointRadius: 0,
          },
        ],
      },
      options: {
        plugins: {
          legend: { labels: { color: "#e2e8f0" } },
          tooltip: { enabled: true, intersect: false },
        },
        scales: {
          x: { ticks: { color: "#94a3b8" }, grid: { color: "rgba(148,163,184,0.2)" } },
          y: { ticks: { color: "#94a3b8" }, grid: { color: "rgba(148,163,184,0.2)" } },
        },
      },
    });
  }
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
  severityChart.data.datasets[0].data = [totals[0]];
  severityChart.data.datasets[1].data = [totals[1]];
  severityChart.data.datasets[2].data = [totals[2]];
  severityChart.data.datasets[3].data = [totals[3]];
  severityChart.update();
}

function initMap() {
  map = L.map("attack-map", { zoomControl: false }).setView([20, 0], 2);
  L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
    attribution: "",
  }).addTo(map);
  markersLayer = L.layerGroup().addTo(map);
  heatLayer = L.layerGroup().addTo(map);
}

function addMapMarker(alert) {
  if (!alert.src_ip || isPrivateIp(alert.src_ip)) return;
  if (alert.geo_lat == null || alert.geo_lon == null) return;
  const color = severityColor(alert.rule_level);
  const marker = L.circleMarker([alert.geo_lat, alert.geo_lon], {
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

function renderAttackHeat(points) {
  if (!heatLayer) return;
  heatLayer.clearLayers();
  if (!points || !points.length) return;
  points.forEach((point) => {
    const count = Number(point.count || 1);
    const severity = Number(point.severity || 0);
    const radius = Math.min(28, 6 + Math.log2(count + 1) * 6);
    const color = severityColor(severity);
    const circle = L.circleMarker([point.lat, point.lon], {
      radius,
      color,
      fillColor: color,
      fillOpacity: 0.35,
      weight: 1,
      className: "map-heat",
    });
    circle.bindTooltip(
      `${point.country || "Unknown"}<br>Alerts: ${count}`,
      { direction: "top", opacity: 0.9 }
    );
    circle.addTo(heatLayer);
  });
}

function renderRow(alert, prepend = false) {
  const level = Number.isFinite(alert.rule_level) ? alert.rule_level : 0;
  const bucket = severityBucket(level);
  const row = document.createElement("tr");
  row.classList.add("row-new");
  if (level >= 10) row.classList.add("row-critical");
  if (level >= 8 && level < 10) row.classList.add("row-high");

  const ipClass = !isPrivateIp(alert.src_ip) ? "ip-attacker" : "";
  let mitre = "—";
  if (alert.mitre_ids) {
    try {
      const ids = Array.isArray(alert.mitre_ids) ? alert.mitre_ids : JSON.parse(alert.mitre_ids);
      mitre = ids.join(", ");
    } catch {
      mitre = alert.mitre_ids;
    }
  }

  row.innerHTML = `
    <td>${formatTimestamp(alert.timestamp)}</td>
    <td>${alert.rule_id}</td>
    <td>${alert.rule_description}</td>
    <td><span class="severity ${bucket}">${level}</span></td>
    <td>${alert.agent_name}</td>
    <td class="${ipClass}">${alert.src_ip || "N/A"}</td>
    <td>${mitre}</td>
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
  let mitre = "—";
  if (alert.mitre_ids) {
    try {
      const ids = Array.isArray(alert.mitre_ids) ? alert.mitre_ids : JSON.parse(alert.mitre_ids);
      mitre = ids.join(", ");
    } catch {
      mitre = alert.mitre_ids;
    }
  }

  const card = document.createElement("div");
  card.className = "timeline-card";
  card.innerHTML = `
    <div class="timeline-header">
      <span class="timeline-severity ${bucket}">${bucket.toUpperCase()}</span>
      <span class="timeline-meta">${formatTimestamp(alert.timestamp)}</span>
    </div>
    <div>${alert.rule_description}</div>
    <div class="timeline-meta">Source IP: ${alert.src_ip || "N/A"}</div>
    <div class="timeline-meta">MITRE: ${mitre}</div>
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
        <td colspan="7" class="muted">No alerts received yet.</td>
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
    const [metricsRes, socRes, attackersRes, timelineRes, rulesRes, hostsRes, incidentsRes, profilesRes, riskRes, mitreRes, mapRes, kpisRes, incidentTimelineRes] = await Promise.all([
      fetch("/metrics"),
      fetch("/metrics/soc"),
      fetch("/top_attackers"),
      fetch("/alerts_over_time"),
      fetch("/rule_statistics"),
      fetch("/risky_hosts"),
      fetch("/api/incidents"),
      fetch("/api/attackers"),
      fetch("/api/risk-scores"),
      fetch("/api/mitre-stats"),
      fetch("/api/attack-map"),
      fetch("/api/incidents/kpis"),
      fetch("/api/incidents/timeline"),
    ]);

    const metrics = await metricsRes.json();
    const soc = await socRes.json();
    const attackers = await attackersRes.json();
    const timeline = await timelineRes.json();
    const rules = await rulesRes.json();
    const hosts = await hostsRes.json();
    const incidents = await incidentsRes.json();
    const profiles = await profilesRes.json();
    const risks = await riskRes.json();
    const mitre = await mitreRes.json();
    const mapData = await mapRes.json();
    const kpis = await kpisRes.json();
    const incidentTimeline = await incidentTimelineRes.json();

    updateMetrics(metrics.metrics);
    if (soc.metrics) {
      METRIC_OPEN_CASES.textContent = soc.metrics.open_investigations ?? 0;
      METRIC_RESOLVED_TODAY.textContent = soc.metrics.resolved_today ?? soc.metrics.resolved_incidents ?? 0;
      METRIC_MTTR.textContent = soc.metrics.mttr_seconds ? `${Math.round(soc.metrics.mttr_seconds / 60)} min` : "—";
      METRIC_ANALYSTS.textContent = soc.metrics.active_analysts ?? "—";
    }
    if (kpis.kpis) {
      if (METRIC_INCIDENTS_OPEN) METRIC_INCIDENTS_OPEN.textContent = kpis.kpis.open ?? 0;
      if (METRIC_INCIDENTS_CONTAINED) METRIC_INCIDENTS_CONTAINED.textContent = kpis.kpis.contained ?? 0;
    }
    updateTopAttackers(attachSeverityToAttackers(attackers.attackers));
    updateCharts(timeline.timeline);
    updateTopRules(attachSeverityToRules(rules.rules));
    updateHosts(hosts.hosts);
    renderIncidents(incidents.incidents || []);
    renderAttackerProfiles(profiles.attackers || []);
    renderRiskScores(risks.risk_scores || []);
    renderMitre(mitre.techniques || []);
    renderAttackHeat(mapData.points || []);
    if (incidentTimelineChart && incidentTimeline.timeline) {
      incidentTimelineChart.data.labels = incidentTimeline.timeline.labels || [];
      incidentTimelineChart.data.datasets[0].data = incidentTimeline.timeline.counts || [];
      incidentTimelineChart.update();
    }

    markUpdated("severity");
    markUpdated("timeline");
    markUpdated("attackers");
    markUpdated("rules");
    markUpdated("hosts");
    markUpdated("incidents");
    markUpdated("risk");
    markUpdated("mitre");
    markUpdated("map");
    markUpdated("incidentTimeline");
  } catch (error) {
    showError(error.message || "Unable to load analytics.");
  }
}

function connectStream() {
  const token = localStorage.getItem("fs_auth_token");
  const streamUrl = token ? `/alerts/stream?token=${encodeURIComponent(token)}` : "/alerts/stream";
  const source = new EventSource(streamUrl);

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
      if (payload.metrics) updateMetrics(payload.metrics);
      if (payload.attackers) updateTopAttackers(attachSeverityToAttackers(payload.attackers));
      if (payload.timeline) updateCharts(payload.timeline);
      if (payload.rules) updateTopRules(attachSeverityToRules(payload.rules));
      if (payload.hosts) updateHosts(payload.hosts);
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

function renderSocActivity(entries) {
  if (!ACTIVITY_FEED) return;
  if (!entries || !entries.length) {
    ACTIVITY_FEED.innerHTML = `<li class="muted">No recent activity yet.</li>`;
    return;
  }
  ACTIVITY_FEED.innerHTML = entries
    .map(
      (entry) =>
        `<li>${formatTimestamp(entry.timestamp)} ${entry.user} ${entry.action} ${entry.target_object}</li>`
    )
    .join("");
  markUpdated("activity");
}

async function loadSocActivity() {
  try {
    const response = await fetch("/soc/activity");
    const payload = await response.json();
    if (!response.ok) throw new Error(payload?.error || "Unable to load SOC activity.");
    renderSocActivity(payload.activity || []);
  } catch (error) {
    renderSocActivity([]);
  }
}


let allowNavigate = false;
document.querySelectorAll("a").forEach((link) => {
  link.addEventListener("click", () => {
    allowNavigate = true;
  });
});

window.addEventListener("beforeunload", (event) => {
  if (allowNavigate) return;
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
loadWazuhManager();
loadWazuhAgents();
loadWazuhSummary();
loadWazuhAlerts();
loadSocActivity();
connectStream();
setInterval(loadAnalytics, 5000);
setInterval(renderFreshness, 1000);
setInterval(loadWazuhAgents, 30000);
setInterval(loadWazuhManager, 60000);
setInterval(loadWazuhSummary, 30000);
setInterval(loadWazuhAlerts, 15000);
setInterval(loadSocActivity, 10000);
