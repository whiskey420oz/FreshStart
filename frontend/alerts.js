const ALERTS_BODY = document.getElementById("alerts-body");
const ERROR_BANNER = document.getElementById("alerts-error");
const FILTER_SEVERITY = document.getElementById("filter-severity");
const FILTER_TIMERANGE = document.getElementById("filter-timerange");
const FILTER_SEARCH = document.getElementById("filter-search");
const SIEM_SEARCH = document.getElementById("siem-search");
const INVESTIGATION_SELECT = document.getElementById("investigation-select");
const SORT_BUTTONS = document.querySelectorAll("[data-sort]");
const DRAWER = document.getElementById("alert-drawer");
const DRAWER_CLOSE = document.getElementById("drawer-close");
const DRAWER_JSON = document.getElementById("drawer-json");
const DRAWER_SUMMARY = document.getElementById("drawer-summary");
const DRAWER_STATUS = document.getElementById("drawer-status");
const CREATE_INCIDENT = document.getElementById("create-incident");
const PAGINATION_INFO = document.getElementById("pagination-info");
const PAGINATION_CONTROLS = document.getElementById("pagination-controls");

const REFRESH_INTERVAL = 5000;
const PAGE_LIMIT = 20;
let currentAlerts = [];
let sortMode = "timestamp";
let selectedAlertId = null;
let selectedAlert = null;
let totalAlerts = 0;
let offset = 0;

const URL_PARAMS = new URLSearchParams(window.location.search);
if (SIEM_SEARCH && URL_PARAMS.get("q")) {
  SIEM_SEARCH.value = URL_PARAMS.get("q");
}

function severityBucket(level) {
  if (level <= 3) return "low";
  if (level <= 6) return "medium";
  if (level <= 9) return "high";
  return "critical";
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

function showError(message) {
  ERROR_BANNER.textContent = message;
  ERROR_BANNER.classList.remove("hidden");
}

function clearError() {
  ERROR_BANNER.textContent = "";
  ERROR_BANNER.classList.add("hidden");
}

function openDrawer(alert) {
  selectedAlertId = alert.id;
  selectedAlert = alert;
  DRAWER_STATUS.value = alert.alert_status || "NEW";
  let mitreLine = `<div><strong>MITRE:</strong> —</div>`;
  if (alert.mitre_ids) {
    try {
      const ids = Array.isArray(alert.mitre_ids) ? alert.mitre_ids : JSON.parse(alert.mitre_ids);
      const tactics = alert.mitre_tactics
        ? (Array.isArray(alert.mitre_tactics) ? alert.mitre_tactics : JSON.parse(alert.mitre_tactics))
        : [];
      mitreLine = `<div><strong>MITRE:</strong> ${ids.join(", ")} ${
        tactics.length ? `· ${tactics.join(", ")}` : ""
      }</div>`;
    } catch {
      mitreLine = `<div><strong>MITRE:</strong> ${alert.mitre_ids}</div>`;
    }
  }
  const eventTime = alert.event_time || alert.timestamp;
  const ingestedAt = alert.ingested_at;
  DRAWER_SUMMARY.innerHTML = `
    <div><strong>Rule:</strong> ${alert.rule_description}</div>
    <div><strong>Severity:</strong> ${alert.rule_level}</div>
    <div><strong>Event Time:</strong> ${formatTimestamp(eventTime)}</div>
    <div><strong>Ingested At:</strong> ${ingestedAt ? formatTimestamp(ingestedAt) : "--"}</div>
    <div><strong>Agent:</strong> ${alert.agent_name} (${alert.agent_ip || "N/A"})</div>
    <div><strong>Source IP:</strong> ${alert.src_ip || "N/A"}</div>
    <div><strong>Destination IP:</strong> ${alert.dest_ip || "N/A"}</div>
    ${mitreLine}
  `;
  DRAWER_JSON.textContent = JSON.stringify(alert, null, 2);
  DRAWER.classList.remove("hidden");
}

function closeDrawer() {
  DRAWER.classList.add("hidden");
  selectedAlertId = null;
  selectedAlert = null;
}

DRAWER_CLOSE.addEventListener("click", closeDrawer);
DRAWER.addEventListener("click", (event) => {
  if (event.target.classList.contains("drawer-backdrop")) {
    closeDrawer();
  }
});

function parseQuery(query) {
  const tokens = query.split(/\s+/).filter(Boolean);
  const filters = {};
  const freeText = [];
  for (const token of tokens) {
    const [key, ...rest] = token.split(":");
    if (rest.length) {
      filters[key.toLowerCase()] = rest.join(":");
    } else {
      freeText.push(token);
    }
  }
  if (freeText.length) filters.text = freeText.join(" ");
  return filters;
}

function applyFilters(alerts) {
  const severity = FILTER_SEVERITY.value;
  const search = FILTER_SEARCH ? FILTER_SEARCH.value.trim().toLowerCase() : "";
  const siemQuery = SIEM_SEARCH ? SIEM_SEARCH.value.trim() : "";
  const queryFilters = siemQuery ? parseQuery(siemQuery) : {};

  return alerts.filter((alert) => {
    const normalized = (alert.severity_label || severityBucket(Number(alert.rule_level) || 0)).toLowerCase();
    if (severity && normalized !== severity) return false;
    if (queryFilters.severity && normalized !== queryFilters.severity) return false;
    if (queryFilters.ip && String(alert.src_ip || "").indexOf(queryFilters.ip) === -1) return false;
    if (queryFilters.agent && String(alert.agent_name || "").toLowerCase().indexOf(queryFilters.agent.toLowerCase()) === -1) {
      return false;
    }
    if (queryFilters.rule && String(alert.rule_id || "").indexOf(queryFilters.rule) === -1) return false;
    if (queryFilters.text) {
      const haystack = `${alert.rule_description} ${alert.src_ip} ${alert.agent_name}`.toLowerCase();
      if (!haystack.includes(queryFilters.text.toLowerCase())) return false;
    }
    if (search) {
      const haystack = `${alert.rule_description} ${alert.src_ip} ${alert.agent_name}`.toLowerCase();
      return haystack.includes(search);
    }
    return true;
  });
}

function sortAlerts(alerts) {
  const sorted = [...alerts];
  if (sortMode === "severity") {
    sorted.sort((a, b) => (b.rule_level || 0) - (a.rule_level || 0));
  } else {
    sorted.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  }
  return sorted;
}

function renderTable(alerts) {
  if (!alerts.length) {
    ALERTS_BODY.innerHTML = `
      <tr>
        <td colspan="6" class="muted">No alerts match the current filters.</td>
      </tr>
    `;
    return;
  }

  ALERTS_BODY.innerHTML = alerts
    .map((alert) => {
      const level = Number(alert.rule_level) || 0;
      const bucket = severityBucket(level);
      const status = alert.alert_status || "NEW";
      const statusClass =
        status === "RESOLVED"
          ? "status-resolved"
          : status === "INVESTIGATING" || status === "IN_PROGRESS"
            ? "status-investigating"
            : status === "FALSE_POSITIVE"
              ? "status-resolved"
              : "status-new";
      return `
        <tr class="alert-row">
          <td>${formatTimestamp(alert.timestamp)}</td>
          <td><span class="severity-pill ${bucket}">${bucket.toUpperCase()}</span></td>
          <td>${alert.rule_description}</td>
          <td class="mono">${alert.src_ip || "N/A"}</td>
          <td>${alert.agent_name}</td>
          <td><span class="status-dot ${statusClass}"></span>${status}</td>
        </tr>
      `;
    })
    .join("");

  ALERTS_BODY.querySelectorAll(".alert-row").forEach((row, index) => {
    row.addEventListener("click", () => openDrawer(alerts[index]));
  });
}

function updateTable() {
  const filtered = applyFilters(currentAlerts);
  const sorted = sortAlerts(filtered);
  renderTable(sorted);
}

function renderPagination() {
  const start = totalAlerts === 0 ? 0 : offset + 1;
  const end = Math.min(offset + PAGE_LIMIT, totalAlerts);
  PAGINATION_INFO.textContent = `Showing ${start}–${end} of ${totalAlerts} alerts`;
  const totalPages = Math.max(1, Math.ceil(totalAlerts / PAGE_LIMIT));
  const currentPage = Math.floor(offset / PAGE_LIMIT) + 1;

  const buttons = [];
  const prevDisabled = currentPage === 1 ? "disabled" : "";
  const nextDisabled = currentPage === totalPages ? "disabled" : "";
  buttons.push(`<button class="ghost" data-page="prev" ${prevDisabled}>Previous</button>`);

  for (let page = 1; page <= totalPages; page += 1) {
    const active = page === currentPage ? "active" : "";
    buttons.push(`<button class="ghost ${active}" data-page="${page}">${page}</button>`);
  }

  buttons.push(`<button class="ghost" data-page="next" ${nextDisabled}>Next</button>`);
  PAGINATION_CONTROLS.innerHTML = buttons.join("");

  PAGINATION_CONTROLS.querySelectorAll("button").forEach((button) => {
    button.addEventListener("click", () => {
      const target = button.dataset.page;
      if (target === "prev" && currentPage > 1) {
        offset = (currentPage - 2) * PAGE_LIMIT;
      } else if (target === "next" && currentPage < totalPages) {
        offset = currentPage * PAGE_LIMIT;
      } else if (!Number.isNaN(Number(target))) {
        offset = (Number(target) - 1) * PAGE_LIMIT;
      }
      fetchAlerts();
    });
  });
}

async function fetchAlerts() {
  try {
    const rangeValue = FILTER_TIMERANGE.value;
    const timerange = rangeValue !== "custom" ? rangeValue : "";
    const params = new URLSearchParams({
      limit: PAGE_LIMIT.toString(),
      offset: offset.toString(),
    });
    if (timerange) {
      params.set("timerange", timerange);
    }
    if (FILTER_SEVERITY.value) {
      params.set("severity", FILTER_SEVERITY.value);
    }
    const response = await fetch(`/alerts?${params.toString()}`);
    const payload = await response.json();
    if (!response.ok) throw new Error(payload?.error || "Failed to load alerts.");
    currentAlerts = payload.alerts || [];
    totalAlerts = payload.total || currentAlerts.length;
    updateTable();
    renderPagination();
    clearError();
  } catch (error) {
    showError(error.message || "Unable to load alerts.");
  }
}

SORT_BUTTONS.forEach((button) => {
  button.addEventListener("click", () => {
    sortMode = button.dataset.sort;
    updateTable();
  });
});

[FILTER_SEVERITY, FILTER_SEARCH, SIEM_SEARCH].forEach((field) => {
  if (!field) return;
  field.addEventListener("input", updateTable);
});

FILTER_TIMERANGE.addEventListener("change", () => {
  offset = 0;
  fetchAlerts();
});

async function updateAlertStatus(status) {
  if (!selectedAlertId) return;
  try {
    let endpoint = null;
    if (status === "INVESTIGATING") endpoint = `/alerts/${selectedAlertId}/investigate`;
    if (status === "IN_PROGRESS") endpoint = `/alerts/${selectedAlertId}/in-progress`;
    if (status === "NEW") endpoint = `/alerts/${selectedAlertId}/new`;
    if (status === "RESOLVED") endpoint = `/alerts/${selectedAlertId}/resolve`;
    if (status === "FALSE_POSITIVE") endpoint = `/alerts/${selectedAlertId}/false-positive`;
    if (!endpoint) return;
    const response = await fetch(endpoint, { method: "POST" });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload?.error || "Failed to update alert status.");
    await fetchAlerts();
  } catch (error) {
    showError(error.message || "Failed to update alert status.");
  }
}

DRAWER_STATUS.addEventListener("change", () => {
  if (!selectedAlertId) return;
  updateAlertStatus(DRAWER_STATUS.value);
});

if (CREATE_INCIDENT) {
  CREATE_INCIDENT.addEventListener("click", async () => {
    if (!selectedAlertId) return;
    try {
      const response = await fetch("/api/incidents/from-alert", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ alert_id: selectedAlertId }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload?.error || "Failed to create incident.");
      if (payload?.incident_id) {
        window.location.href = `/incidents.html#incident-${payload.incident_id}`;
      }
    } catch (error) {
      showError(error.message || "Failed to create incident.");
    }
  });
}

fetchAlerts();
setInterval(fetchAlerts, REFRESH_INTERVAL);
