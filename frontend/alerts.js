const ALERTS_BODY = document.getElementById("alerts-body");
const ERROR_BANNER = document.getElementById("alerts-error");
const FILTER_SEVERITY = document.getElementById("filter-severity");
const FILTER_TIMERANGE = document.getElementById("filter-timerange");
const FILTER_SEARCH = document.getElementById("filter-search");
const INVESTIGATION_SELECT = document.getElementById("investigation-select");
const SORT_BUTTONS = document.querySelectorAll("[data-sort]");
const DRAWER = document.getElementById("alert-drawer");
const DRAWER_CLOSE = document.getElementById("drawer-close");
const DRAWER_JSON = document.getElementById("drawer-json");
const DRAWER_SUMMARY = document.getElementById("drawer-summary");
const DRAWER_STATUS = document.getElementById("drawer-status");
const PAGINATION_INFO = document.getElementById("pagination-info");
const PAGINATION_CONTROLS = document.getElementById("pagination-controls");

const REFRESH_INTERVAL = 5000;
const PAGE_LIMIT = 20;
let currentAlerts = [];
let sortMode = "timestamp";
const statusMap = new Map();
let selectedAlertId = null;
let selectedAlert = null;
let totalAlerts = 0;
let offset = 0;

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

function alertKey(alert) {
  const timestamp = alert.timestamp || "unknown";
  const ruleId = alert.rule_id || "unknown";
  return `alert_${timestamp}_${ruleId}`;
}

function openDrawer(alert) {
  selectedAlertId = alertKey(alert);
  selectedAlert = alert;
  const status = getStoredStatus(selectedAlertId);
  DRAWER_STATUS.value = status;
  DRAWER_SUMMARY.innerHTML = `
    <div><strong>Rule:</strong> ${alert.rule_description}</div>
    <div><strong>Severity:</strong> ${alert.rule_level}</div>
    <div><strong>Timestamp:</strong> ${formatTimestamp(alert.timestamp)}</div>
    <div><strong>Agent:</strong> ${alert.agent_name} (${alert.agent_ip || "N/A"})</div>
    <div><strong>Source IP:</strong> ${alert.src_ip || "N/A"}</div>
    <div><strong>Destination IP:</strong> ${alert.dest_ip || "N/A"}</div>
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

function applyFilters(alerts) {
  const severity = FILTER_SEVERITY.value;
  const search = FILTER_SEARCH.value.trim().toLowerCase();

  return alerts.filter((alert) => {
    const normalized = (alert.severity_label || severityBucket(Number(alert.rule_level) || 0)).toLowerCase();
    if (severity && normalized !== severity) return false;
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
      const alertId = alertKey(alert);
      const status = getStoredStatus(alertId);
      const statusClass =
        status === "Resolved" ? "status-resolved" : status === "Investigating" ? "status-investigating" : "status-new";
      return `
        <tr class="alert-row">
          <td>${formatTimestamp(alert.timestamp)}</td>
          <td><span class="severity ${bucket}">${bucket.toUpperCase()}</span></td>
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
    loadStoredStatuses(currentAlerts);
    if (offset === 0) {
      pruneStoredStatuses(currentAlerts);
    }
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

[FILTER_SEVERITY, FILTER_SEARCH].forEach((field) => {
  field.addEventListener("input", updateTable);
});

FILTER_TIMERANGE.addEventListener("change", () => {
  offset = 0;
  fetchAlerts();
});

DRAWER_STATUS.addEventListener("change", () => {
  if (!selectedAlertId) return;
  setStoredStatus(selectedAlertId, DRAWER_STATUS.value);
  if (DRAWER_STATUS.value === "Investigating") {
    let caseId = localStorage.getItem(`alertCase_${selectedAlertId}`);
    if (!caseId) {
      caseId = INVESTIGATION_SELECT.value || ensureAutoCase();
      INVESTIGATION_SELECT.value = caseId;
    }
    addAlertToInvestigation(caseId, selectedAlertId, selectedAlert);
  }
  updateTable();
});

fetchAlerts();
setInterval(fetchAlerts, REFRESH_INTERVAL);

function getStoredStatus(alertId) {
  if (statusMap.has(alertId)) {
    return statusMap.get(alertId);
  }
  const stored = localStorage.getItem(`alertStatus_${alertId}`);
  if (stored) {
    statusMap.set(alertId, stored);
    return stored;
  }
  return "New";
}

function setStoredStatus(alertId, status) {
  statusMap.set(alertId, status);
  localStorage.setItem(`alertStatus_${alertId}`, status);
}

function loadStoredStatuses(alerts) {
  alerts.forEach((alert) => {
    const alertId = alertKey(alert);
    const stored = localStorage.getItem(`alertStatus_${alertId}`);
    if (stored) {
      statusMap.set(alertId, stored);
    }
  });
}

function pruneStoredStatuses(alerts) {
  const keepKeys = new Set(alerts.slice(0, 100).map(alertKey));
  Object.keys(localStorage).forEach((key) => {
    if (key.startsWith("alertStatus_")) {
      const alertId = key.replace("alertStatus_", "");
      if (!keepKeys.has(alertId)) {
        localStorage.removeItem(key);
        statusMap.delete(alertId);
      }
    }
    if (key.startsWith("alertSnapshot_")) {
      const alertId = key.replace("alertSnapshot_", "");
      if (!keepKeys.has(alertId)) {
        localStorage.removeItem(key);
      }
    }
    if (key.startsWith("alertCase_")) {
      const alertId = key.replace("alertCase_", "");
      if (!keepKeys.has(alertId)) {
        localStorage.removeItem(key);
      }
    }
  });
}

function loadInvestigations() {
  const index = JSON.parse(localStorage.getItem("cases_index") || "[]");
  const options =
    `<option value="">Select case</option>` +
    index
      .map((id) => JSON.parse(localStorage.getItem(`case_${id}`) || "{}"))
      .filter((item) => item.id)
      .map((item) => `<option value="${item.id}">${item.title}</option>`)
      .join("");
  INVESTIGATION_SELECT.innerHTML = options;
}

function addAlertToInvestigation(caseId, alertId, alertData) {
  const caseData = JSON.parse(localStorage.getItem(`case_${caseId}`) || "{}");
  caseData.alerts = caseData.alerts || [];
  if (!caseData.alerts.includes(alertId)) {
    caseData.alerts.push(alertId);
  }
  localStorage.setItem(`alertCase_${alertId}`, caseId);
  if (alertData) {
    localStorage.setItem(`alertSnapshot_${alertId}`, JSON.stringify(alertData));
  }
  localStorage.setItem(`case_${caseId}`, JSON.stringify(caseData));
}

INVESTIGATION_SELECT.addEventListener("change", () => {
  if (!selectedAlertId || !selectedAlert) return;
  addAlertToInvestigation(INVESTIGATION_SELECT.value, selectedAlertId, selectedAlert);
});
loadInvestigations();

function ensureAutoCase() {
  const index = JSON.parse(localStorage.getItem("cases_index") || "[]");
  const existing = index.find((id) => {
    const item = JSON.parse(localStorage.getItem(`case_${id}`) || "{}");
    return item && item.title === "Auto Investigation";
  });
  if (existing) return existing;

  const id = Date.now().toString();
  const caseData = {
    id,
    title: "Auto Investigation",
    description: "Auto-created from Alerts page.",
    status: "Investigating",
    created: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    alerts: [],
    notes: [],
  };
  localStorage.setItem(`case_${id}`, JSON.stringify(caseData));
  const updated = new Set(index);
  updated.add(id);
  localStorage.setItem("cases_index", JSON.stringify([...updated]));
  return id;
}
