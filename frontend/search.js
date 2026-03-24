const SEARCH_FORM = document.getElementById("search-form");
const SEARCH_QUERY = document.getElementById("search-query");
const SEARCH_SEVERITY = document.getElementById("search-severity");
const SEARCH_TIMERANGE = document.getElementById("search-timerange");
const SEARCH_RESULTS = document.getElementById("search-results");
const SEARCH_STATUS = document.getElementById("search-status");
const SEARCH_UPDATED = document.getElementById("search-updated");

const PAGE_LIMIT = 200;

function formatTimestamp(value) {
  if (!value) return "Unknown";
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) return String(value);
  const date = new Date(parsed);
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  }).replace(",", "");
}

function severityBucket(level) {
  if (level <= 3) return "low";
  if (level <= 6) return "medium";
  if (level <= 9) return "high";
  return "critical";
}

function parseQuery(query) {
  const tokens = query.split(/\s+/).filter(Boolean);
  const filters = {};
  const text = [];
  for (const token of tokens) {
    const [key, ...rest] = token.split(":");
    if (rest.length) {
      filters[key.toLowerCase()] = rest.join(":");
    } else {
      text.push(token);
    }
  }
  if (text.length) filters.text = text.join(" ");
  return filters;
}

function matchesFilters(alert, filters) {
  if (filters.severity) {
    const sev = (alert.severity_label || severityBucket(Number(alert.rule_level) || 0)).toLowerCase();
    if (sev !== filters.severity) return false;
  }
  if (filters.ip && String(alert.src_ip || "").indexOf(filters.ip) === -1) return false;
  if (filters.agent && String(alert.agent_name || "").toLowerCase().indexOf(filters.agent.toLowerCase()) === -1) {
    return false;
  }
  if (filters.rule && String(alert.rule_id || "").indexOf(filters.rule) === -1) return false;
  if (filters.text) {
    const haystack = `${alert.rule_description || ""} ${alert.src_ip || ""} ${alert.agent_name || ""}`.toLowerCase();
    if (!haystack.includes(filters.text.toLowerCase())) return false;
  }
  return true;
}

function renderResults(alerts) {
  if (!alerts.length) {
    SEARCH_RESULTS.innerHTML = `<tr><td colspan="5" class="muted">No results found.</td></tr>`;
    return;
  }
  SEARCH_RESULTS.innerHTML = alerts
    .map((alert) => {
      const bucket = severityBucket(Number(alert.rule_level) || 0);
      return `
        <tr>
          <td>${formatTimestamp(alert.timestamp)}</td>
          <td><span class="severity ${bucket}">${bucket.toUpperCase()}</span></td>
          <td>${alert.rule_description || "Unknown rule"}</td>
          <td class="mono">${alert.src_ip || "N/A"}</td>
          <td>${alert.agent_name || "Unknown"}</td>
        </tr>
      `;
    })
    .join("");
}

async function runQuery() {
  const params = new URLSearchParams({
    limit: PAGE_LIMIT.toString(),
    offset: "0",
    timerange: SEARCH_TIMERANGE.value,
  });
  if (SEARCH_SEVERITY.value) params.set("severity", SEARCH_SEVERITY.value);

  SEARCH_STATUS.textContent = "Running query...";
  try {
    const response = await fetch(`/alerts?${params.toString()}`);
    const payload = await response.json();
    if (!response.ok) throw new Error(payload?.error || "Query failed.");
    const filters = parseQuery(SEARCH_QUERY.value.trim());
    if (SEARCH_SEVERITY.value) {
      filters.severity = SEARCH_SEVERITY.value;
    }
    const results = (payload.alerts || []).filter((alert) => matchesFilters(alert, filters));
    renderResults(results);
    SEARCH_STATUS.textContent = `${results.length} results`;
    SEARCH_UPDATED.textContent = `Last updated: ${formatTimestamp(new Date().toISOString())}`;
  } catch (error) {
    SEARCH_STATUS.textContent = "Query failed.";
    SEARCH_RESULTS.innerHTML = `<tr><td colspan="5" class="muted">${error.message}</td></tr>`;
  }
}

if (SEARCH_FORM) {
  SEARCH_FORM.addEventListener("submit", (event) => {
    event.preventDefault();
    runQuery();
  });
}

runQuery();
