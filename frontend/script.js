const ALERTS_BODY = document.getElementById("alerts-body");
const ERROR_BANNER = document.getElementById("error-banner");
const STREAM_STATUS = document.getElementById("stream-status");
const TOTAL_COUNT = document.getElementById("total-count");
const CRITICAL_COUNT = document.getElementById("critical-count");
const TOP_RULES = document.getElementById("top-rules");

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

function getSeverity(level) {
  if (level <= 3) return "low";
  if (level <= 6) return "medium";
  if (level <= 9) return "high";
  return "critical";
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

function updateStats(stats) {
  if (!stats) return;
  TOTAL_COUNT.textContent = stats.total ?? 0;
  CRITICAL_COUNT.textContent = stats.critical ?? 0;

  TOP_RULES.innerHTML = (stats.top_rules || [])
    .map((rule) => `<span class="rule-chip">Rule ${rule.rule_id}: ${rule.count}</span>`)
    .join("");
}

function renderRow(alert, prepend = false) {
  const level = Number.isFinite(alert.rule_level) ? alert.rule_level : 0;
  const severity = getSeverity(level);
  const row = document.createElement("tr");
  row.classList.add("row-new");
  if (level >= 10) row.classList.add("row-critical");
  if (level >= 8 && level < 10) row.classList.add("row-high");

  const ipClass = !isPrivateIp(alert.agent_ip) ? "ip-attacker" : "";

  row.innerHTML = `
    <td>${alert.timestamp}</td>
    <td>${alert.rule_id}</td>
    <td>${alert.rule_description}</td>
    <td><span class="severity ${severity}">${level}</span></td>
    <td>${alert.agent_name}</td>
    <td class="${ipClass}">${alert.agent_ip || "N/A"}</td>
  `;

  if (prepend) {
    ALERTS_BODY.prepend(row);
  } else {
    ALERTS_BODY.appendChild(row);
  }

  setTimeout(() => row.classList.remove("row-new"), 1300);
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
      updateStats(payload.stats);
    }
  };
}

loadInitial();
connectStream();
