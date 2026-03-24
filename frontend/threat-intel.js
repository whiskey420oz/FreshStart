const INPUT = document.getElementById("intel-ip");
const SUBMIT = document.getElementById("intel-submit");
const MESSAGE = document.getElementById("intel-message");
const SUMMARY = document.getElementById("intel-summary");
const ALERTS = document.getElementById("intel-alerts");

function formatTimestamp(value) {
  if (!value) return "—";
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) return String(value);
  return new Date(parsed).toLocaleString();
}

function renderSummary(profile) {
  SUMMARY.innerHTML = `
    <div><strong>IP:</strong> ${profile.src_ip || "—"}</div>
    <div><strong>Country:</strong> ${profile.country || "—"} ${profile.city ? `· ${profile.city}` : ""}</div>
    <div><strong>ASN:</strong> ${profile.asn || "—"}</div>
    <div><strong>ISP:</strong> ${profile.isp || "—"}</div>
    <div><strong>Abuse Score:</strong> ${profile.abuse_score ?? "—"}</div>
    <div><strong>Threat Level:</strong> ${profile.threat_level || "—"}</div>
    <div><strong>Alerts:</strong> ${profile.alert_count ?? 0}</div>
    <div><strong>Targets:</strong> ${profile.targets ?? 0}</div>
    <div><strong>Last Seen:</strong> ${formatTimestamp(profile.last_seen)}</div>
  `;
}

function renderAlerts(rows) {
  if (!rows || !rows.length) {
    ALERTS.innerHTML = `<tr><td colspan="3" class="muted">No alerts found.</td></tr>`;
    return;
  }
  ALERTS.innerHTML = rows
    .map(
      (row) => `
        <tr>
          <td>${formatTimestamp(row.timestamp)}</td>
          <td>${row.rule_description || "—"}</td>
          <td>${row.severity}</td>
        </tr>
      `
    )
    .join("");
}

async function lookup() {
  const ip = (INPUT.value || "").trim();
  if (!ip) {
    MESSAGE.textContent = "Enter a source IP.";
    return;
  }
  MESSAGE.textContent = "Loading...";
  try {
    const response = await fetch(`/api/threat-intel?ip=${encodeURIComponent(ip)}`);
    const payload = await response.json();
    if (!response.ok) throw new Error(payload?.error || "Failed to load intel.");
    renderSummary(payload);
    renderAlerts(payload.recent_alerts || []);
    MESSAGE.textContent = payload.note || "";
  } catch (error) {
    MESSAGE.textContent = error.message;
    SUMMARY.innerHTML = "";
    renderAlerts([]);
  }
}

SUBMIT.addEventListener("click", lookup);
INPUT.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    lookup();
  }
});
