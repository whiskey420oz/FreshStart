const INCIDENTS_BODY = document.getElementById("incidents-body");
const INCIDENTS_UPDATED = document.getElementById("incidents-updated");
const INCIDENT_DRAWER = document.getElementById("incident-drawer");
const INCIDENT_CLOSE = document.getElementById("incident-close");
const INCIDENT_TITLE = document.getElementById("incident-title");
const INCIDENT_META = document.getElementById("incident-meta");
const INCIDENT_STATUS = document.getElementById("incident-status");
const INCIDENT_CREATE_CASE = document.getElementById("incident-create-case");
const INCIDENT_ANALYST = document.getElementById("incident-analyst");
const INCIDENT_ASSIGN = document.getElementById("incident-assign");
const INCIDENT_NOTE = document.getElementById("incident-note");
const INCIDENT_NOTE_SAVE = document.getElementById("incident-note-save");
const INCIDENT_ALERTS = document.getElementById("incident-alerts");
const INCIDENT_TIMELINE = document.getElementById("incident-timeline");

let activeIncidentId = null;

function formatTimestamp(value) {
  if (!value) return "—";
  const dt = new Date(value);
  if (Number.isNaN(dt.getTime())) return value;
  return dt.toLocaleString();
}

function severityBadge(severity) {
  const label = (severity || "low").toLowerCase();
  return `<span class="severity ${label}">${label.toUpperCase()}</span>`;
}

function renderIncidents(items) {
  if (!items.length) {
    INCIDENTS_BODY.innerHTML = `<tr><td colspan="9" class="muted">No correlated incidents yet.</td></tr>`;
    return;
  }
  INCIDENTS_BODY.innerHTML = items
    .map(
      (incident) => `
      <tr class="alert-row" data-id="${incident.incident_id}">
        <td>${incident.incident_id}</td>
        <td>${incident.incident_type}</td>
        <td>${severityBadge(incident.severity)}</td>
        <td class="mono">${incident.src_ip || "—"}</td>
        <td>${(incident.target_hosts || []).join(", ") || "—"}</td>
        <td>${(incident.related_alerts || []).length}</td>
        <td>${incident.status || "open"}</td>
        <td>${formatTimestamp(incident.first_seen)}</td>
        <td>${formatTimestamp(incident.last_seen)}</td>
      </tr>
    `
    )
    .join("");

  INCIDENTS_BODY.querySelectorAll(".alert-row").forEach((row) => {
    row.addEventListener("click", () => openIncident(row.dataset.id));
  });
}

function loadIncidents() {
  fetch("/api/incidents")
    .then((response) => response.json())
    .then((data) => {
      renderIncidents(data.incidents || []);
      INCIDENTS_UPDATED.textContent = `Last updated: ${new Date().toLocaleTimeString()}`;
    })
    .catch(() => {
      INCIDENTS_BODY.innerHTML = `<tr><td colspan="9" class="muted">Failed to load incidents.</td></tr>`;
    });
}

function openIncident(incidentId) {
  fetch(`/api/incidents/${incidentId}`)
    .then((response) => response.json())
    .then((incident) => {
      if (!incident?.incident_id) return;
      activeIncidentId = incidentId;
      INCIDENT_TITLE.textContent = `Incident ${incident.incident_id}`;
      INCIDENT_META.innerHTML = `
        <div><strong>Type:</strong> ${incident.incident_type}</div>
        <div><strong>Severity:</strong> ${incident.severity}</div>
        <div><strong>Source IP:</strong> ${incident.src_ip || "—"}</div>
        <div><strong>Targets:</strong> ${(incident.target_hosts || []).join(", ") || "—"}</div>
      `;
      INCIDENT_STATUS.value = incident.status || "open";
      INCIDENT_ANALYST.value = incident.assigned_analyst || "";
      INCIDENT_NOTE.value = incident.notes || "";
      if (INCIDENT_CREATE_CASE) {
        INCIDENT_CREATE_CASE.dataset.investigationId = incident.investigation_id || "";
        INCIDENT_CREATE_CASE.textContent = incident.investigation_id
          ? `Open Investigation #${incident.investigation_id}`
          : "Open Investigation";
      }

      const related = incident.related_alerts || [];
      INCIDENT_ALERTS.innerHTML = related.length
        ? related.map((id) => `<div>Alert #${id}</div>`).join("")
        : `<div class="muted">No linked alerts.</div>`;

      const timeline = incident.events || [];
      INCIDENT_TIMELINE.innerHTML = timeline.length
        ? timeline.map((item) => `<div>${formatTimestamp(item.created_at)} ${item.message}</div>`).join("")
        : `<div class="muted">No timeline events yet.</div>`;

      INCIDENT_DRAWER.classList.remove("hidden");
    });
}

function closeIncident() {
  INCIDENT_DRAWER.classList.add("hidden");
  activeIncidentId = null;
}

function updateIncidentStatus() {
  if (!activeIncidentId) return;
  fetch(`/api/incidents/${activeIncidentId}/status`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status: INCIDENT_STATUS.value }),
  }).then(() => loadIncidents());
}

function assignIncident() {
  if (!activeIncidentId) return;
  const analyst = INCIDENT_ANALYST.value.trim();
  if (!analyst) return;
  fetch(`/api/incidents/${activeIncidentId}/assign`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ analyst }),
  }).then(() => openIncident(activeIncidentId));
}

function saveIncidentNote() {
  if (!activeIncidentId) return;
  const note = INCIDENT_NOTE.value.trim();
  if (!note) return;
  fetch(`/api/incidents/${activeIncidentId}/notes`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ note }),
  }).then(() => openIncident(activeIncidentId));
}

function openInvestigationFromIncident() {
  if (!activeIncidentId) return;
  const existing = INCIDENT_CREATE_CASE.dataset.investigationId;
  if (existing) {
    window.location.href = `/investigations.html#case-${existing}`;
    return;
  }
  fetch(`/api/incidents/${activeIncidentId}/investigate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
  })
    .then((response) => response.json())
    .then((payload) => {
      if (payload?.investigation_id) {
        window.location.href = `/investigations.html#case-${payload.investigation_id}`;
      }
    });
}

INCIDENT_CLOSE.addEventListener("click", closeIncident);
INCIDENT_DRAWER.addEventListener("click", (event) => {
  if (event.target.classList.contains("drawer-backdrop")) closeIncident();
});
INCIDENT_STATUS.addEventListener("change", updateIncidentStatus);
INCIDENT_ASSIGN.addEventListener("click", assignIncident);
INCIDENT_NOTE_SAVE.addEventListener("click", saveIncidentNote);
if (INCIDENT_CREATE_CASE) {
  INCIDENT_CREATE_CASE.addEventListener("click", openInvestigationFromIncident);
}

loadIncidents();
setInterval(loadIncidents, 5000);

const hash = window.location.hash;
if (hash.startsWith("#incident-")) {
  const incidentId = hash.replace("#incident-", "");
  if (incidentId) {
    openIncident(incidentId);
  }
}
