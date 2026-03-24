const CASE_LIST = document.getElementById("case-list");
const NEW_CASE_BUTTON = document.getElementById("new-case");
const NEW_CASE_MODAL = document.getElementById("new-case-modal");
const NEW_CASE_CLOSE = document.getElementById("new-case-close");
const CREATE_CASE = document.getElementById("create-case");
const CASE_TITLE_INPUT = document.getElementById("case-title-input");
const CASE_DESC_INPUT = document.getElementById("case-desc-input");

const CASE_DRAWER = document.getElementById("case-drawer");
const CASE_CLOSE = document.getElementById("case-close");
const CASE_TITLE = document.getElementById("case-title");
const CASE_META = document.getElementById("case-meta");
const CASE_STATUS = document.getElementById("case-status");
const CASE_ALERTS = document.getElementById("case-alerts");
const CASE_TIMELINE = document.getElementById("case-timeline");
const CASE_NOTE_INPUT = document.getElementById("case-note");
const ADD_NOTE = document.getElementById("add-note");
const CASE_NOTES = document.getElementById("case-notes");

let activeCaseId = null;
let investigations = [];

function renderCaseList() {
  if (!investigations.length) {
    CASE_LIST.innerHTML = `<tr><td colspan="5" class="muted">No investigations created yet.</td></tr>`;
    return;
  }

  CASE_LIST.innerHTML = investigations
    .map(
      (item) => `
        <tr class="alert-row" data-id="${item.id}">
          <td>${item.id}</td>
          <td>${item.title}</td>
          <td>${item.status}</td>
          <td>${item.alert_id ? 1 : 0}</td>
          <td>${item.created_at || "—"}</td>
        </tr>
      `
    )
    .join("");

  CASE_LIST.querySelectorAll(".alert-row").forEach((row) => {
    row.addEventListener("click", () => openCase(row.dataset.id));
  });
}

function openNewCaseModal() {
  NEW_CASE_MODAL.classList.remove("hidden");
  CASE_TITLE_INPUT.value = "";
  CASE_DESC_INPUT.value = "";
}

function closeNewCaseModal() {
  NEW_CASE_MODAL.classList.add("hidden");
}

function createCase() {
  const title = CASE_TITLE_INPUT.value.trim();
  if (!title) return;
  const desc = CASE_DESC_INPUT.value.trim();
  fetch("/investigations", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ analyst_name: "SOC Analyst", notes: desc, title }),
  })
    .then(() => {
      closeNewCaseModal();
      loadInvestigations();
    })
    .catch(() => {
      closeNewCaseModal();
    });
}

function openCase(caseId) {
  fetch(`/investigations/${caseId}`)
    .then((response) => response.json())
    .then((caseData) => {
      if (!caseData.id) return;
      activeCaseId = caseId;
      CASE_TITLE.textContent = caseData.title ? `Case ${caseData.id} · ${caseData.title}` : `Case ${caseData.id}`;
      CASE_META.innerHTML = `
        <div><strong>Status:</strong> ${caseData.status}</div>
        <div><strong>Created:</strong> ${caseData.created_at || "N/A"}</div>
        <div><strong>Analyst:</strong> ${caseData.analyst_name || "N/A"}</div>
        <div><strong>Notes:</strong> ${caseData.notes || "N/A"}</div>
        <div><strong>Incident:</strong> ${
          caseData.incident_id ? `Incident #${caseData.incident_id}` : "—"
        }</div>
      `;
      CASE_STATUS.value = caseData.status;

      if (caseData.alert_id) {
        fetch(`/alerts/${caseData.alert_id}`)
          .then((res) => res.json())
          .then((alert) => {
            CASE_ALERTS.innerHTML = alert?.id
              ? `<div>${alert.timestamp} ${alert.rule_description}</div>`
              : `<div class="muted">No alerts linked.</div>`;
          });
      } else {
        CASE_ALERTS.innerHTML = `<div class="muted">No alerts linked.</div>`;
      }

      const events = caseData.events || [];
      CASE_TIMELINE.innerHTML = events.length
        ? events.map((event) => `<div>${event.created_at} ${event.message}</div>`).join("")
        : `<div class="muted">No timeline events yet.</div>`;

      CASE_NOTES.innerHTML = caseData.notes ? `<div>${caseData.notes}</div>` : `<div class="muted">No notes yet.</div>`;
      CASE_DRAWER.classList.remove("hidden");
    });
}

function closeCase() {
  CASE_DRAWER.classList.add("hidden");
  activeCaseId = null;
}

function updateCaseStatus() {
  if (!activeCaseId) return;
  fetch(`/investigations/${activeCaseId}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status: CASE_STATUS.value }),
  })
    .then(() => loadInvestigations())
    .then(() => openCase(activeCaseId));
}

function addNote() {
  if (!activeCaseId) return;
  const text = CASE_NOTE_INPUT.value.trim();
  if (!text) return;
  fetch(`/investigations/${activeCaseId}/notes`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ note: text }),
  }).then(() => {
    CASE_NOTE_INPUT.value = "";
    openCase(activeCaseId);
  });
}

NEW_CASE_BUTTON.addEventListener("click", openNewCaseModal);
NEW_CASE_CLOSE.addEventListener("click", closeNewCaseModal);
NEW_CASE_MODAL.addEventListener("click", (event) => {
  if (event.target.classList.contains("modal-backdrop")) {
    closeNewCaseModal();
  }
});
CREATE_CASE.addEventListener("click", createCase);
CASE_CLOSE.addEventListener("click", closeCase);
CASE_DRAWER.addEventListener("click", (event) => {
  if (event.target.classList.contains("drawer-backdrop")) {
    closeCase();
  }
});
CASE_STATUS.addEventListener("change", updateCaseStatus);
ADD_NOTE.addEventListener("click", addNote);

function loadInvestigations() {
  fetch("/investigations")
    .then((response) => response.json())
    .then((data) => {
      investigations = data.investigations || [];
      renderCaseList();
    });
}

loadInvestigations();

const hash = window.location.hash;
if (hash.startsWith("#case-")) {
  const caseId = hash.replace("#case-", "");
  if (caseId) {
    openCase(caseId);
  }
}
