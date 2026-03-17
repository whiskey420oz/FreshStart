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

function loadCases() {
  const index = JSON.parse(localStorage.getItem("cases_index") || "[]");
  return index.map((id) => JSON.parse(localStorage.getItem(`case_${id}`) || "{}")).filter(Boolean);
}

function saveCase(caseData) {
  localStorage.setItem(`case_${caseData.id}`, JSON.stringify(caseData));
  const index = new Set(JSON.parse(localStorage.getItem("cases_index") || "[]"));
  index.add(caseData.id);
  localStorage.setItem("cases_index", JSON.stringify([...index]));
}

function renderCaseList() {
  const cases = loadCases();
  if (!cases.length) {
    CASE_LIST.innerHTML = `<tr><td colspan="5" class="muted">No investigations created yet.</td></tr>`;
    return;
  }

  CASE_LIST.innerHTML = cases
    .map(
      (item) => `
        <tr class="alert-row" data-id="${item.id}">
          <td>${item.id}</td>
          <td>${item.title}</td>
          <td>${item.status}</td>
          <td>${(item.alerts || []).length}</td>
          <td>${item.created}</td>
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
  const id = Date.now().toString();
  const caseData = {
    id,
    title,
    description: desc,
    status: "Open",
    created: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    alerts: [],
    notes: [],
  };
  saveCase(caseData);
  closeNewCaseModal();
  renderCaseList();
}

function openCase(caseId) {
  const caseData = JSON.parse(localStorage.getItem(`case_${caseId}`) || "{}");
  if (!caseData.id) return;
  activeCaseId = caseId;
  CASE_TITLE.textContent = caseData.title;
  CASE_META.innerHTML = `
    <div><strong>Status:</strong> ${caseData.status}</div>
    <div><strong>Created:</strong> ${caseData.created}</div>
    <div><strong>Description:</strong> ${caseData.description || "N/A"}</div>
  `;
  CASE_STATUS.value = caseData.status;

  const alerts = (caseData.alerts || []).map((id) => JSON.parse(localStorage.getItem(`alertSnapshot_${id}`) || "{}")).filter(Boolean);
  CASE_ALERTS.innerHTML = alerts.length
    ? alerts.map((alert) => `<div>${alert.timestamp} ${alert.rule_description}</div>`).join("")
    : `<div class="muted">No alerts linked.</div>`;

  CASE_TIMELINE.innerHTML = alerts
    .slice()
    .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))
    .map((alert) => `<div>${alert.timestamp} ${alert.rule_description}</div>`)
    .join("");

  CASE_NOTES.innerHTML = caseData.notes.length
    ? caseData.notes.map((note) => `<div>${note.timestamp} ${note.text}</div>`).join("")
    : `<div class="muted">No notes yet.</div>`;
  CASE_DRAWER.classList.remove("hidden");
}

function closeCase() {
  CASE_DRAWER.classList.add("hidden");
  activeCaseId = null;
}

function updateCaseStatus() {
  if (!activeCaseId) return;
  const caseData = JSON.parse(localStorage.getItem(`case_${activeCaseId}`) || "{}");
  caseData.status = CASE_STATUS.value;
  saveCase(caseData);

  if (caseData.status === "Resolved") {
    (caseData.alerts || []).forEach((alertId) => {
      localStorage.setItem(`alertStatus_${alertId}`, "Resolved");
    });
  }

  renderCaseList();
  openCase(activeCaseId);
}

function addNote() {
  if (!activeCaseId) return;
  const text = CASE_NOTE_INPUT.value.trim();
  if (!text) return;
  const caseData = JSON.parse(localStorage.getItem(`case_${activeCaseId}`) || "{}");
  caseData.notes.push({
    timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    text,
  });
  saveCase(caseData);
  CASE_NOTE_INPUT.value = "";
  openCase(activeCaseId);
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

renderCaseList();
