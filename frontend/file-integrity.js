const FIM_BODY = document.getElementById("fim-body");
const FIM_UPDATED = document.getElementById("fim-updated");
const FIM_ERROR = document.getElementById("fim-error");

function showError(message) {
  if (!FIM_ERROR) return;
  FIM_ERROR.textContent = message;
  FIM_ERROR.classList.remove("hidden");
}

function clearError() {
  if (!FIM_ERROR) return;
  FIM_ERROR.textContent = "";
  FIM_ERROR.classList.add("hidden");
}

function renderFIM(entries) {
  if (!FIM_BODY) return;
  if (!entries.length) {
    FIM_BODY.innerHTML = `<tr><td colspan="4" class="muted">No file integrity events found.</td></tr>`;
    return;
  }
  FIM_BODY.innerHTML = entries
    .map(
      (item) => `
        <tr>
          <td>${item.agent_name || "—"}</td>
          <td class="mono">${item.file_path || "—"}</td>
          <td>${item.event_type || "—"}</td>
          <td>${item.timestamp || "—"}</td>
        </tr>
      `
    )
    .join("");
}

async function loadFIM() {
  try {
    const response = await fetch("/wazuh/file-integrity?limit=50");
    const payload = await response.json();
    if (!response.ok && payload?.status === "disabled") {
      showError(payload.message);
      renderFIM([]);
      return;
    }
    if (!response.ok) throw new Error(payload?.message || "Failed to load file integrity events.");
    renderFIM(payload.changes || []);
    if (FIM_UPDATED) {
      FIM_UPDATED.textContent = `Last updated: ${new Date().toLocaleTimeString()}`;
    }
    clearError();
  } catch (error) {
    showError(error.message || "Unable to load file integrity events.");
  }
}

loadFIM();
setInterval(loadFIM, 30000);
