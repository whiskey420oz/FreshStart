const VULN_BODY = document.getElementById("vuln-body");
const VULN_UPDATED = document.getElementById("vuln-updated");
const VULN_ERROR = document.getElementById("vuln-error");

function showError(message) {
  if (!VULN_ERROR) return;
  VULN_ERROR.textContent = message;
  VULN_ERROR.classList.remove("hidden");
}

function clearError() {
  if (!VULN_ERROR) return;
  VULN_ERROR.textContent = "";
  VULN_ERROR.classList.add("hidden");
}

function renderVulns(entries) {
  if (!VULN_BODY) return;
  if (!entries.length) {
    VULN_BODY.innerHTML = `<tr><td colspan="5" class="muted">No vulnerabilities found.</td></tr>`;
    return;
  }
  VULN_BODY.innerHTML = entries
    .map(
      (item) => `
        <tr>
          <td>${item.agent_name || "—"}</td>
          <td>${item.package_name || "—"}</td>
          <td>${item.cve || "—"}</td>
          <td>${item.severity || "—"}</td>
          <td>${item.cvss_score || "—"}</td>
        </tr>
      `
    )
    .join("");
}

async function loadVulnerabilities() {
  try {
    const response = await fetch("/wazuh/vulnerabilities?limit=50");
    const payload = await response.json();
    if (!response.ok && payload?.status === "disabled") {
      showError(payload.message);
      renderVulns([]);
      return;
    }
    if (!response.ok) throw new Error(payload?.message || "Failed to load vulnerabilities.");
    renderVulns(payload.vulnerabilities || []);
    if (VULN_UPDATED) {
      VULN_UPDATED.textContent = `Last updated: ${new Date().toLocaleTimeString()}`;
    }
    clearError();
  } catch (error) {
    showError(error.message || "Unable to load vulnerabilities.");
  }
}

loadVulnerabilities();
setInterval(loadVulnerabilities, 30000);
