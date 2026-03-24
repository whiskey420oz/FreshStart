const AGENTS_BODY = document.getElementById("agents-body");
const AGENTS_STATUS = document.getElementById("agents-status");
const AGENTS_ERROR = document.getElementById("agents-error");

function formatTimestamp(value) {
  if (!value) return "—";
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) return String(value);
  return new Date(parsed).toLocaleString();
}

function renderAgents(agents) {
  if (!agents || !agents.length) {
    AGENTS_BODY.innerHTML = `
      <tr>
        <td colspan="6" class="muted">No agents found.</td>
      </tr>
    `;
    return;
  }

  AGENTS_BODY.innerHTML = agents
    .map((agent) => {
      const agentId = agent.id || agent.agent_id || "";
      const status = String(agent?.status || "unknown").toLowerCase();
      const badgeClass =
        status === "active"
          ? "active"
          : status === "disconnected"
            ? "disconnected"
            : status === "never_connected"
              ? "never"
              : "disconnected";
      return `
        <tr>
          <td>${agentId || "—"}</td>
          <td>${agent.name || "—"}</td>
          <td class="mono">${agent.ip || agent.ip_address || "—"}</td>
          <td><span class="status-indicator ${badgeClass}">${status}</span></td>
          <td>${formatTimestamp(agent.lastKeepAlive || agent.last_keepalive || agent.last_seen)}</td>
          <td>
            <button class="ghost danger" data-agent-id="${agentId}">Delete</button>
          </td>
        </tr>
      `;
    })
    .join("");
}

function showError(message) {
  if (!AGENTS_ERROR) return;
  AGENTS_ERROR.textContent = message;
  AGENTS_ERROR.classList.remove("hidden");
}

function clearError() {
  if (!AGENTS_ERROR) return;
  AGENTS_ERROR.textContent = "";
  AGENTS_ERROR.classList.add("hidden");
}

function setUpdated() {
  if (!AGENTS_STATUS) return;
  AGENTS_STATUS.textContent = `Last updated: ${new Date().toLocaleTimeString()}`;
}

async function loadAgents() {
  try {
    const response = await fetch("/wazuh/agents");
    const payload = await response.json();
    if (!response.ok) throw new Error(payload?.message || "Wazuh API unavailable.");
    const items = payload?.agents || [];
    renderAgents(items);
    clearError();
    setUpdated();
  } catch (error) {
    showError(error.message || "Wazuh API unavailable.");
  }
}

async function deleteAgent(agentId) {
  if (!agentId) return;
  const confirmed = window.confirm(`Delete agent ${agentId}? This cannot be undone.`);
  if (!confirmed) return;
  try {
    const response = await fetch(`/wazuh/agents/${agentId}`, { method: "DELETE" });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload?.error || "Failed to delete agent.");
    await loadAgents();
  } catch (error) {
    showError(error.message || "Failed to delete agent.");
  }
}

AGENTS_BODY.addEventListener("click", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  if (!target.matches("button[data-agent-id]")) return;
  const agentId = target.getAttribute("data-agent-id");
  deleteAgent(agentId);
});

loadAgents();
setInterval(loadAgents, 30000);
