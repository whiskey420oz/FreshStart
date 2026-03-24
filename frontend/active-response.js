const BLOCK_INPUT = document.getElementById("block-ip-input");
const BLOCK_BUTTON = document.getElementById("block-ip-button");
const RESPONSE_MESSAGE = document.getElementById("response-message");
const RESPONSES_BODY = document.getElementById("responses-body");
const RESPONSES_UPDATED = document.getElementById("responses-updated");

function setMessage(message, isError = false) {
  RESPONSE_MESSAGE.textContent = message;
  RESPONSE_MESSAGE.classList.toggle("error", isError);
  RESPONSE_MESSAGE.classList.toggle("success", !isError);
}

function formatTimestamp(value) {
  if (!value) return "—";
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) return String(value);
  return new Date(parsed).toLocaleString();
}

function renderResponses(responses) {
  if (!RESPONSES_BODY) return;
  if (!responses.length) {
    RESPONSES_BODY.innerHTML = `
      <tr>
        <td colspan="5" class="muted">No response actions recorded yet.</td>
      </tr>
    `;
    return;
  }
  RESPONSES_BODY.innerHTML = responses
    .map(
      (entry) => `
        <tr>
          <td>${formatTimestamp(entry.timestamp)}</td>
          <td>${entry.action_type || "—"}</td>
          <td class="mono">${entry.target_ip || "—"}</td>
          <td>${entry.analyst || "—"}</td>
          <td>${entry.status || "—"}</td>
        </tr>
      `
    )
    .join("");
}

async function loadResponses() {
  try {
    const response = await fetch("/responses");
    const payload = await response.json();
    if (!response.ok) throw new Error(payload?.error || "Failed to load responses.");
    renderResponses(payload.responses || []);
    if (RESPONSES_UPDATED) {
      RESPONSES_UPDATED.textContent = `Last updated: ${new Date().toLocaleTimeString()}`;
    }
  } catch (error) {
    renderResponses([]);
  }
}

async function blockIp() {
  const ip = (BLOCK_INPUT.value || "").trim();
  if (!ip) {
    setMessage("Please enter an IP address.", true);
    return;
  }
  BLOCK_BUTTON.disabled = true;
  setMessage("Sending active response...");
  try {
    const response = await fetch("/api/response/block-ip", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip }),
    });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload?.message || "Failed to block IP.");
    }
    setMessage(payload?.message || "IP blocked successfully.");
    BLOCK_INPUT.value = "";
  } catch (error) {
    setMessage(error.message || "Failed to block IP.", true);
  } finally {
    BLOCK_BUTTON.disabled = false;
  }
}

BLOCK_BUTTON.addEventListener("click", blockIp);
BLOCK_INPUT.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    blockIp();
  }
});

loadResponses();
setInterval(loadResponses, 10000);
