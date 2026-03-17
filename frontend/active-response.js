const BLOCK_INPUT = document.getElementById("block-ip-input");
const BLOCK_BUTTON = document.getElementById("block-ip-button");
const RESPONSE_MESSAGE = document.getElementById("response-message");

function setMessage(message, isError = false) {
  RESPONSE_MESSAGE.textContent = message;
  RESPONSE_MESSAGE.classList.toggle("error", isError);
  RESPONSE_MESSAGE.classList.toggle("success", !isError);
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
