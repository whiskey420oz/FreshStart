const ASSETS_BODY = document.getElementById("assets-body");
const ASSETS_ERROR = document.getElementById("assets-error");

function showAssetsError(message) {
  ASSETS_ERROR.textContent = message;
  ASSETS_ERROR.classList.remove("hidden");
}

function clearAssetsError() {
  ASSETS_ERROR.textContent = "";
  ASSETS_ERROR.classList.add("hidden");
}

function formatTimestamp(value) {
  if (!value) return "Unknown";
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) return String(value);
  const date = new Date(parsed);
  const formatted = date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
  return formatted.replace(",", "");
}

function renderAssets(assets) {
  if (!assets.length) {
    ASSETS_BODY.innerHTML = `
      <tr>
        <td colspan="4" class="muted">No assets reported yet.</td>
      </tr>
    `;
    return;
  }

  ASSETS_BODY.innerHTML = assets
    .map(
      (asset) => `
        <tr>
          <td>${asset.name || "Unknown"}</td>
          <td class="mono">${asset.ip || "N/A"}</td>
          <td>${asset.alerts ?? 0}</td>
          <td>${formatTimestamp(asset.last_seen)}</td>
        </tr>
      `
    )
    .join("");
}

async function loadAssets() {
  try {
    const response = await fetch("/api/assets");
    const payload = await response.json();
    if (!response.ok) throw new Error(payload?.error || "Unable to load assets.");
    clearAssetsError();
    renderAssets(Array.isArray(payload) ? payload : payload.assets || []);
  } catch (error) {
    showAssetsError(error.message || "Unable to load assets.");
  }
}

loadAssets();
setInterval(loadAssets, 10000);
