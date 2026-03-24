const ASSETS_BODY = document.getElementById("assets-body");
const ASSETS_ERROR = document.getElementById("assets-error");
const MANAGED_BODY = document.getElementById("managed-body");
const MANAGED_ERROR = document.getElementById("managed-error");
const ASSET_NAME = document.getElementById("asset-name");
const ASSET_TYPE = document.getElementById("asset-type");
const ASSET_IP = document.getElementById("asset-ip");
const ASSET_OWNER = document.getElementById("asset-owner");
const ASSET_CRITICALITY = document.getElementById("asset-criticality");
const ASSET_NOTES = document.getElementById("asset-notes");
const ASSET_CREATE = document.getElementById("asset-create");

function showAssetsError(message) {
  ASSETS_ERROR.textContent = message;
  ASSETS_ERROR.classList.remove("hidden");
}

function clearAssetsError() {
  ASSETS_ERROR.textContent = "";
  ASSETS_ERROR.classList.add("hidden");
}

function showManagedError(message) {
  if (!MANAGED_ERROR) return;
  MANAGED_ERROR.textContent = message;
  MANAGED_ERROR.classList.remove("hidden");
}

function clearManagedError() {
  if (!MANAGED_ERROR) return;
  MANAGED_ERROR.textContent = "";
  MANAGED_ERROR.classList.add("hidden");
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

function renderManagedAssets(assets) {
  if (!MANAGED_BODY) return;
  if (!assets.length) {
    MANAGED_BODY.innerHTML = `
      <tr>
        <td colspan="7" class="muted">No managed assets yet.</td>
      </tr>
    `;
    return;
  }
  MANAGED_BODY.innerHTML = assets
    .map(
      (asset) => `
        <tr>
          <td>${asset.name || "—"}</td>
          <td>${asset.asset_type || "—"}</td>
          <td class="mono">${asset.ip_address || "—"}</td>
          <td>${asset.owner || "—"}</td>
          <td>${asset.criticality || "—"}</td>
          <td>${asset.notes || "—"}</td>
          <td>
            <button class="ghost" data-action="edit" data-id="${asset.id}">Edit</button>
            <button class="ghost" data-action="delete" data-id="${asset.id}">Delete</button>
          </td>
        </tr>
      `
    )
    .join("");

  MANAGED_BODY.querySelectorAll("button[data-action='delete']").forEach((button) => {
    button.addEventListener("click", async () => {
      const id = button.dataset.id;
      if (!id) return;
      await fetch(`/api/assets/managed/${id}`, { method: "DELETE" });
      loadManagedAssets();
    });
  });

  MANAGED_BODY.querySelectorAll("button[data-action='edit']").forEach((button) => {
    button.addEventListener("click", () => {
      const id = button.dataset.id;
      const asset = assets.find((item) => String(item.id) === String(id));
      if (!asset) return;
      ASSET_NAME.value = asset.name || "";
      ASSET_TYPE.value = asset.asset_type || "";
      ASSET_IP.value = asset.ip_address || "";
      ASSET_OWNER.value = asset.owner || "";
      ASSET_CRITICALITY.value = asset.criticality || "";
      ASSET_NOTES.value = asset.notes || "";
      ASSET_CREATE.dataset.editingId = asset.id;
      ASSET_CREATE.textContent = "Update Asset";
    });
  });
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

async function loadManagedAssets() {
  try {
    const response = await fetch("/api/assets/managed");
    const payload = await response.json();
    if (!response.ok) throw new Error(payload?.error || "Unable to load managed assets.");
    clearManagedError();
    renderManagedAssets(payload.assets || []);
  } catch (error) {
    showManagedError(error.message || "Unable to load managed assets.");
  }
}

async function createManagedAsset() {
  if (!ASSET_NAME || !ASSET_CREATE) return;
  const payload = {
    name: ASSET_NAME.value.trim(),
    asset_type: ASSET_TYPE.value.trim(),
    ip_address: ASSET_IP.value.trim(),
    owner: ASSET_OWNER.value.trim(),
    criticality: ASSET_CRITICALITY.value,
    notes: ASSET_NOTES.value.trim(),
  };
  if (!payload.name) {
    showManagedError("Name is required.");
    return;
  }
  try {
    const editingId = ASSET_CREATE.dataset.editingId;
    const response = await fetch(
      editingId ? `/api/assets/managed/${editingId}` : "/api/assets/managed",
      {
        method: editingId ? "PUT" : "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      }
    );
    const data = await response.json();
    if (!response.ok) throw new Error(data?.error || "Failed to create asset.");
    ASSET_NAME.value = "";
    ASSET_TYPE.value = "";
    ASSET_IP.value = "";
    ASSET_OWNER.value = "";
    ASSET_CRITICALITY.value = "";
    ASSET_NOTES.value = "";
    ASSET_CREATE.dataset.editingId = "";
    ASSET_CREATE.textContent = "Add Asset";
    loadManagedAssets();
  } catch (error) {
    showManagedError(error.message || "Failed to create asset.");
  }
}

if (ASSET_CREATE) {
  ASSET_CREATE.addEventListener("click", createManagedAsset);
}

loadAssets();
setInterval(loadAssets, 10000);
loadManagedAssets();
