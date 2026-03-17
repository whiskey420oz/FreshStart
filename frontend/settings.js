const SETTINGS_ERROR = document.getElementById("settings-error");
const SETTINGS_MESSAGE = document.getElementById("settings-message");
const SAVE_BUTTON = document.getElementById("save-settings");
const FIELD_WAZUH_IP = document.getElementById("setting-wazuh-ip");
const FIELD_SYSLOG_PORT = document.getElementById("setting-syslog-port");
const FIELD_DATABASE = document.getElementById("setting-database");
const FIELD_RESPONSE_MODE = document.getElementById("setting-response-mode");

function showSettingsError(message) {
  SETTINGS_ERROR.textContent = message;
  SETTINGS_ERROR.classList.remove("hidden");
}

function clearSettingsError() {
  SETTINGS_ERROR.textContent = "";
  SETTINGS_ERROR.classList.add("hidden");
}

function setMessage(message, isError = false) {
  SETTINGS_MESSAGE.textContent = message;
  SETTINGS_MESSAGE.classList.toggle("error", isError);
  SETTINGS_MESSAGE.classList.toggle("success", !isError);
}

function populateFields(settings) {
  FIELD_WAZUH_IP.value = settings.wazuh_manager_ip || "";
  FIELD_SYSLOG_PORT.value = settings.syslog_port ?? "";
  FIELD_DATABASE.value = settings.database_type || "";
  FIELD_RESPONSE_MODE.value = settings.response_mode || "";
}

async function loadSettings() {
  try {
    const response = await fetch("/api/settings");
    const payload = await response.json();
    if (!response.ok) throw new Error(payload?.error || "Failed to load settings.");
    clearSettingsError();
    populateFields(payload.settings || {});
  } catch (error) {
    showSettingsError(error.message || "Failed to load settings.");
  }
}

async function saveSettings() {
  const payload = {
    wazuh_manager_ip: FIELD_WAZUH_IP.value.trim(),
    syslog_port: Number(FIELD_SYSLOG_PORT.value || 0),
    database_type: FIELD_DATABASE.value.trim(),
    response_mode: FIELD_RESPONSE_MODE.value.trim(),
  };
  SAVE_BUTTON.disabled = true;
  setMessage("Saving settings...");
  try {
    const response = await fetch("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data?.error || "Failed to save settings.");
    setMessage("Settings saved successfully.");
    populateFields(data.settings || payload);
  } catch (error) {
    setMessage(error.message || "Failed to save settings.", true);
  } finally {
    SAVE_BUTTON.disabled = false;
  }
}

SAVE_BUTTON.addEventListener("click", saveSettings);

loadSettings();
