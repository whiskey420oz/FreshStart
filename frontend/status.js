let TOGGLE_BUTTON;
let STATUS_SYSTEM;
let STATUS_WAZUH;
let STATUS_REDIS;
let STATUS_WORKER;
let USER_PILL;
let LOGOUT_BUTTON;
let FOCUS_TOGGLE;
let GLOBAL_SEARCH_FORM;
let GLOBAL_SEARCH_INPUT;

function setStatusPill(element, state, label) {
  if (!element) return;
  const dot = element.querySelector(".status-dot");
  const text = element.querySelector(".status-text");
  if (dot) {
    dot.classList.remove("ok", "warn", "error");
    dot.classList.add(state);
  }
  if (text) {
    text.textContent = label;
  }
}

function updateStatuses(debug) {
  const wazuhState = debug.wazuh_api === "connected" ? "ok" : "error";
  const redisState = debug.redis === "connected" ? "ok" : "error";
  const systemState = debug.database === "ok" ? "ok" : "warn";
  const workerState =
    debug.redis === "connected" && debug.queue_length < 100 ? "ok" : debug.redis === "connected" ? "warn" : "error";

  setStatusPill(STATUS_SYSTEM, systemState, `System: ${debug.database}`);
  setStatusPill(STATUS_WAZUH, wazuhState, `Wazuh API: ${debug.wazuh_api}`);
  setStatusPill(STATUS_REDIS, redisState, `Redis: ${debug.redis} (${debug.queue_length})`);
  setStatusPill(STATUS_WORKER, workerState, `Worker: ${workerState}`);
}

async function loadStatus() {
  try {
    const response = await fetch("/system/debug");
    const payload = await response.json();
    if (!response.ok) throw new Error("debug unavailable");
    updateStatuses(payload);
  } catch (error) {
    setStatusPill(STATUS_SYSTEM, "warn", "System: unknown");
    setStatusPill(STATUS_WAZUH, "warn", "Wazuh API: unknown");
    setStatusPill(STATUS_REDIS, "warn", "Redis: unknown");
    setStatusPill(STATUS_WORKER, "warn", "Worker: unknown");
  }
}

async function loadUser() {
  if (!USER_PILL) return;
  try {
    const response = await fetch("/auth/me");
    const payload = await response.json();
    if (payload.authenticated) {
      USER_PILL.textContent = `User: ${payload.user?.username || "analyst"}`;
    } else {
      USER_PILL.textContent = "User: --";
    }
  } catch (error) {
    USER_PILL.textContent = "User: --";
  }
}

async function logout() {
  try {
    await fetch("/auth/logout", { method: "POST" });
  } catch (error) {
    // ignore
  }
  localStorage.removeItem("fs_auth_token");
  localStorage.removeItem("fs_auth_host");
  window.location.replace("/login.html");
}

function initStatusUi() {
  TOGGLE_BUTTON = document.getElementById("toggle-sidebar");
  STATUS_SYSTEM = document.getElementById("status-system");
  STATUS_WAZUH = document.getElementById("status-wazuh");
  STATUS_REDIS = document.getElementById("status-redis");
  STATUS_WORKER = document.getElementById("status-worker");
  USER_PILL = document.getElementById("user-pill");
  LOGOUT_BUTTON = document.getElementById("logout-button");
  FOCUS_TOGGLE = document.getElementById("focus-toggle");
  GLOBAL_SEARCH_FORM = document.getElementById("global-search-form");
  GLOBAL_SEARCH_INPUT = document.getElementById("global-search-input");

  if (TOGGLE_BUTTON) {
    TOGGLE_BUTTON.addEventListener("click", () => {
      document.body.classList.toggle("sidebar-collapsed");
      const isCollapsed = document.body.classList.contains("sidebar-collapsed");
      localStorage.setItem("sidebarCollapsed", isCollapsed ? "true" : "false");
    });
  }

  if (localStorage.getItem("sidebarCollapsed") === "true") {
    document.body.classList.add("sidebar-collapsed");
  }

  if (LOGOUT_BUTTON) {
    LOGOUT_BUTTON.addEventListener("click", logout);
  }

  if (FOCUS_TOGGLE) {
    if (localStorage.getItem("focusMode") === "true") {
      document.body.classList.add("focus-mode");
    }
    FOCUS_TOGGLE.addEventListener("click", () => {
      document.body.classList.toggle("focus-mode");
      localStorage.setItem("focusMode", document.body.classList.contains("focus-mode") ? "true" : "false");
    });
  }

  if (GLOBAL_SEARCH_FORM && GLOBAL_SEARCH_INPUT) {
    GLOBAL_SEARCH_FORM.addEventListener("submit", (event) => {
      event.preventDefault();
      const query = GLOBAL_SEARCH_INPUT.value.trim();
      if (!query) return;
      const next = `/alerts.html?q=${encodeURIComponent(query)}`;
      window.location.href = next;
    });
  }

  loadStatus();
  loadUser();
  setInterval(loadStatus, 10000);
  setInterval(loadUser, 30000);
  fetch("/soc/ping", { method: "POST" }).catch(() => {});
  setInterval(() => fetch("/soc/ping", { method: "POST" }).catch(() => {}), 30000);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initStatusUi);
} else {
  initStatusUi();
}
