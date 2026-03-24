const AUTH_TOKEN_KEY = "fs_auth_token";
const AUTH_HOST_KEY = "fs_auth_host";

function getAuthToken() {
  return localStorage.getItem(AUTH_TOKEN_KEY);
}

function setAuthToken(token) {
  if (!token) return;
  localStorage.setItem(AUTH_TOKEN_KEY, token);
  localStorage.setItem(AUTH_HOST_KEY, window.location.origin);
}

function clearAuthToken() {
  localStorage.removeItem(AUTH_TOKEN_KEY);
  localStorage.removeItem(AUTH_HOST_KEY);
}

function isLoginPage() {
  return window.location.pathname.endsWith("/login.html");
}

function buildAuthHeaders(headers = {}) {
  const token = getAuthToken();
  if (!token) return headers;
  return { ...headers, Authorization: `Bearer ${token}` };
}

function tokenHostMismatch() {
  const host = localStorage.getItem(AUTH_HOST_KEY);
  return host && host !== window.location.origin;
}

const originalFetch = window.fetch.bind(window);
window.fetch = async (input, init = {}) => {
  const headers = buildAuthHeaders(init.headers || {});
  const nextInit = { ...init, headers };
  const response = await originalFetch(input, nextInit);
  if (
    response.status === 401 &&
    !isLoginPage() &&
    typeof input === "string" &&
    !input.startsWith("/auth")
  ) {
    clearAuthToken();
    const next = encodeURIComponent(window.location.pathname + window.location.search + window.location.hash);
    window.location.replace(`/login.html?next=${next}`);
  }
  return response;
};

async function checkAuth() {
  try {
    const response = await originalFetch("/auth/me", { headers: buildAuthHeaders() });
    const payload = await response.json();
    if (!payload.auth_required) {
      return true;
    }
    return payload.authenticated === true;
  } catch (error) {
    return false;
  }
}

async function enforceAuth() {
  if (isLoginPage()) return;
  if (tokenHostMismatch()) {
    clearAuthToken();
  }
  const ok = await checkAuth();
  if (!ok) {
    const next = encodeURIComponent(window.location.pathname + window.location.search + window.location.hash);
    window.location.replace(`/login.html?next=${next}`);
  }
}

async function initLoginForm() {
  if (!isLoginPage()) return;
  const form = document.getElementById("login-form");
  const error = document.getElementById("login-error");
  const hostHint = document.getElementById("login-host-hint");
  if (!form) return;
  if (hostHint) {
    hostHint.textContent = window.location.origin;
  }
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (error) error.textContent = "";
    const username = document.getElementById("login-username").value.trim();
    const password = document.getElementById("login-password").value;
    if (!username || !password) {
      if (error) error.textContent = "Username and password are required.";
      return;
    }
    try {
      const response = await originalFetch("/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      const payload = await response.json();
      if (!response.ok) {
        if (error) error.textContent = payload.error || "Login failed.";
        return;
      }
      setAuthToken(payload.token);
      const params = new URLSearchParams(window.location.search);
      const next = params.get("next") || "/index.html";
      window.location.replace(next);
    } catch (err) {
      if (error) error.textContent = "Login failed. Check backend status.";
    }
  });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => {
    enforceAuth();
    initLoginForm();
  });
} else {
  enforceAuth();
  initLoginForm();
}
