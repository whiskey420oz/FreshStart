import base64
import json
import os
from pathlib import Path
import time
from urllib.parse import urlparse

import requests


class WazuhClient:
    def __init__(self):
        self.username = os.getenv("WAZUH_USERNAME", "")
        self.password = os.getenv("WAZUH_PASSWORD", "")
        self._token = None
        self._token_expiry = None
        self._base_url = None
        self._verify = True
        self._settings_path = Path(__file__).with_name("config.yaml")

    def _is_localhost(self, url: str) -> bool:
        host = urlparse(url).hostname or ""
        return host in {"localhost", "127.0.0.1", "::1"}

    def _load_settings(self) -> dict:
        if not self._settings_path.exists():
            return {}
        try:
            import yaml

            with self._settings_path.open("r", encoding="utf-8") as handle:
                return yaml.safe_load(handle) or {}
        except Exception:
            return {}

    def _get_base_url(self) -> str:
        env_url = os.getenv("WAZUH_API_URL")
        if env_url:
            return env_url.rstrip("/")

        settings = self._load_settings()
        settings_url = settings.get("wazuh_api_url")
        if settings_url:
            return settings_url.rstrip("/")
        manager_ip = settings.get("wazuh_manager_ip") or "localhost"
        return f"https://{manager_ip}:55000"

    def _refresh_connection_settings(self) -> str:
        base_url = self._get_base_url().rstrip("/")
        if base_url != self._base_url:
            self._base_url = base_url
            self._verify = not self._is_localhost(self._base_url)
            self._token = None
            self._token_expiry = None
        return self._base_url

    def _decode_exp(self, token: str):
        try:
            parts = token.split(".")
            if len(parts) < 2:
                return None
            payload = parts[1]
            payload += "=" * (-len(payload) % 4)
            data = base64.urlsafe_b64decode(payload.encode("utf-8"))
            decoded = json.loads(data.decode("utf-8"))
            return decoded.get("exp")
        except Exception:
            return None

    def _authenticate(self) -> str:
        if not self.username or not self.password:
            raise RuntimeError("WAZUH_USERNAME and WAZUH_PASSWORD must be set.")

        base_url = self._refresh_connection_settings()
        url = f"{base_url}/security/user/authenticate"
        response = requests.post(url, auth=(self.username, self.password), verify=self._verify, timeout=10)
        if not response.ok:
            raise RuntimeError(f"Wazuh auth failed: {response.status_code} {response.text}")

        payload = response.json()
        token = payload.get("data", {}).get("token") or payload.get("token")
        if not token:
            raise RuntimeError("Wazuh auth response missing token.")

        self._token = token
        self._token_expiry = self._decode_exp(token)
        return token

    def _get_token(self) -> str:
        if not self._token:
            return self._authenticate()
        if self._token_expiry:
            if self._token_expiry - time.time() < 60:
                return self._authenticate()
        return self._token

    def _request(self, method: str, path: str, **kwargs):
        base_url = self._refresh_connection_settings()
        token = self._get_token()
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {token}"
        url = f"{base_url}{path}"
        response = requests.request(method, url, headers=headers, verify=self._verify, timeout=10, **kwargs)
        if response.status_code == 401:
            token = self._authenticate()
            headers["Authorization"] = f"Bearer {token}"
            response = requests.request(method, url, headers=headers, verify=self._verify, timeout=10, **kwargs)
        response.raise_for_status()
        return response.json()

    def get_agents(self, limit: int = 500) -> list:
        payload = self._request("GET", f"/agents?limit={limit}")
        items = payload.get("data", {}).get("affected_items", [])
        assets = []
        for item in items:
            os_info = item.get("os") or {}
            os_name = os_info.get("name") or item.get("os_name") or "Unknown"
            os_version = os_info.get("version") or item.get("os_version")
            if os_version and os_version not in os_name:
                os_name = f"{os_name} {os_version}"

            assets.append(
                {
                    "agent_id": item.get("id") or item.get("agent_id") or "Unknown",
                    "name": item.get("name") or "Unknown",
                    "ip": item.get("ip") or item.get("address") or "N/A",
                    "os": os_name,
                    "status": item.get("status") or "unknown",
                    "last_seen": item.get("lastKeepAlive")
                    or item.get("last_keepalive")
                    or item.get("last_keepalive_time")
                    or "Unknown",
                }
            )
        return assets

    def block_ip(self, ip: str, agents: str | None = None, command: str | None = None) -> dict:
        if not ip:
            raise RuntimeError("IP address is required.")
        agents_list = agents or os.getenv("WAZUH_ACTIVE_RESPONSE_AGENTS", "all")
        command_name = command or os.getenv("WAZUH_ACTIVE_RESPONSE_COMMAND", "firewalld-drop")

        payload = {"command": command_name, "custom": False, "arguments": [ip]}
        return self._request(
            "POST",
            f"/active-response?agents_list={agents_list}",
            json=payload,
        )
