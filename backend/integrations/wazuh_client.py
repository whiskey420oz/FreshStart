import logging
import os
import time
from pathlib import Path

import requests
import yaml

from config import WAZUH_API_URL, WAZUH_USER, WAZUH_PASSWORD


logger = logging.getLogger("freshstart.wazuh_api")


class WazuhApiClient:
    def __init__(self):
        self.base_url = WAZUH_API_URL.rstrip("/")
        self.username = WAZUH_USER
        self.password = WAZUH_PASSWORD
        self.token = None
        self._settings_path = Path(__file__).resolve().parents[1] / "config.yaml"
        self._config_signature = None
        self.alerts_path = "/alerts"
        self.alerts_method = "GET"

    def _load_settings(self) -> dict:
        if not self._settings_path.exists():
            return {}
        try:
            with self._settings_path.open("r", encoding="utf-8") as handle:
                return yaml.safe_load(handle) or {}
        except Exception:
            return {}

    def _refresh_config(self) -> None:
        settings = self._load_settings()
        base_url = os.getenv("WAZUH_API_URL") or settings.get("wazuh_api_url")
        if not base_url:
            manager_ip = settings.get("wazuh_manager_ip") or "localhost"
            base_url = f"https://{manager_ip}:55000"
        username = os.getenv("WAZUH_API_USER") or settings.get("wazuh_api_user") or self.username
        password = os.getenv("WAZUH_API_PASSWORD") or settings.get("wazuh_api_password") or self.password
        alerts_path = os.getenv("WAZUH_ALERTS_PATH") or settings.get("wazuh_alerts_path") or "/alerts"
        alerts_method = (os.getenv("WAZUH_ALERTS_METHOD") or settings.get("wazuh_alerts_method") or "GET").upper()

        signature = f"{base_url}|{username}"
        if signature != self._config_signature:
            self._config_signature = signature
            self.base_url = base_url.rstrip("/")
            self.username = username
            self.password = password
            self.token = None
        self.alerts_path = alerts_path
        self.alerts_method = alerts_method

    def get_token(self) -> str:
        self._refresh_config()
        if not self.username or not self.password:
            raise RuntimeError("WAZUH_API_USER and WAZUH_API_PASSWORD must be set.")
        url = f"{self.base_url}/security/user/authenticate?raw=true"
        try:
            response = requests.get(url, auth=(self.username, self.password), verify=False, timeout=10)
        except requests.RequestException as exc:
            logger.exception("Failed to reach Wazuh API auth endpoint.")
            raise RuntimeError(f"Wazuh auth connection failed: {exc}") from exc

        if not response.ok:
            logger.error("Wazuh auth failed: %s %s", response.status_code, response.text)
            raise RuntimeError(f"Wazuh auth failed: {response.status_code}")

        self.token = response.text.strip()
        return self.token

    def _request(self, method: str, path: str, params: dict | None = None, json_body: dict | None = None):
        self._refresh_config()
        url = f"{self.base_url}{path}"
        attempts = 3
        for attempt in range(attempts):
            if not self.token:
                self.get_token()
            headers = {"Authorization": f"Bearer {self.token}"}
            try:
                response = requests.request(
                    method,
                    url,
                    headers=headers,
                    params=params,
                    json=json_body,
                    verify=False,
                    timeout=10,
                )
            except requests.RequestException as exc:
                logger.exception("Wazuh API request failed: %s %s", method, url)
                if attempt < attempts - 1:
                    time.sleep(1 + attempt)
                    continue
                raise RuntimeError(f"Wazuh API request failed: {exc}") from exc

            if response.status_code == 401:
                self.get_token()
                continue

            if response.status_code in {502, 503, 504} and attempt < attempts - 1:
                time.sleep(1 + attempt)
                continue

            if not response.ok:
                logger.error("Wazuh API request failed: %s %s", response.status_code, response.text)
                raise RuntimeError(f"Wazuh API request failed: {response.status_code}")

            return response.json()

        raise RuntimeError("Wazuh API request failed after retries.")

    def get_agents(self) -> dict:
        return self._request("GET", "/agents")

    def get_agent(self, agent_id: str) -> dict:
        return self._request("GET", f"/agents/{agent_id}")

    def get_manager_info(self) -> dict:
        info = self._request("GET", "/manager/info")
        try:
            status = self._request("GET", "/manager/status")
        except Exception:
            status = {}
        if isinstance(info, dict) and isinstance(status, dict):
            info["manager_status"] = status
        return info

    def get_agents_summary(self) -> dict:
        return self._request("GET", "/agents/summary/status")

    def get_alerts(self, limit: int | None = None) -> dict:
        params = {}
        if limit:
            params["limit"] = limit
        candidates = [self.alerts_path, "/alerts", "/events", "/security/events"]
        methods = [self.alerts_method]
        if self.alerts_method != "POST":
            methods.append("POST")
        for method in methods:
            for candidate in candidates:
                try:
                    json_body = None
                    if method == "POST":
                        if candidate in ("/events", "/security/events"):
                            json_body = {"events": [{"limit": limit or 200}]}
                        else:
                            json_body = {}
                    payload = self._request(method, candidate, params=params, json_body=json_body)
                    if candidate != self.alerts_path or method != self.alerts_method:
                        self.alerts_path = candidate
                        self.alerts_method = method
                        logger.info("Wazuh alerts endpoint set to %s %s", method, candidate)
                    return payload
                except RuntimeError as exc:
                    if "404" in str(exc) or "405" in str(exc):
                        continue
                    raise
        raise RuntimeError("Wazuh API request failed: alerts endpoint not available.")

    def get_alert(self, alert_id: str) -> dict:
        return self._request("GET", f"/alerts/{alert_id}")

    def delete_agent(self, agent_id: str) -> dict:
        return self._request(
            "DELETE",
            f"/agents?pretty=true&older_than=0s&agents_list={agent_id}&status=all",
        )

    def block_ip(self, agent_id: str, ip: str) -> dict:
        payload = {
            "command": "firewall-drop",
            "arguments": [ip],
            "agent_id": agent_id,
        }
        return self._request("POST", "/active-response", json_body=payload)

    def get_vulnerabilities(self, limit: int | None = None) -> dict:
        params = {}
        if limit:
            params["limit"] = limit

        agent_id = None
        try:
            agents = self.get_agents().get("data", {}).get("affected_items", [])
            if agents:
                active = [a for a in agents if str(a.get("status", "")).lower() == "active"]
                agent_id = (active[0] if active else agents[0]).get("id")
        except Exception:
            agent_id = None

        candidates = []
        if agent_id:
            candidates.append(f"/vulnerability/{agent_id}")
            candidates.append(f"/vulnerability/{agent_id}/summary/cve")
        candidates.append("/vulnerability")

        last_error = None
        for path in candidates:
            try:
                return self._request("GET", path, params=params)
            except RuntimeError as exc:
                last_error = exc
                if "404" in str(exc) or "405" in str(exc):
                    continue
                raise

        if last_error:
            raise last_error
        raise RuntimeError("Wazuh API request failed: vulnerability endpoint not available.")

    def get_file_integrity(self, limit: int | None = None) -> dict:
        params = {}
        if limit:
            params["limit"] = limit

        # Wazuh 4.x expects syscheck to be scoped to an agent id.
        # Try to pick the most recent active agent if possible.
        agent_id = None
        try:
            agents = self.get_agents().get("data", {}).get("affected_items", [])
            if agents:
                # Prefer active agents.
                active = [a for a in agents if str(a.get("status", "")).lower() == "active"]
                agent_id = (active[0] if active else agents[0]).get("id")
        except Exception:
            agent_id = None

        candidates = []
        if agent_id:
            candidates.extend(
                [
                    f"/syscheck/{agent_id}",
                    f"/syscheck/{agent_id}/files",
                    f"/syscheck/{agent_id}/files/changed",
                ]
            )
        # Fallback to global endpoint if agent-scoped endpoints are unavailable.
        candidates.append("/syscheck")

        last_error = None
        for path in candidates:
            try:
                return self._request("GET", path, params=params)
            except RuntimeError as exc:
                last_error = exc
                if "404" in str(exc) or "405" in str(exc):
                    continue
                raise

        if last_error:
            raise last_error
        raise RuntimeError("Wazuh API request failed: syscheck endpoint not available.")
