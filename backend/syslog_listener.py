import json
import logging
import socketserver
import threading
from typing import Callable, Optional


logger = logging.getLogger("freshstart.syslog")


def _extract_json(payload: str) -> Optional[dict]:
    # Wazuh syslog includes JSON; extract the JSON object from the syslog envelope.
    start = payload.find("{")
    end = payload.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None

    try:
        return json.loads(payload[start : end + 1])
    except json.JSONDecodeError:
        return None


def _normalize_alert(raw: dict) -> dict:
    # Normalize the syslog JSON into the dashboard schema.
    agent = raw.get("agent", {})
    rule = raw.get("rule", {})
    data = raw.get("data", {}) if isinstance(raw.get("data"), dict) else {}
    source_ip = data.get("srcip") or raw.get("srcip")

    return {
        "timestamp": raw.get("timestamp") or raw.get("@timestamp") or "Unknown",
        "rule_id": rule.get("id") or "Unknown",
        "rule_description": rule.get("description") or raw.get("full_log") or "No description",
        "rule_level": int(rule.get("level", 0) or 0),
        "agent_name": agent.get("name") or "Unknown agent",
        "agent_ip": agent.get("ip") or "N/A",
        "source_ip": source_ip,
        "src_ip": source_ip,
        "protocol": data.get("proto") or data.get("protocol") or raw.get("protocol") or "N/A",
    }


class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        message = data.decode("utf-8", errors="ignore")
        logger.debug("UDP packet received: %s", message)

        logger.debug("Attempting JSON extraction from syslog payload.")
        payload = _extract_json(message)
        if not payload:
            logger.warning("Received invalid JSON syslog message.")
            return

        alert = _normalize_alert(payload)
        if callable(self.server.on_alert):
            self.server.on_alert(alert)
        logger.info("Alert received: rule=%s agent=%s", alert.get("rule_id"), alert.get("agent_name"))


class SyslogListener:
    def __init__(self, host: str = "0.0.0.0", port: int = 1514, on_alert: Optional[Callable[[dict], None]] = None):
        self.host = host
        self.port = port
        self._server = socketserver.ThreadingUDPServer((self.host, self.port), SyslogUDPHandler)
        self._server.on_alert = on_alert
        self._thread: Optional[threading.Thread] = None

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        logger.info("Syslog listener running on UDP port %s", self.port)

    def stop(self):
        self._server.shutdown()
        self._server.server_close()
