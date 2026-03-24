import json
import logging
import socketserver
import threading
import os
from typing import Callable, Optional

from redis_queue.redis_client import get_client


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


def enqueue_alert(alert: dict) -> None:
    client = get_client()
    client.lpush("alerts_queue", json.dumps(alert))


class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        message = data.decode("utf-8", errors="ignore")
        logger.debug("UDP packet received: %s", message)
        if os.getenv("SYSLOG_DEBUG", "").lower() in {"1", "true", "yes"}:
            logger.info("UDP raw syslog: %s", message[:500])

        logger.debug("Attempting JSON extraction from syslog payload.")
        payload = _extract_json(message)
        if not payload:
            logger.warning("UDP syslog JSON extraction failed. Sample: %s", message[:300])
            logger.warning("Received invalid JSON syslog message.")
            return

        print("Alert received from Wazuh")
        if callable(self.server.on_alert):
            self.server.on_alert(payload)
        print("Alert pushed to Redis queue")
        logger.info("Alert received: payload keys=%s", list(payload.keys()))


class SyslogTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            data = self.request.recv(65535)
        except Exception:
            return
        if not data:
            return
        message = data.decode("utf-8", errors="ignore")
        logger.debug("TCP packet received: %s", message)
        if os.getenv("SYSLOG_DEBUG", "").lower() in {"1", "true", "yes"}:
            logger.info("TCP raw syslog: %s", message[:500])

        logger.debug("Attempting JSON extraction from syslog TCP payload.")
        payload = _extract_json(message)
        if not payload:
            logger.warning("TCP syslog JSON extraction failed. Sample: %s", message[:300])
            logger.warning("Received invalid JSON syslog message over TCP.")
            return

        print("Alert received from Wazuh (TCP)")
        if callable(self.server.on_alert):
            self.server.on_alert(payload)
        print("Alert pushed to Redis queue")
        logger.info("Alert received over TCP: payload keys=%s", list(payload.keys()))


class SyslogListener:
    def __init__(self, host: str = "0.0.0.0", port: int = 1514, on_alert: Optional[Callable[[dict], None]] = None):
        self.host = host
        self.port = port
        self._udp_server = socketserver.ThreadingUDPServer((self.host, self.port), SyslogUDPHandler)
        self._udp_server.on_alert = on_alert or enqueue_alert
        self._tcp_server = socketserver.ThreadingTCPServer((self.host, self.port), SyslogTCPHandler)
        self._tcp_server.on_alert = on_alert or enqueue_alert
        self._udp_thread: Optional[threading.Thread] = None
        self._tcp_thread: Optional[threading.Thread] = None

    def start(self):
        if self._udp_thread and self._udp_thread.is_alive():
            return
        self._udp_thread = threading.Thread(target=self._udp_server.serve_forever, daemon=True)
        self._tcp_thread = threading.Thread(target=self._tcp_server.serve_forever, daemon=True)
        self._udp_thread.start()
        self._tcp_thread.start()
        logger.info("Syslog listener running on UDP/TCP port %s", self.port)

    def stop(self):
        self._udp_server.shutdown()
        self._udp_server.server_close()
        self._tcp_server.shutdown()
        self._tcp_server.server_close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    listener = SyslogListener()
    listener.start()
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        listener.stop()
