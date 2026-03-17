import json
import logging
import os
import queue
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_from_directory, stream_with_context
import yaml

from alert_store import (
    add_alert,
    get_alerts_over_time,
    get_assets,
    get_metrics,
    get_risky_hosts,
    get_rule_statistics,
    get_top_attackers,
    query_alerts,
    subscribe,
    unsubscribe,
)
from syslog_listener import SyslogListener
from wazuh_client import WazuhClient


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

app = Flask(__name__, static_folder="../frontend", static_url_path="")
listener = SyslogListener(on_alert=add_alert)
wazuh_client = WazuhClient()
_settings_path = Path(__file__).with_name("config.yaml")


def _default_settings() -> dict:
    return {
        "wazuh_manager_ip": "192.168.33.101",
        "syslog_port": 1514,
        "database_type": "memory",
        "response_mode": "Detect Only",
    }


def _load_settings() -> dict:
    if not _settings_path.exists():
        settings = _default_settings()
        _save_settings(settings)
        return settings
    with _settings_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    settings = _default_settings()
    for key in settings:
        if key in data:
            settings[key] = data[key]
    return settings


def _save_settings(settings: dict) -> None:
    with _settings_path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(settings, handle, sort_keys=False)


def _should_start_listener():
    if not app.debug:
        return True
    return os.environ.get("WERKZEUG_RUN_MAIN") == "true"


if _should_start_listener():
    listener.start()


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.get("/alerts")
def alerts():
    limit = int(request.args.get("limit", 20))
    offset = int(request.args.get("offset", 0))
    timerange = request.args.get("timerange")
    severity = request.args.get("severity")
    results = query_alerts(
        limit=limit,
        offset=offset,
        since_seconds=_parse_timerange(timerange),
        severity=severity,
    )
    return jsonify({"total": results["total"], "alerts": results["alerts"]})


@app.get("/metrics")
def metrics():
    return jsonify({"status": "ok", "metrics": get_metrics()})


@app.get("/top_attackers")
def top_attackers():
    return jsonify({"status": "ok", "attackers": get_top_attackers()})


@app.get("/alerts_over_time")
def alerts_over_time():
    return jsonify({"status": "ok", "timeline": get_alerts_over_time()})


@app.get("/rule_statistics")
def rule_statistics():
    return jsonify({"status": "ok", "rules": get_rule_statistics()})


@app.get("/risky_hosts")
def risky_hosts():
    return jsonify({"status": "ok", "hosts": get_risky_hosts()})


@app.get("/api/assets")
def assets():
    try:
        assets = get_assets()
        return jsonify(assets)
    except Exception as exc:
        logging.exception("Failed to load assets from SQLite")
        return jsonify({"error": str(exc), "assets": []}), 503


@app.post("/api/response/block-ip")
def block_ip():
    payload = request.get_json(silent=True) or {}
    ip = payload.get("ip")
    if not ip:
        return jsonify({"status": "error", "message": "IP address is required."}), 400
    try:
        wazuh_client.block_ip(ip)
        return jsonify({"status": "success", "message": "IP blocked successfully"})
    except Exception as exc:
        logging.exception("Failed to trigger active response for IP")
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.get("/api/settings")
def get_settings():
    try:
        return jsonify({"settings": _load_settings()})
    except Exception as exc:
        logging.exception("Failed to load settings")
        return jsonify({"error": str(exc), "settings": {}}), 500


@app.post("/api/settings")
def update_settings():
    payload = request.get_json(silent=True) or {}
    allowed = set(_default_settings().keys())
    try:
        current = _load_settings()
        for key in allowed:
            if key in payload:
                current[key] = payload[key]
        _save_settings(current)
        return jsonify({"settings": current})
    except Exception as exc:
        logging.exception("Failed to save settings")
        return jsonify({"error": str(exc), "settings": {}}), 500


@app.get("/stream")
def stream():
    client_queue = subscribe()

    def event_stream():
        try:
            while True:
                try:
                    alert = client_queue.get(timeout=15)
                    payload = {
                        "type": "alert",
                        "alert": alert,
                        "metrics": get_metrics(),
                        "timeline": get_alerts_over_time(),
                        "attackers": get_top_attackers(),
                        "rules": get_rule_statistics(),
                        "hosts": get_risky_hosts(),
                    }
                    yield f"data: {json.dumps(payload)}\n\n"
                except queue.Empty:
                    yield ": ping\n\n"
        finally:
            unsubscribe(client_queue)

    return Response(stream_with_context(event_stream()), mimetype="text/event-stream")


@app.get("/<path:path>")
def static_files(path: str):
    return send_from_directory(app.static_folder, path)


def _parse_timerange(timerange: str | None):
    if not timerange:
        return None
    unit = timerange[-1]
    value = int(timerange[:-1]) if timerange[:-1].isdigit() else 0
    if unit == "m":
        return value * 60
    if unit == "h":
        return value * 3600
    if unit == "d":
        return value * 86400
    return None


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=os.getenv("FLASK_DEBUG", "false").lower() == "true")
