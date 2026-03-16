import json
import logging
import os
import queue

from flask import Flask, Response, jsonify, send_from_directory, stream_with_context

from alert_store import get_recent_alerts, get_stats, subscribe, unsubscribe
from syslog_listener import SyslogListener


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

app = Flask(__name__, static_folder="../frontend", static_url_path="")
listener = SyslogListener()


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
    limit = int(os.environ.get("ALERT_LIMIT", "50"))
    return jsonify({"status": "ok", "alerts": get_recent_alerts(limit=limit)})


@app.get("/stats")
def stats():
    return jsonify({"status": "ok", "stats": get_stats()})


@app.get("/stream")
def stream():
    client_queue = subscribe()

    def event_stream():
        try:
            while True:
                try:
                    alert = client_queue.get(timeout=15)
                    payload = {"type": "alert", "alert": alert, "stats": get_stats()}
                    yield f"data: {json.dumps(payload)}\n\n"
                except queue.Empty:
                    yield ": ping\n\n"
        finally:
            unsubscribe(client_queue)

    return Response(stream_with_context(event_stream()), mimetype="text/event-stream")


@app.get("/<path:path>")
def static_files(path: str):
    return send_from_directory(app.static_folder, path)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=os.getenv("FLASK_DEBUG", "false").lower() == "true")
