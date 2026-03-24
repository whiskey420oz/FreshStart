import json
import logging
import os
import queue
import time
import threading
import uuid
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_from_directory, stream_with_context
import yaml

from alert_store import (
    get_alerts_over_time,
    get_alert,
    get_alert_counts,
    get_distinct_agents,
    get_latest_event_timestamp,
    get_assets,
    get_metrics,
    get_risky_hosts,
    get_risk_scores,
    get_mitre_stats,
    get_attack_map_agg,
    get_incident_timeline,
    get_threat_profile,
    get_soc_metrics,
    get_rule_statistics,
    get_top_attackers,
    get_attacker_profiles,
    query_alerts,
    get_ids_for_event_ids,
    get_status_for_event_ids,
    get_audit_logs,
    get_responses,
    add_response,
    update_alert_status,
    create_investigation,
    find_investigation_by_alert,
    find_investigation_by_incident,
    update_investigation_status,
    get_investigations,
    get_investigation,
    add_investigation_event,
    add_audit_log,
    subscribe,
    unsubscribe,
    insert_event,
    get_incidents,
    get_incident,
    update_incident_status,
    assign_incident,
    add_incident_note,
    get_incident_kpis,
    create_incident_from_alert,
    get_managed_assets,
    add_managed_asset,
    update_managed_asset,
    delete_managed_asset,
    create_user,
    list_users,
    authenticate_user,
    create_session,
    get_session,
    delete_session,
    ensure_default_admin,
    update_user_role,
    set_user_active,
)
from integrations.wazuh_client import WazuhApiClient
from redis_queue.redis_client import get_client
from wazuh_client import WazuhClient
from workers.alert_worker import normalize_alert
import opensearch_client as os_client


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

wazuh_client = WazuhClient()
wazuh_api = WazuhApiClient()
app = Flask(__name__, static_folder="../frontend", static_url_path="")
_settings_path = Path(__file__).with_name("config.yaml")
_active_analysts = {}
_active_window_seconds = 300
_backfill_thread = None
_backfill_interval_seconds = 60
_opensearch_thread = None
_opensearch_interval_seconds = 60
def _is_auth_required() -> bool:
    return os.getenv("REQUIRE_AUTH", "false").lower() in {"1", "true", "yes"}


def _auth_bypass_enabled() -> bool:
    return os.getenv("AUTH_BYPASS", "false").lower() in {"1", "true", "yes"}
_opensearch_disabled_until = 0.0


def _get_token_from_request() -> str | None:
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    token = request.args.get("token")
    if token:
        return token
    cookie_token = request.cookies.get("fs_token")
    if cookie_token:
        return cookie_token
    return request.headers.get("X-Auth-Token")


def _current_user() -> dict | None:
    if _auth_bypass_enabled():
        return {"username": "admin", "role": "admin"}
    token = _get_token_from_request()
    if not token:
        return None
    return get_session(token)


def _require_auth(min_role: str | None = None):
    def decorator(func):
        def wrapper(*args, **kwargs):
            if not _is_auth_required() or _auth_bypass_enabled():
                return func(*args, **kwargs)
            user = _current_user()
            if not user:
                return jsonify({"error": "unauthorized"}), 401
            if min_role:
                role = (user.get("role") or "").lower()
                if min_role == "admin" and role != "admin":
                    return jsonify({"error": "forbidden"}), 403
            return func(*args, **kwargs)

        wrapper.__name__ = func.__name__
        return wrapper

    return decorator


def _run_wazuh_backfill():
    while True:
        try:
            payload = wazuh_api.get_alerts(limit=200)
            items = payload.get("data", {}).get("affected_items", []) if isinstance(payload, dict) else []
            inserted = 0
            for raw in items:
                event = normalize_alert(raw)
                if not event.get("event_id"):
                    event["event_id"] = str(uuid.uuid4())
                if insert_event(event):
                    inserted += 1
            if inserted:
                logging.info("Backfill inserted %s new alerts from Wazuh API", inserted)
        except Exception as exc:
            logging.warning("Wazuh backfill failed: %s", exc)
        time.sleep(_backfill_interval_seconds)


def _opensearch_config() -> dict | None:
    settings = _load_settings()
    if os.getenv("OPENSEARCH_ENABLED", "true").lower() in {"0", "false", "no"}:
        return None
    url = os.getenv("OPENSEARCH_URL") or settings.get("opensearch_url")
    if not url:
        return None
    return {
        "url": url.rstrip("/"),
        "user": os.getenv("OPENSEARCH_USER") or settings.get("opensearch_user"),
        "password": os.getenv("OPENSEARCH_PASSWORD") or settings.get("opensearch_password"),
        "index": os.getenv("OPENSEARCH_INDEX") or settings.get("opensearch_index") or "wazuh-alerts-*",
    }


def _query_opensearch(index: str, query: dict, auth, verify: bool):
    import requests

    url = f"{index}/_search"
    session = requests.Session()
    # Avoid system proxy settings interfering with direct VM connections.
    session.trust_env = False
    return session.post(
        url,
        json=query,
        auth=auth,
        verify=verify,
        proxies={"http": None, "https": None},
        timeout=(5, 20),
    )


def _run_opensearch_backfill():
    while True:
        global _opensearch_disabled_until
        if time.time() < _opensearch_disabled_until:
            time.sleep(_opensearch_interval_seconds)
            continue
        config = _opensearch_config()
        if not config:
            time.sleep(_opensearch_interval_seconds)
            continue
        base = config["url"]
        index_url = f"{base}/{config['index']}"
        auth = (config["user"], config["password"]) if config.get("user") else None
        verify = not base.startswith("https://")
        latest_ts = get_latest_event_timestamp()
        range_field = "@timestamp"
        query = {
            "size": 200,
            "sort": [{range_field: {"order": "asc"}}],
            "query": {"range": {range_field: {"gt": latest_ts or "now-1d"}}},
        }
        try:
            response = _query_opensearch(index_url, query, auth, verify)
            if response.status_code == 400:
                range_field = "timestamp"
                query["sort"] = [{range_field: {"order": "asc"}}]
                query["query"] = {"range": {range_field: {"gt": latest_ts or "now-1d"}}}
                response = _query_opensearch(index_url, query, auth, verify)
            if response.status_code == 401:
                logging.warning("OpenSearch backfill auth failed (401). Disabling backfill for 10 minutes.")
                _opensearch_disabled_until = time.time() + 600
                time.sleep(_opensearch_interval_seconds)
                continue
            response.raise_for_status()
            payload = response.json()
            hits = payload.get("hits", {}).get("hits", [])
            logging.info(
                "OpenSearch backfill fetched %s hits (index=%s, range_field=%s, latest_ts=%s)",
                len(hits),
                config.get("index"),
                range_field,
                latest_ts,
            )
            inserted = 0
            for hit in hits:
                source = hit.get("_source", {})
                event = normalize_alert(source)
                event_id = hit.get("_id") or event.get("event_id") or str(uuid.uuid4())
                event["event_id"] = event_id
                if insert_event(event):
                    inserted += 1
            if inserted:
                logging.info("OpenSearch backfill inserted %s alerts", inserted)
        except Exception as exc:
            logging.warning("OpenSearch backfill failed: %s", exc)
        time.sleep(_opensearch_interval_seconds)


def _start_backfill():
    global _backfill_thread
    if _backfill_thread and _backfill_thread.is_alive():
        return
    if os.getenv("ENABLE_WAZUH_BACKFILL", "true").lower() not in {"1", "true", "yes"}:
        logging.info("Wazuh backfill disabled by env.")
    else:
        _backfill_thread = threading.Thread(target=_run_wazuh_backfill, daemon=True)
        _backfill_thread.start()
        logging.info("Wazuh backfill thread started (interval=%ss).", _backfill_interval_seconds)

    global _opensearch_thread
    if not (_opensearch_thread and _opensearch_thread.is_alive()):
        _opensearch_thread = threading.Thread(target=_run_opensearch_backfill, daemon=True)
        _opensearch_thread.start()
        logging.info("OpenSearch backfill thread started (interval=%ss).", _opensearch_interval_seconds)


@app.before_request
def log_request():
    if request.path.startswith(
        (
            "/alerts",
            "/metrics",
            "/investigations",
            "/wazuh",
            "/api",
            "/soc",
            "/responses",
            "/system",
        )
    ):
        logging.info("API request %s %s", request.method, request.path)


@app.before_request
def enforce_auth():
    if not _is_auth_required() or _auth_bypass_enabled():
        return None
    if request.path.startswith("/auth"):
        return None
    # Allow static assets and login page without auth.
    if request.path == "/" or request.path.startswith("/login"):
        return None
    if request.path.endswith((".html", ".js", ".css", ".png", ".jpg", ".svg", ".ico", ".map")):
        return None
    if request.path == "/alerts/stream":
        return None
    protected_prefixes = (
        "/alerts",
        "/metrics",
        "/investigations",
        "/responses",
        "/system",
        "/wazuh",
        "/api",
        "/soc",
        "/stream",
    )
    if request.path.startswith(protected_prefixes):
        user = _current_user()
        if not user:
            return jsonify({"error": "unauthorized"}), 401
    return None


def _default_settings() -> dict:
    return {
        "wazuh_manager_ip": "192.168.33.207",
        "wazuh_api_url": "",
        "wazuh_alerts_path": "/alerts",
        "syslog_port": 1514,
        "database_type": "memory",
        "response_mode": "Detect Only",
        "redis_host": "127.0.0.1",
        "redis_port": 6379,
        "opensearch_url": "",
        "opensearch_user": "",
        "opensearch_password": "",
        "opensearch_index": "wazuh-alerts-*",
        "opensearch_events_index": "freshstart-events",
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




@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.get("/alerts")
def alerts():
    limit = int(request.args.get("limit", 20))
    offset = int(request.args.get("offset", 0))
    timerange = request.args.get("timerange")
    severity = request.args.get("severity")
    storage = os.getenv("PRIMARY_STORAGE", "sqlite").lower()
    if storage == "opensearch":
        try:
            results = os_client.search_events(limit=limit, offset=offset, timerange=timerange, severity=severity)
            event_ids = [alert.get("event_id") for alert in results.get("alerts", []) if alert.get("event_id")]
            status_map = get_status_for_event_ids(event_ids)
            for alert in results.get("alerts", []):
                event_id = alert.get("event_id")
                status = status_map.get(event_id, {})
                alert["id"] = status.get("id")
                if status.get("alert_status"):
                    alert["alert_status"] = status.get("alert_status")
                if status.get("resolved_at"):
                    alert["resolved_at"] = status.get("resolved_at")
                if "src_ip" not in alert:
                    alert["src_ip"] = alert.get("source_ip")
                if "rule_level" not in alert:
                    alert["rule_level"] = alert.get("severity")
                if not alert.get("timestamp") and alert.get("event_time"):
                    alert["timestamp"] = alert.get("event_time")
        except Exception as exc:
            logging.warning("OpenSearch alerts query failed, falling back to SQLite: %s", exc)
            results = query_alerts(
                limit=limit,
                offset=offset,
                since_seconds=_parse_timerange(timerange),
                severity=severity,
            )
    else:
        results = query_alerts(
            limit=limit,
            offset=offset,
            since_seconds=_parse_timerange(timerange),
            severity=severity,
        )
    return jsonify({"total": results["total"], "alerts": results["alerts"]})


@app.get("/alerts/<int:alert_id>")
def alert_detail(alert_id: int):
    storage = os.getenv("PRIMARY_STORAGE", "sqlite").lower()
    if storage == "opensearch":
        alert = get_alert(alert_id)
        if not alert:
            return jsonify({"error": "Alert not found"}), 404
        add_audit_log("analyst", "view_alert", f"alert:{alert_id}")
        return jsonify(alert)
    alert = get_alert(alert_id)
    if not alert:
        return jsonify({"error": "Alert not found"}), 404
    add_audit_log("analyst", "view_alert", f"alert:{alert_id}")
    return jsonify(alert)


def _update_alert_with_action(alert_id: int, status: str, action: str):
    update_alert_status(alert_id, status)
    investigation_id = find_investigation_by_alert(alert_id)
    if status == "INVESTIGATING":
        if not investigation_id:
            investigation_id = create_investigation(
                alert_id, analyst_name="SOC Analyst", notes=None, title=f"Alert {alert_id}"
            )
        else:
            update_investigation_status(investigation_id, "INVESTIGATING")
        add_investigation_event(investigation_id, "status_change", "Alert marked investigating.")
    elif investigation_id:
        update_investigation_status(investigation_id, status)
        add_investigation_event(investigation_id, "status_change", f"Alert marked {status}.")
    add_audit_log("analyst", action, f"alert:{alert_id}")


@app.post("/alerts/<int:alert_id>/investigate")
def alert_investigate(alert_id: int):
    try:
        _update_alert_with_action(alert_id, "INVESTIGATING", "investigate_alert")
        return jsonify({"status": "ok", "alert_id": alert_id, "alert_status": "INVESTIGATING"})
    except Exception as exc:
        logging.exception("Failed to update alert status")
        return jsonify({"error": str(exc)}), 503


@app.post("/alerts/<int:alert_id>/in-progress")
def alert_in_progress(alert_id: int):
    try:
        _update_alert_with_action(alert_id, "IN_PROGRESS", "in_progress_alert")
        return jsonify({"status": "ok", "alert_id": alert_id, "alert_status": "IN_PROGRESS"})
    except Exception as exc:
        logging.exception("Failed to update alert status")
        return jsonify({"error": str(exc)}), 503


@app.post("/alerts/<int:alert_id>/new")
def alert_new(alert_id: int):
    try:
        _update_alert_with_action(alert_id, "NEW", "reset_alert")
        return jsonify({"status": "ok", "alert_id": alert_id, "alert_status": "NEW"})
    except Exception as exc:
        logging.exception("Failed to update alert status")
        return jsonify({"error": str(exc)}), 503


@app.post("/alerts/<int:alert_id>/resolve")
def alert_resolve(alert_id: int):
    try:
        _update_alert_with_action(alert_id, "RESOLVED", "resolve_alert")
        return jsonify({"status": "ok", "alert_id": alert_id, "alert_status": "RESOLVED"})
    except Exception as exc:
        logging.exception("Failed to resolve alert")
        return jsonify({"error": str(exc)}), 503


@app.post("/alerts/<int:alert_id>/false-positive")
def alert_false_positive(alert_id: int):
    try:
        _update_alert_with_action(alert_id, "FALSE_POSITIVE", "false_positive_alert")
        return jsonify({"status": "ok", "alert_id": alert_id, "alert_status": "FALSE_POSITIVE"})
    except Exception as exc:
        logging.exception("Failed to mark false positive")
        return jsonify({"error": str(exc)}), 503


@app.get("/investigations")
def investigations():
    try:
        return jsonify({"investigations": get_investigations()})
    except Exception as exc:
        logging.exception("Failed to load investigations")
        return jsonify({"error": str(exc)}), 503


@app.get("/investigations/<int:investigation_id>")
def investigation_detail(investigation_id: int):
    try:
        investigation = get_investigation(investigation_id)
        if not investigation:
            return jsonify({"error": "Investigation not found"}), 404
        return jsonify(investigation)
    except Exception as exc:
        logging.exception("Failed to load investigation")
        return jsonify({"error": str(exc)}), 503


@app.post("/investigations")
def investigation_create():
    payload = request.get_json(silent=True) or {}
    alert_id = payload.get("alert_id")
    incident_id = payload.get("incident_id")
    analyst_name = payload.get("analyst_name")
    notes = payload.get("notes")
    title = payload.get("title")
    try:
        investigation_id = create_investigation(alert_id, analyst_name, notes, title=title, incident_id=incident_id)
        if alert_id:
            update_alert_status(int(alert_id), "INVESTIGATING")
        add_audit_log(analyst_name or "analyst", "create_investigation", f"investigation:{investigation_id}")
        return jsonify({"id": investigation_id, "status": "INVESTIGATING"})
    except Exception as exc:
        logging.exception("Failed to create investigation")
        return jsonify({"error": str(exc)}), 503


@app.get("/metrics/soc")
def soc_metrics():
    try:
        metrics = get_soc_metrics()
        now = time.time()
        active = {
            key: last_seen
            for key, last_seen in _active_analysts.items()
            if now - last_seen < _active_window_seconds
        }
        _active_analysts.clear()
        _active_analysts.update(active)
        metrics["active_analysts"] = len(active)
        return jsonify({"metrics": metrics})
    except Exception as exc:
        logging.exception("Failed to load SOC metrics")
        return jsonify({"error": str(exc)}), 503


@app.post("/soc/ping")
def soc_ping():
    user = _current_user()
    analyst = (user.get("username") if user else None) or request.headers.get("X-Analyst") or request.remote_addr or "unknown"
    _active_analysts[analyst] = time.time()
    return jsonify({"status": "ok"})


@app.get("/soc/activity")
def soc_activity():
    try:
        return jsonify({"activity": get_audit_logs(limit=12)})
    except Exception as exc:
        logging.exception("Failed to load SOC activity")
        return jsonify({"error": str(exc)}), 503


def _has_users() -> bool:
    try:
        return len(list_users()) > 0
    except Exception:
        return False


@app.post("/auth/login")
def auth_login():
    payload = request.get_json(silent=True) or {}
    username = payload.get("username")
    password = payload.get("password")
    try:
        user = authenticate_user(username, password)
        if not user:
            return jsonify({"error": "invalid_credentials"}), 401
        token = str(uuid.uuid4())
        ttl = int(os.getenv("SESSION_TTL_SECONDS", "3600"))
        create_session(user["id"], token, ttl_seconds=ttl)
        response = jsonify({"token": token, "user": {"username": user["username"], "role": user["role"]}})
        response.set_cookie(
            "fs_token",
            token,
            max_age=ttl,
            samesite="Lax",
        )
        return response
    except Exception as exc:
        logging.exception("Login failed")
        return jsonify({"error": str(exc)}), 503


@app.get("/auth/me")
def auth_me():
    if not _is_auth_required():
        return jsonify({"authenticated": True, "auth_required": False, "user": {"username": "local", "role": "admin"}})
    user = _current_user()
    if not user:
        return jsonify({"authenticated": False, "auth_required": True}), 200
    return jsonify(
        {
            "authenticated": True,
            "auth_required": True,
            "user": {"username": user.get("username"), "role": user.get("role")},
        }
    )


@app.post("/auth/logout")
def auth_logout():
    token = _get_token_from_request()
    if token:
        delete_session(token)
    response = jsonify({"status": "ok"})
    response.delete_cookie("fs_token")
    return response


@app.get("/auth/users")
@_require_auth(min_role="admin")
def auth_users():
    return jsonify({"users": list_users()})


@app.post("/auth/users")
def auth_users_create():
    payload = request.get_json(silent=True) or {}
    username = payload.get("username")
    password = payload.get("password")
    role = payload.get("role") or "analyst"
    if _is_auth_required() and not _auth_bypass_enabled():
        user = _current_user()
        if not user or user.get("role") != "admin":
            return jsonify({"error": "forbidden"}), 403
    else:
        if not _has_users():
            role = "admin"
    try:
        user_id = create_user(username, password, role=role)
        return jsonify({"status": "ok", "id": user_id, "role": role})
    except Exception as exc:
        logging.exception("Failed to create user")
        return jsonify({"error": str(exc)}), 503


@app.post("/auth/users/<int:user_id>/role")
@_require_auth(min_role="admin")
def auth_users_role(user_id: int):
    payload = request.get_json(silent=True) or {}
    role = payload.get("role")
    if not role:
        return jsonify({"error": "role is required"}), 400
    try:
        update_user_role(user_id, role)
        return jsonify({"status": "ok"})
    except Exception as exc:
        logging.exception("Failed to update role")
        return jsonify({"error": str(exc)}), 503


@app.post("/auth/users/<int:user_id>/active")
@_require_auth(min_role="admin")
def auth_users_active(user_id: int):
    payload = request.get_json(silent=True) or {}
    active = payload.get("active")
    if active is None:
        return jsonify({"error": "active is required"}), 400
    try:
        set_user_active(user_id, bool(active))
        return jsonify({"status": "ok"})
    except Exception as exc:
        logging.exception("Failed to update user active")
        return jsonify({"error": str(exc)}), 503


@app.post("/investigations/<int:investigation_id>")
def investigation_update(investigation_id: int):
    payload = request.get_json(silent=True) or {}
    status = payload.get("status")
    try:
        if status:
            update_investigation_status(investigation_id, status)
            add_audit_log("analyst", "update_investigation", f"investigation:{investigation_id}")
        return jsonify({"status": "ok"})
    except Exception as exc:
        logging.exception("Failed to update investigation")
        return jsonify({"error": str(exc)}), 503


@app.post("/investigations/<int:investigation_id>/notes")
def investigation_notes(investigation_id: int):
    payload = request.get_json(silent=True) or {}
    note = payload.get("note")
    if not note:
        return jsonify({"error": "note is required"}), 400
    try:
        add_investigation_event(investigation_id, "analyst_note", note)
        add_audit_log("analyst", "add_note", f"investigation:{investigation_id}")
        return jsonify({"status": "ok"})
    except Exception as exc:
        logging.exception("Failed to add investigation note")
        return jsonify({"error": str(exc)}), 503


@app.get("/system/debug")
def system_debug():
    wazuh_status = "unknown"
    try:
        wazuh_api.get_manager_info()
        wazuh_status = "connected"
    except Exception:
        wazuh_status = "unreachable"

    redis_status = "unknown"
    queue_length = 0
    try:
        redis_client = get_client()
        redis_client.ping()
        redis_status = "connected"
        queue_length = int(redis_client.llen("alerts_queue") or 0)
    except Exception:
        redis_status = "unreachable"

    db_status = "unknown"
    try:
        counts = get_alert_counts()
        db_status = "ok"
    except Exception:
        counts = {"total_alerts": 0}
        db_status = "error"

    opensearch_status = "disabled"
    if _opensearch_config():
        opensearch_status = "auth_error" if time.time() < _opensearch_disabled_until else "enabled"

    return jsonify(
        {
            "auth_required": _is_auth_required(),
            "auth_bypass": _auth_bypass_enabled(),
            "wazuh_api": wazuh_status,
            "redis": redis_status,
            "database": db_status,
            "opensearch": opensearch_status,
            "alerts_stored": counts.get("total_alerts", 0),
            "agents_detected": get_distinct_agents(),
            "queue_length": queue_length,
        }
    )


@app.get("/metrics")
def metrics():
    storage = os.getenv("PRIMARY_STORAGE", "sqlite").lower()
    if storage == "opensearch":
        try:
            severity_counts = os_client.count_by_severity()
            total = os_client.count_total()
            agents = os_client.count_distinct("agent_name")
            suspicious_ips = 0
            try:
                ips = os_client.distinct_source_ips()
                suspicious_ips = len([ip for ip in ips if _is_public_ip(ip)])
            except Exception:
                suspicious_ips = 0
            metrics = {
                "total_alerts": total,
                "critical_alerts": severity_counts.get("critical", 0),
                "high_alerts": severity_counts.get("high", 0),
                "active_agents": agents,
                "suspicious_ips": suspicious_ips,
                "events_processed": total,
            }
            if total == 0:
                fallback = get_metrics()
                if fallback.get("total_alerts", 0) > 0:
                    logging.warning("OpenSearch metrics empty, falling back to SQLite metrics.")
                    return jsonify({"status": "ok", "metrics": fallback})
            return jsonify({"status": "ok", "metrics": metrics})
        except Exception as exc:
            logging.warning("OpenSearch metrics failed, falling back to SQLite: %s", exc)
    return jsonify({"status": "ok", "metrics": get_metrics()})


@app.get("/top_attackers")
def top_attackers():
    storage = os.getenv("PRIMARY_STORAGE", "sqlite").lower()
    if storage == "opensearch":
        try:
            return jsonify({"status": "ok", "attackers": os_client.get_top_attackers()})
        except Exception as exc:
            logging.warning("OpenSearch top attackers failed, falling back to SQLite: %s", exc)
    return jsonify({"status": "ok", "attackers": get_top_attackers()})


@app.get("/api/attackers")
def attacker_profiles():
    try:
        storage = os.getenv("PRIMARY_STORAGE", "sqlite").lower()
        if storage == "opensearch":
            try:
                return jsonify({"attackers": os_client.get_attacker_profiles()})
            except Exception as exc:
                logging.warning("OpenSearch attacker profiles failed, falling back to SQLite: %s", exc)
        return jsonify({"attackers": get_attacker_profiles()})
    except Exception as exc:
        logging.exception("Failed to load attacker profiles")
        return jsonify({"error": str(exc)}), 503


@app.get("/alerts_over_time")
def alerts_over_time():
    storage = os.getenv("PRIMARY_STORAGE", "sqlite").lower()
    if storage == "opensearch":
        try:
            return jsonify({"status": "ok", "timeline": os_client.get_alerts_over_time()})
        except Exception as exc:
            logging.warning("OpenSearch timeline failed, falling back to SQLite: %s", exc)
    return jsonify({"status": "ok", "timeline": get_alerts_over_time()})


@app.get("/rule_statistics")
def rule_statistics():
    storage = os.getenv("PRIMARY_STORAGE", "sqlite").lower()
    if storage == "opensearch":
        try:
            return jsonify({"status": "ok", "rules": os_client.get_rule_statistics()})
        except Exception as exc:
            logging.warning("OpenSearch rule stats failed, falling back to SQLite: %s", exc)
    return jsonify({"status": "ok", "rules": get_rule_statistics()})


@app.get("/risky_hosts")
def risky_hosts():
    storage = os.getenv("PRIMARY_STORAGE", "sqlite").lower()
    if storage == "opensearch":
        try:
            return jsonify({"status": "ok", "hosts": os_client.get_risky_hosts()})
        except Exception as exc:
            logging.warning("OpenSearch risky hosts failed, falling back to SQLite: %s", exc)
    return jsonify({"status": "ok", "hosts": get_risky_hosts()})


@app.get("/api/risk-scores")
def risk_scores():
    try:
        storage = os.getenv("PRIMARY_STORAGE", "sqlite").lower()
        if storage == "opensearch":
            try:
                return jsonify({"risk_scores": os_client.get_risk_scores()})
            except Exception as exc:
                logging.warning("OpenSearch risk scores failed, falling back to SQLite: %s", exc)
        return jsonify({"risk_scores": get_risk_scores()})
    except Exception as exc:
        logging.exception("Failed to load risk scores")
        return jsonify({"error": str(exc)}), 503


@app.get("/api/mitre-stats")
def mitre_stats():
    try:
        storage = os.getenv("PRIMARY_STORAGE", "sqlite").lower()
        if storage == "opensearch":
            try:
                return jsonify({"techniques": os_client.get_mitre_stats()})
            except Exception as exc:
                logging.warning("OpenSearch MITRE stats failed, falling back to SQLite: %s", exc)
        return jsonify({"techniques": get_mitre_stats()})
    except Exception as exc:
        logging.exception("Failed to load MITRE stats")
        return jsonify({"error": str(exc)}), 503


@app.get("/api/attack-map")
def attack_map():
    try:
        storage = os.getenv("PRIMARY_STORAGE", "sqlite").lower()
        if storage == "opensearch":
            try:
                return jsonify({"points": os_client.get_attack_map_agg()})
            except Exception as exc:
                logging.warning("OpenSearch attack map failed, falling back to SQLite: %s", exc)
        return jsonify({"points": get_attack_map_agg()})
    except Exception as exc:
        logging.exception("Failed to load attack map data")
        return jsonify({"error": str(exc)}), 503


@app.get("/api/incidents/timeline")
def incident_timeline():
    try:
        return jsonify({"timeline": get_incident_timeline()})
    except Exception as exc:
        logging.exception("Failed to load incident timeline")
        return jsonify({"error": str(exc)}), 503


@app.get("/api/threat-intel")
def threat_intel():
    ip = request.args.get("ip")
    if not ip:
        return jsonify({"error": "ip is required"}), 400
    try:
        storage = os.getenv("PRIMARY_STORAGE", "sqlite").lower()
        if storage == "opensearch":
            try:
                profile = os_client.get_threat_profile(ip)
            except Exception as exc:
                logging.warning("OpenSearch threat intel failed, falling back to SQLite: %s", exc)
                profile = get_threat_profile(ip)
        else:
            profile = get_threat_profile(ip)
        if not profile.get("alert_count"):
            profile["note"] = "No local alerts found for this IP yet."
        return jsonify(profile)
    except Exception as exc:
        logging.exception("Failed to load threat intel")
        return jsonify({"error": str(exc)}), 503


@app.get("/api/incidents")
def incidents_api():
    try:
        return jsonify({"incidents": get_incidents()})
    except Exception as exc:
        logging.exception("Failed to load incidents")
        return jsonify({"error": str(exc)}), 503


@app.get("/api/incidents/kpis")
def incidents_kpis():
    try:
        return jsonify({"kpis": get_incident_kpis()})
    except Exception as exc:
        logging.exception("Failed to load incident KPIs")
        return jsonify({"error": str(exc)}), 503


@app.post("/api/incidents/from-alert")
def incident_from_alert():
    payload = request.get_json(silent=True) or {}
    alert_id = payload.get("alert_id")
    if not alert_id:
        return jsonify({"error": "alert_id is required"}), 400
    try:
        incident_id = create_incident_from_alert(int(alert_id))
        if not incident_id:
            return jsonify({"error": "Alert not found"}), 404
        add_audit_log("analyst", "create_incident", f"alert:{alert_id}")
        return jsonify({"status": "ok", "incident_id": incident_id})
    except Exception as exc:
        logging.exception("Failed to create incident from alert")
        return jsonify({"error": str(exc)}), 503


@app.get("/api/incidents/<int:incident_id>")
def incident_detail_api(incident_id: int):
    try:
        incident = get_incident(incident_id)
        if not incident:
            return jsonify({"error": "Incident not found"}), 404
        return jsonify(incident)
    except Exception as exc:
        logging.exception("Failed to load incident")
        return jsonify({"error": str(exc)}), 503


@app.post("/api/incidents/<int:incident_id>/status")
def incident_status_api(incident_id: int):
    payload = request.get_json(silent=True) or {}
    status = payload.get("status")
    if not status:
        return jsonify({"error": "status is required"}), 400
    try:
        update_incident_status(incident_id, status)
        if status == "investigating":
            existing = find_investigation_by_incident(incident_id)
            if not existing:
                create_investigation(
                    alert_id=None,
                    analyst_name="SOC Analyst",
                    notes=None,
                    title=f"Incident {incident_id}",
                    incident_id=incident_id,
                )
        add_audit_log("analyst", "update_incident_status", f"incident:{incident_id}")
        return jsonify({"status": "ok", "incident_id": incident_id, "incident_status": status})
    except Exception as exc:
        logging.exception("Failed to update incident status")
        return jsonify({"error": str(exc)}), 503


@app.post("/api/incidents/<int:incident_id>/assign")
def incident_assign_api(incident_id: int):
    payload = request.get_json(silent=True) or {}
    analyst = payload.get("analyst")
    if not analyst:
        return jsonify({"error": "analyst is required"}), 400
    try:
        assign_incident(incident_id, analyst)
        add_audit_log("analyst", "assign_incident", f"incident:{incident_id}")
        return jsonify({"status": "ok", "incident_id": incident_id, "assigned_analyst": analyst})
    except Exception as exc:
        logging.exception("Failed to assign incident")
        return jsonify({"error": str(exc)}), 503


@app.post("/api/incidents/<int:incident_id>/investigate")
def incident_investigate_api(incident_id: int):
    try:
        existing = find_investigation_by_incident(incident_id)
        if not existing:
            existing = create_investigation(
                alert_id=None,
                analyst_name="SOC Analyst",
                notes=None,
                title=f"Incident {incident_id}",
                incident_id=incident_id,
            )
        update_incident_status(incident_id, "investigating")
        add_audit_log("analyst", "investigate_incident", f"incident:{incident_id}")
        return jsonify({"status": "ok", "incident_id": incident_id, "investigation_id": existing})
    except Exception as exc:
        logging.exception("Failed to create investigation for incident")
        return jsonify({"error": str(exc)}), 503


@app.post("/api/incidents/<int:incident_id>/notes")
def incident_note_api(incident_id: int):
    payload = request.get_json(silent=True) or {}
    note = payload.get("note")
    if not note:
        return jsonify({"error": "note is required"}), 400
    try:
        add_incident_note(incident_id, note)
        add_audit_log("analyst", "add_incident_note", f"incident:{incident_id}")
        return jsonify({"status": "ok", "incident_id": incident_id})
    except Exception as exc:
        logging.exception("Failed to add incident note")
        return jsonify({"error": str(exc)}), 503


@app.get("/api/assets")
def assets():
    try:
        storage = os.getenv("PRIMARY_STORAGE", "sqlite").lower()
        if storage == "opensearch":
            try:
                assets = os_client.get_assets()
            except Exception as exc:
                logging.warning("OpenSearch assets failed, falling back to SQLite: %s", exc)
                assets = get_assets()
        else:
            assets = get_assets()
        return jsonify(assets)
    except Exception as exc:
        logging.exception("Failed to load assets from SQLite")
        return jsonify({"error": str(exc), "assets": []}), 503


@app.get("/api/assets/managed")
def managed_assets():
    try:
        return jsonify({"assets": get_managed_assets()})
    except Exception as exc:
        logging.exception("Failed to load managed assets")
        return jsonify({"error": str(exc)}), 503


@app.post("/api/assets/managed")
def managed_assets_create():
    payload = request.get_json(silent=True) or {}
    name = payload.get("name")
    if not name:
        return jsonify({"error": "name is required"}), 400
    try:
        asset_id = add_managed_asset(payload)
        add_audit_log("analyst", "create_asset", f"asset:{asset_id}")
        return jsonify({"status": "ok", "id": asset_id})
    except Exception as exc:
        logging.exception("Failed to create asset")
        return jsonify({"error": str(exc)}), 503


@app.put("/api/assets/managed/<int:asset_id>")
def managed_assets_update(asset_id: int):
    payload = request.get_json(silent=True) or {}
    try:
        update_managed_asset(asset_id, payload)
        add_audit_log("analyst", "update_asset", f"asset:{asset_id}")
        return jsonify({"status": "ok"})
    except Exception as exc:
        logging.exception("Failed to update asset")
        return jsonify({"error": str(exc)}), 503


@app.delete("/api/assets/managed/<int:asset_id>")
def managed_assets_delete(asset_id: int):
    try:
        delete_managed_asset(asset_id)
        add_audit_log("analyst", "delete_asset", f"asset:{asset_id}")
        return jsonify({"status": "ok"})
    except Exception as exc:
        logging.exception("Failed to delete asset")
        return jsonify({"error": str(exc)}), 503


@app.post("/api/response/block-ip")
def block_ip():
    payload = request.get_json(silent=True) or {}
    ip = payload.get("ip")
    if not ip:
        return jsonify({"status": "error", "message": "IP address is required."}), 400
    try:
        wazuh_client.block_ip(ip)
        add_response("block_ip", ip, analyst="analyst", status="success")
        add_audit_log("analyst", "block_ip", f"ip:{ip}")
        return jsonify({"status": "success", "message": "IP blocked successfully"})
    except Exception as exc:
        logging.exception("Failed to trigger active response for IP")
        add_response("block_ip", ip, analyst="analyst", status="error")
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.get("/wazuh/agents")
def wazuh_agents():
    try:
        payload = wazuh_api.get_agents()
        items = payload.get("data", {}).get("affected_items", []) if isinstance(payload, dict) else []
        normalized = []
        for agent in items:
            os_info = agent.get("os")
            os_name = os_info.get("name") if isinstance(os_info, dict) else os_info
            normalized.append(
                {
                    "agent_id": agent.get("id"),
                    "name": agent.get("name"),
                    "ip": agent.get("ip"),
                    "os": os_name,
                    "status": agent.get("status"),
                    "last_keepalive": agent.get("lastKeepAlive"),
                }
            )
        if not normalized:
            logging.info("Wazuh agents returned empty list. Raw payload: %s", payload)
        return jsonify({"status": "ok", "agents": normalized})
    except Exception as exc:
        logging.exception("Failed to fetch Wazuh agents")
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.get("/wazuh/agents/<agent_id>")
def wazuh_agent(agent_id: str):
    try:
        return jsonify(wazuh_api.get_agent(agent_id))
    except Exception as exc:
        logging.exception("Failed to fetch Wazuh agent")
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.delete("/wazuh/agents/<agent_id>")
def wazuh_agent_delete(agent_id: str):
    try:
        return jsonify(wazuh_api.delete_agent(agent_id))
    except Exception as exc:
        logging.exception("Failed to delete Wazuh agent")
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.get("/wazuh/manager")
def wazuh_manager():
    try:
        return jsonify(wazuh_api.get_manager_info())
    except Exception as exc:
        logging.exception("Failed to fetch Wazuh manager info")
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.get("/wazuh/agents/summary")
def wazuh_agents_summary():
    try:
        payload = wazuh_api.get_agents_summary()
        items = payload.get("data", {}).get("affected_items", []) if isinstance(payload, dict) else []
        summary = items[0] if items else {}
        if summary.get("total", 0) == 0:
            logging.info("Wazuh agents summary returned zero agents. Raw payload: %s", payload)
            try:
                agents_payload = wazuh_api.get_agents()
                agents = agents_payload.get("data", {}).get("affected_items", [])
                counts = {"active": 0, "disconnected": 0, "never_connected": 0}
                for agent in agents:
                    status = str(agent.get("status") or "").lower()
                    if status == "active":
                        counts["active"] += 1
                    elif status == "disconnected":
                        counts["disconnected"] += 1
                    elif status == "never_connected":
                        counts["never_connected"] += 1
                summary = {
                    "active": counts["active"],
                    "disconnected": counts["disconnected"],
                    "never_connected": counts["never_connected"],
                    "total": len(agents),
                }
            except Exception:
                logging.exception("Failed to derive agent summary from /agents")
        return jsonify(
            {
                "status": "ok",
                "active": summary.get("active", 0),
                "disconnected": summary.get("disconnected", 0),
                "never_connected": summary.get("never_connected", 0),
                "total": summary.get("total", 0),
            }
        )
    except Exception as exc:
        logging.exception("Failed to fetch Wazuh agents summary")
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.get("/wazuh/alerts")
def wazuh_alerts():
    limit = int(request.args.get("limit", 50))
    severity = request.args.get("severity")
    try:
        payload = wazuh_api.get_alerts(limit=limit)
        items = payload.get("data", {}).get("affected_items", []) if isinstance(payload, dict) else []
        normalized = []
        for alert in items:
            rule = alert.get("rule", {}) if isinstance(alert.get("rule"), dict) else {}
            agent = alert.get("agent", {}) if isinstance(alert.get("agent"), dict) else {}
            data = alert.get("data", {}) if isinstance(alert.get("data"), dict) else {}
            win = data.get("win", {}) if isinstance(data.get("win"), dict) else {}
            win_event = win.get("eventdata", {}) if isinstance(win.get("eventdata"), dict) else {}
            aws = data.get("aws", {}) if isinstance(data.get("aws"), dict) else {}
            source_ip = (
                data.get("srcip")
                or alert.get("srcip")
                or win_event.get("ipAddress")
                or aws.get("sourceIPAddress")
            )
            level = int(rule.get("level") or 0)
            severity_label = _severity_bucket(level)
            normalized.append(
                {
                    "timestamp": alert.get("timestamp") or alert.get("@timestamp"),
                    "agent_name": agent.get("name"),
                    "rule_id": rule.get("id"),
                    "rule_description": rule.get("description"),
                    "severity_level": level,
                    "severity_label": severity_label.upper(),
                    "source_ip": source_ip,
                    "raw": alert,
                }
            )

        if severity:
            severity = severity.lower()
            normalized = [
                alert for alert in normalized if _severity_bucket(int(alert["severity_level"] or 0)) == severity
            ]

        return jsonify({"status": "ok", "alerts": normalized[:limit]})
    except Exception as exc:
        if "404" in str(exc):
            logging.warning("Wazuh /alerts not available, falling back to SQLite.")
            results = query_alerts(limit=limit, offset=0, since_seconds=None, severity=severity)
            fallback = []
            for alert in results["alerts"]:
                level = int(alert.get("rule_level") or 0)
                fallback.append(
                    {
                        "timestamp": alert.get("timestamp"),
                        "agent_name": alert.get("agent_name"),
                        "rule_id": alert.get("rule_id"),
                        "rule_description": alert.get("rule_description"),
                        "severity_level": level,
                        "severity_label": _severity_bucket(level).upper(),
                        "source_ip": alert.get("src_ip"),
                        "raw": alert,
                    }
                )
            return jsonify({"status": "ok", "alerts": fallback[:limit]})
        logging.exception("Failed to fetch Wazuh alerts")
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.get("/wazuh/alerts/<alert_id>")
def wazuh_alert(alert_id: str):
    try:
        return jsonify(wazuh_api.get_alert(alert_id))
    except Exception as exc:
        logging.exception("Failed to fetch Wazuh alert detail")
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.post("/wazuh/block-ip")
def wazuh_block_ip():
    payload = request.get_json(silent=True) or {}
    agent_id = payload.get("agent_id")
    ip = payload.get("ip")
    if not agent_id or not ip:
        return jsonify({"status": "error", "message": "agent_id and ip are required."}), 400
    try:
        wazuh_api.block_ip(agent_id, ip)
        add_response("block_ip", ip, alert_id=None, analyst="analyst", status="executed")
        add_audit_log("analyst", "wazuh_block_ip", f"agent:{agent_id} ip:{ip}")
        return jsonify({"status": "executed"})
    except Exception as exc:
        logging.exception("Failed to execute active response")
        add_response("block_ip", ip, alert_id=None, analyst="analyst", status="error")
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.get("/responses")
def responses():
    try:
        return jsonify({"responses": get_responses(limit=50)})
    except Exception as exc:
        logging.exception("Failed to load response history")
        return jsonify({"error": str(exc), "responses": []}), 503


@app.get("/wazuh/vulnerabilities")
def wazuh_vulnerabilities():
    limit = int(request.args.get("limit", 20))
    try:
        payload = wazuh_api.get_vulnerabilities(limit=limit)
        items = payload.get("data", {}).get("affected_items", []) if isinstance(payload, dict) else []
        normalized = []
        for vuln in items:
            package = vuln.get("package", {}) if isinstance(vuln.get("package"), dict) else {}
            normalized.append(
                {
                    "agent_name": vuln.get("agent_name") or vuln.get("agent"),
                    "package_name": package.get("name") or vuln.get("package_name"),
                    "cve": vuln.get("cve"),
                    "severity": vuln.get("severity"),
                    "cvss_score": vuln.get("cvss_score"),
                }
            )
        return jsonify({"status": "ok", "vulnerabilities": normalized[:limit]})
    except Exception as exc:
        message = str(exc)
        if "404" in message or "405" in message:
            return (
                jsonify(
                    {
                        "status": "disabled",
                        "message": "This feature requires the Wazuh Vulnerability Detection module.",
                    }
                ),
                503,
            )
        logging.exception("Failed to fetch vulnerabilities")
        return jsonify({"status": "error", "message": message}), 503


@app.get("/wazuh/file-integrity")
def wazuh_file_integrity():
    limit = int(request.args.get("limit", 20))
    try:
        payload = wazuh_api.get_file_integrity(limit=limit)
        items = payload.get("data", {}).get("affected_items", []) if isinstance(payload, dict) else []
        normalized = []
        for entry in items:
            normalized.append(
                {
                    "agent_name": entry.get("agent_name") or entry.get("agent"),
                    "file_path": entry.get("path") or entry.get("file"),
                    "event_type": entry.get("type") or entry.get("event"),
                    "timestamp": entry.get("timestamp"),
                }
            )
        return jsonify({"status": "ok", "changes": normalized[:limit]})
    except Exception as exc:
        message = str(exc)
        if "404" in message or "405" in message:
            return (
                jsonify(
                    {
                        "status": "disabled",
                        "message": "File Integrity Monitoring (syscheck) is not enabled.",
                    }
                ),
                503,
            )
        logging.exception("Failed to fetch file integrity changes")
        return jsonify({"status": "error", "message": message}), 503


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
        logging.info("Settings updated: %s", {key: current.get(key) for key in allowed})
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


@app.get("/alerts/stream")
def alerts_stream():
    if _is_auth_required() and not _auth_bypass_enabled():
        token = _get_token_from_request()
        if not token:
            return jsonify({"error": "unauthorized"}), 401
    def event_stream():
        redis_client = get_client()
        pubsub = redis_client.pubsub()
        pubsub.subscribe("alerts_stream")
        try:
            yield ": connected\n\n"
            while True:
                message = pubsub.get_message(timeout=15)
                if not message:
                    yield ": ping\n\n"
                    continue
                if message.get("type") != "message":
                    continue
                try:
                    alert = json.loads(message.get("data") or "{}")
                except (TypeError, json.JSONDecodeError):
                    continue
                payload = {"type": "alert", "alert": alert}
                yield f"data: {json.dumps(payload)}\n\n"
        finally:
            pubsub.unsubscribe("alerts_stream")
            pubsub.close()

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


def _severity_bucket(level: int) -> str:
    if level <= 3:
        return "low"
    if level <= 6:
        return "medium"
    if level <= 9:
        return "high"
    return "critical"


def _is_public_ip(ip: str | None) -> bool:
    if not ip:
        return False
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127."):
        return False
    if ip.startswith("169.254."):
        return False
    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) > 1:
            second = int(parts[1]) if parts[1].isdigit() else 0
            return not (16 <= second <= 31)
    return True


if __name__ == "__main__":
    ensure_default_admin(
        os.getenv("DEFAULT_ADMIN_USER", ""),
        os.getenv("DEFAULT_ADMIN_PASSWORD", ""),
    )
    _start_backfill()
    app.run(host="0.0.0.0", port=5000, debug=os.getenv("FLASK_DEBUG", "false").lower() == "true")
