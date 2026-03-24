import json
import logging
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from collections import defaultdict, deque
from pathlib import Path
from queue import Queue
from typing import Deque, Dict, List, Tuple, Optional

import requests
from werkzeug.security import generate_password_hash, check_password_hash

logger = logging.getLogger("freshstart.alert_store")

_MAX_ALERTS = 1000
_alerts: Deque[Dict] = deque(maxlen=_MAX_ALERTS)
_lock = threading.Lock()
_subscribers: List[Queue] = []
_total_count = 0
_critical_count = 0
_rule_recent: Deque[Tuple[float, str, str]] = deque()
_ip_recent: Deque[Tuple[float, str]] = deque()
_agent_recent: Deque[Tuple[float, str]] = deque()
_geo_cache: Dict[str, Tuple[float, float, str, float]] = {}

_DB_PATH = Path(__file__).with_name("alerts.db")


def _connect():
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, column_def: str) -> None:
    columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {column_def}")


def _init_db() -> None:
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                rule_id TEXT,
                rule_level INTEGER,
                rule_description TEXT,
                agent_name TEXT,
                agent_ip TEXT,
                src_ip TEXT,
                geo_lat REAL,
                geo_lon REAL,
                geo_country TEXT,
                alert_status TEXT DEFAULT 'NEW'
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT,
                event_time TEXT,
                ingested_at TEXT,
                timestamp TEXT,
                agent_name TEXT,
                agent_ip TEXT,
                host TEXT,
                rule_id TEXT,
                rule_description TEXT,
                severity INTEGER,
                severity_label TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                username TEXT,
                event_category TEXT,
                raw_event TEXT,
                geo_lat REAL,
                geo_lon REAL,
                geo_country TEXT,
                geo_city TEXT,
                asn TEXT,
                isp TEXT,
                abuse_score INTEGER,
                threat_level TEXT,
                mitre_ids TEXT,
                mitre_tactics TEXT,
                alert_status TEXT DEFAULT 'NEW',
                resolved_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER,
                incident_id INTEGER,
                title TEXT,
                analyst_name TEXT,
                notes TEXT,
                created_at TEXT,
                updated_at TEXT,
                status TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS investigation_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id INTEGER,
                event_type TEXT,
                message TEXT,
                created_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user TEXT,
                action TEXT,
                target_object TEXT,
                timestamp TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS responses (
                response_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                action_type TEXT,
                target_ip TEXT,
                alert_id INTEGER,
                analyst TEXT,
                status TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT,
                incident_type TEXT,
                severity TEXT,
                first_seen TEXT,
                last_seen TEXT,
                related_alerts TEXT,
                src_ip TEXT,
                target_hosts TEXT,
                status TEXT,
                assigned_analyst TEXT,
                notes TEXT,
                created_at TEXT,
                updated_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS incident_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER,
                event_type TEXT,
                message TEXT,
                created_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS managed_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                asset_type TEXT,
                ip_address TEXT,
                owner TEXT,
                criticality TEXT,
                notes TEXT,
                created_at TEXT,
                updated_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password_hash TEXT,
                role TEXT,
                active INTEGER DEFAULT 1,
                created_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE,
                user_id INTEGER,
                created_at TEXT,
                expires_at TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        _ensure_column(conn, "alerts", "geo_lat", "REAL")
        _ensure_column(conn, "alerts", "geo_lon", "REAL")
        _ensure_column(conn, "alerts", "geo_country", "TEXT")
        _ensure_column(conn, "alerts", "alert_status", "TEXT DEFAULT 'NEW'")
        _ensure_column(conn, "events", "event_id", "TEXT")
        _ensure_column(conn, "events", "event_time", "TEXT")
        _ensure_column(conn, "events", "ingested_at", "TEXT")
        _ensure_column(conn, "events", "agent_ip", "TEXT")
        _ensure_column(conn, "events", "host", "TEXT")
        _ensure_column(conn, "events", "severity_label", "TEXT")
        _ensure_column(conn, "events", "source_ip", "TEXT")
        _ensure_column(conn, "events", "destination_ip", "TEXT")
        _ensure_column(conn, "events", "username", "TEXT")
        _ensure_column(conn, "events", "event_category", "TEXT")
        _ensure_column(conn, "events", "raw_event", "TEXT")
        _ensure_column(conn, "events", "geo_lat", "REAL")
        _ensure_column(conn, "events", "geo_lon", "REAL")
        _ensure_column(conn, "events", "geo_country", "TEXT")
        _ensure_column(conn, "events", "geo_city", "TEXT")
        _ensure_column(conn, "events", "asn", "TEXT")
        _ensure_column(conn, "events", "isp", "TEXT")
        _ensure_column(conn, "events", "abuse_score", "INTEGER")
        _ensure_column(conn, "events", "threat_level", "TEXT")
        _ensure_column(conn, "events", "mitre_ids", "TEXT")
        _ensure_column(conn, "events", "mitre_tactics", "TEXT")
        _ensure_column(conn, "events", "alert_status", "TEXT DEFAULT 'NEW'")
        _ensure_column(conn, "events", "resolved_at", "TEXT")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_events_event_id ON events(event_id)")
        _ensure_column(conn, "investigations", "title", "TEXT")
        _ensure_column(conn, "investigations", "incident_id", "INTEGER")
        _ensure_column(conn, "incidents", "title", "TEXT")
        _ensure_column(conn, "managed_assets", "asset_type", "TEXT")
        conn.execute("UPDATE alerts SET alert_status = 'NEW' WHERE alert_status IS NULL OR alert_status = ''")
        conn.execute("UPDATE events SET alert_status = 'NEW' WHERE alert_status IS NULL OR alert_status = ''")
        conn.execute("UPDATE events SET event_time = timestamp WHERE event_time IS NULL")
        conn.execute("UPDATE events SET ingested_at = timestamp WHERE ingested_at IS NULL")
        conn.commit()

    _backfill_events()


def _backfill_events() -> None:
    with _connect() as conn:
        row = conn.execute("SELECT COUNT(*) as count FROM events").fetchone()
        if row and row["count"]:
            return
        rows = conn.execute(
            """
            SELECT timestamp, rule_id, rule_level, rule_description, agent_name, src_ip
            FROM alerts
            ORDER BY id DESC
            """
        ).fetchall()
        for row in rows:
            severity = int(row["rule_level"] or 0)
            severity_label = _severity_bucket(severity)
            conn.execute(
                """
                INSERT INTO events (
                    event_id,
                    event_time,
                    ingested_at,
                    timestamp,
                    agent_name,
                    host,
                    rule_id,
                    rule_description,
                    severity,
                    severity_label,
                    source_ip,
                    raw_event,
                    alert_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    row["timestamp"],
                    _now_iso(),
                    row["timestamp"],
                    row["agent_name"],
                    row["agent_name"],
                    row["rule_id"],
                    row["rule_description"],
                    severity,
                    severity_label,
                    row["src_ip"],
                    None,
                    "NEW",
                ),
            )
        conn.commit()


def _insert_alert(alert: Dict) -> None:
    agent_name = alert.get("agent_name")
    agent_ip = alert.get("agent_ip")
    if not agent_name or agent_name == "Unknown agent":
        agent_name = None
    if not agent_ip or agent_ip == "N/A":
        agent_ip = None

    geo = _lookup_geo(alert.get("src_ip"))

    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO alerts (
                timestamp,
                rule_id,
                rule_level,
                rule_description,
                agent_name,
                agent_ip,
                src_ip,
                geo_lat,
                geo_lon,
                geo_country,
                alert_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert.get("timestamp"),
                alert.get("rule_id"),
                int(alert.get("rule_level", 0) or 0),
                alert.get("rule_description"),
                agent_name,
                agent_ip,
                alert.get("src_ip"),
                geo[0] if geo else None,
                geo[1] if geo else None,
                geo[2] if geo else None,
                alert.get("alert_status", "NEW"),
            ),
        )
        conn.commit()


def _insert_event(event: Dict) -> bool:
    geo = _lookup_geo(event.get("source_ip"))
    geo_lat = event.get("geo_lat") if event.get("geo_lat") is not None else (geo[0] if geo else None)
    geo_lon = event.get("geo_lon") if event.get("geo_lon") is not None else (geo[1] if geo else None)
    geo_country = event.get("geo_country") if event.get("geo_country") is not None else (geo[2] if geo else None)
    with _connect() as conn:
        cursor = conn.execute(
            """
            INSERT OR IGNORE INTO events (
                event_id,
                event_time,
                ingested_at,
                timestamp,
                agent_name,
                agent_ip,
                host,
                rule_id,
                rule_description,
                severity,
                severity_label,
                source_ip,
                destination_ip,
                username,
                event_category,
                raw_event,
                geo_lat,
                geo_lon,
                geo_country,
                geo_city,
                asn,
                isp,
                abuse_score,
                threat_level,
                mitre_ids,
                mitre_tactics,
                alert_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.get("event_id"),
                event.get("event_time") or event.get("timestamp"),
                event.get("ingested_at") or _now_iso(),
                event.get("timestamp"),
                event.get("agent_name"),
                event.get("agent_ip"),
                event.get("host"),
                event.get("rule_id"),
                event.get("rule_description"),
                int(event.get("severity", 0) or 0),
                event.get("severity_label"),
                event.get("source_ip"),
                event.get("destination_ip"),
                event.get("username"),
                event.get("event_category"),
                event.get("raw_event"),
                geo_lat,
                geo_lon,
                geo_country,
                event.get("geo_city"),
                event.get("asn"),
                event.get("isp"),
                event.get("abuse_score"),
                event.get("threat_level"),
                event.get("mitre_ids"),
                event.get("mitre_tactics"),
                event.get("alert_status", "NEW"),
            ),
        )
        conn.commit()
    return cursor.rowcount > 0


def _row_to_event(row: sqlite3.Row) -> Dict:
    event = {
        "id": row["id"],
        "event_id": row["event_id"],
        "event_time": row["event_time"],
        "ingested_at": row["ingested_at"],
        "timestamp": row["timestamp"],
        "agent_name": row["agent_name"],
        "agent_ip": row["agent_ip"],
        "host": row["host"],
        "rule_id": row["rule_id"],
        "rule_description": row["rule_description"],
        "severity": row["severity"],
        "severity_level": row["severity"],
        "rule_level": row["severity"],
        "severity_label": row["severity_label"],
        "source_ip": row["source_ip"],
        "destination_ip": row["destination_ip"],
        "username": row["username"],
        "event_category": row["event_category"],
        "raw_event": row["raw_event"],
        "geo_lat": row["geo_lat"],
        "geo_lon": row["geo_lon"],
        "geo_country": row["geo_country"],
        "geo_city": row["geo_city"],
        "asn": row["asn"],
        "isp": row["isp"],
        "abuse_score": row["abuse_score"],
        "threat_level": row["threat_level"],
        "mitre_ids": row["mitre_ids"],
        "mitre_tactics": row["mitre_tactics"],
        "alert_status": row["alert_status"],
        "src_ip": row["source_ip"],
    }
    if not event["severity_label"]:
        event["severity_label"] = _severity_bucket(int(event.get("severity", 0) or 0))
    return event


def add_alert(alert: Dict) -> None:
    # Ensure a consistent timestamp for analytics.
    alert.setdefault("received_at", time.time())
    level = int(alert.get("rule_level", 0) or 0)
    alert["severity_label"] = _severity_bucket(level)
    alert.setdefault("alert_status", "NEW")
    alert.setdefault("event_id", str(uuid.uuid4()))
    alert.setdefault("severity_label", _severity_bucket(int(alert.get("severity", 0) or 0)).upper())

    try:
        _insert_event(alert)
    except Exception:
        logger.exception("Failed to insert event into SQLite")

    with _lock:
        global _total_count, _critical_count
        _alerts.appendleft(alert)
        _total_count += 1
        if level >= 10:
            _critical_count += 1

        rule_id = str(alert.get("rule_id") or "Unknown")
        rule_desc = str(alert.get("rule_description") or "Unknown")
        _rule_recent.append((alert["received_at"], rule_id, rule_desc))

        src_ip = alert.get("src_ip")
        if src_ip:
            _ip_recent.append((alert["received_at"], str(src_ip)))

        agent_name = alert.get("agent_name")
        if agent_name:
            _agent_recent.append((alert["received_at"], str(agent_name)))

        _prune_recent_locked()

        for subscriber in list(_subscribers):
            _push_to_subscriber(subscriber, alert)


def insert_alert(alert: Dict) -> None:
    add_alert(alert)


def insert_event(event: Dict) -> bool:
    try:
        return _insert_event(event)
    except Exception:
        logger.exception("Failed to insert event into SQLite")
        return False


def get_assets() -> List[Dict]:
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT
                agent_name,
                agent_ip,
                COUNT(*) as alert_count,
                MAX(timestamp) as last_seen
            FROM events
            WHERE agent_name IS NOT NULL
            GROUP BY agent_name, agent_ip
            ORDER BY last_seen DESC
            """
        ).fetchall()
    return [
        {
            "name": row["agent_name"],
            "ip": row["agent_ip"],
            "alerts": row["alert_count"],
            "last_seen": row["last_seen"],
        }
        for row in rows
    ]


def get_recent_alerts(limit: int = 50) -> List[Dict]:
    with _lock:
        return list(_alerts)[:limit]


def query_alerts(
    limit: int = 50,
    offset: int = 0,
    since_seconds: Optional[int] = None,
    severity: Optional[str] = None,
) -> Dict:
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM events ORDER BY id DESC").fetchall()
    alerts = [_row_to_event(row) for row in rows]

    if since_seconds is not None:
        cutoff = time.time() - since_seconds
        alerts = [alert for alert in alerts if _parse_event_time(alert) >= cutoff]

    if severity:
        severity = severity.lower()
        alerts = [alert for alert in alerts if str(alert.get("severity_label", "")).lower() == severity]

    total = len(alerts)
    page = alerts[offset : offset + limit]
    return {"alerts": page, "total": total}


def get_alert(alert_id: int) -> Optional[Dict]:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM events WHERE id = ?", (alert_id,)).fetchone()
    if not row:
        return None
    return _row_to_event(row)


def get_ids_for_event_ids(event_ids: List[str]) -> Dict[str, int]:
    if not event_ids:
        return {}
    placeholders = ",".join(["?"] * len(event_ids))
    with _connect() as conn:
        rows = conn.execute(
            f"SELECT id, event_id FROM events WHERE event_id IN ({placeholders})",
            event_ids,
        ).fetchall()
    return {row["event_id"]: int(row["id"]) for row in rows if row["event_id"]}


def get_status_for_event_ids(event_ids: List[str]) -> Dict[str, Dict]:
    if not event_ids:
        return {}
    placeholders = ",".join(["?"] * len(event_ids))
    with _connect() as conn:
        rows = conn.execute(
            f"SELECT id, event_id, alert_status, resolved_at FROM events WHERE event_id IN ({placeholders})",
            event_ids,
        ).fetchall()
    return {
        row["event_id"]: {
            "id": int(row["id"]),
            "alert_status": row["alert_status"],
            "resolved_at": row["resolved_at"],
        }
        for row in rows
        if row["event_id"]
    }


def update_alert_status(alert_id: int, status: str) -> None:
    with _connect() as conn:
        resolved_at = _now_iso() if status == "RESOLVED" else None
        conn.execute(
            "UPDATE events SET alert_status = ?, resolved_at = ? WHERE id = ?",
            (status, resolved_at, alert_id),
        )
        conn.commit()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_investigation(
    alert_id: int | None,
    analyst_name: str | None,
    notes: str | None,
    title: str | None = None,
    incident_id: int | None = None,
) -> int:
    created = _now_iso()
    with _connect() as conn:
        cursor = conn.execute(
            """
            INSERT INTO investigations (alert_id, incident_id, title, analyst_name, notes, created_at, updated_at, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (alert_id, incident_id, title, analyst_name, notes, created, created, "INVESTIGATING"),
        )
        investigation_id = int(cursor.lastrowid)
        conn.commit()
    add_investigation_event(investigation_id, "investigation_started", "Investigation created.")
    return investigation_id


def add_investigation_event(investigation_id: int, event_type: str, message: str) -> None:
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO investigation_events (investigation_id, event_type, message, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (investigation_id, event_type, message, _now_iso()),
        )
        conn.commit()


def update_investigation_status(investigation_id: int, status: str) -> None:
    with _connect() as conn:
        conn.execute(
            "UPDATE investigations SET status = ?, updated_at = ? WHERE id = ?",
            (status, _now_iso(), investigation_id),
        )
        conn.commit()
    add_investigation_event(investigation_id, "status_change", f"Status set to {status}.")


def get_investigations() -> List[Dict]:
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM investigations ORDER BY id DESC").fetchall()
    return [dict(row) for row in rows]


def get_investigation(investigation_id: int) -> Optional[Dict]:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM investigations WHERE id = ?", (investigation_id,)).fetchone()
        if not row:
            return None
        events = conn.execute(
            "SELECT * FROM investigation_events WHERE investigation_id = ? ORDER BY id ASC",
            (investigation_id,),
        ).fetchall()
    data = dict(row)
    data["events"] = [dict(event) for event in events]
    return data


def find_investigation_by_alert(alert_id: int) -> Optional[int]:
    with _connect() as conn:
        row = conn.execute(
            "SELECT id FROM investigations WHERE alert_id = ? ORDER BY id DESC LIMIT 1", (alert_id,)
        ).fetchone()
    return int(row["id"]) if row else None


def find_investigation_by_incident(incident_id: int) -> Optional[int]:
    with _connect() as conn:
        row = conn.execute(
            "SELECT id FROM investigations WHERE incident_id = ? ORDER BY id DESC LIMIT 1",
            (incident_id,),
        ).fetchone()
    return int(row["id"]) if row else None


def add_audit_log(user: str, action: str, target_object: str) -> None:
    with _connect() as conn:
        conn.execute(
            "INSERT INTO audit_logs (user, action, target_object, timestamp) VALUES (?, ?, ?, ?)",
            (user, action, target_object, _now_iso()),
        )
        conn.commit()


def get_audit_logs(limit: int = 10) -> List[Dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT user, action, target_object, timestamp FROM audit_logs ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def add_response(
    action_type: str,
    target_ip: str,
    alert_id: int | None = None,
    analyst: str | None = None,
    status: str | None = None,
) -> None:
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO responses (timestamp, action_type, target_ip, alert_id, analyst, status)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (_now_iso(), action_type, target_ip, alert_id, analyst, status),
        )
        conn.commit()


def get_responses(limit: int = 20) -> List[Dict]:
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT response_id, timestamp, action_type, target_ip, alert_id, analyst, status
            FROM responses
            ORDER BY response_id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def upsert_incident(
    incident_type: str,
    severity: str,
    first_seen: str,
    last_seen: str,
    related_alerts: List[int],
    src_ip: str | None,
    target_hosts: List[str],
) -> int:
    related_alerts_json = json.dumps(sorted(set(related_alerts)))
    target_hosts_json = json.dumps(sorted(set(target_hosts)))
    title = incident_type.replace("_", " ").title()
    with _connect() as conn:
        existing = conn.execute(
            """
            SELECT incident_id, related_alerts, target_hosts
            FROM incidents
            WHERE incident_type = ? AND src_ip = ? AND status IN ('open', 'investigating')
            ORDER BY incident_id DESC
            LIMIT 1
            """,
            (incident_type, src_ip),
        ).fetchone()
        now = _now_iso()
        if existing:
            existing_alerts = json.loads(existing["related_alerts"] or "[]")
            existing_targets = json.loads(existing["target_hosts"] or "[]")
            merged_alerts = sorted(set(existing_alerts + related_alerts))
            merged_targets = sorted(set(existing_targets + target_hosts))
            conn.execute(
                """
                UPDATE incidents
                SET severity = ?, last_seen = ?, related_alerts = ?, target_hosts = ?, updated_at = ?
                WHERE incident_id = ?
                """,
                (
                    severity,
                    last_seen,
                    json.dumps(merged_alerts),
                    json.dumps(merged_targets),
                    now,
                    existing["incident_id"],
                ),
            )
            conn.commit()
            return int(existing["incident_id"])

        cursor = conn.execute(
            """
            INSERT INTO incidents (
                title,
                incident_type,
                severity,
                first_seen,
                last_seen,
                related_alerts,
                src_ip,
                target_hosts,
                status,
                assigned_analyst,
                notes,
                created_at,
                updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                title,
                incident_type,
                severity,
                first_seen,
                last_seen,
                related_alerts_json,
                src_ip,
                target_hosts_json,
                "open",
                None,
                None,
                now,
                now,
            ),
        )
        conn.commit()
        return int(cursor.lastrowid)


def get_incidents(limit: int = 100) -> List[Dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM incidents ORDER BY incident_id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    incidents = []
    for row in rows:
        data = dict(row)
        data["related_alerts"] = json.loads(data.get("related_alerts") or "[]")
        data["target_hosts"] = json.loads(data.get("target_hosts") or "[]")
        with _connect() as conn:
            link = conn.execute(
                "SELECT id FROM investigations WHERE incident_id = ? ORDER BY id DESC LIMIT 1",
                (data["incident_id"],),
            ).fetchone()
        data["investigation_id"] = int(link["id"]) if link else None
        incidents.append(data)
    return incidents


def get_incident_kpis() -> Dict:
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT
                SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) as open_count,
                SUM(CASE WHEN status = 'investigating' THEN 1 ELSE 0 END) as investigating_count,
                SUM(CASE WHEN status = 'contained' THEN 1 ELSE 0 END) as contained_count,
                SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) as resolved_count
            FROM incidents
            """
        ).fetchone()
    return {
        "open": int(row["open_count"] or 0),
        "investigating": int(row["investigating_count"] or 0),
        "contained": int(row["contained_count"] or 0),
        "resolved": int(row["resolved_count"] or 0),
    }


def get_incident(incident_id: int) -> Optional[Dict]:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM incidents WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()
    if not row:
        return None
    data = dict(row)
    data["related_alerts"] = json.loads(data.get("related_alerts") or "[]")
    data["target_hosts"] = json.loads(data.get("target_hosts") or "[]")
    with _connect() as conn:
        link = conn.execute(
            "SELECT id FROM investigations WHERE incident_id = ? ORDER BY id DESC LIMIT 1",
            (incident_id,),
        ).fetchone()
    data["investigation_id"] = int(link["id"]) if link else None
    with _connect() as conn:
        events = conn.execute(
            "SELECT * FROM incident_events WHERE incident_id = ? ORDER BY id ASC",
            (incident_id,),
        ).fetchall()
    data["events"] = [dict(event) for event in events]
    return data


def add_incident_event(incident_id: int, event_type: str, message: str) -> None:
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO incident_events (incident_id, event_type, message, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (incident_id, event_type, message, _now_iso()),
        )
        conn.commit()


def update_incident_status(incident_id: int, status: str) -> None:
    with _connect() as conn:
        conn.execute(
            "UPDATE incidents SET status = ?, updated_at = ? WHERE incident_id = ?",
            (status, _now_iso(), incident_id),
        )
        conn.commit()
    add_incident_event(incident_id, "status_change", f"Status set to {status}.")


def assign_incident(incident_id: int, analyst: str) -> None:
    with _connect() as conn:
        conn.execute(
            "UPDATE incidents SET assigned_analyst = ?, updated_at = ? WHERE incident_id = ?",
            (analyst, _now_iso(), incident_id),
        )
        conn.commit()
    add_incident_event(incident_id, "assign", f"Assigned to {analyst}.")


def add_incident_note(incident_id: int, note: str) -> None:
    with _connect() as conn:
        conn.execute(
            "UPDATE incidents SET notes = ?, updated_at = ? WHERE incident_id = ?",
            (note, _now_iso(), incident_id),
        )
        conn.commit()
    add_incident_event(incident_id, "note", note)


def create_incident_from_alert(alert_id: int) -> Optional[int]:
    alert = get_alert(alert_id)
    if not alert:
        return None
    severity = _severity_bucket(int(alert.get("severity") or 0))
    now = _now_iso()
    title = f"Alert {alert_id} · {alert.get('rule_description') or 'Incident'}"
    with _connect() as conn:
        cursor = conn.execute(
            """
            INSERT INTO incidents (
                title,
                incident_type,
                severity,
                first_seen,
                last_seen,
                related_alerts,
                src_ip,
                target_hosts,
                status,
                assigned_analyst,
                notes,
                created_at,
                updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                title,
                "manual_alert",
                severity,
                alert.get("timestamp") or now,
                alert.get("timestamp") or now,
                json.dumps([alert_id]),
                alert.get("source_ip"),
                json.dumps([alert.get("agent_name")] if alert.get("agent_name") else []),
                "open",
                None,
                None,
                now,
                now,
            ),
        )
        conn.commit()
        incident_id = int(cursor.lastrowid)
    add_incident_event(incident_id, "created", f"Incident created from alert {alert_id}.")
    return incident_id


def get_soc_metrics() -> Dict:
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT
                COUNT(*) as total_alerts,
                SUM(CASE WHEN severity >= 10 THEN 1 ELSE 0 END) as critical_alerts,
                SUM(CASE WHEN severity BETWEEN 7 AND 9 THEN 1 ELSE 0 END) as high_alerts,
                SUM(CASE WHEN severity BETWEEN 4 AND 6 THEN 1 ELSE 0 END) as medium_alerts,
                SUM(CASE WHEN severity <= 3 THEN 1 ELSE 0 END) as low_alerts,
                SUM(CASE WHEN alert_status = 'RESOLVED' THEN 1 ELSE 0 END) as resolved_alerts,
                SUM(CASE WHEN alert_status = 'FALSE_POSITIVE' THEN 1 ELSE 0 END) as false_positives
            FROM events
            """
        ).fetchone()
        resolved_rows = conn.execute(
            """
            SELECT timestamp, resolved_at
            FROM events
            WHERE alert_status = 'RESOLVED' AND resolved_at IS NOT NULL
            """
        ).fetchall()
        investigations = conn.execute(
            "SELECT COUNT(*) as open_investigations FROM investigations WHERE status != 'RESOLVED'"
        ).fetchone()
        resolved_today = conn.execute(
            """
            SELECT COUNT(*) as count
            FROM events
            WHERE alert_status = 'RESOLVED'
              AND resolved_at IS NOT NULL
              AND date(resolved_at) = date('now')
            """
        ).fetchone()

    mttr_seconds = 0
    if resolved_rows:
        deltas = []
        for row_item in resolved_rows:
            created_ts = _parse_timestamp(row_item["timestamp"])
            resolved_ts = _parse_timestamp(row_item["resolved_at"])
            if resolved_ts and created_ts and resolved_ts >= created_ts:
                deltas.append(resolved_ts - created_ts)
        if deltas:
            mttr_seconds = int(sum(deltas) / len(deltas))
    return {
        "total_alerts": int(row["total_alerts"] or 0),
        "alerts_by_severity": {
            "critical": int(row["critical_alerts"] or 0),
            "high": int(row["high_alerts"] or 0),
            "medium": int(row["medium_alerts"] or 0),
            "low": int(row["low_alerts"] or 0),
        },
        "open_investigations": int(investigations["open_investigations"] or 0),
        "resolved_incidents": int(row["resolved_alerts"] or 0),
        "resolved_today": int(resolved_today["count"] or 0),
        "false_positives": int(row["false_positives"] or 0),
        "mttr_seconds": mttr_seconds,
    }


def get_metrics() -> Dict:
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT
                COUNT(*) as total_alerts,
                SUM(CASE WHEN severity >= 10 THEN 1 ELSE 0 END) as critical_alerts,
                SUM(CASE WHEN severity >= 7 THEN 1 ELSE 0 END) as high_alerts,
                COUNT(DISTINCT agent_name) as active_agents
            FROM events
            """
        ).fetchone()
        ips = conn.execute("SELECT DISTINCT source_ip FROM events WHERE source_ip IS NOT NULL").fetchall()

    suspicious_ips = {ip["source_ip"] for ip in ips if _is_public_ip(ip["source_ip"])}
    total_alerts = int(row["total_alerts"] or 0)
    return {
        "total_alerts": total_alerts,
        "critical_alerts": int(row["critical_alerts"] or 0),
        "high_alerts": int(row["high_alerts"] or 0),
        "active_agents": int(row["active_agents"] or 0),
        "suspicious_ips": len(suspicious_ips),
        "events_processed": total_alerts,
    }


def get_top_attackers(limit: int = 5) -> List[Dict]:
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT source_ip, COUNT(*) as alert_count, MAX(timestamp) as last_seen
            FROM events
            WHERE source_ip IS NOT NULL
            GROUP BY source_ip
            ORDER BY alert_count DESC
            LIMIT 20
            """
        ).fetchall()

    attackers = []
    for row in rows:
        ip = row["source_ip"]
        if not _is_public_ip(ip):
            continue
        attackers.append(
            {
                "src_ip": ip,
                "count": row["alert_count"],
                "country": "Unknown",
                "last_seen": row["last_seen"],
            }
        )
        if len(attackers) >= limit:
            break
    return attackers


def get_attacker_profiles(limit: int = 5) -> List[Dict]:
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT source_ip, COUNT(*) as alert_count, COUNT(DISTINCT agent_name) as targets, MAX(timestamp) as last_seen,
                   MAX(geo_country) as country, MAX(severity) as max_severity
            FROM events
            WHERE source_ip IS NOT NULL
            GROUP BY source_ip
            ORDER BY alert_count DESC
            LIMIT 50
            """
        ).fetchall()

    profiles = []
    for row in rows:
        ip = row["source_ip"]
        if not _is_public_ip(ip):
            continue
        with _connect() as conn:
            types = conn.execute(
                """
                SELECT rule_description, COUNT(*) as cnt
                FROM events
                WHERE source_ip = ? AND rule_description IS NOT NULL
                GROUP BY rule_description
                ORDER BY cnt DESC
                LIMIT 3
                """,
                (ip,),
            ).fetchall()
        profiles.append(
            {
                "src_ip": ip,
                "count": row["alert_count"],
                "targets": row["targets"],
                "country": row["country"] or "Unknown",
                "attack_types": [item["rule_description"] for item in types if item["rule_description"]],
                "last_seen": row["last_seen"],
                "severity": row["max_severity"],
            }
        )
        if len(profiles) >= limit:
            break
    return profiles


def get_rule_statistics(limit: int = 5) -> List[Dict]:
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT rule_id, rule_description, COUNT(*) as alert_count
            FROM events
            GROUP BY rule_id, rule_description
            ORDER BY alert_count DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [
        {
            "rule_id": row["rule_id"],
            "rule_description": row["rule_description"],
            "count": row["alert_count"],
            "sparkline": [],
        }
        for row in rows
    ]


def get_risky_hosts(limit: int = 5) -> List[Dict]:
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT agent_name, COUNT(*) as alert_count, MAX(severity) as max_level, MAX(timestamp) as last_seen
            FROM events
            WHERE agent_name IS NOT NULL
            GROUP BY agent_name
            ORDER BY alert_count DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [
        {
            "host": row["agent_name"],
            "count": row["alert_count"],
            "highest_severity": row["max_level"],
            "last_activity": row["last_seen"],
        }
        for row in rows
    ]


def get_risk_scores(limit: int = 10) -> List[Dict]:
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT
                agent_name,
                SUM(CASE WHEN severity >= 10 THEN 1 ELSE 0 END) as critical_count,
                SUM(CASE WHEN severity BETWEEN 7 AND 9 THEN 1 ELSE 0 END) as high_count,
                SUM(CASE WHEN severity BETWEEN 4 AND 6 THEN 1 ELSE 0 END) as medium_count,
                MAX(timestamp) as last_seen
            FROM events
            WHERE agent_name IS NOT NULL
            GROUP BY agent_name
            ORDER BY (critical_count * 5 + high_count * 3 + medium_count) DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    results = []
    for row in rows:
        score = int((row["critical_count"] or 0) * 5 + (row["high_count"] or 0) * 3 + (row["medium_count"] or 0))
        results.append(
            {
                "host": row["agent_name"],
                "risk_score": score,
                "critical": int(row["critical_count"] or 0),
                "high": int(row["high_count"] or 0),
                "medium": int(row["medium_count"] or 0),
                "last_seen": row["last_seen"],
            }
        )
    return results


def get_mitre_stats(limit: int = 10) -> List[Dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT mitre_ids, mitre_tactics FROM events WHERE mitre_ids IS NOT NULL ORDER BY id DESC LIMIT 2000"
        ).fetchall()
    counts: Dict[str, int] = {}
    tactics: Dict[str, List[str]] = {}
    for row in rows:
        ids_raw = row["mitre_ids"]
        if not ids_raw:
            continue
        try:
            ids = json.loads(ids_raw)
        except Exception:
            ids = [ids_raw]
        t_raw = row["mitre_tactics"]
        try:
            t_list = json.loads(t_raw) if t_raw else []
        except Exception:
            t_list = [t_raw] if t_raw else []
        for mid in ids:
            if not mid:
                continue
            key = str(mid)
            counts[key] = counts.get(key, 0) + 1
            if t_list:
                tactics[key] = t_list
    stats = [
        {"technique": key, "count": counts[key], "tactics": tactics.get(key, [])}
        for key in counts
    ]
    stats.sort(key=lambda item: item["count"], reverse=True)
    return stats[:limit]


def get_attack_map_agg(limit: int = 200) -> List[Dict]:
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT
                geo_country as country,
                ROUND(geo_lat, 1) as lat,
                ROUND(geo_lon, 1) as lon,
                COUNT(*) as count,
                MAX(severity) as max_severity
            FROM events
            WHERE geo_lat IS NOT NULL AND geo_lon IS NOT NULL
            GROUP BY country, lat, lon
            ORDER BY count DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [
        {
            "country": row["country"] or "Unknown",
            "lat": row["lat"],
            "lon": row["lon"],
            "count": row["count"],
            "severity": row["max_severity"],
        }
        for row in rows
    ]


def get_incident_timeline(window_hours: int = 24) -> Dict:
    now = time.time()
    window_start = now - window_hours * 3600
    bucket_seconds = 3600
    bucket_count = window_hours
    labels = []
    buckets = [0 for _ in range(bucket_count)]

    with _connect() as conn:
        rows = conn.execute("SELECT created_at FROM incidents").fetchall()

    for row in rows:
        ts = _parse_timestamp(row["created_at"])
        if ts < window_start:
            continue
        bucket_index = int((ts - window_start) // bucket_seconds)
        if 0 <= bucket_index < len(buckets):
            buckets[bucket_index] += 1

    for i in range(len(buckets)):
        label_time = window_start + (i * bucket_seconds)
        labels.append(time.strftime("%H:%M", time.localtime(label_time)))

    return {"labels": labels, "counts": buckets}


def get_threat_profile(ip: str) -> Dict:
    with _connect() as conn:
        summary = conn.execute(
            """
            SELECT
                COUNT(*) as alert_count,
                COUNT(DISTINCT agent_name) as targets,
                MAX(timestamp) as last_seen,
                MAX(geo_country) as country,
                MAX(geo_city) as city,
                MAX(asn) as asn,
                MAX(isp) as isp,
                MAX(abuse_score) as abuse_score,
                MAX(threat_level) as threat_level
            FROM events
            WHERE source_ip = ?
            """,
            (ip,),
        ).fetchone()
        recent = conn.execute(
            """
            SELECT id, timestamp, rule_description, severity
            FROM events
            WHERE source_ip = ?
            ORDER BY id DESC
            LIMIT 10
            """,
            (ip,),
        ).fetchall()
    return {
        "src_ip": ip,
        "alert_count": int(summary["alert_count"] or 0),
        "targets": int(summary["targets"] or 0),
        "last_seen": summary["last_seen"],
        "country": summary["country"],
        "city": summary["city"],
        "asn": summary["asn"],
        "isp": summary["isp"],
        "abuse_score": summary["abuse_score"],
        "threat_level": summary["threat_level"],
        "recent_alerts": [dict(row) for row in recent],
    }


def get_managed_assets() -> List[Dict]:
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM managed_assets ORDER BY id DESC").fetchall()
    return [dict(row) for row in rows]


def add_managed_asset(payload: Dict) -> int:
    now = _now_iso()
    with _connect() as conn:
        cursor = conn.execute(
            """
            INSERT INTO managed_assets (name, asset_type, ip_address, owner, criticality, notes, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload.get("name"),
                payload.get("asset_type"),
                payload.get("ip_address"),
                payload.get("owner"),
                payload.get("criticality"),
                payload.get("notes"),
                now,
                now,
            ),
        )
        conn.commit()
        return int(cursor.lastrowid)


def update_managed_asset(asset_id: int, payload: Dict) -> None:
    with _connect() as conn:
        conn.execute(
            """
            UPDATE managed_assets
            SET name = ?, asset_type = ?, ip_address = ?, owner = ?, criticality = ?, notes = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                payload.get("name"),
                payload.get("asset_type"),
                payload.get("ip_address"),
                payload.get("owner"),
                payload.get("criticality"),
                payload.get("notes"),
                _now_iso(),
                asset_id,
            ),
        )
        conn.commit()


def delete_managed_asset(asset_id: int) -> None:
    with _connect() as conn:
        conn.execute("DELETE FROM managed_assets WHERE id = ?", (asset_id,))
        conn.commit()


def get_alerts_over_time(window_minutes: int = 60, bucket_seconds: int = 300) -> Dict:
    now = time.time()
    window_start = now - window_minutes * 60
    bucket_count = window_minutes * 60 // bucket_seconds

    labels = []
    buckets = [
        {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for _ in range(int(bucket_count))
    ]

    with _connect() as conn:
        rows = conn.execute(
            "SELECT timestamp, severity FROM events ORDER BY id DESC LIMIT 2000"
        ).fetchall()

    for row in rows:
        ts = _parse_timestamp(row["timestamp"])
        if ts < window_start:
            continue
        bucket_index = int((ts - window_start) // bucket_seconds)
        if bucket_index < 0 or bucket_index >= len(buckets):
            continue
        level = int(row["severity"] or 0)
        severity = _severity_bucket(level)
        buckets[bucket_index][severity] += 1

    for i in range(len(buckets)):
        label_time = window_start + (i * bucket_seconds)
        labels.append(time.strftime("%H:%M", time.localtime(label_time)))

    return {
        "labels": labels,
        "series": {
            "critical": [bucket["critical"] for bucket in buckets],
            "high": [bucket["high"] for bucket in buckets],
            "medium": [bucket["medium"] for bucket in buckets],
            "low": [bucket["low"] for bucket in buckets],
        },
    }


def subscribe() -> Queue:
    queue = Queue(maxsize=200)
    with _lock:
        _subscribers.append(queue)
    return queue


def unsubscribe(queue: Queue) -> None:
    with _lock:
        if queue in _subscribers:
            _subscribers.remove(queue)


def _push_to_subscriber(queue: Queue, alert: Dict) -> None:
    try:
        queue.put_nowait(alert)
    except Exception:
        pass


def _prune_recent_locked() -> None:
    cutoff = time.time() - 300
    while _rule_recent and _rule_recent[0][0] < cutoff:
        _rule_recent.popleft()
    while _ip_recent and _ip_recent[0][0] < cutoff:
        _ip_recent.popleft()
    while _agent_recent and _agent_recent[0][0] < cutoff:
        _agent_recent.popleft()


def _severity_bucket(level: int) -> str:
    if level <= 3:
        return "low"
    if level <= 6:
        return "medium"
    if level <= 9:
        return "high"
    return "critical"


def _sparkline_for_rule(rule_id: str, buckets: int = 6) -> List[int]:
    now = time.time()
    bucket_seconds = 300
    series = [0 for _ in range(buckets)]
    for ts, rid, _ in _rule_recent:
        if rid != rule_id:
            continue
        offset = int((now - ts) // bucket_seconds)
        index = buckets - 1 - offset
        if 0 <= index < buckets:
            series[index] += 1
    return series


def _format_time(timestamp: float) -> str:
    if not timestamp:
        return "Unknown"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))


def _is_public_ip(ip: str) -> bool:
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


def _lookup_geo(ip: str | None) -> Optional[Tuple[float, float, str]]:
    if not ip or not _is_public_ip(ip):
        return None

    cached = _geo_cache.get(ip)
    if cached:
        lat, lon, country, timestamp = cached
        if time.time() - timestamp < 3600:
            return lat, lon, country

    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,lat,lon"},
            timeout=2,
        )
        if response.ok:
            payload = response.json()
            if payload.get("status") == "success":
                lat = payload.get("lat")
                lon = payload.get("lon")
                country = payload.get("country")
                _geo_cache[ip] = (lat, lon, country, time.time())
                return lat, lon, country
    except Exception:
        logger.exception("Geo lookup failed for IP %s", ip)
    return None


def get_geo_for_ip(ip: str | None) -> Optional[Tuple[float, float, str]]:
    return _lookup_geo(ip)


def get_alert_counts() -> Dict:
    with _connect() as conn:
        total = conn.execute("SELECT COUNT(*) as count FROM events").fetchone()["count"]
    return {"total_alerts": int(total or 0)}


def get_distinct_agents() -> int:
    with _connect() as conn:
        row = conn.execute(
            "SELECT COUNT(DISTINCT agent_name) as count FROM events WHERE agent_name IS NOT NULL"
        ).fetchone()
    return int(row["count"] or 0)


def get_latest_event_timestamp() -> str | None:
    with _connect() as conn:
        row = conn.execute("SELECT timestamp FROM events ORDER BY id DESC LIMIT 1").fetchone()
    if not row:
        return None
    return row["timestamp"]


def get_recent_events_for_correlation(src_ip: str, window_seconds: int = 600, limit: int = 500) -> List[Dict]:
    if not src_ip:
        return []
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT * FROM events
            WHERE source_ip = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (src_ip, limit),
        ).fetchall()
    alerts = [_row_to_event(row) for row in rows]
    cutoff = time.time() - window_seconds
    return [alert for alert in alerts if _parse_event_time(alert) >= cutoff]


def _parse_timestamp(value: str) -> float:
    if not value:
        return 0.0
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(value, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except Exception:
        return 0.0


def _parse_event_time(alert: Dict) -> float:
    return _parse_timestamp(alert.get("event_time") or alert.get("timestamp"))


_init_db()


def create_user(username: str, password: str, role: str = "analyst") -> int:
    if not username or not password:
        raise ValueError("username and password are required")
    now = _now_iso()
    password_hash = generate_password_hash(password)
    with _connect() as conn:
        cursor = conn.execute(
            """
            INSERT INTO users (username, password_hash, role, active, created_at)
            VALUES (?, ?, ?, 1, ?)
            """,
            (username, password_hash, role, now),
        )
        conn.commit()
        return int(cursor.lastrowid)


def list_users() -> List[Dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, username, role, active, created_at FROM users ORDER BY id ASC"
        ).fetchall()
    return [dict(row) for row in rows]


def authenticate_user(username: str, password: str) -> Optional[Dict]:
    if not username or not password:
        return None
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ? AND active = 1",
            (username,),
        ).fetchone()
    if not row:
        return None
    if not check_password_hash(row["password_hash"], password):
        return None
    return dict(row)


def create_session(user_id: int, token: str, ttl_seconds: int = 3600) -> None:
    now = time.time()
    expires = now + ttl_seconds
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO sessions (token, user_id, created_at, expires_at)
            VALUES (?, ?, ?, ?)
            """,
            (token, user_id, _now_iso(), _format_time(expires)),
        )
        conn.commit()


def get_session(token: str) -> Optional[Dict]:
    if not token:
        return None
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT s.token, s.user_id, s.expires_at, u.username, u.role, u.active
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token = ?
            """,
            (token,),
        ).fetchone()
    if not row:
        return None
    expires_ts = _parse_timestamp(row["expires_at"])
    if expires_ts and expires_ts < time.time():
        delete_session(token)
        return None
    if row["active"] != 1:
        return None
    return dict(row)


def delete_session(token: str) -> None:
    with _connect() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()


def ensure_default_admin(username: str, password: str) -> None:
    if not username or not password:
        return
    with _connect() as conn:
        row = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if row:
            return
    create_user(username, password, role="admin")


def update_user_role(user_id: int, role: str) -> None:
    with _connect() as conn:
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        conn.commit()


def set_user_active(user_id: int, active: bool) -> None:
    with _connect() as conn:
        conn.execute("UPDATE users SET active = ? WHERE id = ?", (1 if active else 0, user_id))
        conn.commit()
