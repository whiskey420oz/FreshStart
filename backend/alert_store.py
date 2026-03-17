import logging
import sqlite3
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from queue import Queue
from typing import Deque, Dict, List, Tuple, Optional

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

_DB_PATH = Path(__file__).with_name("alerts.db")


def _connect():
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


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
                status TEXT DEFAULT 'new'
            )
            """
        )
        conn.commit()


def _insert_alert(alert: Dict) -> None:
    agent_name = alert.get("agent_name")
    agent_ip = alert.get("agent_ip")
    if not agent_name or agent_name == "Unknown agent":
        agent_name = None
    if not agent_ip or agent_ip == "N/A":
        agent_ip = None

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
                status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert.get("timestamp"),
                alert.get("rule_id"),
                int(alert.get("rule_level", 0) or 0),
                alert.get("rule_description"),
                agent_name,
                agent_ip,
                alert.get("src_ip"),
                alert.get("status", "new"),
            ),
        )
        conn.commit()


def add_alert(alert: Dict) -> None:
    # Ensure a consistent timestamp for analytics.
    alert.setdefault("received_at", time.time())
    level = int(alert.get("rule_level", 0) or 0)
    alert["severity_label"] = _severity_bucket(level)

    try:
        _insert_alert(alert)
    except Exception:
        logger.exception("Failed to insert alert into SQLite")

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


def get_assets() -> List[Dict]:
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT
                agent_name,
                agent_ip,
                COUNT(*) as alert_count,
                MAX(timestamp) as last_seen
            FROM alerts
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
    with _lock:
        alerts = list(_alerts)
    if since_seconds is not None:
        cutoff = time.time() - since_seconds
        alerts = [alert for alert in alerts if alert.get("received_at", 0) >= cutoff]
    if severity:
        severity = severity.lower()
        alerts = [
            alert
            for alert in alerts
            if (alert.get("severity_label") or _severity_bucket(int(alert.get("rule_level", 0) or 0))) == severity
        ]
    total = len(alerts)
    page = alerts[offset : offset + limit]
    for alert in page:
        if "severity_label" not in alert:
            alert["severity_label"] = _severity_bucket(int(alert.get("rule_level", 0) or 0))
    return {"alerts": page, "total": total}


def get_metrics() -> Dict:
    with _lock:
        _prune_recent_locked()
        high_count = sum(1 for alert in _alerts if int(alert.get("rule_level", 0) or 0) >= 7)
        active_agents = {name for _, name in _agent_recent}
        suspicious_ips = {ip for _, ip in _ip_recent if _is_public_ip(ip)}
        return {
            "total_alerts": _total_count,
            "critical_alerts": _critical_count,
            "high_alerts": high_count,
            "active_agents": len(active_agents),
            "suspicious_ips": len(suspicious_ips),
            "events_processed": _total_count,
        }


def get_top_attackers(limit: int = 5) -> List[Dict]:
    with _lock:
        _prune_recent_locked()
        counts: Dict[str, int] = defaultdict(int)
        last_seen: Dict[str, float] = {}
        for timestamp, ip in _ip_recent:
            if not _is_public_ip(ip):
                continue
            counts[ip] += 1
            last_seen[ip] = max(last_seen.get(ip, 0), timestamp)

        sorted_ips = sorted(counts.items(), key=lambda item: item[1], reverse=True)[:limit]
        return [
            {
                "src_ip": ip,
                "count": count,
                "country": "Unknown",
                "last_seen": _format_time(last_seen.get(ip, 0)),
            }
            for ip, count in sorted_ips
        ]


def get_rule_statistics(limit: int = 5) -> List[Dict]:
    with _lock:
        _prune_recent_locked()
        counts: Dict[str, int] = defaultdict(int)
        descriptions: Dict[str, str] = {}
        for _, rule_id, rule_desc in _rule_recent:
            counts[rule_id] += 1
            descriptions[rule_id] = rule_desc

        top_rules = sorted(counts.items(), key=lambda item: item[1], reverse=True)[:limit]
        return [
            {
                "rule_id": rule_id,
                "rule_description": descriptions.get(rule_id, "Unknown"),
                "count": count,
                "sparkline": _sparkline_for_rule(rule_id),
            }
            for rule_id, count in top_rules
        ]


def get_risky_hosts(limit: int = 5) -> List[Dict]:
    with _lock:
        counts: Dict[str, int] = defaultdict(int)
        max_severity: Dict[str, int] = defaultdict(int)
        last_activity: Dict[str, float] = {}
        for alert in _alerts:
            name = str(alert.get("agent_name") or "Unknown")
            counts[name] += 1
            level = int(alert.get("rule_level", 0) or 0)
            max_severity[name] = max(max_severity[name], level)
            last_activity[name] = max(last_activity.get(name, 0), alert.get("received_at", 0))

        top_hosts = sorted(counts.items(), key=lambda item: item[1], reverse=True)[:limit]
        return [
            {
                "host": host,
                "count": count,
                "highest_severity": max_severity.get(host, 0),
                "last_activity": _format_time(last_activity.get(host, 0)),
            }
            for host, count in top_hosts
        ]


def get_alerts_over_time(window_minutes: int = 60, bucket_seconds: int = 300) -> Dict:
    with _lock:
        now = time.time()
        window_start = now - window_minutes * 60
        bucket_count = window_minutes * 60 // bucket_seconds

        labels = []
        buckets = [
            {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for _ in range(int(bucket_count))
        ]

        for alert in _alerts:
            ts = alert.get("received_at", now)
            if ts < window_start:
                continue
            bucket_index = int((ts - window_start) // bucket_seconds)
            if bucket_index < 0 or bucket_index >= len(buckets):
                continue
            level = int(alert.get("rule_level", 0) or 0)
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


_init_db()
