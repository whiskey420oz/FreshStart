import logging
import time
from datetime import datetime, timezone
from typing import Dict, List, Tuple

from alert_store import upsert_incident

logger = logging.getLogger("freshstart.correlation")


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


def _severity_label(levels: List[int]) -> str:
    max_level = max(levels) if levels else 0
    if max_level >= 10:
        return "critical"
    if max_level >= 7:
        return "high"
    if max_level >= 4:
        return "medium"
    return "low"


def _looks_like_auth_failure(description: str) -> bool:
    text = (description or "").lower()
    return any(
        keyword in text
        for keyword in (
            "logon failure",
            "authentication failed",
            "failed password",
            "ssh",
            "invalid user",
        )
    )


def correlate_recent_events(events: List[Dict]) -> List[Tuple[str, Dict]]:
    incidents = []
    if not events:
        return incidents

    now = time.time()
    by_src = {}
    for event in events:
        src = event.get("source_ip")
        if not src:
            continue
        by_src.setdefault(src, []).append(event)

    for src_ip, src_events in by_src.items():
        # Brute force detection: >=5 auth failures in 5 minutes.
        auth_events = [
            e
            for e in src_events
            if _looks_like_auth_failure(e.get("rule_description"))
            and now - _parse_timestamp(e.get("timestamp")) <= 300
        ]
        if len(auth_events) >= 5:
            incidents.append(
                (
                    "SSH Brute Force Attempt",
                    {
                        "incident_type": "ssh_bruteforce",
                        "events": auth_events,
                        "src_ip": src_ip,
                        "targets": {e.get("agent_name") for e in auth_events if e.get("agent_name")},
                    },
                )
            )

        # Lateral movement: same IP hits >=3 hosts in 10 minutes.
        recent_events = [
            e for e in src_events if now - _parse_timestamp(e.get("timestamp")) <= 600
        ]
        targets = {e.get("agent_name") for e in recent_events if e.get("agent_name")}
        if len(targets) >= 3:
            incidents.append(
                (
                    "Possible Lateral Movement",
                    {
                        "incident_type": "lateral_movement",
                        "events": recent_events,
                        "src_ip": src_ip,
                        "targets": targets,
                    },
                )
            )

        # Port scan: >=20 events in 5 minutes from the same IP.
        scan_events = [
            e for e in src_events if now - _parse_timestamp(e.get("timestamp")) <= 300
        ]
        if len(scan_events) >= 20:
            incidents.append(
                (
                    "Port Scan Detected",
                    {
                        "incident_type": "port_scan",
                        "events": scan_events,
                        "src_ip": src_ip,
                        "targets": {e.get("agent_name") for e in scan_events if e.get("agent_name")},
                    },
                )
            )

    return incidents


def correlate_and_store(event: Dict, recent_events: List[Dict]) -> List[int]:
    incident_ids = []
    for title, data in correlate_recent_events(recent_events):
        levels = [int(e.get("severity") or 0) for e in data.get("events", [])]
        severity = _severity_label(levels)
        timestamps = [
            _parse_timestamp(e.get("timestamp"))
            for e in data.get("events", [])
            if e.get("timestamp")
        ]
        first_seen = (
            datetime.fromtimestamp(min(timestamps), tz=timezone.utc).isoformat()
            if timestamps
            else datetime.now(timezone.utc).isoformat()
        )
        last_seen = (
            datetime.fromtimestamp(max(timestamps), tz=timezone.utc).isoformat()
            if timestamps
            else datetime.now(timezone.utc).isoformat()
        )
        alert_ids = [
            int(e.get("id"))
            for e in data.get("events", [])
            if e.get("id") is not None
        ]
        incident_id = upsert_incident(
            incident_type=data.get("incident_type"),
            severity=severity,
            first_seen=first_seen,
            last_seen=last_seen,
            related_alerts=alert_ids,
            src_ip=data.get("src_ip"),
            target_hosts=list(data.get("targets", [])),
        )
        logger.info("Correlation created/updated incident %s (%s)", incident_id, title)
        incident_ids.append(incident_id)
    return incident_ids
