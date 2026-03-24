import json
import logging
import os
import sys
import time

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from alert_store import insert_alert, get_geo_for_ip, get_recent_events_for_correlation
from correlation import correlate_and_store
from enrichment import enrich_ip
from mitre_map import MITRE_RULE_MAP, MITRE_TACTIC_MAP
from opensearch_client import index_event
from redis_queue.redis_client import get_client


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("freshstart.worker")


def normalize_alert(raw: dict) -> dict:
    agent = raw.get("agent", {})
    rule = raw.get("rule", {})
    data = raw.get("data", {}) if isinstance(raw.get("data"), dict) else {}
    win = data.get("win", {}) if isinstance(data.get("win"), dict) else {}
    win_event = win.get("eventdata", {}) if isinstance(win.get("eventdata"), dict) else {}
    aws = data.get("aws", {}) if isinstance(data.get("aws"), dict) else {}
    event_category = None
    if isinstance(rule.get("groups"), list) and rule.get("groups"):
        event_category = rule.get("groups")[0]
    source_ip = (
        data.get("srcip")
        or raw.get("srcip")
        or win_event.get("IpAddress")
        or win_event.get("ipAddress")
        or aws.get("sourceIPAddress")
    )
    destination_ip = data.get("dstip")
    username = win_event.get("TargetUserName") or data.get("user")

    rule_id = rule.get("id") or raw.get("rule_id") or "Unknown"
    rule_description = rule.get("description") or raw.get("description") or raw.get("full_log") or "No description"
    mitre = rule.get("mitre", {}) if isinstance(rule.get("mitre"), dict) else {}
    mitre_ids = mitre.get("id") if isinstance(mitre.get("id"), list) else None
    if not mitre_ids and rule_id in MITRE_RULE_MAP:
        mitre_ids = MITRE_RULE_MAP.get(rule_id)
    mitre_tactics = mitre.get("tactic") if isinstance(mitre.get("tactic"), list) else None
    if not mitre_tactics and mitre_ids:
        first = mitre_ids[0] if isinstance(mitre_ids, list) and mitre_ids else None
        if first and first in MITRE_TACTIC_MAP:
            mitre_tactics = MITRE_TACTIC_MAP.get(first)
    rule_level = rule.get("level")
    if rule_level is None:
        rule_level = raw.get("severity", 0)
    if isinstance(rule_level, str):
        severity_map = {"low": 1, "medium": 5, "high": 8, "critical": 12}
        rule_level = severity_map.get(rule_level.lower(), 0)

    severity = int(rule_level or 0)
    if severity <= 3:
        severity_label = "LOW"
    elif severity <= 6:
        severity_label = "MEDIUM"
    elif severity <= 9:
        severity_label = "HIGH"
    else:
        severity_label = "CRITICAL"

    event_time = raw.get("timestamp") or raw.get("@timestamp")
    ingested_at = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
    return {
        "event_id": raw.get("id") or raw.get("event_id"),
        "event_time": event_time,
        "ingested_at": ingested_at,
        "timestamp": event_time or "Unknown",
        "agent_name": agent.get("name"),
        "agent_ip": agent.get("ip"),
        "host": agent.get("name"),
        "rule_id": rule_id,
        "rule_description": rule_description,
        "severity": severity,
        "severity_label": severity_label,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "username": username,
        "event_category": event_category,
        "raw_event": json.dumps(raw, ensure_ascii=False),
        "mitre_ids": json.dumps(mitre_ids) if mitre_ids else None,
        "mitre_tactics": json.dumps(mitre_tactics) if mitre_tactics else None,
        "alert_status": "NEW",
        "rule_level": severity,
        "src_ip": source_ip,
        "protocol": data.get("proto") or data.get("protocol") or raw.get("protocol") or "N/A",
    }


def run_worker():
    logger.info("Worker started")
    while True:
        client = get_client()
        item = client.brpop("alerts_queue", timeout=5)
        if not item:
            continue
        _, payload = item
        try:
            print("Worker received alert from Redis")
            raw = json.loads(payload)
            if isinstance(raw, dict) and isinstance(raw.get("message"), dict):
                raw = raw["message"]
            elif isinstance(raw, dict) and isinstance(raw.get("message"), str):
                try:
                    raw = json.loads(raw["message"])
                except Exception:
                    pass
            alert = normalize_alert(raw)
            enrichment = enrich_ip(alert.get("source_ip"))
            if enrichment:
                alert.update(enrichment)
            logger.info("Received alert rule_id=%s", alert.get("rule_id"))
            insert_alert(alert)
            index_event(alert)
            geo = get_geo_for_ip(alert.get("source_ip"))
            if geo:
                alert["geo_lat"] = geo[0]
                alert["geo_lon"] = geo[1]
                alert["geo_country"] = geo[2]
            try:
                recent = get_recent_events_for_correlation(alert.get("source_ip"))
                correlate_and_store(alert, recent)
            except Exception:
                logger.exception("Correlation failed for alert %s", alert.get("event_id"))
            client.publish("alerts_stream", json.dumps(alert))
            print("Alert inserted into SQLite")
            logger.info("Alert stored successfully")
        except Exception:
            logger.exception("Failed to process alert payload")
            time.sleep(0.2)


if __name__ == "__main__":
    run_worker()
