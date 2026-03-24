import json
import os
from pathlib import Path
from typing import Dict, Optional

import requests
import yaml


_settings_path = Path(__file__).with_name("config.yaml")


def _load_settings() -> dict:
    if not _settings_path.exists():
        return {}
    with _settings_path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def _config() -> dict | None:
    settings = _load_settings()
    url = os.getenv("OPENSEARCH_URL") or settings.get("opensearch_url")
    if not url:
        return None
    return {
        "url": url.rstrip("/"),
        "user": os.getenv("OPENSEARCH_USER") or settings.get("opensearch_user"),
        "password": os.getenv("OPENSEARCH_PASSWORD") or settings.get("opensearch_password"),
        "index": os.getenv("OPENSEARCH_EVENTS_INDEX")
        or settings.get("opensearch_events_index")
        or "freshstart-events",
    }


def _session():
    session = requests.Session()
    session.trust_env = False
    return session


def _post_search(body: dict) -> dict | None:
    config = _config()
    if not config:
        return None
    auth = (config["user"], config["password"]) if config.get("user") else None
    url = f"{config['url']}/{config['index']}/_search"
    session = _session()
    response = session.post(
        url,
        data=json.dumps(body),
        headers={"Content-Type": "application/json"},
        auth=auth,
        verify=False,
        proxies={"http": None, "https": None},
        timeout=(5, 20),
    )
    if not response.ok:
        return None
    return response.json()


def _terms_field(field: str) -> str:
    if field.endswith(".keyword"):
        return field
    return f"{field}.keyword"


def _safe_terms(field: str, size: int = 10):
    return {"terms": {"field": _terms_field(field), "size": size}}


def index_event(event: Dict) -> bool:
    config = _config()
    if not config:
        return False
    event_id = event.get("event_id")
    if not event_id:
        return False
    auth = (config["user"], config["password"]) if config.get("user") else None
    url = f"{config['url']}/{config['index']}/_doc/{event_id}"
    session = _session()
    try:
        doc = dict(event)
        if "timestamp" in doc and "event_time" not in doc:
            doc["event_time"] = doc.get("timestamp")
        if "ingested_at" not in doc:
            doc["ingested_at"] = event.get("ingested_at")
        response = session.put(
            url,
            data=json.dumps(doc),
            headers={"Content-Type": "application/json"},
            auth=auth,
            verify=False,
            proxies={"http": None, "https": None},
            timeout=(5, 15),
        )
        response.raise_for_status()
        return True
    except Exception:
        return False


def search_events(limit: int = 20, offset: int = 0, timerange: Optional[str] = None, severity: Optional[str] = None):
    config = _config()
    if not config:
        return {"alerts": [], "total": 0}
    auth = (config["user"], config["password"]) if config.get("user") else None
    url = f"{config['url']}/{config['index']}/_search"
    must = []
    if timerange:
        must.append({"range": {"timestamp": {"gte": f"now-{timerange}"}}})
    if severity:
        must.append({"term": {_terms_field("severity_label"): severity.upper()}})
    query = {"bool": {"must": must}} if must else {"match_all": {}}
    body = {
        "from": offset,
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": query,
    }
    session = _session()
    response = session.post(
        url,
        data=json.dumps(body),
        headers={"Content-Type": "application/json"},
        auth=auth,
        verify=False,
        proxies={"http": None, "https": None},
        timeout=(5, 15),
    )
    response.raise_for_status()
    payload = response.json()
    hits = payload.get("hits", {})
    total = hits.get("total", {}).get("value", 0) if isinstance(hits.get("total"), dict) else hits.get("total", 0)
    alerts = []
    for hit in hits.get("hits", []):
        source = hit.get("_source", {}) or {}
        source["_opensearch_id"] = hit.get("_id")
        if "event_id" not in source and hit.get("_id"):
            source["event_id"] = hit.get("_id")
        if not source.get("timestamp") and source.get("event_time"):
            source["timestamp"] = source.get("event_time")
    alerts.append(source)
    return {"alerts": alerts, "total": total}


def get_event_by_id(event_id: str) -> Optional[Dict]:
    config = _config()
    if not config:
        return None
    auth = (config["user"], config["password"]) if config.get("user") else None
    url = f"{config['url']}/{config['index']}/_doc/{event_id}"
    session = _session()
    response = session.get(
        url,
        auth=auth,
        verify=False,
        proxies={"http": None, "https": None},
        timeout=(5, 15),
    )
    if not response.ok:
        return None
    payload = response.json()
    source = payload.get("_source", {}) or {}
    source["_opensearch_id"] = payload.get("_id")
    if "event_id" not in source:
        source["event_id"] = payload.get("_id")
    return source


def count_by_severity():
    config = _config()
    if not config:
        return {"critical": 0, "high": 0, "medium": 0, "low": 0}
    auth = (config["user"], config["password"]) if config.get("user") else None
    url = f"{config['url']}/{config['index']}/_search"
    body = {
        "size": 0,
        "aggs": {
            "by_severity": {
                "terms": {"field": "severity_label.keyword", "size": 10}
            }
        },
    }
    session = _session()
    response = session.post(
        url,
        data=json.dumps(body),
        headers={"Content-Type": "application/json"},
        auth=auth,
        verify=False,
        proxies={"http": None, "https": None},
        timeout=(5, 15),
    )
    if not response.ok:
        return {"critical": 0, "high": 0, "medium": 0, "low": 0}
    buckets = response.json().get("aggregations", {}).get("by_severity", {}).get("buckets", [])
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for bucket in buckets:
        key = str(bucket.get("key") or "").lower()
        if key in counts:
            counts[key] = int(bucket.get("doc_count") or 0)
    return counts


def count_total():
    config = _config()
    if not config:
        return 0
    auth = (config["user"], config["password"]) if config.get("user") else None
    url = f"{config['url']}/{config['index']}/_count"
    session = _session()
    response = session.get(
        url,
        auth=auth,
        verify=False,
        proxies={"http": None, "https": None},
        timeout=(5, 15),
    )
    if not response.ok:
        return 0
    return int(response.json().get("count") or 0)


def count_distinct(field: str) -> int:
    config = _config()
    if not config:
        return 0
    body = {"size": 0, "aggs": {"uniq": {"cardinality": {"field": _terms_field(field)}}}}
    payload = _post_search(body)
    if not payload:
        return 0
    return int(payload.get("aggregations", {}).get("uniq", {}).get("value") or 0)


def distinct_source_ips(limit: int = 10000) -> list[str]:
    body = {
        "size": 0,
        "aggs": {"ips": _safe_terms("source_ip", size=limit)},
    }
    payload = _post_search(body)
    if not payload:
        return []
    buckets = payload.get("aggregations", {}).get("ips", {}).get("buckets", [])
    return [bucket.get("key") for bucket in buckets if bucket.get("key")]


def get_top_attackers(limit: int = 5) -> list[Dict]:
    body = {
        "size": 0,
        "aggs": {
            "by_ip": {
                "terms": {"field": _terms_field("source_ip"), "size": 50},
                "aggs": {
                    "max_severity": {"max": {"field": "severity"}},
                    "last_seen": {"max": {"field": "timestamp"}},
                    "country": {"terms": {"field": _terms_field("geo_country"), "size": 1}},
                },
            }
        },
    }
    payload = _post_search(body)
    if not payload:
        return []
    attackers = []
    for bucket in payload.get("aggregations", {}).get("by_ip", {}).get("buckets", []):
        country_bucket = bucket.get("country", {}).get("buckets", [])
        attackers.append(
            {
                "src_ip": bucket.get("key"),
                "count": int(bucket.get("doc_count") or 0),
                "country": country_bucket[0].get("key") if country_bucket else "Unknown",
                "last_seen": bucket.get("last_seen", {}).get("value_as_string"),
                "severity": int(bucket.get("max_severity", {}).get("value") or 0),
            }
        )
    attackers.sort(key=lambda item: item["count"], reverse=True)
    return attackers[:limit]


def get_rule_statistics(limit: int = 5) -> list[Dict]:
    body = {
        "size": 0,
        "aggs": {
            "by_rule": {
                "terms": {"field": _terms_field("rule_id"), "size": max(limit, 20)},
                "aggs": {
                    "desc": {"terms": {"field": _terms_field("rule_description"), "size": 1}},
                    "max_severity": {"max": {"field": "severity"}},
                },
            }
        },
    }
    payload = _post_search(body)
    if not payload:
        return []
    rules = []
    for bucket in payload.get("aggregations", {}).get("by_rule", {}).get("buckets", []):
        desc_bucket = bucket.get("desc", {}).get("buckets", [])
        rules.append(
            {
                "rule_id": bucket.get("key"),
                "rule_description": desc_bucket[0].get("key") if desc_bucket else bucket.get("key"),
                "count": int(bucket.get("doc_count") or 0),
                "severity": int(bucket.get("max_severity", {}).get("value") or 0),
                "sparkline": [],
            }
        )
    rules.sort(key=lambda item: item["count"], reverse=True)
    return rules[:limit]


def get_alerts_over_time(window_minutes: int = 60, bucket_seconds: int = 300) -> Dict:
    interval = f"{bucket_seconds}s"
    body = {
        "size": 0,
        "query": {"range": {"timestamp": {"gte": f"now-{window_minutes}m"}}},
        "aggs": {
            "timeline": {
                "date_histogram": {
                    "field": "timestamp",
                    "fixed_interval": interval,
                    "min_doc_count": 0,
                    "extended_bounds": {"min": f"now-{window_minutes}m", "max": "now"},
                },
                "aggs": {
                    "by_severity": {"terms": {"field": _terms_field("severity_label"), "size": 10}}
                },
            }
        },
    }
    payload = _post_search(body)
    if not payload:
        return {"labels": [], "series": {"critical": [], "high": [], "medium": [], "low": []}}
    buckets = payload.get("aggregations", {}).get("timeline", {}).get("buckets", [])
    labels = []
    series = {"critical": [], "high": [], "medium": [], "low": []}
    for bucket in buckets:
        labels.append(bucket.get("key_as_string", "")[11:16] if bucket.get("key_as_string") else "")
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for sev in bucket.get("by_severity", {}).get("buckets", []):
            key = str(sev.get("key") or "").lower()
            if key in counts:
                counts[key] = int(sev.get("doc_count") or 0)
        for key in series:
            series[key].append(counts[key])
    return {"labels": labels, "series": series}


def get_risky_hosts(limit: int = 5) -> list[Dict]:
    body = {
        "size": 0,
        "aggs": {
            "by_host": {
                "terms": {"field": _terms_field("agent_name"), "size": max(limit, 20)},
                "aggs": {
                    "max_severity": {"max": {"field": "severity"}},
                    "last_seen": {"max": {"field": "timestamp"}},
                },
            }
        },
    }
    payload = _post_search(body)
    if not payload:
        return []
    hosts = []
    for bucket in payload.get("aggregations", {}).get("by_host", {}).get("buckets", []):
        hosts.append(
            {
                "host": bucket.get("key"),
                "count": int(bucket.get("doc_count") or 0),
                "highest_severity": int(bucket.get("max_severity", {}).get("value") or 0),
                "last_activity": bucket.get("last_seen", {}).get("value_as_string"),
            }
        )
    hosts.sort(key=lambda item: item["count"], reverse=True)
    return hosts[:limit]


def get_risk_scores(limit: int = 10) -> list[Dict]:
    body = {
        "size": 0,
        "aggs": {
            "by_host": {
                "terms": {"field": _terms_field("agent_name"), "size": max(limit, 50)},
                "aggs": {
                    "critical": {"filter": {"range": {"severity": {"gte": 10}}}},
                    "high": {"filter": {"range": {"severity": {"gte": 7, "lte": 9}}}},
                    "medium": {"filter": {"range": {"severity": {"gte": 4, "lte": 6}}}},
                    "last_seen": {"max": {"field": "timestamp"}},
                },
            }
        },
    }
    payload = _post_search(body)
    if not payload:
        return []
    results = []
    for bucket in payload.get("aggregations", {}).get("by_host", {}).get("buckets", []):
        critical = int(bucket.get("critical", {}).get("doc_count") or 0)
        high = int(bucket.get("high", {}).get("doc_count") or 0)
        medium = int(bucket.get("medium", {}).get("doc_count") or 0)
        score = critical * 5 + high * 3 + medium
        results.append(
            {
                "host": bucket.get("key"),
                "risk_score": score,
                "critical": critical,
                "high": high,
                "medium": medium,
                "last_seen": bucket.get("last_seen", {}).get("value_as_string"),
            }
        )
    results.sort(key=lambda item: item["risk_score"], reverse=True)
    return results[:limit]


def get_mitre_stats(limit: int = 10) -> list[Dict]:
    body = {
        "size": 0,
        "aggs": {"by_mitre": {"terms": {"field": _terms_field("mitre_ids"), "size": 200}}},
    }
    payload = _post_search(body)
    if not payload:
        return []
    stats = []
    for bucket in payload.get("aggregations", {}).get("by_mitre", {}).get("buckets", []):
        key = bucket.get("key")
        if not key:
            continue
        try:
            parsed = json.loads(key) if isinstance(key, str) and key.startswith("[") else key
        except Exception:
            parsed = key
        if isinstance(parsed, list):
            for mid in parsed:
                stats.append({"technique": mid, "count": int(bucket.get("doc_count") or 0), "tactics": []})
        else:
            stats.append({"technique": parsed, "count": int(bucket.get("doc_count") or 0), "tactics": []})
    stats.sort(key=lambda item: item["count"], reverse=True)
    return stats[:limit]


def get_attack_map_agg(limit: int = 200) -> list[Dict]:
    body = {
        "size": 0,
        "aggs": {
            "by_geo": {
                "composite": {
                    "size": limit,
                    "sources": [
                        {"lat": {"terms": {"field": "geo_lat"}}},
                        {"lon": {"terms": {"field": "geo_lon"}}},
                        {"country": {"terms": {"field": _terms_field("geo_country")}}},
                    ],
                },
                "aggs": {"max_severity": {"max": {"field": "severity"}}},
            }
        },
    }
    payload = _post_search(body)
    if not payload:
        return []
    points = []
    for bucket in payload.get("aggregations", {}).get("by_geo", {}).get("buckets", []):
        key = bucket.get("key") or {}
        lat = key.get("lat")
        lon = key.get("lon")
        if lat is None or lon is None:
            continue
        points.append(
            {
                "country": key.get("country") or "Unknown",
                "lat": lat,
                "lon": lon,
                "count": int(bucket.get("doc_count") or 0),
                "severity": int(bucket.get("max_severity", {}).get("value") or 0),
            }
        )
    return points


def get_assets(limit: int = 200) -> list[Dict]:
    body = {
        "size": 0,
        "aggs": {
            "by_asset": {
                "composite": {
                    "size": limit,
                    "sources": [
                        {"agent_name": {"terms": {"field": _terms_field("agent_name")}}},
                        {"agent_ip": {"terms": {"field": _terms_field("agent_ip")}}},
                    ],
                },
                "aggs": {"last_seen": {"max": {"field": "timestamp"}}},
            }
        },
    }
    payload = _post_search(body)
    if not payload:
        return []
    assets = []
    for bucket in payload.get("aggregations", {}).get("by_asset", {}).get("buckets", []):
        key = bucket.get("key") or {}
        assets.append(
            {
                "name": key.get("agent_name"),
                "ip": key.get("agent_ip"),
                "alerts": int(bucket.get("doc_count") or 0),
                "last_seen": bucket.get("last_seen", {}).get("value_as_string"),
            }
        )
    assets.sort(key=lambda item: item.get("last_seen") or "", reverse=True)
    return assets


def get_attacker_profiles(limit: int = 5) -> list[Dict]:
    body = {
        "size": 0,
        "aggs": {
            "by_ip": {
                "terms": {"field": _terms_field("source_ip"), "size": max(limit, 20)},
                "aggs": {
                    "targets": {"cardinality": {"field": _terms_field("agent_name")}},
                    "last_seen": {"max": {"field": "timestamp"}},
                    "country": {"terms": {"field": _terms_field("geo_country"), "size": 1}},
                    "attack_types": {"terms": {"field": _terms_field("rule_description"), "size": 3}},
                    "max_severity": {"max": {"field": "severity"}},
                },
            }
        },
    }
    payload = _post_search(body)
    if not payload:
        return []
    profiles = []
    for bucket in payload.get("aggregations", {}).get("by_ip", {}).get("buckets", []):
        country_bucket = bucket.get("country", {}).get("buckets", [])
        attack_types = bucket.get("attack_types", {}).get("buckets", [])
        profiles.append(
            {
                "src_ip": bucket.get("key"),
                "count": int(bucket.get("doc_count") or 0),
                "targets": int(bucket.get("targets", {}).get("value") or 0),
                "country": country_bucket[0].get("key") if country_bucket else "Unknown",
                "attack_types": [item.get("key") for item in attack_types if item.get("key")],
                "last_seen": bucket.get("last_seen", {}).get("value_as_string"),
                "severity": int(bucket.get("max_severity", {}).get("value") or 0),
            }
        )
    profiles.sort(key=lambda item: item["count"], reverse=True)
    return profiles[:limit]


def get_threat_profile(ip: str) -> Dict:
    body = {
        "size": 0,
        "query": {"term": {_terms_field("source_ip"): ip}},
        "aggs": {
            "targets": {"cardinality": {"field": _terms_field("agent_name")}},
            "last_seen": {"max": {"field": "timestamp"}},
            "country": {"terms": {"field": _terms_field("geo_country"), "size": 1}},
            "city": {"terms": {"field": _terms_field("geo_city"), "size": 1}},
            "asn": {"terms": {"field": _terms_field("asn"), "size": 1}},
            "isp": {"terms": {"field": _terms_field("isp"), "size": 1}},
            "abuse_score": {"max": {"field": "abuse_score"}},
            "threat_level": {"terms": {"field": _terms_field("threat_level"), "size": 1}},
            "recent": {
                "top_hits": {
                    "size": 10,
                    "sort": [{"timestamp": {"order": "desc"}}],
                    "_source": ["timestamp", "rule_description", "severity"],
                }
            },
        },
    }
    payload = _post_search(body)
    if not payload:
        return {"src_ip": ip, "alert_count": 0, "recent_alerts": []}
    total = payload.get("hits", {}).get("total", {})
    count = total.get("value") if isinstance(total, dict) else total or 0
    aggs = payload.get("aggregations", {})
    def _bucket_value(key):
        buckets = aggs.get(key, {}).get("buckets", [])
        return buckets[0].get("key") if buckets else None
    recent_hits = aggs.get("recent", {}).get("hits", {}).get("hits", [])
    return {
        "src_ip": ip,
        "alert_count": int(count or 0),
        "targets": int(aggs.get("targets", {}).get("value") or 0),
        "last_seen": aggs.get("last_seen", {}).get("value_as_string"),
        "country": _bucket_value("country"),
        "city": _bucket_value("city"),
        "asn": _bucket_value("asn"),
        "isp": _bucket_value("isp"),
        "abuse_score": int(aggs.get("abuse_score", {}).get("value") or 0),
        "threat_level": _bucket_value("threat_level"),
        "recent_alerts": [
            {
                "timestamp": hit.get("_source", {}).get("timestamp"),
                "rule_description": hit.get("_source", {}).get("rule_description"),
                "severity": hit.get("_source", {}).get("severity"),
            }
            for hit in recent_hits
        ],
    }
