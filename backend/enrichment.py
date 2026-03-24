import logging
import os
import time
from typing import Dict, Optional

import requests


logger = logging.getLogger("freshstart.enrichment")

_cache: Dict[str, Dict] = {}
_cache_ttl_seconds = 3600


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


def _get_cached(ip: str) -> Optional[Dict]:
    cached = _cache.get(ip)
    if not cached:
        return None
    if time.time() - cached.get("_cached_at", 0) > _cache_ttl_seconds:
        return None
    return cached.copy()


def _set_cached(ip: str, data: Dict) -> None:
    data["_cached_at"] = time.time()
    _cache[ip] = data


def _geo_lookup(ip: str) -> Dict:
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,city,lat,lon,isp,as"},
            timeout=3,
        )
        if response.ok:
            payload = response.json()
            if payload.get("status") == "success":
                return {
                    "geo_country": payload.get("country"),
                    "geo_city": payload.get("city"),
                    "geo_lat": payload.get("lat"),
                    "geo_lon": payload.get("lon"),
                    "isp": payload.get("isp"),
                    "asn": payload.get("as"),
                }
    except Exception:
        logger.exception("Geo/ASN lookup failed for %s", ip)
    return {}


def _abuseipdb_lookup(ip: str) -> Dict:
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return {}
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=5,
        )
        if response.ok:
            payload = response.json().get("data", {})
            score = payload.get("abuseConfidenceScore")
            return {"abuse_score": score}
    except Exception:
        logger.exception("AbuseIPDB lookup failed for %s", ip)
    return {}


def _otx_lookup(ip: str) -> Dict:
    api_key = os.getenv("OTX_API_KEY")
    if not api_key:
        return {}
    try:
        response = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            headers={"X-OTX-API-KEY": api_key},
            timeout=5,
        )
        if response.ok:
            payload = response.json()
            pulse_info = payload.get("pulse_info") or {}
            pulse_count = pulse_info.get("count") or 0
            return {"otx_pulses": pulse_count}
    except Exception:
        logger.exception("OTX lookup failed for %s", ip)
    return {}


def _threat_level(abuse_score: Optional[int], otx_pulses: Optional[int]) -> str:
    score = abuse_score or 0
    pulses = otx_pulses or 0
    if score >= 70 or pulses >= 5:
        return "high"
    if score >= 30 or pulses >= 1:
        return "medium"
    return "low"


def enrich_ip(ip: Optional[str]) -> Dict:
    if not ip or not isinstance(ip, str):
        return {}
    if not _is_public_ip(ip):
        return {}

    cached = _get_cached(ip)
    if cached:
        cached.pop("_cached_at", None)
        return cached

    data = {}
    data.update(_geo_lookup(ip))
    data.update(_abuseipdb_lookup(ip))
    data.update(_otx_lookup(ip))
    data["threat_level"] = _threat_level(data.get("abuse_score"), data.get("otx_pulses"))

    _set_cached(ip, data)
    data.pop("_cached_at", None)
    return data
