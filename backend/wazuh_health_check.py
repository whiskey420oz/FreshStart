import json
import shutil
import ssl
import subprocess
import sys
from datetime import datetime, timezone
from typing import Dict, List
from urllib.request import urlopen


CHECKS = [
    {
        "id": "wazuh_manager_status",
        "description": "Verify Wazuh manager service status",
        "command": ["systemctl", "status", "wazuh-manager"],
    },
    {
        "id": "wazuh_manager_logs",
        "description": "Check manager logs for queue overflow or flood warnings",
        "command": ["sudo", "tail", "-n", "500", "/var/ossec/logs/ossec.log"],
    },
    {
        "id": "opensearch_health",
        "description": "Verify OpenSearch cluster health",
        "command": "https://localhost:9200/_cluster/health?pretty",
    },
    {
        "id": "system_cpu",
        "description": "Check CPU usage",
        "command": ["bash", "-lc", "top -b -n 1 | head -n 15"],
    },
    {
        "id": "system_ram",
        "description": "Check RAM usage",
        "command": ["free", "-h"],
    },
    {
        "id": "system_disk_io",
        "description": "Check disk I/O",
        "command": ["bash", "-lc", "iostat -xz 1 3"],
    },
    {
        "id": "system_network_latency",
        "description": "Check network latency",
        "command": ["ping", "-c", "4", "8.8.8.8"],
    },
    {
        "id": "top_log_sources",
        "description": "Identify top log sources by volume",
        "command": ["bash", "-lc", "awk '{print $5}' /var/ossec/logs/ossec.log | sort | uniq -c | sort -nr | head -n 10"],
    },
    {
        "id": "event_drop_or_delay",
        "description": "Determine if events are being dropped or delayed",
        "command": ["bash", "-lc", "grep -E 'dropped|discard|queue is full|queue is 90% full|flood' /var/ossec/logs/ossec.log | tail -n 50"],
    },
]


QUEUE_PATTERNS = [
    "queue is full",
    "queue is 90% full",
    "flood",
    "discarding event",
    "event dropped",
    "overflow",
]


def _run_command(cmd) -> Dict:
    if isinstance(cmd, str) and cmd.startswith("https://"):
        return _fetch_url(cmd)

    if isinstance(cmd, list) and cmd and cmd[0] not in {"bash", "sh"}:
        if shutil.which(cmd[0]) is None:
            return {"ok": False, "error": f"Command not found: {cmd[0]}", "stdout": "", "stderr": ""}

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return {
            "ok": result.returncode == 0,
            "stdout": (result.stdout or "").strip(),
            "stderr": (result.stderr or "").strip(),
            "returncode": result.returncode,
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc), "stdout": "", "stderr": ""}


def _fetch_url(url: str) -> Dict:
    try:
        context = ssl._create_unverified_context()
        with urlopen(url, context=context, timeout=10) as response:
            body = response.read().decode("utf-8", errors="ignore")
        return {"ok": True, "stdout": body, "stderr": "", "returncode": 0}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "stdout": "", "stderr": ""}


def _extract_queue_findings(log_text: str) -> List[str]:
    hits = []
    if not log_text:
        return hits
    lower = log_text.lower()
    for pattern in QUEUE_PATTERNS:
        if pattern in lower:
            hits.append(pattern)
    return hits


def _summarize_opensearch(stdout: str) -> str:
    try:
        data = json.loads(stdout)
        return data.get("status", "unknown")
    except Exception:
        return "unknown"


def _build_report(checks: Dict) -> Dict:
    manager_status = checks.get("wazuh_manager_status", {})
    logs = checks.get("wazuh_manager_logs", {})
    os_health = checks.get("opensearch_health", {})

    queue_hits = _extract_queue_findings(logs.get("stdout", ""))
    os_status = _summarize_opensearch(os_health.get("stdout", ""))

    report = {
        "Wazuh_Manager_Status": {
            "status": "healthy" if manager_status.get("ok") else "unhealthy",
            "evidence": manager_status.get("stdout", "")[:2000],
        },
        "Event_Queue_Status": {
            "status": "degraded" if queue_hits else "ok",
            "evidence": queue_hits or "No queue overflow indicators found.",
        },
        "OpenSearch_Health": {
            "status": os_status,
            "evidence": os_health.get("stdout", "")[:2000] if os_health.get("ok") else os_health.get("error"),
        },
        "System_Resource_Usage": {
            "cpu": checks.get("system_cpu", {}).get("stdout", ""),
            "ram": checks.get("system_ram", {}).get("stdout", ""),
            "disk_io": checks.get("system_disk_io", {}).get("stdout", ""),
            "network_latency": checks.get("system_network_latency", {}).get("stdout", ""),
        },
        "Log_Volume_Analysis": {
            "top_sources": checks.get("top_log_sources", {}).get("stdout", ""),
            "notes": checks.get("event_drop_or_delay", {}).get("stdout", ""),
        },
        "Recommended_Action": [],
    }

    actions = []
    if queue_hits:
        actions.append("Increase Wazuh agent queue buffer")
        actions.append("Reduce log collection volume")
        actions.append("Investigate abnormal log floods")
    if os_status == "red":
        actions.append("Scale OpenSearch indexing")
    if not actions:
        actions.append("Confirm system is healthy if issue is temporary")
    report["Recommended_Action"] = actions
    return report


def main():
    results = {}
    for check in CHECKS:
        result = _run_command(check["command"])
        results[check["id"]] = result

    report = _build_report(results)
    output = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": results,
        "report": report,
    }
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    sys.exit(main())
