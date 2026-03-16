import threading
import time
from collections import deque
from queue import Queue
from typing import Deque, Dict, List, Tuple

_MAX_ALERTS = 500
_alerts: Deque[Dict] = deque(maxlen=_MAX_ALERTS)
_lock = threading.Lock()
_subscribers: List[Queue] = []
_total_count = 0
_critical_count = 0
_rule_recent: Deque[Tuple[float, str]] = deque()


def add_alert(alert: Dict) -> None:
    with _lock:
        global _total_count, _critical_count
        _alerts.appendleft(alert)
        _total_count += 1
        if int(alert.get("rule_level", 0) or 0) >= 10:
            _critical_count += 1
        rule_id = alert.get("rule_id") or "Unknown"
        _rule_recent.append((time.time(), str(rule_id)))
        _prune_rule_recent_locked()
        for subscriber in list(_subscribers):
            _push_to_subscriber(subscriber, alert)


def get_recent_alerts(limit: int = 50) -> List[Dict]:
    with _lock:
        return list(_alerts)[:limit]


def get_alert_count() -> int:
    with _lock:
        return len(_alerts)


def subscribe() -> Queue:
    queue = Queue(maxsize=100)
    with _lock:
        _subscribers.append(queue)
    return queue


def unsubscribe(queue: Queue) -> None:
    with _lock:
        if queue in _subscribers:
            _subscribers.remove(queue)


def get_stats() -> Dict:
    with _lock:
        _prune_rule_recent_locked()
        top_rules = _get_top_rules_locked()
        return {
            "total": _total_count,
            "critical": _critical_count,
            "top_rules": top_rules,
        }


def _push_to_subscriber(queue: Queue, alert: Dict) -> None:
    try:
        queue.put_nowait(alert)
    except Exception:
        pass


def _prune_rule_recent_locked() -> None:
    cutoff = time.time() - 300
    while _rule_recent and _rule_recent[0][0] < cutoff:
        _rule_recent.popleft()


def _get_top_rules_locked() -> List[Dict]:
    counts: Dict[str, int] = {}
    for _, rule_id in _rule_recent:
        counts[rule_id] = counts.get(rule_id, 0) + 1
    top = sorted(counts.items(), key=lambda item: item[1], reverse=True)[:5]
    return [{"rule_id": rule_id, "count": count} for rule_id, count in top]
