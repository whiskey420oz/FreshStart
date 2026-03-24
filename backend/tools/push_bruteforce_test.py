import json
import time
from datetime import datetime, timezone

from backend.redis_queue.redis_client import get_client


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def main():
    client = get_client()
    src_ip = "185.220.101.5"
    agent = {"id": "008", "name": "LAB-FreshStart", "ip": "192.168.33.203"}
    rule = {"id": "5710", "level": 8, "description": "SSH authentication failed."}

    for _ in range(6):
        payload = {
            "timestamp": _now_iso(),
            "rule": rule,
            "agent": agent,
            "data": {"srcip": src_ip, "protocol": "ssh"},
        }
        client.lpush("alerts_queue", json.dumps(payload))
        time.sleep(0.2)

    print("Bruteforce test alerts pushed to Redis.")


if __name__ == "__main__":
    main()
