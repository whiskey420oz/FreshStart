import json
import random
import time
from datetime import datetime, timezone

from backend.redis_queue.redis_client import get_client


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def main():
    client = get_client()
    agent = {"id": "008", "name": "LAB-FreshStart", "ip": "192.168.33.203"}
    rule = {"id": "5710", "level": 8, "description": "SSH authentication failed."}

    # Public IPs for test simulation
    src_ips = [
        "185.220.101.5",
        "45.155.205.23",
        "91.240.118.172",
        "103.157.96.49",
        "162.247.74.216",
        "185.100.87.41",
        "89.187.163.24",
        "64.227.132.144",
    ]

    for _ in range(40):
        src_ip = random.choice(src_ips)
        payload = {
            "timestamp": _now_iso(),
            "rule": rule,
            "agent": agent,
            "data": {"srcip": src_ip, "protocol": "ssh"},
        }
        client.lpush("alerts_queue", json.dumps(payload))
        time.sleep(0.05)

    print("SSH flood test alerts pushed to Redis.")


if __name__ == "__main__":
    main()
