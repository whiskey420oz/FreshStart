import json
import socket
from datetime import datetime, timezone

test_alert = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "rule": {"id": "99999", "description": "pipeline test alert", "level": 3},
    "agent": {"name": "TEST-AGENT", "ip": "192.0.2.10"},
    "data": {"srcip": "198.51.100.10", "protocol": "tcp"},
}

message = f"<13>{json.dumps(test_alert)}"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(message.encode("utf-8"), ("127.0.0.1", 1514))
sock.close()
print("Test alert sent to syslog listener on UDP 1514")
