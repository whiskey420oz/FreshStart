# Vector Buffering (Enterprise-Grade Offline Safety)

This project can optionally use **Vector** as a durable buffer in front of Redis so alerts are not lost when FreshStart is offline.

## Why Vector
- Disk-backed buffering (survives restarts)
- High throughput
- Simple to run compared to Kafka

## Architecture
Wazuh Manager -> syslog_output (format=json) -> Vector (disk buffer) -> Redis (alerts_queue) -> worker -> SQLite/OpenSearch

## Vector Config (Template)
Save as `vector/vector.toml`:

```toml
[sources.wazuh_syslog]
type = "syslog"
address = "0.0.0.0:1514"
mode = "udp"

[transforms.extract_json]
type = "remap"
inputs = ["wazuh_syslog"]
source = """
.message = parse_json!(.message)
"""

[sinks.redis_queue]
type = "redis"
inputs = ["extract_json"]
endpoint = "redis://127.0.0.1:6379"
method = "list"
key = "alerts_queue"
encoding.codec = "json"

[sinks.redis_queue.buffer]
type = "disk"
max_size = 10737418240 # 10 GB disk buffer
```

## How To Use
1) Install Vector on the FreshStart host (or a nearby relay VM).
2) Set Wazuh `syslog_output` to point to the Vector host IP.
3) Start Vector: `vector --config vector/vector.toml`
4) Start FreshStart normally (`start_freshstart.py`).

## Notes
- If you use Vector, you can stop `syslog_listener.py` (Vector takes over UDP 1514).
- Redis remains the queue for worker processing.
- This is a good stepping stone before Kafka.
