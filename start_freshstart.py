import json
import os
import socket
import subprocess
import sys
import time
import yaml

root = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.join(root, "backend")
log_dir = os.path.join(root, "logs")
python_exe = sys.executable
pids_path = os.path.join(log_dir, "freshstart_pids.json")
config_path = os.path.join(backend_dir, "config.yaml")


def _load_config():
    if not os.path.exists(config_path):
        return {}
    try:
        with open(config_path, "r", encoding="utf-8") as handle:
            return yaml.safe_load(handle) or {}
    except Exception:
        return {}


def _check_tcp_port(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except Exception:
        return False


def _check_udp_bind(host: str, port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def _ensure_logs():
    os.makedirs(log_dir, exist_ok=True)


def _open_log(name: str):
    path = os.path.join(log_dir, name)
    return open(path, "a", encoding="utf-8")


def _check_startup():
    config = _load_config()
    redis_host = config.get("redis_host", "127.0.0.1")
    redis_port = int(config.get("redis_port", 6379))
    syslog_port = int(config.get("syslog_port", 1514))

    redis_up = _check_tcp_port(redis_host, redis_port)
    if not redis_up:
        print(f"Warning: Redis not reachable at {redis_host}:{redis_port}")

    if _check_tcp_port("127.0.0.1", 5000):
        print("Warning: Port 5000 is already in use.")

    if not _check_udp_bind("0.0.0.0", syslog_port):
        print(f"Warning: UDP port {syslog_port} is already in use.")


print("Starting FreshStart services...")
_ensure_logs()
_check_startup()

syslog_log = _open_log("syslog_listener.log")
worker_log = _open_log("alert_worker.log")
app_log = _open_log("flask_app.log")

use_vector = os.environ.get("USE_VECTOR", "false").lower() in {"1", "true", "yes"}
syslog_port = int(_load_config().get("syslog_port", 1514))
if not use_vector and not _check_udp_bind("0.0.0.0", syslog_port):
    print(f"UDP port {syslog_port} is already in use. Assuming Vector is handling syslog.")
    use_vector = True
syslog_proc = None
if not use_vector:
    print(f"Syslog listener: ON (UDP {syslog_port})")
    syslog_proc = subprocess.Popen(
        [python_exe, "syslog_listener.py"],
        cwd=backend_dir,
        stdout=syslog_log,
        stderr=syslog_log,
    )
else:
    print("Syslog listener: OFF (Vector mode)")
    print("Vector ingestion: ON (external service)")
worker_proc = subprocess.Popen(
    [python_exe, "-m", "workers.alert_worker"],
    cwd=backend_dir,
    stdout=worker_log,
    stderr=worker_log,
)
print("Alert worker: ON")
app_proc = subprocess.Popen(
    [python_exe, "app.py"],
    cwd=backend_dir,
    stdout=app_log,
    stderr=app_log,
    env={
        **os.environ,
        "ENABLE_WAZUH_BACKFILL": os.environ.get("ENABLE_WAZUH_BACKFILL", "false"),
        "PRIMARY_STORAGE": os.environ.get("PRIMARY_STORAGE", "opensearch"),
    },
)
print("Flask API: ON (port 5000)")
print(f"Primary storage: {os.environ.get('PRIMARY_STORAGE', 'opensearch')}")
print(f"Wazuh backfill: {os.environ.get('ENABLE_WAZUH_BACKFILL', 'false')}")

time.sleep(0.2)
pids = {
    "syslog_listener": syslog_proc.pid if syslog_proc else None,
    "alert_worker": worker_proc.pid,
    "flask_app": app_proc.pid,
}
with open(pids_path, "w", encoding="utf-8") as handle:
    json.dump(pids, handle, indent=2)

print("All services started.")
input("Press ENTER to exit launcher...")
