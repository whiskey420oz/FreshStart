import os
from pathlib import Path

try:
    import yaml
except ModuleNotFoundError:
    yaml = None
from redis import Redis

_CLIENT = None
_CONFIG = {}
_SETTINGS_PATH = Path(__file__).resolve().parents[1] / "config.yaml"


def _load_settings() -> dict:
    if yaml is None:
        return {}
    if not _SETTINGS_PATH.exists():
        return {}
    try:
        with _SETTINGS_PATH.open("r", encoding="utf-8") as handle:
            return yaml.safe_load(handle) or {}
    except Exception:
        return {}


def _get_config() -> dict:
    env_host = os.getenv("REDIS_HOST")
    env_port = os.getenv("REDIS_PORT")
    settings = _load_settings()
    host = env_host or settings.get("redis_host") or "127.0.0.1"
    port = int(env_port or settings.get("redis_port") or 6379)
    return {"host": host, "port": port}


def get_client() -> Redis:
    global _CLIENT, _CONFIG
    config = _get_config()
    if _CLIENT is None or config != _CONFIG:
        _CONFIG = config
        _CLIENT = Redis(host=config["host"], port=config["port"], decode_responses=True)
    return _CLIENT


redis_client = get_client()
