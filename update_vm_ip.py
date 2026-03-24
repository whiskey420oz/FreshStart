import os
import sys
from pathlib import Path

import yaml


def load_config(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def save_config(path: Path, data: dict) -> None:
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(data, handle, sort_keys=False)


def main() -> int:
    root = Path(__file__).resolve().parent
    config_path = root / "backend" / "config.yaml"
    if not config_path.exists():
        print(f"Config not found at {config_path}")
        return 1

    new_ip = input("Enter New IP: ").strip()
    if not new_ip:
        print("No IP provided. Exiting.")
        return 1

    data = load_config(config_path)
    updates = {
        "wazuh_manager_ip": new_ip,
        "wazuh_api_url": f"https://{new_ip}:55000",
        "redis_host": new_ip,
        "opensearch_url": f"https://{new_ip}:9200",
    }

    changed = []
    for key, value in updates.items():
        old = data.get(key)
        if old != value:
            data[key] = value
            changed.append((key, old, value))

    save_config(config_path, data)

    if not changed:
        print("No changes needed. Config already matches the provided IP.")
        return 0

    print("Updated config values:")
    for key, old, new in changed:
        print(f"- {key}: {old} -> {new}")

    print(f"\nSaved: {config_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
