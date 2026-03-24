import json
import os
import subprocess
import sys

root = os.path.dirname(os.path.abspath(__file__))
log_dir = os.path.join(root, "logs")
pids_path = os.path.join(log_dir, "freshstart_pids.json")


def _kill_pid(pid: int) -> bool:
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], check=False)
        else:
            os.kill(pid, 9)
        return True
    except Exception:
        return False


def main():
    if not os.path.exists(pids_path):
        print("No PID file found. Nothing to stop.")
        return

    with open(pids_path, "r", encoding="utf-8") as handle:
        pids = json.load(handle)

    for name, pid in pids.items():
        if pid is None:
            print(f"{name} (none): skipped")
            continue
        success = _kill_pid(int(pid))
        status = "stopped" if success else "failed"
        print(f"{name} ({pid}): {status}")

    try:
        os.remove(pids_path)
    except OSError:
        pass


if __name__ == "__main__":
    sys.exit(main())
