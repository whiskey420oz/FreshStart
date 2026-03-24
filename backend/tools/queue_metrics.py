import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from redis_queue.redis_client import get_client


def main():
    redis_client = get_client()
    try:
        redis_client.ping()
        status = "connected"
    except Exception:
        status = "disconnected"
    length = redis_client.llen("alerts_queue") if status == "connected" else "unknown"
    print(f"Redis status: {status}")
    print(f"alerts_queue length: {length}")


if __name__ == "__main__":
    main()
