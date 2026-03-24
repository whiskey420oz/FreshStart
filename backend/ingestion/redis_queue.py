"""
Compatibility wrapper for Redis queue client.
"""

from redis_queue.redis_client import get_client, redis_client  # noqa: F401

__all__ = ["get_client", "redis_client"]
