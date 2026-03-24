from redis_queue.redis_client import redis_client


redis_client.set("test_key", "freshstart")
print(redis_client.get("test_key"))
