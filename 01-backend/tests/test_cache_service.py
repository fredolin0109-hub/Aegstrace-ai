import threading
import pytest
from app.services.cache_service import TTLRUCache, clear_scan_caches, url_features_cache, dsa_analysis_cache


class FakeClock:
    def __init__(self, start_time: float = 1000.0):
        self.current_time = start_time

    def time(self) -> float:
        return self.current_time

    def advance(self, seconds: float) -> None:
        self.current_time += seconds


def test_cache_basic_set_get():
    cache = TTLRUCache(maxsize=10, ttl=60.0)
    cache.set("key1", "val1")
    assert cache.get("key1") == "val1"


def test_cache_miss():
    cache = TTLRUCache(maxsize=10, ttl=60.0)
    assert cache.get("nonexistent") is None
    stats = cache.stats()
    assert stats["misses"] == 1
    assert stats["hits"] == 0


def test_cache_hit():
    cache = TTLRUCache(maxsize=10, ttl=60.0)
    cache.set("a", 100)
    assert cache.get("a") == 100
    stats = cache.stats()
    assert stats["hits"] == 1
    assert stats["misses"] == 0


def test_cache_ttl_expiration():
    clock = FakeClock(1000.0)
    cache = TTLRUCache(maxsize=10, ttl=10.0, time_func=clock.time)
    cache.set("k1", "v1")
    assert cache.get("k1") == "v1"

    # Advance time by 5 seconds (not expired)
    clock.advance(5.0)
    assert cache.get("k1") == "v1"

    # Advance time past TTL (total +11s)
    clock.advance(6.0)
    assert cache.get("k1") is None
    stats = cache.stats()
    assert stats["misses"] >= 1


def test_cache_lru_eviction():
    cache = TTLRUCache(maxsize=3, ttl=60.0)
    cache.set("k1", 1)
    cache.set("k2", 2)
    cache.set("k3", 3)

    # Access k1 to mark as recently used
    assert cache.get("k1") == 1

    # Insert k4 -> should evict LRU key (k2)
    cache.set("k4", 4)
    assert cache.get("k2") is None
    assert cache.get("k1") == 1
    assert cache.get("k3") == 3
    assert cache.get("k4") == 4
    stats = cache.stats()
    assert stats["evictions"] >= 1


def test_cache_update_existing_key():
    cache = TTLRUCache(maxsize=5, ttl=60.0)
    cache.set("k1", "initial")
    assert cache.get("k1") == "initial"

    cache.set("k1", "updated")
    assert cache.get("k1") == "updated"
    assert cache.stats()["size"] == 1


def test_cache_clear():
    cache = TTLRUCache(maxsize=5, ttl=60.0)
    cache.set("k1", 1)
    cache.set("k2", 2)
    cache.clear()
    assert cache.get("k1") is None
    assert cache.get("k2") is None
    stats = cache.stats()
    assert stats["size"] == 0
    assert stats["hits"] == 0


def test_cache_stats():
    cache = TTLRUCache(maxsize=10, ttl=30.0)
    cache.set("a", 1)
    cache.set("b", 2)
    cache.get("a")
    cache.get("missing")
    stats = cache.stats()
    assert stats["maxsize"] == 10
    assert stats["ttl"] == 30.0
    assert stats["size"] == 2
    assert stats["hits"] == 1
    assert stats["misses"] == 1


def test_cache_mutable_value_isolation():
    cache = TTLRUCache(maxsize=10, ttl=60.0)
    original_dict = {"items": [1, 2, 3], "status": "active"}

    cache.set("dict_key", original_dict)

    # Mutate original dictionary outside cache
    original_dict["items"].append(4)
    original_dict["status"] = "mutated"

    cached_val = cache.get("dict_key")
    assert cached_val == {"items": [1, 2, 3], "status": "active"}

    # Mutate returned dictionary from cache
    cached_val["items"].append(99)
    cached_val_again = cache.get("dict_key")
    assert cached_val_again == {"items": [1, 2, 3], "status": "active"}


def test_cache_thread_safety():
    cache = TTLRUCache(maxsize=500, ttl=60.0)
    threads = []
    errors = []

    def worker(thread_id: int):
        try:
            for i in range(100):
                key = f"key_{thread_id}_{i}"
                cache.set(key, {"id": thread_id, "i": i})
                val = cache.get(key)
                if val is not None:
                    assert val["id"] == thread_id
        except Exception as e:
            errors.append(e)

    for t_id in range(10):
        t = threading.Thread(target=worker, args=(t_id,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    assert len(errors) == 0


def test_clear_scan_caches():
    url_features_cache.set(("http://test.com", "test.com", False), {"feat": 1})
    dsa_analysis_cache.set(("http://test.com", "test.com", None, ()), {"dsa": 1})

    clear_scan_caches()

    assert url_features_cache.get(("http://test.com", "test.com", False)) is None
    assert dsa_analysis_cache.get(("http://test.com", "test.com", None, ())) is None
