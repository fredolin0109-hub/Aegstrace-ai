import time
import pytest
from cache.memory_cache import MemoryCache, CacheEntry
from cache.cache_manager import ThreatCacheManager


def test_cache_hit_and_miss():
    cache = MemoryCache(max_size=10, default_ttl=60.0)
    assert cache.get("nonexistent") is None
    assert cache.stats()["misses"] == 1
    assert cache.stats()["hits"] == 0

    cache.set("key1", {"reputation": "SAFE"})
    val = cache.get("key1")
    assert val == {"reputation": "SAFE"}
    assert cache.stats()["hits"] == 1


def test_cache_ttl_expiration():
    # Cache with very short TTL
    cache = MemoryCache(max_size=10, default_ttl=0.1)
    cache.set("short_key", "temporary_value")
    assert cache.get("short_key") == "temporary_value"

    # Wait for TTL to expire
    time.sleep(0.15)
    assert cache.get("short_key") is None
    assert cache.has("short_key") is False


def test_cache_custom_ttl():
    cache = MemoryCache(max_size=10, default_ttl=100.0)
    # Override default TTL with 0.1s
    cache.set("override_key", "fast_expire", ttl=0.1)
    assert cache.get("override_key") == "fast_expire"

    time.sleep(0.15)
    assert cache.get("override_key") is None


def test_cache_lru_eviction():
    # max_size=3
    cache = MemoryCache(max_size=3, default_ttl=60.0)
    cache.set("a", 1)
    cache.set("b", 2)
    cache.set("c", 3)
    assert cache.size() == 3

    # Adding a 4th key should evict 'a' (the least recently used)
    cache.set("d", 4)
    assert cache.size() == 3
    assert cache.get("a") is None
    assert cache.get("b") == 2
    assert cache.get("c") == 3
    assert cache.get("d") == 4
    assert cache.stats()["evictions"] == 1


def test_cache_lru_access_ordering():
    # Accessing an item should refresh its LRU position so it is not evicted
    cache = MemoryCache(max_size=3, default_ttl=60.0)
    cache.set("a", 1)
    cache.set("b", 2)
    cache.set("c", 3)

    # Access 'a' so 'b' becomes the oldest
    _ = cache.get("a")

    # Add 'd' -> 'b' should be evicted, not 'a'
    cache.set("d", 4)
    assert cache.get("b") is None
    assert cache.get("a") == 1
    assert cache.get("c") == 3
    assert cache.get("d") == 4


def test_cache_update_existing_key():
    cache = MemoryCache(max_size=3, default_ttl=60.0)
    cache.set("k", "v1")
    assert cache.get("k") == "v1"
    cache.set("k", "v2")
    assert cache.get("k") == "v2"
    assert cache.size() == 1


def test_cache_delete_and_clear():
    cache = MemoryCache(max_size=5, default_ttl=60.0)
    cache.set("k1", 10)
    cache.set("k2", 20)
    assert cache.delete("k1") is True
    assert cache.delete("k1") is False
    assert cache.get("k1") is None
    assert cache.get("k2") == 20

    cache.clear()
    assert cache.size() == 0
    assert cache.get("k2") is None
    assert cache.stats()["hits"] == 0
    assert cache.stats()["misses"] == 1


def test_cache_cleanup_expired():
    cache = MemoryCache(max_size=5, default_ttl=0.1)
    cache.set("e1", "val1")
    cache.set("e2", "val2")
    time.sleep(0.15)
    purged = cache.cleanup_expired()
    assert purged == 2
    assert cache.size() == 0


def test_cache_manager_normalization_and_keys():
    mgr = ThreatCacheManager(max_size=100, default_ttl=300.0)
    # Target normalization
    assert mgr.normalize_target("https://www.Example.COM/path/page?q=1", "url") == "https://www.example.com/path/page?q=1"
    assert mgr.normalize_target("  BadDomain.XYZ:8080/foo  ", "domain") == "baddomain.xyz"
    assert mgr.normalize_target(" 192.168.1.1 ", "ip") == "192.168.1.1"

    key1 = mgr.generate_key("example.com", "domain")
    assert key1 == "threat_intel:domain:example.com"

    key2 = mgr.generate_key("example.com", "domain", provider="virustotal")
    assert key2 == "threat_intel:domain:example.com:virustotal"


def test_cache_manager_reputation_flow():
    mgr = ThreatCacheManager(max_size=50, default_ttl=300.0)
    assert mgr.get_reputation("target.org") is None

    mgr.set_reputation("target.org", {"score": 0.85, "verdict": "HIGH_RISK"})
    cached = mgr.get_reputation("target.org")
    assert cached is not None
    assert cached["score"] == 0.85
    assert cached["verdict"] == "HIGH_RISK"

    # Invalidate
    mgr.invalidate("target.org")
    assert mgr.get_reputation("target.org") is None


def test_cache_ttl_zero_expires_immediately():
    cache = MemoryCache(max_size=10, default_ttl=60.0)
    cache.set("zero_ttl_key", "instant_death", ttl=0)
    assert cache.get("zero_ttl_key") is None
    assert cache.has("zero_ttl_key") is False

    cache.set("neg_ttl_key", "already_dead", ttl=-5.0)
    assert cache.get("neg_ttl_key") is None


def test_cache_infinite_ttl():
    cache = MemoryCache(max_size=10, default_ttl=0.1)
    cache.set("eternal_key", "forever", ttl=float("inf"))
    time.sleep(0.15)
    assert cache.get("eternal_key") == "forever"


def test_cache_opportunistic_eviction_prunes_expired_first():
    # Cache with capacity 2
    cache = MemoryCache(max_size=2, default_ttl=60.0)
    cache.set("expired_item", "old", ttl=0.1)
    cache.set("active_item", "fresh", ttl=60.0)
    time.sleep(0.15)

    # Now cache has 2 items, but 'expired_item' is expired.
    # Adding a 3rd item should prune 'expired_item' instead of evicting active_item!
    cache.set("new_item", "brand_new")
    assert cache.get("active_item") == "fresh"
    assert cache.get("new_item") == "brand_new"
    assert cache.get("expired_item") is None


def test_cache_manager_ipv6_brackets_and_ports():
    mgr = ThreatCacheManager(max_size=100, default_ttl=300.0)
    assert mgr.normalize_target("[2001:db8::1]:8080") == "2001:db8::1"
    assert mgr.normalize_target("2001:0db8::0001") == "2001:db8::1"
    assert mgr.normalize_target("::1") == "::1"

