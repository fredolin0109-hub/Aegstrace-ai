import time
import threading
from typing import Any, Dict, Optional, List
from collections import OrderedDict
from dataclasses import dataclass


@dataclass
class CacheEntry:
    key: str
    value: Any
    expires_at: Optional[float]
    created_at: float
    last_accessed: float
    hits: int = 0

    def is_expired(self, current_time: Optional[float] = None) -> bool:
        if self.expires_at is None:
            return False
        now = current_time if current_time is not None else time.time()
        return now >= self.expires_at


class MemoryCache:
    """
    High-performance, thread-safe, in-memory TTL cache with LRU eviction.
    Protects downstream threat intelligence APIs from rate-limit exhaustion.
    """

    def __init__(self, max_size: int = 1000, default_ttl: float = 3600.0):
        if max_size <= 0:
            raise ValueError("max_size must be greater than 0")
        if default_ttl <= 0:
            raise ValueError("default_ttl must be greater than 0")

        self.max_size = max_size
        self.default_ttl = float(default_ttl)
        self._lock = threading.RLock()
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._hits = 0
        self._misses = 0
        self._evictions = 0

    def get(self, key: str, default: Any = None) -> Any:
        """
        Retrieves a cached value by key.
        If expired, deletes the entry and returns default.
        On hit, moves item to the most-recently-used position.
        """
        with self._lock:
            now = time.time()
            if key not in self._cache:
                self._misses += 1
                return default

            entry = self._cache[key]
            if entry.is_expired(now):
                # Expired entry: evict and record miss
                del self._cache[key]
                self._misses += 1
                return default

            # Cache hit: record hit and mark as most recently used
            entry.last_accessed = now
            entry.hits += 1
            self._cache.move_to_end(key, last=True)
            self._hits += 1
            return entry.value

    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        """
        Stores an item in the cache with an optional custom TTL in seconds.
        If ttl <= 0, the item expires immediately.
        If ttl is float('inf'), the item never expires.
        If the cache exceeds max_size, least recently used items are evicted.
        """
        with self._lock:
            now = time.time()
            effective_ttl = float(ttl) if ttl is not None else self.default_ttl
            if effective_ttl == float("inf"):
                expires_at = None
            else:
                expires_at = now + effective_ttl

            if key in self._cache:
                # Update existing key
                entry = self._cache[key]
                entry.value = value
                entry.expires_at = expires_at
                entry.last_accessed = now
                self._cache.move_to_end(key, last=True)
                return

            # Check capacity: opportunistically prune an expired entry before evicting LRU
            if len(self._cache) >= self.max_size:
                expired_key = None
                for k, v in self._cache.items():
                    if v.is_expired(now):
                        expired_key = k
                        break
                if expired_key is not None:
                    del self._cache[expired_key]
                else:
                    # Evict oldest / least-recently-used (first item in OrderedDict)
                    self._cache.popitem(last=False)
                    self._evictions += 1

            self._cache[key] = CacheEntry(
                key=key,
                value=value,
                expires_at=expires_at,
                created_at=now,
                last_accessed=now,
                hits=0,
            )

    def delete(self, key: str) -> bool:
        """Deletes a key from the cache. Returns True if removed, False otherwise."""
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False

    def has(self, key: str) -> bool:
        """Checks if a valid, unexpired key exists in cache without altering access order."""
        with self._lock:
            now = time.time()
            if key not in self._cache:
                return False
            entry = self._cache[key]
            if entry.is_expired(now):
                del self._cache[key]
                return False
            return True

    def clear(self) -> None:
        """Clears all entries and resets statistics."""
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0
            self._evictions = 0

    def size(self) -> int:
        """Returns the current count of active, unexpired entries in the cache."""
        with self._lock:
            now = time.time()
            expired_keys = [k for k, v in self._cache.items() if v.is_expired(now)]
            for k in expired_keys:
                del self._cache[k]
            return len(self._cache)

    def cleanup_expired(self) -> int:
        """Purges all expired entries from cache and returns count of removed items."""
        with self._lock:
            now = time.time()
            expired = [k for k, v in self._cache.items() if v.is_expired(now)]
            for k in expired:
                del self._cache[k]
            return len(expired)

    def stats(self) -> Dict[str, Any]:
        """Returns diagnostic metrics for performance monitoring."""
        with self._lock:
            now = time.time()
            active_size = sum(1 for v in self._cache.values() if not v.is_expired(now))
            total_requests = self._hits + self._misses
            hit_ratio = (self._hits / total_requests) if total_requests > 0 else 0.0
            return {
                "size": active_size,
                "max_size": self.max_size,
                "default_ttl": self.default_ttl,
                "hits": self._hits,
                "misses": self._misses,
                "hit_ratio": round(hit_ratio, 4),
                "evictions": self._evictions,
            }
