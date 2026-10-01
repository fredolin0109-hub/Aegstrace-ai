import copy
import time
from collections import OrderedDict
from dataclasses import dataclass
from threading import RLock
from typing import Any, Dict, Optional, Tuple, Callable


@dataclass
class CacheEntry:
    value: Any
    expires_at: float


class TTLRUCache:
    """
    Thread-safe in-memory TTL + LRU cache built strictly using Python stdlib.
    Uses time.monotonic() for time expiration and OrderedDict for LRU tracking.
    Protects stored and retrieved values with deepcopy to ensure isolation against
    accidental mutations of mutable objects.
    """

    def __init__(
        self,
        maxsize: int = 1024,
        ttl: float = 60.0,
        time_func: Optional[Callable[[], float]] = None,
    ):
        if maxsize <= 0:
            raise ValueError("maxsize must be greater than 0")
        if ttl <= 0:
            raise ValueError("ttl must be greater than 0")

        self.maxsize = maxsize
        self.ttl = ttl
        self._time_func = time_func or time.monotonic
        self._cache: OrderedDict[Any, CacheEntry] = OrderedDict()
        self._lock = RLock()

        # Telemetry metrics
        self._hits = 0
        self._misses = 0
        self._evictions = 0

    def get(self, key: Any) -> Optional[Any]:
        with self._lock:
            now = self._time_func()
            if key not in self._cache:
                self._misses += 1
                return None

            entry = self._cache[key]
            if now >= entry.expires_at:
                del self._cache[key]
                self._misses += 1
                self._evictions += 1
                return None

            self._cache.move_to_end(key)
            self._hits += 1
            return copy.deepcopy(entry.value)

    def set(self, key: Any, value: Any, ttl: Optional[float] = None) -> None:
        with self._lock:
            now = self._time_func()
            effective_ttl = ttl if ttl is not None and ttl > 0 else self.ttl
            expires_at = now + effective_ttl
            val_copy = copy.deepcopy(value)

            if key in self._cache:
                self._cache[key] = CacheEntry(value=val_copy, expires_at=expires_at)
                self._cache.move_to_end(key)
                return

            while len(self._cache) >= self.maxsize:
                self._cache.popitem(last=False)
                self._evictions += 1

            self._cache[key] = CacheEntry(value=val_copy, expires_at=expires_at)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0
            self._evictions = 0

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            now = self._time_func()
            expired_keys = [k for k, v in self._cache.items() if now >= v.expires_at]
            for k in expired_keys:
                del self._cache[k]
                self._evictions += 1

            return {
                "maxsize": self.maxsize,
                "ttl": self.ttl,
                "size": len(self._cache),
                "hits": self._hits,
                "misses": self._misses,
                "evictions": self._evictions,
            }


# Default cache settings for backend URL scan optimizations
# TTL prevents stale cached results, while LRU limits overall memory usage
DEFAULT_CACHE_MAXSIZE = 1024
DEFAULT_CACHE_TTL_SECONDS = 60.0

# Global thread-safe TTL/LRU caches for repeated URL feature extraction & DSA analysis
url_features_cache = TTLRUCache(maxsize=DEFAULT_CACHE_MAXSIZE, ttl=DEFAULT_CACHE_TTL_SECONDS)
dsa_analysis_cache = TTLRUCache(maxsize=DEFAULT_CACHE_MAXSIZE, ttl=DEFAULT_CACHE_TTL_SECONDS)


def clear_scan_caches() -> None:
    """Clears all scan-related caches (URL features and DSA domain analysis)."""
    url_features_cache.clear()
    dsa_analysis_cache.clear()
