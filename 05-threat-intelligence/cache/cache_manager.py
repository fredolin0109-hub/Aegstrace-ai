import re
import ipaddress
from urllib.parse import urlparse
from typing import Any, Dict, Optional
from cache.memory_cache import MemoryCache


class ThreatCacheManager:
    """
    Coordinates caching for threat intelligence lookups across domains, IPs, URLs,
    and individual upstream provider query results.
    """

    def __init__(self, max_size: int = 5000, default_ttl: float = 3600.0):
        self.default_ttl = default_ttl
        self.cache = MemoryCache(max_size=max_size, default_ttl=default_ttl)

    @staticmethod
    def normalize_target(target: str, target_type: Optional[str] = None) -> str:
        """Standardizes domains, IPs, and URLs for deterministic cache keys."""
        cleaned = target.strip().lower()
        if not cleaned:
            return ""

        # Handle bracketed IPv6 (e.g. [2001:db8::1] or [2001:db8::1]:8080)
        if cleaned.startswith("[") and "]" in cleaned:
            bracket_end = cleaned.index("]")
            host_part = cleaned[1:bracket_end]
            try:
                ip_obj = ipaddress.ip_address(host_part)
                if target_type == "url" or "/" in cleaned[bracket_end:]:
                    # Retain as URL
                    pass
                else:
                    return str(ip_obj)
            except ValueError:
                pass

        # Auto-detect or handle target types
        if target_type == "ip":
            try:
                return str(ipaddress.ip_address(cleaned))
            except ValueError:
                return cleaned

        # Direct IP check
        try:
            ip_obj = ipaddress.ip_address(cleaned)
            if target_type != "url":
                return str(ip_obj)
        except ValueError:
            pass

        if target_type == "url" or "://" in cleaned:
            # Normalize URL: scheme + netloc + path without trailing slash
            try:
                parsed = urlparse(cleaned if "://" in cleaned else f"http://{cleaned}")
                scheme = (parsed.scheme or "http").lower()
                netloc = (parsed.netloc or "").lower()
                path = parsed.path.rstrip("/")
                query = f"?{parsed.query}" if parsed.query else ""
                return f"{scheme}://{netloc}{path}{query}"
            except Exception:
                return cleaned

        # If target_type is None but contains path, treat as URL
        if target_type is None and "/" in cleaned:
            try:
                parsed = urlparse(f"http://{cleaned}")
                scheme = (parsed.scheme or "http").lower()
                netloc = (parsed.netloc or "").lower()
                path = parsed.path.rstrip("/")
                query = f"?{parsed.query}" if parsed.query else ""
                return f"{scheme}://{netloc}{path}{query}"
            except Exception:
                pass

        # Otherwise treat as domain: strip path and ports
        if "/" in cleaned:
            cleaned = cleaned.split("/")[0]
        if ":" in cleaned and not cleaned.count(":") > 1:  # not IPv6
            cleaned = cleaned.split(":")[0]

        return cleaned.strip(".")

    def generate_key(
        self,
        target: str,
        target_type: str = "domain",
        provider: Optional[str] = None,
    ) -> str:
        """Constructs a namespaced cache key."""
        norm_target = self.normalize_target(target, target_type)
        provider_part = f":{provider.lower()}" if provider else ""
        return f"threat_intel:{target_type.lower()}:{norm_target}{provider_part}"

    def get_reputation(
        self,
        target: str,
        target_type: str = "domain",
        provider: Optional[str] = None,
    ) -> Optional[Any]:
        """Fetches reputation record from cache."""
        key = self.generate_key(target, target_type, provider)
        return self.cache.get(key)

    def set_reputation(
        self,
        target: str,
        value: Any,
        target_type: str = "domain",
        provider: Optional[str] = None,
        ttl: Optional[float] = None,
    ) -> None:
        """Caches reputation record with specified or default TTL."""
        key = self.generate_key(target, target_type, provider)
        self.cache.set(key, value, ttl=ttl)

    def invalidate(
        self,
        target: str,
        target_type: str = "domain",
        provider: Optional[str] = None,
    ) -> bool:
        """Evicts a specific target or target+provider from cache."""
        key = self.generate_key(target, target_type, provider)
        return self.cache.delete(key)

    def clear(self) -> None:
        """Clears all cached threat intelligence entries."""
        self.cache.clear()

    def stats(self) -> Dict[str, Any]:
        """Returns cache telemetry."""
        return self.cache.stats()


# Shared singleton instance for platform-wide threat intelligence caching
global_threat_cache = ThreatCacheManager()
