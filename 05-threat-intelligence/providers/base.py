from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
import ipaddress
from urllib.parse import urlparse


@dataclass
class ProviderResult:
    """Standardized output from any threat intelligence source."""
    source_name: str
    is_malicious: bool
    threat_score: float  # Normalized between 0.0 (safe) and 1.0 (critical threat)
    confidence: float    # Confidence between 0.0 (uncertain) and 1.0 (verified)
    categories: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    available: bool = True
    cached: bool = False
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_name": self.source_name,
            "is_malicious": self.is_malicious,
            "threat_score": round(self.threat_score, 4),
            "confidence": round(self.confidence, 4),
            "categories": self.categories,
            "raw_data": self.raw_data,
            "available": self.available,
            "cached": self.cached,
            "error_message": self.error_message,
        }


class BaseThreatProvider(ABC):
    """
    Abstract base class establishing the contract for all threat intelligence providers.
    Supports domains, IP addresses, and URLs with graceful fallback on failure.
    """

    def __init__(
        self,
        source_name: str,
        weight: float = 1.0,
        enabled: bool = True,
        timeout: float = 5.0,
    ):
        self.source_name = source_name
        self.weight = weight
        self.enabled = enabled
        self.timeout = timeout

    @abstractmethod
    def is_available(self) -> bool:
        """Determines if the provider is currently usable (e.g. API key present and active)."""
        pass

    @abstractmethod
    def lookup(self, target: str, target_type: str = "domain") -> ProviderResult:
        """
        Executes reputation query against upstream provider.
        Must catch all internal errors and return a valid ProviderResult without raising.
        """
        pass

    @staticmethod
    def normalize_target(target: str, target_type: str = "domain") -> str:
        """Sanitizes target string based on detected or supplied target_type."""
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
                    pass
                else:
                    return str(ip_obj)
            except ValueError:
                pass

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

        if target_type == "url":
            if not (cleaned.startswith("http://") or cleaned.startswith("https://")):
                cleaned = f"http://{cleaned}"
            return cleaned

        # Default to domain extraction
        if "://" in cleaned:
            parsed = urlparse(cleaned)
            cleaned = parsed.hostname or cleaned
        if "/" in cleaned:
            cleaned = cleaned.split("/")[0]
        if ":" in cleaned and not cleaned.count(":") > 1:
            cleaned = cleaned.split(":")[0]

        return cleaned.strip(".")
