import sys
from pathlib import Path
from typing import Optional, Dict, Any, List

# Ensure 02-dsa-engine is discoverable
_root = Path(__file__).resolve().parents[2]
_dsa_path = _root / "02-dsa-engine"
if _dsa_path.exists() and str(_dsa_path) not in sys.path:
    sys.path.insert(0, str(_dsa_path))

try:
    from engine import global_dsa_engine
    from hashmap import DomainEntry
except ImportError:
    global_dsa_engine = None
    DomainEntry = None

from providers.base import BaseThreatProvider, ProviderResult


class LocalFallbackProvider(BaseThreatProvider):
    """
    Zero-credential, high-performance local threat intelligence fallback provider.
    Always available. Leverages 02-dsa-engine's polynomial ThreatDomainHashMap,
    prefix trie signature matcher, and algorithmic threat heuristics.
    """

    SUSPICIOUS_TLDS = {
        "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "club", "work",
        "cam", "fit", "rest", "stream", "live", "link", "guru", "cc", "icu"
    }

    def __init__(self, weight: float = 0.25, enabled: bool = True):
        super().__init__(source_name="local_dsa", weight=weight, enabled=enabled, timeout=0.1)

    def is_available(self) -> bool:
        """Local engine is always available without external internet or credentials."""
        return self.enabled

    def lookup(self, target: str, target_type: str = "domain") -> ProviderResult:
        norm_target = self.normalize_target(target, target_type)
        if not norm_target:
            return ProviderResult(
                source_name=self.source_name,
                is_malicious=False,
                threat_score=0.0,
                confidence=0.0,
                categories=[],
                raw_data={},
                available=True,
                error_message="Invalid target",
            )

        # 1. Query DSA Hash Map with parent fallback if domain or url
        domain_target = norm_target
        if target_type == "url" or "://" in domain_target or "/" in domain_target:
            domain_target = self.normalize_target(domain_target, "domain")

        entry = None
        if global_dsa_engine and hasattr(global_dsa_engine, "domain_hashmap") and target_type != "ip":
            hmap = global_dsa_engine.domain_hashmap
            entry = hmap.get(domain_target)
            if not entry and "." in domain_target:
                parts = domain_target.split(".")
                for i in range(1, len(parts) - 1):
                    parent = ".".join(parts[i:])
                    entry = hmap.get(parent)
                    if entry:
                        break

        if entry:
            cat = entry.category.upper()
            if cat == "MALICIOUS":
                return ProviderResult(
                    source_name=self.source_name,
                    is_malicious=True,
                    threat_score=max(0.90, entry.reputation_score),
                    confidence=0.98,
                    categories=[entry.threat_type],
                    raw_data={
                        "domain": entry.domain,
                        "category": cat,
                        "threat_type": entry.threat_type,
                        "metadata": entry.metadata,
                    },
                    available=True,
                )
            elif cat == "SUSPICIOUS":
                return ProviderResult(
                    source_name=self.source_name,
                    is_malicious=True,
                    threat_score=max(0.50, entry.reputation_score),
                    confidence=0.90,
                    categories=[entry.threat_type],
                    raw_data={
                        "domain": entry.domain,
                        "category": cat,
                        "threat_type": entry.threat_type,
                        "metadata": entry.metadata,
                    },
                    available=True,
                )
            elif cat == "SAFE":
                return ProviderResult(
                    source_name=self.source_name,
                    is_malicious=False,
                    threat_score=0.0,
                    confidence=0.99,
                    categories=["TRUSTED_ALLOWLIST"],
                    raw_data={
                        "domain": entry.domain,
                        "category": cat,
                        "metadata": entry.metadata,
                    },
                    available=True,
                )

        # 2. DSA Pattern Trie Matcher
        trie_matches = []
        if global_dsa_engine and hasattr(global_dsa_engine, "trie"):
            trie_matches = global_dsa_engine.trie.search_patterns_in_text(target)

        # 3. Local Heuristic Checks
        categories: List[str] = []
        heuristic_score = 0.05

        if trie_matches:
            matched_pats = [m["pattern"] for m in trie_matches]
            categories.extend(matched_pats)
            heuristic_score = max(heuristic_score, 0.70)

        # Check suspicious TLD
        if target_type != "ip" and "." in domain_target:
            tld = domain_target.split(".")[-1]
            if tld in self.SUSPICIOUS_TLDS:
                heuristic_score += 0.25
                categories.append(f"SUSPICIOUS_TLD:.{tld}")

        is_mal = heuristic_score >= 0.50
        conf = 0.80 if is_mal else 0.50

        return ProviderResult(
            source_name=self.source_name,
            is_malicious=is_mal,
            threat_score=round(min(1.0, heuristic_score), 4),
            confidence=conf,
            categories=categories,
            raw_data={"trie_matches": len(trie_matches)},
            available=True,
        )
