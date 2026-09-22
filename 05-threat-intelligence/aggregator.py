import sys
import ipaddress
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

# Ensure 05-threat-intelligence submodules are importable
_pkg_root = Path(__file__).resolve().parent
if str(_pkg_root) not in sys.path:
    sys.path.insert(0, str(_pkg_root))

from cache.cache_manager import ThreatCacheManager, global_threat_cache
from domain_info import DomainInfoResolver, DomainMetadata, default_domain_resolver
from reputation import ReputationEngine, CompositeReputation, default_reputation_engine
from providers.base import BaseThreatProvider, ProviderResult
from providers.virustotal import VirusTotalProvider
from providers.abuseipdb import AbuseIPDBProvider
from providers.alienvault import AlienVaultOTXProvider
from providers.urlscan import URLScanProvider
from providers.local_fallback import LocalFallbackProvider


@dataclass
class AggregatedThreatReport:
    """Standard aggregated threat intelligence report."""
    target: str
    target_type: str
    composite_score: float
    verdict: str  # SAFE, SUSPICIOUS, HIGH_RISK
    confidence: float
    sources_consulted: List[str]
    sources_available: List[str]
    sources_cached: List[str] = field(default_factory=list)
    cached: bool = False
    indicators: List[Dict[str, Any]] = field(default_factory=list)
    provider_details: Dict[str, Any] = field(default_factory=dict)
    domain_info: Optional[Dict[str, Any]] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "composite_score": round(self.composite_score, 4),
            "verdict": self.verdict,
            "confidence": round(self.confidence, 4),
            "sources_consulted": self.sources_consulted,
            "sources_available": self.sources_available,
            "sources_cached": self.sources_cached,
            "cached": self.cached,
            "indicators": self.indicators,
            "provider_details": self.provider_details,
            "domain_info": self.domain_info,
            "timestamp": self.timestamp,
        }


class ThreatIntelligenceAggregator:
    """
    Coordinates multi-source threat intelligence aggregation with caching,
    DNS domain resolution, provider queries, and composite reputation scoring.
    """

    def __init__(
        self,
        providers: Optional[List[BaseThreatProvider]] = None,
        cache_manager: Optional[ThreatCacheManager] = None,
        domain_resolver: Optional[DomainInfoResolver] = None,
        reputation_engine: Optional[ReputationEngine] = None,
    ):
        self.cache_manager = cache_manager or global_threat_cache
        self.domain_resolver = domain_resolver or default_domain_resolver
        self.reputation_engine = reputation_engine or default_reputation_engine

        if providers is not None:
            self.providers = list(providers)
        else:
            # Default provider stack: external feeds + local DSA fallback
            self.providers = [
                VirusTotalProvider(),
                AbuseIPDBProvider(),
                AlienVaultOTXProvider(),
                URLScanProvider(),
                LocalFallbackProvider(),
            ]

    @staticmethod
    def detect_target_type(target: str) -> str:
        """Classifies target as 'ip', 'url', or 'domain'."""
        cleaned = target.strip()
        # Handle bracketed IPv6 [2001:db8::1]
        if cleaned.startswith("[") and "]" in cleaned:
            bracket_end = cleaned.index("]")
            try:
                ipaddress.ip_address(cleaned[1:bracket_end])
                if "/" in cleaned[bracket_end:]:
                    return "url"
                return "ip"
            except ValueError:
                pass

        try:
            ipaddress.ip_address(cleaned)
            return "ip"
        except ValueError:
            pass

        if cleaned.startswith("http://") or cleaned.startswith("https://") or "/" in cleaned:
            return "url"

        return "domain"

    def get_available_sources(self) -> List[str]:
        """Returns names of all configured providers that are currently available."""
        return [p.source_name for p in self.providers if p.is_available()]

    def lookup(
        self,
        target: str,
        target_type: Optional[str] = None,
        force_refresh: bool = False,
        ttl: Optional[float] = None,
    ) -> AggregatedThreatReport:
        """
        Executes multi-source threat intelligence lookup.
        Checks cache, resolves domain info, queries available feeds, and computes composite score.
        """
        if not target or not isinstance(target, str) or not target.strip():
            return AggregatedThreatReport(
                target="",
                target_type=target_type or "domain",
                composite_score=0.0,
                verdict="SAFE",
                confidence=0.50,
                sources_consulted=[],
                sources_available=[],
                cached=False,
                indicators=[],
                provider_details={},
            )

        actual_type = target_type or self.detect_target_type(target)
        norm_target = self.cache_manager.normalize_target(target, actual_type)

        # 1. Check Cache (if not force_refresh)
        if not force_refresh:
            cached_data = self.cache_manager.get_reputation(norm_target, actual_type)
            if cached_data:
                # Return cached report with cached=True
                return AggregatedThreatReport(
                    target=cached_data["target"],
                    target_type=cached_data["target_type"],
                    composite_score=cached_data["composite_score"],
                    verdict=cached_data["verdict"],
                    confidence=cached_data["confidence"],
                    sources_consulted=cached_data["sources_consulted"],
                    sources_available=cached_data["sources_available"],
                    sources_cached=cached_data.get("sources_available", []),
                    cached=True,
                    indicators=cached_data["indicators"],
                    provider_details=cached_data["provider_details"],
                    domain_info=cached_data.get("domain_info"),
                    timestamp=cached_data.get("timestamp", datetime.now(timezone.utc).isoformat()),
                )

        # 2. Domain & DNS Metadata Resolution
        domain_meta: Optional[DomainMetadata] = None
        if actual_type in ("domain", "url"):
            domain_meta = self.domain_resolver.resolve(norm_target)

        # 3. Query All Configured Providers with Per-Provider Caching
        provider_results: List[ProviderResult] = []
        sources_consulted: List[str] = []
        sources_available: List[str] = []
        sources_cached: List[str] = []
        provider_details: Dict[str, Any] = {}

        for provider in self.providers:
            sources_consulted.append(provider.source_name)
            is_avail = provider.is_available()

            if is_avail:
                sources_available.append(provider.source_name)

                # Check per-provider cache if not force_refresh
                cached_prov = None
                if not force_refresh:
                    cached_prov = self.cache_manager.get_reputation(
                        norm_target, actual_type, provider=provider.source_name
                    )

                if cached_prov:
                    res = ProviderResult(
                        source_name=cached_prov.get("source_name", provider.source_name),
                        is_malicious=cached_prov.get("is_malicious", False),
                        threat_score=cached_prov.get("threat_score", 0.0),
                        confidence=cached_prov.get("confidence", 0.5),
                        categories=cached_prov.get("categories", []),
                        raw_data=cached_prov.get("raw_data", {}),
                        available=cached_prov.get("available", True),
                        cached=True,
                        error_message=cached_prov.get("error_message"),
                    )
                    sources_cached.append(provider.source_name)
                else:
                    res = provider.lookup(norm_target, target_type=actual_type)
                    # Cache successful provider result
                    if res.available and not res.error_message:
                        self.cache_manager.set_reputation(
                            norm_target,
                            res.to_dict(),
                            target_type=actual_type,
                            provider=provider.source_name,
                            ttl=ttl,
                        )

                provider_results.append(res)
                provider_details[provider.source_name] = res.to_dict()
            else:
                provider_details[provider.source_name] = {
                    "source_name": provider.source_name,
                    "available": False,
                    "cached": False,
                    "error_message": "Provider not configured or API key missing",
                }

        # 4. Reputation Engine Calculation
        comp_rep: CompositeReputation = self.reputation_engine.calculate(
            results=provider_results,
            domain_meta=domain_meta,
        )

        domain_info_dict = domain_meta.to_dict() if domain_meta else None

        report = AggregatedThreatReport(
            target=norm_target,
            target_type=actual_type,
            composite_score=comp_rep.composite_score,
            verdict=comp_rep.verdict,
            confidence=comp_rep.confidence,
            sources_consulted=sources_consulted,
            sources_available=sources_available,
            sources_cached=sources_cached,
            cached=False,
            indicators=comp_rep.indicators,
            provider_details=provider_details,
            domain_info=domain_info_dict,
        )

        # 5. Store Composite in Cache
        self.cache_manager.set_reputation(
            target=norm_target,
            value=report.to_dict(),
            target_type=actual_type,
            ttl=ttl,
        )

        return report

    def clear_cache(self) -> None:
        """Flushes the threat cache."""
        self.cache_manager.clear()

    def cache_stats(self) -> Dict[str, Any]:
        """Returns cache telemetry."""
        return self.cache_manager.stats()


# Shared singleton aggregator
global_threat_aggregator = ThreatIntelligenceAggregator()
