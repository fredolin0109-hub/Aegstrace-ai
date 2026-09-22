import pytest
from aggregator import ThreatIntelligenceAggregator, AggregatedThreatReport
from providers.local_fallback import LocalFallbackProvider
from cache.cache_manager import ThreatCacheManager


def test_aggregator_target_type_detection():
    agg = ThreatIntelligenceAggregator()
    assert agg.detect_target_type("192.168.1.1") == "ip"
    assert agg.detect_target_type("https://evil.com/login") == "url"
    assert agg.detect_target_type("bad-domain.xyz") == "domain"


def test_aggregator_lookup_known_malicious():
    agg = ThreatIntelligenceAggregator()
    report = agg.lookup("paypa1.com", force_refresh=True)

    assert isinstance(report, AggregatedThreatReport)
    assert report.target == "paypa1.com"
    assert report.target_type == "domain"
    assert report.verdict == "HIGH_RISK"
    assert report.composite_score >= 0.70
    assert report.cached is False
    assert "local_dsa" in report.sources_available
    assert "local_dsa" in report.sources_consulted
    assert len(report.indicators) > 0


def test_aggregator_lookup_known_safe():
    agg = ThreatIntelligenceAggregator()
    report = agg.lookup("google.com", force_refresh=True)

    assert report.target == "google.com"
    assert report.verdict == "SAFE"
    assert report.composite_score == 0.0
    assert report.cached is False


def test_aggregator_caching_behavior():
    custom_cache = ThreatCacheManager(max_size=10, default_ttl=60.0)
    agg = ThreatIntelligenceAggregator(cache_manager=custom_cache)

    # First lookup: cache miss
    first_report = agg.lookup("example-cached.com")
    assert first_report.cached is False

    # Second lookup: cache hit
    second_report = agg.lookup("example-cached.com")
    assert second_report.cached is True
    assert second_report.target == first_report.target
    assert second_report.composite_score == first_report.composite_score

    # Force refresh bypasses cache
    refreshed_report = agg.lookup("example-cached.com", force_refresh=True)
    assert refreshed_report.cached is False


def test_aggregator_sources_tracking():
    agg = ThreatIntelligenceAggregator()
    report = agg.lookup("10.0.0.1", target_type="ip", force_refresh=True)

    assert "local_dsa" in report.sources_consulted
    assert "virustotal" in report.sources_consulted
    assert "abuseipdb" in report.sources_consulted
    # sources_available contains only providers with credentials or local availability
    assert "local_dsa" in report.sources_available


def test_aggregator_empty_target():
    agg = ThreatIntelligenceAggregator()
    report = agg.lookup("")
    assert report.target == ""
    assert report.verdict == "SAFE"
    assert report.composite_score == 0.0


def test_aggregator_url_normalization_ordering():
    agg = ThreatIntelligenceAggregator()
    report = agg.lookup("example.com/login", force_refresh=True)
    assert report.target_type == "url"
    assert report.target == "http://example.com/login"


def test_aggregator_per_provider_caching():
    custom_cache = ThreatCacheManager(max_size=20, default_ttl=300.0)
    agg = ThreatIntelligenceAggregator(cache_manager=custom_cache)

    rep1 = agg.lookup("test-provider-cache.org", force_refresh=True)
    assert rep1.cached is False

    # Check that individual provider cache has an entry
    cached_dsa = custom_cache.get_reputation("test-provider-cache.org", "domain", provider="local_dsa")
    assert cached_dsa is not None
    assert cached_dsa["source_name"] == "local_dsa"


def test_aggregator_multiple_malicious_consensus():
    from unittest.mock import MagicMock
    from providers.base import BaseThreatProvider, ProviderResult

    class MockMaliciousProvider(BaseThreatProvider):
        def __init__(self, name, score):
            super().__init__(source_name=name, weight=0.30)
            self._score = score

        def is_available(self):
            return True

        def lookup(self, target, target_type="domain"):
            return ProviderResult(
                source_name=self.source_name,
                is_malicious=True,
                threat_score=self._score,
                confidence=0.85,
                categories=["malware"],
            )

    p1 = MockMaliciousProvider("mock_feed_1", 0.75)
    p2 = MockMaliciousProvider("mock_feed_2", 0.72)
    agg = ThreatIntelligenceAggregator(providers=[p1, p2])

    report = agg.lookup("dangerous-site.org", force_refresh=True)
    assert report.verdict == "HIGH_RISK"
    assert report.composite_score >= 0.70
    assert len(report.sources_available) == 2

