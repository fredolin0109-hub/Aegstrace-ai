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
