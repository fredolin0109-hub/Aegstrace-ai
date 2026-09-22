import pytest
from providers.base import ProviderResult
from domain_info import DomainMetadata
from reputation import ReputationEngine, CompositeReputation


def test_reputation_empty_results():
    engine = ReputationEngine()
    rep = engine.calculate([])
    assert rep.composite_score == 0.05
    assert rep.verdict == "SAFE"
    assert rep.confidence == 0.50
    assert len(rep.indicators) == 0


def test_reputation_allowlist_safe_override():
    engine = ReputationEngine()
    safe_result = ProviderResult(
        source_name="local_dsa",
        is_malicious=False,
        threat_score=0.0,
        confidence=0.99,
        categories=["TRUSTED_ALLOWLIST"],
        available=True,
    )
    # Even if another provider had an ambiguous low score
    other_result = ProviderResult(
        source_name="alienvault_otx",
        is_malicious=False,
        threat_score=0.15,
        confidence=0.60,
        available=True,
    )
    rep = engine.calculate([safe_result, other_result])
    assert rep.composite_score == 0.0
    assert rep.verdict == "SAFE"
    assert rep.confidence == 0.99


def test_reputation_authoritative_malicious_override():
    engine = ReputationEngine()
    # High certainty malicious result
    vt_result = ProviderResult(
        source_name="virustotal",
        is_malicious=True,
        threat_score=0.95,
        confidence=0.95,
        categories=["phishing"],
        available=True,
    )
    # Neutral/quiet result from other provider
    neutral_result = ProviderResult(
        source_name="urlscan",
        is_malicious=False,
        threat_score=0.0,
        confidence=0.50,
        available=True,
    )
    rep = engine.calculate([vt_result, neutral_result])
    # Should not be diluted below HIGH_RISK threshold (>= 0.70)
    assert rep.composite_score >= 0.75
    assert rep.verdict == "HIGH_RISK"
    assert any(ind["type"] == "PROVIDER_THREAT_DETECTION" for ind in rep.indicators)


def test_reputation_weighted_consensus():
    engine = ReputationEngine()
    # Moderate suspicious findings across two providers
    res1 = ProviderResult(
        source_name="virustotal",
        is_malicious=True,
        threat_score=0.45,
        confidence=0.80,
        available=True,
    )
    res2 = ProviderResult(
        source_name="abuseipdb",
        is_malicious=True,
        threat_score=0.55,
        confidence=0.80,
        available=True,
    )
    rep = engine.calculate([res1, res2])
    assert 0.40 <= rep.composite_score <= 0.60
    assert rep.verdict == "SUSPICIOUS"
    assert rep.confidence >= 0.80


def test_reputation_domain_heuristics_impact():
    engine = ReputationEngine()
    # Mild provider score
    res = ProviderResult(
        source_name="local_dsa",
        is_malicious=False,
        threat_score=0.20,
        confidence=0.60,
        available=True,
    )
    domain_meta = DomainMetadata(
        domain="bad-phish.xyz",
        tld="xyz",
        is_suspicious_tld=True,
        entropy=4.1,
        is_high_entropy=True,
    )
    rep = engine.calculate([res], domain_meta=domain_meta)
    # Heuristics should bump score higher
    assert rep.composite_score > 0.35
    assert rep.verdict in ("SUSPICIOUS", "HIGH_RISK")
    assert any(ind["type"] == "SUSPICIOUS_TLD" for ind in rep.indicators)
    assert any(ind["type"] == "HIGH_ENTROPY_DOMAIN" for ind in rep.indicators)
