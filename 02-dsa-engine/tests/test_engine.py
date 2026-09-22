import pytest
from engine import DSAEngine


def test_dsa_engine_trusted_domain():
    engine = DSAEngine()
    result = engine.analyze_url_dsa(
        raw_url="https://google.com/search?q=cybersecurity",
        domain="google.com"
    )

    assert result.dsa_verdict == "SAFE"
    assert result.dsa_risk_score == 0.0
    assert result.known_domain_match is not None
    assert result.known_domain_match["category"] == "SAFE"


def test_dsa_engine_known_malicious_typosquat():
    engine = DSAEngine()
    result = engine.analyze_url_dsa(
        raw_url="http://paypa1.com/login-verify",
        domain="paypa1.com"
    )

    assert result.dsa_verdict == "HIGH_RISK"
    assert result.dsa_risk_score >= 0.90
    assert result.known_domain_match is not None
    assert result.known_domain_match["threat_type"] == "TYPOSQUATTING"
    assert len(result.trie_matches) > 0


def test_dsa_engine_pattern_and_graph_analysis():
    engine = DSAEngine()
    result = engine.analyze_url_dsa(
        raw_url="http://unknown-domain.com/banking-online/metamask-restore",
        domain="unknown-domain.com",
        ip_address="198.51.100.2"
    )

    assert result.dsa_risk_score >= 0.40
    assert result.graph_summary["total_nodes"] >= 3
    patterns = [m["pattern"] for m in result.trie_matches]
    assert "banking-online" in patterns
    assert "metamask-restore" in patterns


def test_dsa_engine_subdomain_and_cctld_fallback():
    engine = DSAEngine()
    # Add a ccTLD threat entry
    engine.domain_hashmap.put("paypa1.co.uk", category="MALICIOUS", reputation_score=0.96, threat_type="TYPOSQUATTING")

    # Multi-level subdomain under ccTLD
    res_cctld = engine.analyze_url_dsa(
        raw_url="http://login.verify.paypa1.co.uk/auth",
        domain="login.verify.paypa1.co.uk"
    )
    assert res_cctld.dsa_verdict == "HIGH_RISK"
    assert res_cctld.known_domain_match is not None
    assert res_cctld.known_domain_match["domain"] == "paypa1.co.uk"

    # Multi-level subdomain under standard domain
    res_safe = engine.analyze_url_dsa(
        raw_url="https://mail.corp.google.com/inbox",
        domain="mail.corp.google.com"
    )
    assert res_safe.dsa_verdict == "SAFE"
    assert res_safe.dsa_risk_score == 0.0


def test_dsa_engine_redirect_loop_detection():
    engine = DSAEngine()
    res = engine.analyze_url_dsa(
        raw_url="http://short.url/start",
        domain="short.url",
        redirect_chain=[
            "http://hop1.com",
            "http://hop2.com",
            "http://hop1.com"
        ]
    )
    assert res.graph_summary["has_redirect_loop"] is True
    assert any(ind["indicator_type"] == "GRAPH_REDIRECT_LOOP" for ind in res.detected_indicators)
    assert res.dsa_risk_score >= 0.35


def test_dsa_engine_suspicious_domain_handling():
    engine = DSAEngine()
    engine.domain_hashmap.put("gray-reputation.net", category="SUSPICIOUS", reputation_score=0.60, threat_type="UNVERIFIED")

    res = engine.analyze_url_dsa(
        raw_url="https://gray-reputation.net/download",
        domain="gray-reputation.net"
    )
    assert res.dsa_verdict == "SUSPICIOUS"
    assert res.dsa_risk_score >= 0.60
    assert any(ind["indicator_type"] == "KNOWN_SUSPICIOUS_DOMAIN" for ind in res.detected_indicators)
