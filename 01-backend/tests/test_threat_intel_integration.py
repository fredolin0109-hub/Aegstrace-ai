import pytest


def test_threat_intel_lookup_benign(client):
    response = client.get("/api/threat-intel/lookup", params={"target": "google.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["target"] == "google.com"
    assert data["target_type"] == "domain"
    assert data["verdict"] == "SAFE"
    assert data["composite_score"] == 0.0
    assert "local_dsa" in data["sources_available"]


def test_threat_intel_lookup_malicious(client):
    response = client.get("/api/threat-intel/lookup", params={"target": "paypa1.com", "refresh": "true"})
    assert response.status_code == 200
    data = response.json()
    assert data["target"] == "paypa1.com"
    assert data["verdict"] == "HIGH_RISK"
    assert data["composite_score"] >= 0.70
    assert len(data["indicators"]) > 0
    assert "local_dsa" in data["sources_available"]


def test_threat_intel_lookup_ip(client):
    response = client.get("/api/threat-intel/lookup", params={"target": "127.0.0.1", "target_type": "ip"})
    assert response.status_code == 200
    data = response.json()
    assert data["target"] == "127.0.0.1"
    assert data["target_type"] == "ip"
    assert data["verdict"] == "SAFE"


def test_threat_intel_lookup_caching(client):
    unique_target = "cache-test-domain-109283.org"

    # First lookup: cache miss
    resp1 = client.get("/api/threat-intel/lookup", params={"target": unique_target, "refresh": "true"})
    assert resp1.status_code == 200
    assert resp1.json()["cached"] is False

    # Second lookup: cache hit
    resp2 = client.get("/api/threat-intel/lookup", params={"target": unique_target})
    assert resp2.status_code == 200
    assert resp2.json()["cached"] is True
    assert resp2.json()["target"] == unique_target

    # Third lookup with force refresh: cache bypassed
    resp3 = client.get("/api/threat-intel/lookup", params={"target": unique_target, "refresh": "true"})
    assert resp3.status_code == 200
    assert resp3.json()["cached"] is False


def test_threat_intel_validation_errors(client):
    # Missing target
    resp_missing = client.get("/api/threat-intel/lookup")
    assert resp_missing.status_code == 422

    # Empty target
    resp_empty = client.get("/api/threat-intel/lookup", params={"target": ""})
    assert resp_empty.status_code == 422


def test_threat_intel_stats(client):
    response = client.get("/api/threat-intel/stats")
    assert response.status_code == 200
    data = response.json()
    assert "cache_stats" in data
    assert "available_sources" in data
    assert "local_dsa" in data["available_sources"]


def test_scan_service_threat_intel_integration(client):
    # Benign scan with threat intel verification
    benign_resp = client.post("/api/analyze", json={"url": "https://www.google.com"})
    assert benign_resp.status_code == 200
    benign_data = benign_resp.json()
    assert benign_data["classification"] == "SAFE"
    assert "threat_intel" in benign_data["features"]
    assert benign_data["features"]["threat_intel"]["verdict"] == "SAFE"
    assert benign_data["threat_intel_verdict"] == "SAFE"

    # Malicious scan with threat intel verification
    mal_resp = client.post("/api/analyze", json={"url": "http://paypa1.com/account-verification"})
    assert mal_resp.status_code == 200
    mal_data = mal_resp.json()
    assert mal_data["classification"] == "HIGH_RISK"
    assert mal_data["threat_intel_verdict"] == "HIGH_RISK"
    assert mal_data["threat_intel_score"] >= 0.70
    assert any(ind["indicator_type"] in ("THREAT_INTEL_REPUTATION", "TYPOSQUATTING", "PROVIDER_THREAT_DETECTION") for ind in mal_data["indicators"])


def test_threat_intel_clear_cache_endpoint(client):
    # Prime cache
    _ = client.get("/api/threat-intel/lookup", params={"target": "clear-cache-domain.org"})

    # Clear cache
    clear_resp = client.post("/api/threat-intel/clear-cache")
    assert clear_resp.status_code == 200
    assert "flushed successfully" in clear_resp.json()["message"]

    # Verify cache is empty
    stats_resp = client.get("/api/threat-intel/stats")
    assert stats_resp.status_code == 200
    assert stats_resp.json()["cache_stats"]["size"] == 0


def test_threat_intel_invalid_target_type(client):
    resp = client.get("/api/threat-intel/lookup", params={"target": "example.com", "target_type": "invalid_type"})
    assert resp.status_code == 422
    assert "target_type must be one of" in resp.json()["detail"]


def test_threat_intel_sources_cached_field(client):
    resp = client.get("/api/threat-intel/lookup", params={"target": "example.com", "refresh": "true"})
    assert resp.status_code == 200
    data = resp.json()
    assert "sources_cached" in data
    assert isinstance(data["sources_cached"], list)


def test_evaluate_heuristics_preserves_prior_score_with_ti_indicators():
    from app.services.scan_service import evaluate_heuristics

    # Baseline features
    features = {
        "is_ip_address": False,
        "has_at_symbol": False,
        "is_suspicious_tld": False,
        "subdomain_count": 0,
        "detected_keywords": [],
        "is_https": True,
        "url_length": 25,
        "tld": "com",
    }
    # Simulate ML result predicting high risk 0.85
    ml_result = {
        "risk_score": 0.85,
        "classification": "HIGH_RISK",
        "confidence": 0.90,
    }
    # Simulate Threat Intel report with a provider detection that has a lower score 0.40
    threat_intel_report = {
        "composite_score": 0.40,
        "verdict": "SUSPICIOUS",
        "confidence": 0.70,
        "indicators": [
            {
                "type": "PROVIDER_THREAT_DETECTION",
                "source": "virustotal",
                "severity": "MEDIUM",
                "details": {"threat_score": 0.40, "categories": ["phish"]},
            }
        ],
    }

    score, classification, confidence, recommendation, indicators = evaluate_heuristics(
        features=features,
        domain="suspicious-ml.com",
        ml_result=ml_result,
        threat_intel_report=threat_intel_report,
    )

    # Score must NOT have been overwritten by 0.40; it must remain >= 0.85 from ML
    assert score >= 0.85
    assert classification == "HIGH_RISK"


