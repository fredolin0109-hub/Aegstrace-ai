def test_analyze_benign_url(client):
    payload = {"url": "https://www.google.com"}
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["url"] == "https://www.google.com"
    assert data["domain"] == "www.google.com"
    assert data["classification"] == "SAFE"
    assert data["risk_score"] < 0.35
    assert data["recommendation"] == "ALLOW"
    assert "features" in data
    assert data["features"]["is_https"] is True


def test_analyze_suspicious_phishing_url(client):
    payload = {"url": "http://192.168.1.50/login-paypal-verify.php?auth=true"}
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == "HIGH_RISK"
    assert data["risk_score"] >= 0.70
    assert data["recommendation"] == "BLOCK"
    assert len(data["indicators"]) > 0
    indicator_types = [ind["indicator_type"] for ind in data["indicators"]]
    assert "IP_HOST" in indicator_types


def test_analyze_suspicious_tld_and_subdomains(client):
    payload = {"url": "http://secure.account.billing.update.verify.evil-login.xyz/signin"}
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] >= 0.35
    assert data["classification"] in ("SUSPICIOUS", "HIGH_RISK")
    assert len(data["indicators"]) > 0


def test_analyze_missing_or_invalid_url(client):
    # Empty string should fail validation
    response = client.post("/api/analyze", json={"url": ""})
    assert response.status_code in (400, 422)

    # Missing url key
    response = client.post("/api/analyze", json={})
    assert response.status_code == 422


def test_url_feature_extraction_caching():
    from app.services.cache_service import clear_scan_caches, url_features_cache
    from app.services.scan_service import extract_url_features

    clear_scan_caches()
    url = "https://example.com/test-page"
    domain = "example.com"
    is_ip = False

    # First call: cache miss, calculates features
    feat1 = extract_url_features(url, domain, is_ip)
    stats1 = url_features_cache.stats()
    assert stats1["hits"] == 0
    assert stats1["misses"] == 1

    # Second call: cache hit, returns cached result
    feat2 = extract_url_features(url, domain, is_ip)
    stats2 = url_features_cache.stats()
    assert stats2["hits"] == 1
    assert feat1 == feat2


def test_dsa_analysis_caching(db_session):
    from unittest.mock import patch
    from app.services.cache_service import clear_scan_caches, dsa_analysis_cache
    from app.services.scan_service import perform_scan, global_dsa_engine

    clear_scan_caches()
    raw_url = "https://cache-test-domain.com/login"

    with patch.object(global_dsa_engine, "analyze_url_dsa", wraps=global_dsa_engine.analyze_url_dsa) as mock_dsa:
        # First scan: DSA engine executes
        scan1 = perform_scan(db=db_session, raw_url=raw_url)
        assert mock_dsa.call_count == 1

        # Second scan: DSA engine is NOT executed again (cache hit)
        scan2 = perform_scan(db=db_session, raw_url=raw_url)
        assert mock_dsa.call_count == 1
        assert dsa_analysis_cache.stats()["hits"] == 1

        assert scan1.risk_score == scan2.risk_score
        assert scan1.classification == scan2.classification

